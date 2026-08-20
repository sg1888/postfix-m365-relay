<#
.SYNOPSIS
  Configure Exchange Online for a Postfix XOAUTH2 mail relay.

.DESCRIPTION
  Does the tenant-side work that can be automated, checks each step, and prints
  the values to paste into config/mail-relay.conf.

  It grants exactly what has been measured as necessary and nothing else:

    SMTP.SendAsApp    application permission (you consent in the portal)
    service principal Exchange's record of the application
    FullAccess        on the relay mailbox

  It does NOT grant SendAs, does NOT create an application access policy, and
  does NOT create a management scope or role assignment. They are not part of
  the documented minimum SMTP app-only permission model.

.PARAMETER Mailbox
  The relay mailbox. Must be a LICENSED REGULAR USER MAILBOX -- a shared mailbox
  authenticates and then fails at submission with an error that reads like a
  permissions problem, cannot carry a per-application From display name, and
  cannot have an application access policy applied to it.

.PARAMETER ClientId
  Application (client) ID of the app registration. To share one registration
  between projects, pass the same value -- see mail-relay.conf.example.

.PARAMETER EnterpriseAppObjectId
  Object ID of the ENTERPRISE APPLICATION, from Entra > Enterprise applications
  > your app > Object ID. This is a DIFFERENT GUID from the app registration's
  object ID, on a different blade. Confusing the two is the most common failure
  in this step. Only needed when the service principal does not yet exist.

.PARAMETER WhatIfOnly
  Report what would change and change nothing.

.PARAMETER EnableSendFromAlias
  Opt in to enabling SendFromAliasEnabled for the whole Exchange organization.
  Required only for passthrough mode; collapse mode does not need it.

.EXAMPLE
  .\setup-exchange.ps1 -Mailbox relay@example.com `
      -ClientId 00000000-1111-2222-3333-444444444444 `
      -EnterpriseAppObjectId 55555555-6666-7777-8888-999999999999

.NOTES
  TIMING. Exchange permission changes have been measured taking up to 90
  minutes to take effect. A probe run within two hours of a change carries no
  information -- not weak evidence, none. If you change something after running
  this, wait two hours before concluding anything about the result.

  Enable the tenant audit log before you start, so changes can be timestamped:
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$ClientId,
    [string]$EnterpriseAppObjectId,
    [string]$DisplayName = "Mail relay",
    [switch]$EnableSendFromAlias,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
$script:Problems = @()
$script:EnabledSendFromAlias = $false

function Step   { param($n, $t) Write-Host "`n=== $n. $t ===" -ForegroundColor Cyan }
function Good   { param($m) Write-Host "  ok      $m" -ForegroundColor Green }
function Warn   { param($m) Write-Host "  warn    $m" -ForegroundColor Yellow }
function Bad    { param($m) Write-Host "  FAILED  $m" -ForegroundColor Red; $script:Problems += $m }
function Manual { param($m) Write-Host "  MANUAL  $m" -ForegroundColor Magenta }

# --- connect -----------------------------------------------------------------
Step 0 "Connect to Exchange Online"

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "  installing ExchangeOnlineManagement..."
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
}
Import-Module ExchangeOnlineManagement

try   { Get-OrganizationConfig | Out-Null; Good "already connected" }
catch { Connect-ExchangeOnline -ShowBanner:$false; Good "connected" }

# --- audit log ---------------------------------------------------------------
Step 1 "Tenant audit log"

$audit = Get-AdminAuditLogConfig
if ($audit.UnifiedAuditLogIngestionEnabled) {
    Good "unified audit log is on -- permission changes will be timestamped"
} else {
    Warn "unified audit log is OFF. Turn it on before changing anything:"
    Warn "  Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$true"
    Warn "Without it, a permission change cannot be timed against the relay's log,"
    Warn "which is what made the original outage take a day to diagnose."
}

# --- mailbox -----------------------------------------------------------------
Step 2 "The mailbox"

$mb = Get-Mailbox -Identity $Mailbox -ErrorAction SilentlyContinue
if (-not $mb) {
    Bad "mailbox $Mailbox not found. Create it in the M365 admin centre first."
    Manual "It must be a regular user mailbox with a licence (Exchange Online Plan 1 is enough)."
    Manual "Block sign-in: app-only OAuth never signs in, so it costs nothing."
    Manual "Use a purpose-built mailbox that receives no real mail -- the application"
    Manual "will be able to read it, and FullAccess is required."
    exit 1
}

if ($mb.RecipientTypeDetails -eq 'UserMailbox') {
    Good "RecipientTypeDetails = UserMailbox"
} else {
    Bad "RecipientTypeDetails = $($mb.RecipientTypeDetails). Must be UserMailbox."
    Manual "Convert it:  Set-Mailbox -Identity $Mailbox -Type Regular"
    Manual "A shared mailbox authenticates fine and then fails at submission with"
    Manual "430 STOREDRV mailbox logon failure, which reads like a permissions fault."
}

if ($mb.SkuAssigned) { Good "licence assigned" }
else {
    Bad "no licence. Unlicensed mailboxes cannot use SMTP AUTH."
    Manual "Assign one in the M365 admin centre, then re-run."
}

# --- SMTP AUTH ---------------------------------------------------------------
Step 3 "SMTP AUTH on the mailbox"

$cas = Get-CASMailbox -Identity $Mailbox
if ($cas.SmtpClientAuthenticationDisabled -eq $false) {
    Good "SmtpClientAuthenticationDisabled = False"
} elseif ($WhatIfOnly) {
    Warn "would run: Set-CASMailbox -Identity $Mailbox -SmtpClientAuthenticationDisabled `$false"
} else {
    Set-CASMailbox -Identity $Mailbox -SmtpClientAuthenticationDisabled $false
    Good "enabled on this mailbox only"
}

$org = Get-TransportConfig
Good "org-wide SmtpClientAuthenticationDisabled = $($org.SmtpClientAuthenticationDisabled) (True is correct; the per-mailbox setting overrides it)"

# --- service principal -------------------------------------------------------
Step 4 "Exchange service principal"

$sp = Get-ServicePrincipal -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $ClientId }
if ($sp) {
    Good "exists -- Identity $($sp.Identity)"
} elseif ($WhatIfOnly) {
    Warn "would create a service principal for $ClientId"
} elseif (-not $EnterpriseAppObjectId) {
    Bad "no service principal, and -EnterpriseAppObjectId was not supplied."
    Manual "Entra > Enterprise applications > your app > Object ID."
    Manual "NOT the app registration's object ID -- different GUID, different blade."
    exit 1
} else {
    New-ServicePrincipal -AppId $ClientId -ObjectId $EnterpriseAppObjectId -DisplayName $DisplayName | Out-Null
    $sp = Get-ServicePrincipal | Where-Object { $_.AppId -eq $ClientId }
    Good "created -- Identity $($sp.Identity)"
}

# --- mailbox permission ------------------------------------------------------
Step 5 "FullAccess on the mailbox"

if ($sp) {
    $existing = Get-MailboxPermission -Identity $Mailbox |
        Where-Object { $_.User -notlike 'NT AUTHORITY*' -and $_.AccessRights -contains 'FullAccess' -and -not $_.Deny }

    if ($existing) {
        Good "already granted to: $($existing.User -join ', ')"
        Good "(Get-MailboxPermission prints display names, not GUIDs -- compare names, not shapes)"
    } elseif ($WhatIfOnly) {
        Warn "would run: Add-MailboxPermission -Identity $Mailbox -User $($sp.Identity) -AccessRights FullAccess"
    } else {
        Add-MailboxPermission -Identity $Mailbox -User $sp.Identity -AccessRights FullAccess -Confirm:$false | Out-Null
        Good "granted"
        Warn "This can take up to 90 minutes to take effect. A probe before then proves nothing."
    }
}

# --- what must not be there --------------------------------------------------
Step 6 "Check for things that should NOT exist"

$policies = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $ClientId }
if ($policies) {
    Warn "$($policies.Count) application access policy/policies exist for this AppId:"
    $policies | ForEach-Object { Warn "  $($_.ScopeName) -- $($_.AccessRight)" }
    Warn "Not required for SMTP. A RestrictAccess policy is a RESTRAINT, not a grant --"
    Warn "deleting one WIDENS what the app may open, and several for one AppId union"
    Warn "together. Check Test-ApplicationAccessPolicy returns Granted for $Mailbox."
} else {
    Good "no application access policy -- correct"
}

$roles = Get-ManagementRoleAssignment -ErrorAction SilentlyContinue |
    Where-Object { $_.RoleAssigneeName -match [regex]::Escape($DisplayName) }
if ($roles) {
    Warn "management role assignment(s) found: $($roles.Name -join ', ')"
    Warn "Application Mail.Send scopes GRAPH, not SMTP. Not needed here."
} else {
    Good "no management role assignment -- correct"
}

$sendAs = Get-RecipientPermission -Identity $Mailbox -ErrorAction SilentlyContinue |
    Where-Object { $_.Trustee -notlike 'NT AUTHORITY*' }
if ($sendAs) {
    Warn "SendAs is granted to: $($sendAs.Trustee -join ', ')"
    Warn "Not required by this design -- the relay rewrites every envelope to the"
    Warn "mailbox it authenticates as, so sending-as-another-identity never happens."
    Warn "Harmless to keep. If you remove it, wait two hours before believing the result."
} else {
    Good "no SendAs -- correct"
}

# --- same-mailbox aliases ----------------------------------------------------
Step 7 "Same-mailbox alias sending (passthrough mode only)"

$aliasConfig = Get-OrganizationConfig
if ($aliasConfig.SendFromAliasEnabled) {
    Good "SendFromAliasEnabled is already on for the organization"
} elseif (-not $EnableSendFromAlias) {
    Warn "left off. Collapse mode does not need this."
    Warn "For passthrough mode, review the org-wide impact and re-run with -EnableSendFromAlias."
} elseif ($WhatIfOnly) {
    Warn "would enable SendFromAliasEnabled for the ENTIRE Exchange organization"
} else {
    Warn "ORG-WIDE CHANGE: this enables sending from aliases for every mailbox in the tenant."
    Set-OrganizationConfig -SendFromAliasEnabled $true
    $script:EnabledSendFromAlias = $true
    Good "enabled SendFromAliasEnabled org-wide"
    Warn "Wait two hours before an SMTP XOAUTH2 alias test carries any information."
}

# --- what you still have to do by hand ---------------------------------------
Step 8 "Manual steps -- these need a browser"

Manual "1. App registration > API permissions > Add a permission"
Manual "   > 'APIs my organization uses' tab (NOT Microsoft Graph)"
Manual "   > Office 365 Exchange Online > Application permissions > SMTP.SendAsApp"
Manual "   > Add, then GRANT ADMIN CONSENT. The row must read 'Granted'."
Manual ""
Manual "2. App registration > Certificates & secrets > Certificates > Upload"
Manual "   Start the container once. Its log prints the PUBLIC certificate and"
Manual "   SHA-1 thumbprint. Upload only that public PEM; the private key stays"
Manual "   in the mail-relay-state volume."
Manual ""
Manual "3. Do NOT add Mail.Read or Mail.ReadWrite. Nothing here reads mail, and"
Manual "   certificate rotation works with roles: [] -- measured."
Manual ""
Manual "4. Do NOT assign users to the enterprise application. Client-credentials"
Manual "   flows do not use interactive user assignments."

# --- output ------------------------------------------------------------------
Step 9 "Values for config/mail-relay.conf"

$tenantId = (Get-OrganizationConfig).Guid
Write-Host ""
Write-Host "MAIL_RELAY_TENANT=$tenantId"
Write-Host "MAIL_RELAY_CLIENT_ID=$ClientId"
Write-Host "MAIL_RELAY_ENTERPRISE_APP_OBJECT_ID=$EnterpriseAppObjectId"
Write-Host "MAIL_SEND_MAILBOX=$Mailbox"
Write-Host "# Certificate thumbprint is derived from the certificate in the state volume."
Write-Host "# SendFromAliasEnabled changed by this run: $script:EnabledSendFromAlias"
Write-Host ""

if ($script:Problems) {
    Write-Host "$($script:Problems.Count) problem(s) must be fixed before the relay will work:" -ForegroundColor Red
    $script:Problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Tenant side is ready, subject to the manual steps in section 8." -ForegroundColor Green
Write-Host "If you changed a permission just now, wait two hours before testing." -ForegroundColor Yellow
