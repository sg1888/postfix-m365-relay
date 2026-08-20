<#
.SYNOPSIS
  Configure Exchange Online for a Postfix XOAUTH2 mail relay.

.DESCRIPTION
  Does the tenant-side work that can be automated, checks each step, and prints
  the values to paste into config/mail-relay.conf.

  It configures the current claims-less Exchange App RBAC path:

    service principal              Exchange's record of the Entra application
    management scope               mailboxes in one dedicated group
    Application SMTP.SendAsApp     SMTP submission within that scope

  The app registration intentionally has no API permissions. In particular,
  do not add the similarly named Office 365 Exchange Online application
  permission SMTP.SendAsApp: Microsoft says that claim triggers an unnecessary
  mailbox-permission check when App RBAC is used. No FullAccess or SendAs
  mailbox permission is required by this path.

.PARAMETER Mailbox
  The relay mailbox. A purpose-built unlicensed shared mailbox is recommended.
  Shared mailboxes need no separate license up to 50 GB unless licensed
  archiving, hold, or advanced compliance features are required. A licensed
  regular user mailbox remains supported but normally wastes a license here.

.PARAMETER ScopeGroup
  Identity or email address of a dedicated Exchange distribution group or
  mail-enabled security group whose direct members are the mailboxes this app
  may submit as. The script obtains its DistinguishedName itself; do not paste a
  guessed DN into a filter.

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
      -ScopeGroup postfix-m365-relay-mailboxes@example.com `
      -ClientId 00000000-1111-2222-3333-444444444444 `
      -EnterpriseAppObjectId 55555555-6666-7777-8888-999999999999

.NOTES
  TIMING. Exchange permission changes have been measured taking up to 90
  minutes to take effect. A probe run within two hours of a change carries no
  information -- not weak evidence, none. If you change something after running
  this, wait two hours before concluding anything about the result.

  Enable the tenant audit log before you start, so changes can be timestamped:
    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

.LINK
  https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/smtp-app-rbac-onboarding
.LINK
  https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac
.LINK
  https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/test-serviceprincipalauthorization?view=exchange-ps
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$ScopeGroup,
    [Parameter(Mandatory)][string]$ClientId,
    [string]$EnterpriseAppObjectId,
    [string]$DisplayName = "Mail relay",
    [string]$ScopeName,
    [string]$RoleAssignmentName,
    [switch]$EnableSendFromAlias,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
$script:Problems = @()
$script:EnabledSendFromAlias = $false

# Defaults include the first client-ID segment so two relay applications can
# coexist without silently reusing one another's scope or assignment names.
$clientLabel = ($ClientId -split '-')[0]
if (-not $ScopeName) { $ScopeName = "postfix-m365-relay-$clientLabel-mailboxes" }
if (-not $RoleAssignmentName) { $RoleAssignmentName = "postfix-m365-relay-$clientLabel-smtp" }

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
    Manual "Recommended: create a purpose-built shared mailbox and block sign-in."
    Manual "The shared mailbox needs no separate license up to 50 GB unless you"
    Manual "enable a licensed archive, hold, or advanced compliance feature."
    exit 1
}

switch ($mb.RecipientTypeDetails) {
    'SharedMailbox' {
        Good "RecipientTypeDetails = SharedMailbox (recommended)"
        if ($mb.SkuAssigned) {
            Warn "a license is assigned; it is unnecessary below 50 GB unless this"
            Warn "mailbox uses licensed archive, hold, or advanced compliance features"
        } else {
            Good "no mailbox license assigned (supported for a shared mailbox up to 50 GB)"
        }
    }
    'UserMailbox' {
        Warn "RecipientTypeDetails = UserMailbox; supported, but a shared mailbox is recommended"
        if ($mb.SkuAssigned) { Good "regular mailbox license assigned" }
        else { Bad "an unlicensed UserMailbox is unsupported; convert it to SharedMailbox or license it" }
    }
    default {
        Bad "RecipientTypeDetails = $($mb.RecipientTypeDetails). Use SharedMailbox or UserMailbox."
    }
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

# --- group, scope, and App RBAC role ----------------------------------------
Step 5 "Scoped Application SMTP.SendAsApp role"

$scopeGroupObject = Get-DistributionGroup -Identity $ScopeGroup -ErrorAction SilentlyContinue
if (-not $scopeGroupObject) {
    Bad "scope group $ScopeGroup was not found. Create a dedicated distribution"
    Manual "or mail-enabled security group, then add $Mailbox as a direct member."
} else {
    Good "scope group = $($scopeGroupObject.PrimarySmtpAddress)"
    $members = Get-DistributionGroupMember -Identity $scopeGroupObject.Identity -ResultSize Unlimited
    $mailboxIsMember = $members | Where-Object {
        $_.PrimarySmtpAddress -and $_.PrimarySmtpAddress.ToString() -ieq $mb.PrimarySmtpAddress.ToString()
    }
    if ($mailboxIsMember) {
        Good "$Mailbox is a direct group member"
    } else {
        Bad "$Mailbox is not a direct member of $($scopeGroupObject.PrimarySmtpAddress)"
        Manual "Add-DistributionGroupMember -Identity '$($scopeGroupObject.Identity)' -Member '$Mailbox'"
    }

    # Microsoft documents MemberOfGroup using the group's actual Exchange DN.
    # Doubling a single quote is OPATH escaping; interpolating an email address
    # or a hand-built CN here is a common way to create a valid but empty scope.
    $escapedGroupDn = $scopeGroupObject.DistinguishedName.Replace("'", "''")
    $scopeFilter = "MemberOfGroup -eq '$escapedGroupDn'"
    $scope = Get-ManagementScope -Identity $ScopeName -ErrorAction SilentlyContinue
    if (-not $scope) {
        if ($WhatIfOnly) {
            Warn "would create management scope '$ScopeName' with $scopeFilter"
        } else {
            New-ManagementScope -Name $ScopeName -RecipientRestrictionFilter $scopeFilter | Out-Null
            $scope = Get-ManagementScope -Identity $ScopeName
            Good "created management scope $ScopeName"
        }
    } elseif (
        $scope.RecipientRestrictionFilter -notmatch 'MemberOfGroup' -or
        $scope.RecipientRestrictionFilter -notmatch [regex]::Escape($scopeGroupObject.DistinguishedName)
    ) {
        Bad "existing scope $ScopeName does not target this group's DistinguishedName; refusing to reuse it"
    } else {
        Good "management scope $ScopeName already exists"
    }

    $assignment = Get-ManagementRoleAssignment -Identity $RoleAssignmentName -ErrorAction SilentlyContinue
    if (-not $assignment -and $scope -and $sp) {
        if ($WhatIfOnly) {
            Warn "would assign 'Application SMTP.SendAsApp' to $ClientId in scope '$ScopeName'"
        } else {
            New-ManagementRoleAssignment -Name $RoleAssignmentName `
                -Role 'Application SMTP.SendAsApp' -App $ClientId `
                -CustomResourceScope $ScopeName | Out-Null
            $assignment = Get-ManagementRoleAssignment -Identity $RoleAssignmentName
            Good "created role assignment $RoleAssignmentName"
            Warn "Exchange authorization caches can take time; wait two hours before SMTP conclusions."
        }
    } elseif ($assignment) {
        if ($assignment.Role -ne 'Application SMTP.SendAsApp') {
            Bad "existing assignment $RoleAssignmentName has role $($assignment.Role), not Application SMTP.SendAsApp"
        } elseif ($assignment.CustomResourceScope -ne $ScopeName) {
            Bad "existing assignment $RoleAssignmentName uses scope $($assignment.CustomResourceScope), not $ScopeName"
        } else {
            Good "role assignment $RoleAssignmentName already exists"
        }
    }

    if ($sp -and -not $WhatIfOnly) {
        $authorization = Test-ServicePrincipalAuthorization -Identity $sp.Identity -Resource $Mailbox |
            Where-Object { $_.RoleName -eq 'Application SMTP.SendAsApp' }
        if ($authorization -and $authorization.InScope -eq $true) {
            Good "Test-ServicePrincipalAuthorization: Application SMTP.SendAsApp InScope=True"
        } else {
            Warn "authorization test is not InScope=True yet. Recheck group membership,"
            Warn "scope, and role assignment; if just changed, allow the two-hour cache window."
        }
    }
}

# --- legacy/additive grants --------------------------------------------------
Step 6 "Check for legacy or additive grants"

$policies = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $ClientId }
if ($policies) {
    Warn "$($policies.Count) application access policy/policies exist for this AppId:"
    $policies | ForEach-Object { Warn "  $($_.ScopeName) -- $($_.AccessRight)" }
    Warn "Application Access Policies are superseded by App RBAC for this relay."
    Warn "Do not delete one casually: Entra grants and App RBAC grants are additive,"
    Warn "and changing a restraint can widen access. Audit it separately."
} else {
    Good "no legacy Application Access Policy found"
}

$unexpectedRoles = Get-ManagementRoleAssignment -ErrorAction SilentlyContinue |
    Where-Object {
        $_.RoleAssigneeName -match [regex]::Escape($DisplayName) -and
        $_.Name -ne $RoleAssignmentName
    }
if ($unexpectedRoles) {
    Warn "additional application role assignment(s) found: $($unexpectedRoles.Name -join ', ')"
    Warn "App RBAC and Entra API permissions are additive. Confirm each extra role"
    Warn "is intended; this script requires only Application SMTP.SendAsApp."
} else {
    Good "no additional App RBAC role assignments found for this display name"
}

$fullAccess = Get-MailboxPermission -Identity $Mailbox -ErrorAction SilentlyContinue |
    Where-Object { $_.User -notlike 'NT AUTHORITY*' -and $_.AccessRights -contains 'FullAccess' -and -not $_.Deny }
if ($fullAccess) {
    Warn "FullAccess mailbox permission(s) exist: $($fullAccess.User -join ', ')"
    Warn "The claims-less Application SMTP.SendAsApp path does not require FullAccess."
    Warn "Review ownership before removing legacy access; this script will not remove it."
} else {
    Good "no FullAccess mailbox permission -- correct for claims-less App RBAC"
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

Manual "1. App registration > API permissions: leave the application with NO"
Manual "   API permissions. If Office 365 Exchange Online SMTP.SendAsApp was"
Manual "   added for an older setup, remove it. App RBAC uses the Exchange role"
Manual "   named 'Application SMTP.SendAsApp', not an Entra permission claim."
Manual ""
Manual "2. App registration > Certificates & secrets > Certificates > Upload"
Manual "   Start the container once. Its log prints the PUBLIC certificate and"
Manual "   SHA-1 thumbprint. Upload only that public PEM; the private key stays"
Manual "   in the mail-relay-state volume."
Manual ""
Manual "3. Do NOT add Mail.Read, Mail.ReadWrite, Mail.Send, or SMTP.SendAsApp"
Manual "   under API permissions. The claims-less Outlook token has roles: []."
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
Write-Host "# Exchange App RBAC scope group: $ScopeGroup"
Write-Host "# Exchange management scope: $ScopeName"
Write-Host "# Exchange role assignment: $RoleAssignmentName"
Write-Host "# Certificate thumbprint is derived from the certificate in the state volume."
Write-Host "# SendFromAliasEnabled changed by this run: $script:EnabledSendFromAlias"
Write-Host ""

if ($script:Problems) {
    Write-Host "$($script:Problems.Count) problem(s) must be fixed before the relay will work:" -ForegroundColor Red
    $script:Problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Tenant side is configured for claims-less Exchange App RBAC, subject to section 8." -ForegroundColor Green
Write-Host "If you changed a permission just now, wait two hours before testing." -ForegroundColor Yellow
