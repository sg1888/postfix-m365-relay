<#
.SYNOPSIS
  Reverse everything setup-exchange.ps1 did to Exchange Online.

.DESCRIPTION
  Removes, in dependency order, the claims-less App RBAC objects created by the
  setup script:

    role assignment   Application SMTP.SendAsApp within the mailbox scope
    management scope  optional; may be shared with another assignment
    service principal optional; may be shared with another relay
    SMTP AUTH         optional per-mailbox override, back to tenant default

  It does NOT touch the mailbox, the app registration, the enterprise
  application, or the certificate. Those can be shared with
  anything else using the same identity, and deleting an app registration
  destroys a credential that other systems may still hold.

  Everything is shown before it is removed, and nothing is removed without
  -Confirm being answered or -Force being passed.

.PARAMETER Mailbox
  The relay mailbox to clean up.

.PARAMETER ClientId
  Application (client) ID whose grants should be removed.

.PARAMETER RemoveServicePrincipal
  Also remove the Exchange service principal. Off by default: if a second
  project shares this application, removing it breaks that project too, and it
  is the object every Exchange App RBAC assignment points at.

.PARAMETER RemoveManagementScope
  Also remove the named management scope after its role assignment is gone.
  Off by default because another application role can reuse the same scope.

.PARAMETER RestoreSmtpAuthDefault
  Set SmtpClientAuthenticationDisabled back to $null on the mailbox, so it
  inherits the organisation default again.

.PARAMETER DisableSendFromAlias
  Disable alias sending for the whole organization. Never automatic: the setup
  script cannot know whether another administrator or workload relies on it.

.PARAMETER WhatIfOnly
  Report what would be removed and remove nothing.

.PARAMETER Force
  Skip confirmation. Intended for scripted teardown of a test tenant.

.EXAMPLE
  .\undo-exchange.ps1 -Mailbox relay@example.com -ClientId 0000... -WhatIfOnly

.EXAMPLE
  .\undo-exchange.ps1 -Mailbox relay@example.com -ClientId 0000... `
      -RemoveServicePrincipal -RestoreSmtpAuthDefault

.NOTES
  TIMING. Exchange permission changes take up to 90 minutes to take effect.
  Mail may keep flowing for over an hour after this script reports success.
  That is not a failure and it is not proof the removal did not work -- it is
  the same propagation delay that makes diagnosis here so treacherous.

  Do not run this expecting to observe an immediate result. If you are
  bisecting rather than decommissioning, remove ONE thing, wait two hours, and
  keep a send test running throughout.

  Before decommissioning: raise MAIL_QUEUE_LIFETIME so anything queued during
  the transition survives, then stop the container. Lifecycle loops are inside it.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Mailbox,
    [Parameter(Mandatory)][string]$ClientId,
    [string]$ScopeName,
    [string]$RoleAssignmentName,
    [switch]$RemoveManagementScope,
    [switch]$RemoveServicePrincipal,
    [switch]$RestoreSmtpAuthDefault,
    [switch]$DisableSendFromAlias,
    [switch]$WhatIfOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:Removed = @()
$script:Skipped = @()
$clientLabel = ($ClientId -split '-')[0]
if (-not $ScopeName) { $ScopeName = "postfix-m365-relay-$clientLabel-mailboxes" }
if (-not $RoleAssignmentName) { $RoleAssignmentName = "postfix-m365-relay-$clientLabel-smtp" }

function Step { param($n, $t) Write-Host "`n=== $n. $t ===" -ForegroundColor Cyan }
function Good { param($m) Write-Host "  ok      $m" -ForegroundColor Green }
function Note { param($m) Write-Host "  --      $m" -ForegroundColor DarkGray }
function Warn { param($m) Write-Host "  warn    $m" -ForegroundColor Yellow }

function Confirm-Removal {
    param([string]$What)
    if ($WhatIfOnly) { Warn "would remove: $What"; $script:Skipped += $What; return $false }
    if ($Force)      { return $true }
    $answer = Read-Host "  Remove $What ? [y/N]"
    if ($answer -match '^(y|yes)$') { return $true }
    Note "skipped by operator: $What"
    $script:Skipped += $What
    return $false
}

# --- connect -----------------------------------------------------------------
Step 0 "Connect to Exchange Online"

Import-Module ExchangeOnlineManagement
try   { Get-OrganizationConfig | Out-Null; Good "already connected" }
catch { Connect-ExchangeOnline -ShowBanner:$false; Good "connected" }

$sp = Get-ServicePrincipal -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $ClientId }
if ($sp) { Good "service principal: $($sp.DisplayName) -- Identity $($sp.Identity)" }
else     { Warn "no Exchange service principal for $ClientId; permission cleanup may find nothing" }

# --- show before doing -------------------------------------------------------
Step 1 "What exists now"

$assignment = Get-ManagementRoleAssignment -Identity $RoleAssignmentName -ErrorAction SilentlyContinue
$scope = Get-ManagementScope -Identity $ScopeName -ErrorAction SilentlyContinue
$legacyFullAccess = Get-MailboxPermission -Identity $Mailbox -ErrorAction SilentlyContinue |
    Where-Object { $_.User -notlike 'NT AUTHORITY*' -and $_.AccessRights -contains 'FullAccess' }
$legacySendAs = Get-RecipientPermission -Identity $Mailbox -ErrorAction SilentlyContinue |
    Where-Object { $_.Trustee -notlike 'NT AUTHORITY*' }
$cas = Get-CASMailbox -Identity $Mailbox -ErrorAction SilentlyContinue

if ($assignment) { Note "role assignment: $($assignment.Name) -- $($assignment.Role)" }
else             { Note "role assignment: none named $RoleAssignmentName" }
if ($scope)      { Note "management scope: $($scope.Name) -- $($scope.RecipientRestrictionFilter)" }
else             { Note "management scope: none named $ScopeName" }
if ($legacyFullAccess) { Warn "legacy FullAccess exists; not created or removed by the App RBAC workflow" }
if ($legacySendAs)     { Warn "legacy SendAs exists; not created or removed by the App RBAC workflow" }
Note "SmtpClientAuthenticationDisabled = $($cas.SmtpClientAuthenticationDisabled)"

# --- 2. App RBAC role assignment --------------------------------------------
Step 2 "Application SMTP.SendAsApp role assignment"

if ($assignment) {
    if (Confirm-Removal "role assignment $RoleAssignmentName") {
        Remove-ManagementRoleAssignment -Identity $assignment.Identity -Confirm:$false
        Good "removed $RoleAssignmentName"
        $script:Removed += "role assignment ($RoleAssignmentName)"
    }
} else { Note "nothing to remove" }

# --- 3. management scope -----------------------------------------------------
Step 3 "Mailbox management scope"

if (-not $RemoveManagementScope) {
    Note "kept (pass -RemoveManagementScope only after checking other role assignments)"
} elseif ($scope) {
    $scopeUsers = Get-ManagementRoleAssignment -ErrorAction SilentlyContinue |
        Where-Object { $_.CustomResourceScope -eq $ScopeName }
    if ($scopeUsers) {
        Warn "scope is still referenced by: $($scopeUsers.Name -join ', ')"
        Warn "refusing to remove a scope that another role assignment uses"
    } elseif (Confirm-Removal "management scope $ScopeName") {
        Remove-ManagementScope -Identity $scope.Identity -Confirm:$false
        Good "removed $ScopeName"
        $script:Removed += "management scope ($ScopeName)"
    }
} else { Note "none exists" }

# --- 4. service principal ----------------------------------------------------
Step 4 "Exchange service principal"

if (-not $RemoveServicePrincipal) {
    Note "kept (pass -RemoveServicePrincipal to remove)"
    Note "It is what every App RBAC assignment points at, and a second project"
    Note "sharing this application would lose access with it."
} elseif ($sp) {
    if (Confirm-Removal "Exchange service principal $($sp.DisplayName)") {
        Remove-ServicePrincipal -Identity $sp.Identity -Confirm:$false | Out-Null
        Good "removed"
        $script:Removed += "service principal ($($sp.DisplayName))"
    }
} else { Note "none exists" }

# --- 5. SMTP AUTH ------------------------------------------------------------
Step 5 "SMTP AUTH on the mailbox"

if (-not $RestoreSmtpAuthDefault) {
    Note "left as-is (pass -RestoreSmtpAuthDefault to inherit the tenant default)"
} elseif ($cas.SmtpClientAuthenticationDisabled -eq $false) {
    if (Confirm-Removal "the per-mailbox SMTP AUTH override on $Mailbox") {
        Set-CASMailbox -Identity $Mailbox -SmtpClientAuthenticationDisabled $null
        Good "restored to tenant default"
        $script:Removed += "SMTP AUTH override"
    }
} else { Note "already at the tenant default" }

# --- 6. optional org-wide alias setting -------------------------------------
Step 6 "Organization-wide alias sending"

$aliasConfig = Get-OrganizationConfig
if (-not $DisableSendFromAlias) {
    Note "left as-is (pass -DisableSendFromAlias only after checking every tenant workload)"
} elseif (-not $aliasConfig.SendFromAliasEnabled) {
    Note "already disabled"
} elseif (Confirm-Removal "ORG-WIDE SendFromAliasEnabled setting") {
    Warn "This affects every mailbox in the Exchange organization, not only this relay."
    Set-OrganizationConfig -SendFromAliasEnabled $false
    Good "disabled SendFromAliasEnabled org-wide"
    $script:Removed += "organization-wide alias sending"
}

# --- 7. what this deliberately does not touch --------------------------------
Step 7 "Left alone on purpose"

Note "the mailbox itself, its shared/user type, group membership, and any license"
Note "the app registration and its certificate"
Note "the enterprise application"
Note ""
Note "To finish decommissioning, by hand, once nothing else uses the identity:"
Note "  - confirm App registrations > API permissions remains empty for App RBAC"
Note "  - Certificates & secrets > delete the certificate"
Note "  - delete the app registration, then the mailbox"
Note ""
Note "On the relay host:"
Note "  docker compose down"
Note "  remove mail-relay-state only after backing up or securely deleting its OAuth key"
Note "  remove mail-relay-spool only after confirming no deferred messages remain"

# --- summary -----------------------------------------------------------------
Step 8 "Summary"

if ($script:Removed) {
    Write-Host "  Removed:" -ForegroundColor Green
    $script:Removed | ForEach-Object { Write-Host "    - $_" -ForegroundColor Green }
} else {
    Write-Host "  Nothing was removed." -ForegroundColor DarkGray
}
if ($script:Skipped) {
    Write-Host "  Skipped:" -ForegroundColor Yellow
    $script:Skipped | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
}

Write-Host ""
Write-Host "Mail may keep working for up to 90 minutes. That is propagation delay," -ForegroundColor Yellow
Write-Host "not a failed removal. Re-run Test-ServicePrincipalAuthorization in two hours." -ForegroundColor Yellow
