# Microsoft 365 setup: shared mailbox with scoped App RBAC

The recommended identity is a **dedicated, unlicensed shared mailbox**. Do not
use it for ordinary correspondence, support traffic, user sign-in, or message
storage. Its purpose is only to provide the Microsoft 365 outbox used by this
relay. Keeping it empty and purpose-specific reduces both the value of the
mailbox and the effect of a configuration mistake.

This project uses Microsoft's claims-less Exchange **RBAC for Applications**
path. The app registration has no API permissions. Exchange grants only
`Application SMTP.SendAsApp`, restricted to mailboxes in one dedicated group.
Microsoft describes the role as permitting SMTP client submission; it does not
grant mail read, mail write, calendar, contacts, or general Graph access:

- [Configure SMTP onboarding to App RBAC](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/smtp-app-rbac-onboarding)
- [RBAC for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [OAuth for IMAP, POP, and SMTP](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)

## What the security boundary permits

| Capability | Relay app |
|---|---:|
| Submit through SMTP as the dedicated in-scope mailbox | yes |
| Submit as a mailbox outside the management scope | no |
| Read or search mailbox messages | no |
| Use Microsoft Graph `Mail.Read`, `Mail.ReadWrite`, or `Mail.Send` | no |
| Sign in interactively as the shared mailbox | no |
| Authenticate with a reusable mailbox password | no |

This is deliberately narrower than the older Entra-permission plus
`FullAccess` approach. Do **not** add the Office 365 Exchange Online application
permission named `SMTP.SendAsApp`; Microsoft warns that the claim causes an
unnecessary mailbox-permission check in the App RBAC flow. Do not grant
`FullAccess`, `SendAs`, Graph `Mail.Send`, or either Graph mail-reading role.
App RBAC and Entra permissions are additive, so an extra grant expands access
rather than replacing this scope.

The certificate is still a powerful sending credential. Protect the state
volume, restrict the management scope, and test both an allowed and a denied
mailbox. “Cannot read mail” does not mean “harmless if stolen”: an attacker with
the private key could submit mail as an in-scope mailbox until the credential is
removed.

## 1. Create the dedicated shared mailbox

In the Microsoft 365 admin center, create a shared mailbox such as
`relay@example.com`. Then:

1. Use it only for this relay. Do not publish it as a contact address or use its
   inbox for business messages.
2. Block sign-in for the account that anchors the shared mailbox. App-only OAuth
   does not use interactive sign-in.
3. Do not assign delegates unless a documented operational procedure needs
   them. The relay does not require a human member, `FullAccess`, or `SendAs`.
4. Leave the shared mailbox unlicensed when it stays within Microsoft's
   unlicensed limits.

Microsoft permits a shared mailbox to store up to 50 GB without its own license.
A license is required for more than 50 GB and for certain archive, hold, and
advanced compliance features. The tenant itself must have a subscription that
includes Exchange Online. Review the current limits before relying on the
unlicensed status:

- [About shared mailboxes](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide)
- [Exchange Online limits](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits)
- [Create a shared mailbox](https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide)

Because this mailbox is outbound-only, monitor its size and avoid retaining
copies indefinitely. Reaching the storage limit can prevent new sends.

## 2. Create the app registration—with no API permissions

In Microsoft Entra admin center:

1. Open **Entra ID → App registrations → New registration**.
2. Choose accounts in this organizational directory only. No redirect URI is
   needed.
3. Record **Directory (tenant) ID** and **Application (client) ID**.
4. Open **Enterprise applications**, select the corresponding application, and
   record that object's **Object ID**. It is not the app registration Object ID.
5. Open **API permissions** and leave the list empty. Remove legacy
   `SMTP.SendAsApp`, `Mail.Send`, `Mail.Read`, and `Mail.ReadWrite` permissions
   if this is a new relay-only app that inherited an earlier experiment.

Do not assign a user to the enterprise application. Client-credentials OAuth
uses the certificate, not an interactive user session.

## 3. Create the mailbox-scope group

Create one dedicated Exchange distribution group or mail-enabled security group,
for example `postfix-m365-relay-mailboxes@example.com`. Add the relay shared
mailbox as a **direct** member. Do not add broad groups, ordinary users, or all
mailboxes.

You provide the group's identity or email address to the setup script. You do
not provide its distinguished name. The script retrieves Exchange's real
`DistinguishedName` and uses Microsoft's documented `MemberOfGroup` filter:

```powershell
$group = Get-DistributionGroup -Identity 'postfix-m365-relay-mailboxes@example.com'
New-ManagementScope -Name '<scope-name>' `
  -RecipientRestrictionFilter "MemberOfGroup -eq '$($group.DistinguishedName)'"
```

Microsoft's management-scope example explains why the DN comes from the group
object: [create a `MemberOfGroup` custom management scope](https://learn.microsoft.com/en-us/exchange/create-custom-management-scope-exchange-2013-help).

## 4. Run the guarded Exchange setup

Start with a read-only preview:

```powershell
./powershell/setup-exchange.ps1 `
  -Mailbox relay@example.com `
  -ScopeGroup postfix-m365-relay-mailboxes@example.com `
  -ClientId 11111111-1111-1111-1111-111111111111 `
  -EnterpriseAppObjectId 22222222-2222-2222-2222-222222222222 `
  -WhatIfOnly
```

Review the output, then omit `-WhatIfOnly`. The script:

1. validates that the mailbox is `SharedMailbox` (recommended) or a licensed
   `UserMailbox` (supported compatibility option);
2. enables SMTP AUTH only on that mailbox while allowing the organization-wide
   setting to remain disabled;
3. creates Exchange's service-principal reference with `New-ServicePrincipal`;
4. validates direct membership in the dedicated scope group;
5. creates a `MemberOfGroup` management scope;
6. assigns `Application SMTP.SendAsApp` with `New-ManagementRoleAssignment`;
7. runs `Test-ServicePrincipalAuthorization` against the mailbox;
8. reports legacy or additive grants for manual review without deleting them.

These are the Microsoft references used to implement and audit those commands:

- [`New-ServicePrincipal` and App RBAC configuration](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [SMTP-specific `Application SMTP.SendAsApp` onboarding](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/smtp-app-rbac-onboarding)
- [`Test-ServicePrincipalAuthorization` syntax and `InScope`](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/test-serviceprincipalauthorization?view=exchange-ps)

`Test-ServicePrincipalAuthorization` is a configuration check, not a delivery
proof. Exchange authorization is cached. Record the last change time and wait a
full two hours before treating SMTP success or failure as evidence.

## 5. Upload only the public certificate

Start the container with its state volume. On first boot it generates an
RSA-4096 client key and prints the public certificate and SHA-1 thumbprint.
Upload the public PEM under **App registrations → Certificates & secrets →
Certificates**. Never upload, email, or copy the private key from the state
volume.

The container retries token minting. After certificate and Exchange propagation
complete, it begins submitting without a mailbox password.

## 6. Prove the scope and display names

Use test recipients and unique Message-IDs:

1. Send two messages through the relay using distinct configured display names,
   including a bracketed name such as `MyServer [TestServer]`.
2. Require local queue acceptance, verified TLS to Microsoft, Microsoft SMTP
   `250`, and recipient-side arrival showing the shared mailbox address and exact
   names.
3. Acquire a valid app token but attempt SMTP AUTH as a clearly out-of-scope test
   mailbox. Microsoft must reject AUTH; no message may be sent.
4. Keep the shared mailbox as the configured baseline only after both positive
   and negative checks pass.

This project observed an unlicensed shared mailbox submit successfully through
claims-less `Application SMTP.SendAsApp`; bracketed and parenthesized display
names were preserved exactly at the recipient. That observation applies to the
tested App RBAC design—not to older `FullAccess` or Entra-permission workflows.

## Adding or removing an authorized mailbox

The same service principal and app registration may cover another mailbox by
adding it to the existing dedicated scope group. A separate group and scope are
not required unless the mailbox needs a different authorization boundary.

After changing membership, wait two hours, then run:

```powershell
Test-ServicePrincipalAuthorization `
  -Identity 11111111-1111-1111-1111-111111111111 `
  -Resource relay@example.com |
  Format-Table RoleName,AllowedResourceScope,InScope
```

Removing a mailbox from the group revokes the scoped grant after propagation.
Always perform a negative SMTP AUTH test after the waiting period; do not infer
revocation solely from the group-management command succeeding.
