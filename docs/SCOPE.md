# Scope and supported platforms

This is an outbound SMTP submission relay. It accepts mail from configured
Docker applications or explicitly trusted/authenticated LAN devices, then relays
it to Microsoft 365 over TLS using app-only XOAUTH2.

This project is intentionally provider-specific. It will not add Gmail, generic
OAuth discovery, arbitrary token endpoints, or provider plug-ins. Those would
reshape the threat model and test matrix and belong in a different project.

It does not provide local mailboxes, inbound MX service, bounce resubmission,
arbitrary SendAs, DKIM signing, spam filtering, or Gmail service auth. Microsoft
365 owns DKIM, SPF, DMARC, reputation, and final delivery.

The managed Postfix layer always controls relay restrictions, sender checking,
OAuth auth, TLS-before-AUTH, and local-delivery refusal. Use `POSTFIX_*` to tune
the remaining surface, not to bypass these boundaries.

## Microsoft authorization boundary

Use a dedicated shared mailbox with claims-less Exchange App RBAC. The app
registration has no API permissions, no `FullAccess`, and no mail-reading role.
Exchange grants only `Application SMTP.SendAsApp` scoped to one group-backed
mailbox. The app can submit as that mailbox only—no message reading, no
cross-mailbox SendAs. Keep the mailbox dedicated to relay output and block
interactive sign-in.

See [MICROSOFT-SETUP.md](MICROSOFT-SETUP.md) for Microsoft's source documents,
licensing caveats, exact PowerShell workflow, and positive/negative proof.

## Platforms

| Platform | Status |
|---|---|
| `linux/amd64`, any level (incl. default-CPU VMs) | default `latest` / `ubuntu` (Ubuntu) |
| `linux/amd64`, x86-64-v3 | also `alma-v3` |
| `linux/amd64/v2` | `alma-v2` |
| `linux/arm64` with a 64-bit OS | default `latest` / `ubuntu`, and `alma-v3` |
| 32-bit ARM or x86 | unsupported in v1 |
| Raspberry Pi 3 with 32-bit Raspberry Pi OS | unsupported until a 64-bit OS is installed |

AlmaLinux 10 is the only distribution target. CI must verify `sasl-xoauth2` 0.27,
Python `cryptography`, and `saslpasswd2` in every published variant before
marking a platform verified.

## Security boundary

The local Docker network is the first trust boundary. The published posture adds
interface binding and IP/password policy. Neither is for an Internet-facing
listener. The upstream credential can send as a real mailbox—treat it like any
production service key.
