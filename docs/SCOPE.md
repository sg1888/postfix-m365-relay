# Scope and supported platforms

This project is a narrow outbound SMTP submission relay. It accepts mail from
configured Docker applications or explicitly trusted/authenticated LAN devices,
then relays it to Microsoft 365 over TLS using app-only XOAUTH2.

`postfix-m365-relay` is intentionally provider-specific. It will not add Gmail,
generic OAuth discovery, arbitrary token endpoints, or provider plug-ins. Those
features would change the threat model and test matrix and belong in a separate
future project with a different name.

It does not provide local mailboxes, inbound Internet MX service, bounce
resubmission, arbitrary foreign-mailbox SendAs, DKIM signing, spam filtering, or
Gmail service-account auth. Microsoft 365 owns DKIM, SPF, DMARC, reputation, and
final delivery.

The managed Postfix block always controls relay restrictions, sender checking,
OAuth authentication, TLS-before-AUTH, and local-delivery refusal. `POSTFIX_*`
is for tuning the remaining surface, not bypassing those boundaries.

## Platforms

| Platform | Status |
|---|---|
| `linux/amd64`, x86-64-v3 | supported by the normal image |
| `linux/amd64/v2` | supported by a separate `-x86-64-v2` tag |
| `linux/arm64` with a 64-bit OS | supported by the normal image |
| 32-bit ARM or x86 | unsupported in v1 |
| Raspberry Pi 3 with 32-bit Raspberry Pi OS | unsupported until a 64-bit OS is installed |

AlmaLinux 10 is the only distribution target. CI assertions must observe
`sasl-xoauth2` 0.27, Python `cryptography`, and `saslpasswd2` in every published
variant before the platform is called verified.

## Security boundary

The local posture's Docker network is its first trust boundary. The published
posture adds interface binding and IP/password policy. Neither posture is for an
Internet-facing listener. The upstream credential can send as a real tenant
mailbox and therefore deserves the same care as any production service key.
