# Sender addresses and display-name rewriting

This relay keeps three values apart:

1. the SMTP envelope sender (`MAIL FROM`), used for authorization and bounces;
2. the visible `From` address in the message header;
3. the visible display name beside that header address.

In collapse mode—the recommended setup—configured application addresses are just
local identifiers. No need for actual Microsoft 365 mailboxes or aliases. Postfix
admits only exact configured envelope senders, rewrites the envelope with
`sender_canonical`, and rewrites the visible header with
`smtp_header_checks`.

```text
Application submits                         Microsoft and recipient see
-----------------------------------------   ------------------------------------
MAIL FROM:<diun@relay.example.com>       -> MAIL FROM:<relay@example.com>
From: "DIUN" <diun@relay.example.com>   -> From: "Diun [Server A]" <relay@example.com>
```

Unknown envelope senders are rejected before rewriting. The catch-all canonical
map is not an open “accept anything” rule, whatever it looks like.

## How this relates to Postfix `canonical_maps`

For Postfix users: this is the relay's managed take on sender canonical maps.
The generated configuration uses Postfix's sender-specific `sender_canonical_maps`,
part of the broader canonical-address-rewriting family:

```text
sender_canonical_maps = regexp:/etc/postfix/sender_canonical
sender_canonical_classes = envelope_sender
```

The narrow setting is deliberate. Postfix's general `canonical_maps` rewrites
both senders and recipients in envelopes and headers alike. This relay must
never touch a recipient without warning, so it only enables the sender-specific
variant. The work splits instead:

- `smtpd_sender_restrictions` admits only configured envelope senders;
- `sender_canonical_maps` rewrites only the accepted envelope sender; and
- `smtp_header_checks` separately rewrites the visible `From:` address and
  display name, including correct quoting of special characters.

That split is why `MAIL_SENDER_*` is a safer, container-managed take on
`canonical_maps` that still handles display-name changes like
`Diun [MyHostName]`. See Postfix's
[address rewriting overview](https://www.postfix.org/ADDRESS_REWRITING_README.html)
and [`canonical(5)` reference](https://www.postfix.org/canonical.5.html) for details.

## Configuration vocabulary

```env
MAIL_SEND_MAILBOX=relay@example.com
MAIL_SENDER_MODE=collapse

MAIL_SENDER_DIUN=diun@relay.example.com
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

The suffix (`DIUN`) ties one address to an optional forced name. Alphanumerics
and underscores only. It's a config key—never shows up in a message.

| Setting | Purpose |
|---|---|
| `MAIL_SEND_MAILBOX` | Microsoft 365 shared mailbox used for final submission |
| `MAIL_SENDER_<KEY>` | exact envelope address allowed to submit |
| `MAIL_SENDER_NAME_<KEY>` | display name forced when the visible From address matches that sender |
| `MAIL_SENDER_NAME_FALLBACK` | name used when a message has only a bare From address |
| `MAIL_SENDER_MODE` | `collapse` (recommended) or `passthrough` |
| `MAIL_PASSTHROUGH_SENDERS` | explicit same-mailbox aliases allowed to remain unchanged |

## Scenario 1: a container has a fixed display name

Diun always emits `DIUN`; its From address is yours to set:

```env
MAIL_SENDER_DIUN=diun@relay.example.com
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

Point Diun at `diun@relay.example.com`. Postfix replaces the display name:

```text
Input:  From: "DIUN" <diun@relay.example.com>
Output: From: "Diun [Server A]" <relay@example.com>
```

No display-name setting needed in the app. Just use the configured sender address.

## Scenario 2: two hosts run the same application

Display-name rules key off the From address, not source IP. Give each
installation its own local sender:

```env
MAIL_SENDER_DIUN_SERVER_A=diun-server-a@relay.example.com
MAIL_SENDER_NAME_DIUN_SERVER_A=Diun [Server A]

MAIL_SENDER_DIUN_SERVER_B=diun-server-b@relay.example.com
MAIL_SENDER_NAME_DIUN_SERVER_B=Diun [Server B]
```

If both clients submit from `diun@relay.example.com`, the relay can't tell which
display name belongs to which. Either assign distinct sender addresses, or run
separate relay instances.

## Scenario 3: the application fixes both name and address

If an application always sends exactly this:

```text
From: "Built-in notifier" <notifications@vendor.invalid>
```

authorize that exact address:

```env
MAIL_SENDER_VENDOR=notifications@vendor.invalid
MAIL_SENDER_NAME_VENDOR=Inventory [Warehouse]
```

In collapse mode, the domain doesn't need to exist in Microsoft 365. Outbound
goes through the dedicated shared mailbox.

If the application also uses that same address as envelope sender, it's accepted
and rewritten. If it uses a different envelope sender, configure that too or the
transaction is rejected.

## Scenario 4: the application sends a bare address

Some clients omit a display name:

```text
From: monitor@relay.example.com
```

When the address has a matching `MAIL_SENDER_NAME_*`, that name is used. For any
other accepted bare address, the fallback applies:

```env
MAIL_SENDER_NAME_FALLBACK=System notification
```

Result:

```text
From: "System notification" <relay@example.com>
```

Assign a name for every sender. Clearer than relying on the fallback.

## Scenario 5: special characters in display names

Display names can hold spaces and common punctuation:

```env
MAIL_SENDER_BACKUP=backup@relay.example.com
MAIL_SENDER_NAME_BACKUP=Backups (Primary) [Rack A/B]

MAIL_SENDER_REPORTS=reports@relay.example.com
MAIL_SENDER_NAME_REPORTS=Reports, Finance & Ops #42: Green

MAIL_SENDER_STORAGE=storage@relay.example.com
MAIL_SENDER_NAME_STORAGE=O'Brien's NAS
```

The renderer escapes Postfix regexp replacement syntax and RFC 5322 quoted
strings separately. Tests cover brackets, parentheses, quotes, apostrophes,
backslashes, commas, colons, dollar signs, Unicode, and emoji.

Names stay on one line. Carriage returns and newlines are rejected at boot to
stop header injection.

## Scenario 6: literal host names versus interpolation

Configuration is parsed as data, not shell code. Safe, but variables don't
expand:

```env
# Literal text; it does NOT substitute the host name.
MAIL_SENDER_NAME_DIUN=Diun [${HOSTNAME}]
```

Set the desired value explicitly per host:

```env
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

Environment-variable overrides are supported, but Docker Compose must pass the
resolved value. No generic templates or command substitution here.

## Scenario 7: an unauthorized sender

Suppose only this address is configured:

```env
MAIL_SENDER_DIUN=diun@relay.example.com
```

These outcomes differ deliberately:

| Envelope sender | Result |
|---|---|
| `diun@relay.example.com` | accepted, then rewritten |
| `relay@example.com` | accepted as the authenticated mailbox identity |
| `root@relay.example.com` | rejected |
| `attacker@example.net` | rejected |

Unknown envelope addresses don't get rescued by the catch-all collapse rule. A
compromised client stays locked to sender identities you explicitly configured.

## Scenario 8: envelope and header do not agree

SMTP allows different envelope and visible From addresses. Admission checks the
envelope; display-name selection checks the visible header.

```text
MAIL FROM:<diun@relay.example.com>             configured
From: "anything" <other@example.net>           not configured
```

The transaction is admitted because the envelope sender is configured, but
collapse mode still replaces the visible address with `MAIL_SEND_MAILBOX`.
The sender-specific `MAIL_SENDER_NAME_DIUN` rule can't match a header that says
`other@example.net`, so the generic header rule may preserve `anything`.

For deterministic names, use the same `MAIL_SENDER_*` address in both envelope
and header. Display names are not a security boundary. The envelope sender
allowlist and Microsoft mailbox scope are.

## Scenario 9: choosing local sender domains

Collapse mode accepts any syntactically valid address with a dotted domain.
These local addresses need no DNS records, mailbox, or shared-mailbox alias—
recipients never see them.

Recommended organization:

```text
diun@relay.example.com
grafana@relay.example.com
printer-lobby@relay.example.com
authelia@relay.example.com
```

One dedicated subdomain keeps config auditable. The relay doesn't require a
shared domain; it authorizes exact addresses, not every address under one.

Examples using `example.com`, `example.net`, and `.invalid` are documentation
placeholders. Replace them with addresses appropriate for the installation.

## Scenario 10: preserving a real shared-mailbox alias

Alias passthrough is optional and not automatic:

```env
MAIL_SENDER_MODE=passthrough
MAIL_SENDER_ALERTS=alerts@example.com
MAIL_SENDER_NAME_ALERTS=Infrastructure alerts
MAIL_PASSTHROUGH_SENDERS=alerts@example.com
```

Every passthrough address must satisfy all of these conditions:

1. It is listed as `MAIL_SENDER_*`, which permits its envelope sender locally.
2. It is also listed in `MAIL_PASSTHROUGH_SENDERS`, which bypasses collapse.
3. It is an actual proxy alias on the same `MAIL_SEND_MAILBOX` shared mailbox.
4. Its domain is an accepted Microsoft 365 domain.
5. `SendFromAliasEnabled` is enabled for the entire Exchange organization.
6. SMTP XOAUTH2 app-only alias submission is watched working after the required
   propagation period.

The relay can't discover aliases automatically—the claims-less App RBAC design
grants no Graph or mail-reading permissions. Typos and unprovisioned aliases
surface only on send. Unlisted senders collapse rather than bounce.

Passthrough is release-gated until live alias testing is done. Use collapse
mode—it's the supported default.

## Inspecting the generated policy

After restarting for a configuration change:

```bash
docker exec postfix-m365-relay postconf -h sender_canonical_maps
docker exec postfix-m365-relay postconf -h sender_canonical_classes
docker exec postfix-m365-relay postconf -h smtp_header_checks
docker exec postfix-m365-relay postconf -h smtpd_sender_restrictions
```

Expected managed values include:

```text
sender_canonical_maps = regexp:/etc/postfix/sender_canonical
sender_canonical_classes = envelope_sender
smtp_header_checks = regexp:/etc/postfix/header_checks
smtpd_sender_restrictions = check_sender_access texthash:/etc/postfix/sender_access, reject
```

To inspect a single envelope rewrite without sending mail:

```bash
docker exec postfix-m365-relay \
  postmap -q diun@relay.example.com regexp:/etc/postfix/sender_canonical
```

It should print `MAIL_SEND_MAILBOX`. Map inspection is a config check only. Send
a test message to verify Microsoft and recipient-visible behavior.
