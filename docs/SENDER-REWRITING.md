# Sender addresses and display-name rewriting

This relay treats three values separately:

1. the SMTP envelope sender (`MAIL FROM`), used for authorization and bounces;
2. the visible `From` address in the message header;
3. the visible display name beside that header address.

In the recommended `collapse` mode, configured application addresses are local
identifiers. They do not need to be Microsoft 365 mailboxes or aliases. Postfix
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
map is therefore not an open “accept anything” rule.

## How this relates to Postfix `canonical_maps`

For administrators familiar with native Postfix, this feature is the relay's
managed equivalent of a sender canonical map. More precisely, the generated
configuration uses Postfix's sender-specific `sender_canonical_maps`, which is
one member of the broader canonical-address-rewriting family:

```text
sender_canonical_maps = regexp:/etc/postfix/sender_canonical
sender_canonical_classes = envelope_sender
```

The narrower setting is intentional. Postfix's general `canonical_maps` can
rewrite both sender and recipient addresses in both SMTP envelopes and message
headers. This relay must not unexpectedly rewrite recipients, so it does not
enable that broad map. Its responsibilities are divided instead:

- `smtpd_sender_restrictions` admits only configured envelope senders;
- `sender_canonical_maps` rewrites only the accepted envelope sender; and
- `smtp_header_checks` separately rewrites the visible `From:` address and
  display name, including correct quoting of special characters.

This separation is why `MAIL_SENDER_*` feels like a safer, container-managed
version of `canonical_maps`, while still supporting display-name changes such
as `Diun [MyHostName]`. See Postfix's official
[address rewriting overview](https://www.postfix.org/ADDRESS_REWRITING_README.html)
and [`canonical(5)` reference](https://www.postfix.org/canonical.5.html) for the
underlying Postfix behavior.

## Configuration vocabulary

```env
MAIL_SEND_MAILBOX=relay@example.com
MAIL_SENDER_MODE=collapse

MAIL_SENDER_DIUN=diun@relay.example.com
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

The suffix (`DIUN`) joins one address and one optional forced name. It may
contain uppercase letters, digits, and underscores. It is only a configuration
key and never appears in a message.

| Setting | Purpose |
|---|---|
| `MAIL_SEND_MAILBOX` | Microsoft 365 shared mailbox used for final submission |
| `MAIL_SENDER_<KEY>` | exact envelope address allowed to submit |
| `MAIL_SENDER_NAME_<KEY>` | display name forced when the visible From address matches that sender |
| `MAIL_SENDER_NAME_FALLBACK` | name used when a message has only a bare From address |
| `MAIL_SENDER_MODE` | `collapse` (recommended) or `passthrough` |
| `MAIL_PASSTHROUGH_SENDERS` | explicit same-mailbox aliases allowed to remain unchanged |

## Scenario 1: a container has a fixed display name

Diun might always emit `DIUN`, but its From address is configurable:

```env
MAIL_SENDER_DIUN=diun@relay.example.com
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

Configure Diun to send from `diun@relay.example.com`. Postfix replaces its fixed
display name:

```text
Input:  From: "DIUN" <diun@relay.example.com>
Output: From: "Diun [Server A]" <relay@example.com>
```

The application does not need a display-name setting of its own. It only needs
to use the configured sender address.

## Scenario 2: two hosts run the same application

Display-name rules are selected by From address, not source IP or container
name. Give each installation a distinct local sender:

```env
MAIL_SENDER_DIUN_SERVER_A=diun-server-a@relay.example.com
MAIL_SENDER_NAME_DIUN_SERVER_A=Diun [Server A]

MAIL_SENDER_DIUN_SERVER_B=diun-server-b@relay.example.com
MAIL_SENDER_NAME_DIUN_SERVER_B=Diun [Server B]
```

If both clients submit from `diun@relay.example.com`, one relay cannot infer
which desired display name belongs to which host. Either configure distinct
sender addresses as above or run separately configured relay instances.

## Scenario 3: the application fixes both name and address

If an application always sends this:

```text
From: "Built-in notifier" <notifications@vendor.invalid>
```

authorize that exact address:

```env
MAIL_SENDER_VENDOR=notifications@vendor.invalid
MAIL_SENDER_NAME_VENDOR=Inventory [Warehouse]
```

The domain does not need to exist in Microsoft 365 in collapse mode. The
outbound address is still the dedicated shared mailbox.

If the application also uses `notifications@vendor.invalid` as its envelope
sender, it is accepted and rewritten. If it uses a different envelope sender,
that second address must be configured or the SMTP transaction is rejected.

## Scenario 4: the application sends a bare address

Some clients omit a display name:

```text
From: monitor@relay.example.com
```

When the address has a matching `MAIL_SENDER_NAME_*`, that configured name is
used. For any otherwise accepted bare address that reaches the generic rule,
the fallback applies:

```env
MAIL_SENDER_NAME_FALLBACK=System notification
```

Result:

```text
From: "System notification" <relay@example.com>
```

Defining a name for every sender is clearer and is recommended over relying on
the fallback.

## Scenario 5: special characters in display names

Display names may contain spaces and common punctuation:

```env
MAIL_SENDER_BACKUP=backup@relay.example.com
MAIL_SENDER_NAME_BACKUP=Backups (Primary) [Rack A/B]

MAIL_SENDER_REPORTS=reports@relay.example.com
MAIL_SENDER_NAME_REPORTS=Reports, Finance & Ops #42: Green

MAIL_SENDER_STORAGE=storage@relay.example.com
MAIL_SENDER_NAME_STORAGE=O'Brien's NAS
```

The renderer separately escapes Postfix regexp replacement syntax and RFC 5322
quoted strings. Live and isolated tests cover brackets, parentheses, quotes,
apostrophes, backslashes, commas, colons, dollar signs, Unicode, and emoji.

Names must remain on one line. A carriage return or newline is rejected at boot
to prevent header injection.

## Scenario 6: literal host names versus interpolation

Configuration is parsed as data, never shell code. This is safe but means shell
variables are not expanded:

```env
# Literal text; it does NOT substitute the host name.
MAIL_SENDER_NAME_DIUN=Diun [${HOSTNAME}]
```

Set the desired value explicitly per host:

```env
MAIL_SENDER_NAME_DIUN=Diun [Server A]
```

Environment-variable overrides are supported, but Docker Compose must provide
the already resolved complete value. The relay itself has no generic template
or command-substitution feature.

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

An unknown envelope address is not rescued by the catch-all collapse rule. This
limits a compromised client to sender identities the administrator explicitly
configured.

## Scenario 8: envelope and header do not agree

SMTP permits different envelope and visible From addresses. Admission checks
the envelope sender; display-name selection checks the visible header address.

```text
MAIL FROM:<diun@relay.example.com>             configured
From: "anything" <other@example.net>           not configured
```

The transaction is admitted because the envelope sender is configured, but
collapse mode still replaces the visible address with `MAIL_SEND_MAILBOX`.
The sender-specific `MAIL_SENDER_NAME_DIUN` rule cannot match a header that says
`other@example.net`, so the generic header rule may preserve `anything`.

For deterministic names, configure applications so envelope and header From use
the same `MAIL_SENDER_*` address. Do not treat display names as an authentication
boundary; the exact envelope sender allowlist and Microsoft mailbox scope are
the security boundaries.

## Scenario 9: choosing local sender domains

Collapse mode accepts any syntactically valid full address with a dotted domain.
The local addresses need no DNS records, Microsoft mailbox, or shared-mailbox
alias because recipients never see them.

Recommended organization:

```text
diun@relay.example.com
grafana@relay.example.com
printer-lobby@relay.example.com
authelia@relay.example.com
```

Using one dedicated subdomain makes configuration easy to audit. The software
does not require one shared domain and authorizes exact addresses—not every
address under that domain.

Examples using `example.com`, `example.net`, and `.invalid` are documentation
placeholders. Replace them with addresses appropriate for the installation.

## Scenario 10: preserving a real shared-mailbox alias

Alias passthrough is optional and is not automatic:

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

The relay cannot discover aliases automatically because the claims-less App
RBAC design deliberately grants no Graph or mail-reading permissions. A typo or
unprovisioned alias can therefore be detected only by validation and a real
send. Unlisted senders continue to collapse rather than creating a bounce path.

Passthrough remains release-gated until the live alias test is completed. Use
collapse mode for the supported default.

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

To inspect an individual envelope rewrite without sending mail:

```bash
docker exec postfix-m365-relay \
  postmap -q diun@relay.example.com regexp:/etc/postfix/sender_canonical
```

It should print `MAIL_SEND_MAILBOX`. Treat map inspection as a configuration
check only; a delivered test message is still required to verify Microsoft and
recipient-visible behavior.
