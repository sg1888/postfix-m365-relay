# Configuration

Start with the generated `/config/mail-relay.conf`. On an empty writable
`/config`, first startup copies the image's fully commented sample and waits
without opening SMTP until the required values below are present. Save the file
in place; no container recreation is needed for that first transition.

The file parser accepts only `MAIL_*`, `POSTFIX_*`, `TZ`, and `RELAY_PORT`. It
treats values as literal data: it does not run shell expansion, command
substitution, or backslash escapes. A variable explicitly supplied by Docker or
an orchestrator wins over the file, including an explicitly empty value. Later
file changes require a container restart because Postfix config and credentials
are deliberately rendered once at boot.

Everything in this document is optional unless you choose the published-device
posture.

## Required and recommended values

| Variable | Required | Meaning |
|---|---:|---|
| `MAIL_RELAY_TENANT` | yes | Entra tenant ID |
| `MAIL_RELAY_CLIENT_ID` | yes | app registration client ID |
| `MAIL_SEND_MAILBOX` | yes | licensed regular mailbox used for submission |
| `MAIL_SENDER_<KEY>` | one or more | address an application may use at `MAIL FROM` |
| `MAIL_SENDER_NAME_<KEY>` | no | forced display name for that sender |
| `MAIL_ADMIN_EMAIL` | recommended | alert, verification, and rotation-proof recipient |

`MAIL_RELAY_ENTERPRISE_APP_OBJECT_ID` is a record for the one-time PowerShell
setup. The running container does not read it.

## General options

| Variable | Default | Meaning |
|---|---|---|
| `MAIL_AUTH_MODE` | `microsoft-cert` | only implemented upstream mode; `delegated` is reserved |
| `MAIL_RELAY_DOMAIN` | `relay.example.local` | sender namespace and inbound SASL realm |
| `MAIL_RELAY_HOSTNAME` | `postfix-m365-relay.example.local` | Postfix hostname and self-signed TLS subject |
| `RELAY_PORT` | `2525` | unprivileged inbound container port |
| `MAIL_UPSTREAM_HOST` | `smtp.office365.com` | Microsoft submission host |
| `MAIL_UPSTREAM_PORT` | `587` | Microsoft submission port |
| `MAIL_UPSTREAM_TLS_SECURITY_LEVEL` | `secure` | `secure` verifies identity; `encrypt` only requires encryption |
| `MAIL_UPSTREAM_CA_EXTRA_FILE` | empty | mounted public corporate TLS-inspection CA bundle |
| `MAIL_QUEUE_LIFETIME` | `12h` | deferred and bounce queue lifetime |
| `MAIL_RELAY_MAX_SIZE` | `3m` | accepted message size (`k`, `m`, or bytes) |
| `MAIL_RELAY_RATE_LIMIT` | `200` | connections per ten minutes per client |
| `MAIL_SENDER_NAME_FALLBACK` | `the relay` | name for a bare From address |
| `TZ` | container `/etc/localtime` | IANA timezone used by Postfix and local-time tools |

Container engines do not portably inherit the server's timezone. Set, for
example, `TZ=America/New_York` for predictable behavior. If `TZ` is omitted,
the standard C runtime uses `/etc/localtime`: bind-mount the server's
`/etc/localtime` read-only if matching it is important. Without either choice,
the image uses UTC. Relay audit prefixes deliberately remain UTC so incident
timelines from multiple hosts can be compared safely.

## Sender modes

### Collapse (default)

```env
MAIL_SENDER_MODE=collapse
MAIL_SENDER_BACKUP=backup@relay.example.local
MAIL_SENDER_NAME_BACKUP=Backups
```

Only configured `MAIL_SENDER_*` addresses may submit. Their envelope sender and
header address become `MAIL_SEND_MAILBOX`; their display name is preserved or
forced. This is the safe, measured mode.

### Passthrough

```env
MAIL_SENDER_MODE=passthrough
MAIL_PASSTHROUGH_SENDERS=alerts@example.com,reports@example.com
```

Allowlisted addresses remain unchanged. Every unlisted permitted sender still
collapses to the main mailbox, so an alias mistake does not create a bounce
pipeline. The addresses must be proxy aliases on that same mailbox.

Do not call this verified until the SMTP XOAUTH2 app-only alias gate in
`TESTING.md` has been observed against dedicated test objects.
`SendFromAliasEnabled` is org-wide.

## Inbound policy

| `MAIL_INBOUND_AUTH` | Who can relay | SASL | Default TLS |
|---|---|---:|---|
| `off` | Docker subnet only; trusted networks forbidden | no | `off` |
| `ip` | Docker subnet plus `MAIL_TRUSTED_NETWORKS` | no | `off` |
| `smtp-auth` | loopback or authenticated users | yes | `may` |
| `ip-or-auth` | trusted IPs or authenticated users | yes | `may` |
| `ip-and-auth` | trusted IPs and authenticated users | yes | `require` |

Loopback is always permitted so the in-container verifier can submit without a
stored probe password. It is unreachable from outside the container.

Boot refuses these unsafe or contradictory combinations:

- `0.0.0.0/0` or `::/0` in `MAIL_TRUSTED_NETWORKS`;
- trusted networks with policy `off`;
- any password-auth policy with `MAIL_INBOUND_TLS=off`;
- password auth without a readable `MAIL_SMTPD_USERS_FILE`.

### `off`

```yaml
environment:
  MAIL_INBOUND_AUTH: off
```

Use only for an unpublished Docker-network listener. `MAIL_TRUSTED_NETWORKS`
must be empty.

### `ip`

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip
  MAIL_INBOUND_TLS: off
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32
```

Suitable for a fixed printer on a controlled VLAN. The device-to-relay message
is plaintext; the upstream Microsoft hop always requires TLS.

Equivalent `docker run` additions:

```bash
-p 192.0.2.10:2525:2525 \
-e MAIL_INBOUND_AUTH=ip \
-e MAIL_TRUSTED_NETWORKS=192.0.2.50/32
```

### `smtp-auth`

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: smtp-auth
  MAIL_INBOUND_TLS: require
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
secrets: [smtpd_users]
```

Every non-loopback client, including another Docker container, must STARTTLS and
authenticate. IP membership buys nothing.

### `ip-or-auth` (mixed fleet)

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip-or-auth
  MAIL_INBOUND_TLS: may
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
secrets: [smtpd_users]
```

The fixed printer at `.50` may send plaintext by IP. A roaming device outside
that allowlist must STARTTLS and authenticate. Pre-STARTTLS EHLO must not show
AUTH; after STARTTLS it must show exactly PLAIN and LOGIN.

### `ip-and-auth`

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip-and-auth
  MAIL_INBOUND_TLS: require
  MAIL_TRUSTED_NETWORKS: 192.0.2.0/28
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
secrets: [smtpd_users]
```

Both gates must pass. A correct password from the wrong IP and a correct IP
without a password are both rejected.

## Inbound TLS

`off`, `may`, and `require` map to Postfix `none`, `may`, and `encrypt`.
Whenever inbound SASL is enabled, `smtpd_tls_auth_only=yes` is force-asserted.

With no BYO files, the container creates a separate RSA-2048 self-signed server
pair under `/var/lib/mail-relay/inbound-tls`. The OAuth Graph rotation code
refuses paths outside `/var/lib/mail-relay/secrets`, so the lifecycles cannot
cross. It is valid for 3,650 days by default and is automatically renewed 365
days before expiry, using the same private key followed by `postfix reload`.
Exact-certificate pinning may still require a client trust update at renewal;
use an externally managed CA certificate where seamless public trust matters.

For BYO TLS:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /run/secrets/inbound_tls_cert
  MAIL_INBOUND_TLS_KEY: /run/secrets/inbound_tls_key
secrets:
  - inbound_tls_cert
  - inbound_tls_key
```

`MAIL_INBOUND_TLS_CERT` should point to a fullchain PEM when the issuer uses an
intermediate CA: leaf certificate first, then intermediate issuer certificates.
Certbot's `fullchain.pem` has exactly that shape. There is intentionally no
separate chain variable; Postfix's similarly named `smtpd_tls_chain_files`
expects private-key material as part of a replacement interface and is not an
intermediates-only input.

Replace mounted files, then restart the container to validate and serve them
deterministically.
Do not weaken AlmaLinux crypto policy for TLS-1.0-only hardware; use IP policy.

## Certificates and loops

| Variable | Default |
|---|---|
| `MAIL_CERT_VALIDITY_DAYS` | `730` |
| `MAIL_CERT_RENEW_AT_DAYS` | half of validity |
| `MAIL_CERT_GRACE_DAYS` | `7` |
| `MAIL_INBOUND_TLS_VALIDITY_DAYS` | `3650` |
| `MAIL_INBOUND_TLS_RENEW_AT_DAYS` | `365` |
| `MAIL_TOKEN_LOOP_SECONDS` | `300` |
| `MAIL_ROTATION_LOOP_SECONDS` | `86400` |
| `MAIL_VERIFY_LOOP_SECONDS` | `3600` |
| `MAIL_VERIFY_SEND` | `yes` when an admin email exists |
| `MAIL_CA_BUNDLE_MAX_AGE_DAYS` | `90` |

Loop timing overrides are primarily for isolated tests. Rotation always stages,
adds, waits for replication, proves token and delivery, swaps atomically,
re-mints immediately, and retires the old key on a later run.

### What can expire during unattended operation

- The OAuth access token is short-lived. The five-minute loop re-mints it when
  fewer than 30 minutes remain; it is not a certificate and is never renewed on
  a fixed 30-minute schedule.
- The generated OAuth app certificate defaults to 730 days and attempts a
  proven, staged rotation halfway through its life. If every app certificate
  expires or external policy blocks Graph `addKey`, recovery requires an Entra
  administrator; alerts are therefore essential.
- The generated inbound STARTTLS certificate follows the independent 3,650/365
  day lifecycle above. A BYO certificate is never overwritten: its CA/ACME or
  secret-manager owner must replace it and restart the container. The verifier
  and daily rotation check alert inside its renewal window.
- Microsoft owns and rotates the certificate presented by
  `smtp.office365.com`; there is no Microsoft leaf certificate to renew or pin
  in this project. The `secure` default validates its chain, hostname, and
  validity against the image CA bundle. `encrypt` remains an explicit
  compatibility mode but does not authenticate the server.
- CA roots, distro security packages, DNS, tenant permissions, mailbox licenses,
  Conditional Access, SMTP AUTH settings, webhook credentials, disk capacity,
  and system time can all change independently. No container can guarantee
  years of truly zero maintenance. Rebuild/pull patched images regularly,
  restart onto the reviewed digest, retain the state/spool volumes, and monitor
  the hourly probes and rotation alerts.

The verifier reports an image CA bundle older than 90 days and repeats an
email/webhook maintenance warning weekly. This does not mutate a running image;
replace it with a tested, current image digest. Increase the threshold only if
your organization has a different documented patch cadence.

### Corporate TLS inspection

An inspecting firewall terminates TLS and can read the XOAUTH2 bearer token and
message. If that is an accepted organizational tradeoff, mount its **public
root CA certificate** and set `MAIL_UPSTREAM_CA_EXTRA_FILE` to that path. Boot
rejects missing, malformed, expired, not-yet-valid, or private-key-bearing
files. The runtime bundle contains both normal public roots and the corporate
root, while `secure` still requires the replacement leaf certificate to match
`smtp.office365.com`. Without explicit trust, inspection fails closed and mail
defers for the configured queue lifetime.

```yaml
environment:
  MAIL_UPSTREAM_CA_EXTRA_FILE: /run/secrets/corporate_smtp_ca
secrets:
  - corporate_smtp_ca
```

## Mounted `main.cf` and `POSTFIX_*`

Mount a base configuration at `/etc/postfix-m365-relay/main.cf`. It replaces the
generated base. Then any environment variable `POSTFIX_<name>` becomes a lower-
cased `name = value` through `postconf`.

Finally, the visible `postfix-m365-relay (managed)` block force-asserts the
upstream OAuth settings, relay restrictions, sender guard and rewrites, local-
delivery refusal, and all inbound SASL/TLS policy. A mounted file cannot turn
the image into an open relay or expose AUTH before TLS.

## Hardened read-only variant

```yaml
read_only: true
tmpfs:
  - /etc/postfix
  - /run
  - /var/lib/postfix
volumes:
  - mail-relay-state:/var/lib/mail-relay
  - mail-relay-spool:/var/spool/postfix
```

Tier 2 remains compatible because sasldb2 is rebuilt in `/run/mail-relay`.

## Images

Use the normal tag for arm64 and x86-64-v3. Use the matching
`-x86-64-v2` tag for older x86 hardware. Docker Hub is primary and GHCR mirrors
the same release. Pin by digest after testing.
