# Configuration

Start with the generated `/config/mail-relay.conf`. The first boot copies the
fully commented sample to an empty writable `/config` and refuses SMTP traffic
until you set the required values below. Save the file; no container restart needed.

The parser accepts only `MAIL_*`, `POSTFIX_*`, `TZ`, and `RELAY_PORT` as literal
values—no shell expansion, substitution, or escape sequences. Docker or orchestrator
env vars override the file, including empty ones. File changes after boot don't take
effect without a restart; config and credentials render once on startup, by design.

Everything here is optional unless you expose the relay publicly.

## Required and recommended values

| Variable | Required | Meaning |
|---|---:|---|
| `MAIL_RELAY_TENANT` | yes | Entra tenant ID |
| `MAIL_RELAY_CLIENT_ID` | yes | app registration client ID |
| `MAIL_SEND_MAILBOX` | yes | dedicated shared mailbox used only for relay submission (recommended); licensed user mailbox supported |
| `MAIL_SENDER_<KEY>` | no | address an application may use at `MAIL FROM`; optional — with none set, all senders collapse to `MAIL_SEND_MAILBOX` |
| `MAIL_SENDER_NAME_<KEY>` | no | forced display name for that sender |
| `MAIL_ADMIN_EMAIL` | recommended | alert, verification, and rotation-proof recipient |

`MAIL_RELAY_ENTERPRISE_APP_OBJECT_ID` is setup-time only. The running container
doesn't touch it.

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
| `MAIL_SENDER_ALLOWLIST` | `off` | `off`: accept any envelope sender from an authorized client and collapse it. `on`: reject any From not equal to `MAIL_SEND_MAILBOX` or a configured `MAIL_SENDER_*` |
| `TZ` | container `/etc/localtime` | IANA timezone used by Postfix and local-time tools |

Container engines don't inherit your server's timezone. Set `TZ=America/New_York`
to be explicit. Omit it and the C runtime tries `/etc/localtime`—bind-mount that
if it matters. Neither and you get UTC. Audit prefixes stay UTC on purpose so
incident timelines line up across hosts.

## Sender modes

### Collapse (default)

```env
MAIL_SENDER_MODE=collapse
# Named senders are optional. Define one only to pin a display name:
MAIL_SENDER_BACKUP=backup@relay.example.local
MAIL_SENDER_NAME_BACKUP=Backups
```

Both envelope and header become `MAIL_SEND_MAILBOX`; display names are preserved
(the app's own, or `MAIL_SENDER_NAME_FALLBACK` for a bare address) or forced by a
matching `MAIL_SENDER_NAME_<KEY>`. By default (`MAIL_SENDER_ALLOWLIST=off`) any
envelope sender from an already-authorized client is accepted and collapsed — no
per-application registration needed. Set `MAIL_SENDER_ALLOWLIST=on` to restrict
submission to `MAIL_SEND_MAILBOX` and configured `MAIL_SENDER_*` addresses. Safe
and boring—high praise.

### Passthrough

```env
MAIL_SENDER_MODE=passthrough
MAIL_PASSTHROUGH_SENDERS=alerts@example.com,reports@example.com
```

Allowlisted addresses pass through untouched. Everything else collapses to the
main mailbox, so stray aliases don't spawn bounces. The addresses must be proxy
aliases on that same mailbox.

Don't call this verified until you've tested the SMTP XOAUTH2 app-only alias gate
in `TESTING.md` against dedicated test objects. `SendFromAliasEnabled` is org-wide.

Fixed-host naming, multi-host scenarios, unsupported senders, domain choices,
envelope/header mismatches, special characters, and full alias requirements: see
[SENDER-REWRITING.md](SENDER-REWRITING.md).

## Inbound policy

| `MAIL_INBOUND_AUTH` | Who can relay | SASL | Default TLS |
|---|---|---:|---|
| `off` | Docker subnet only; trusted networks forbidden | no | `off` |
| `ip` | Docker subnet plus `MAIL_TRUSTED_NETWORKS` | no | `off` |
| `smtp-auth` | loopback or authenticated users | yes | `may` |
| `ip-or-auth` | trusted IPs or authenticated users | yes | `may` |
| `ip-and-auth` | trusted IPs and authenticated users | yes | `require` |

Loopback is always open so the in-container verifier can submit without storing
a probe password. Nothing outside can reach it.

Boot refuses these unsafe or contradictory combinations:

- `0.0.0.0/0` or `::/0` in `MAIL_TRUSTED_NETWORKS`;
- trusted networks with policy `off`;
- any password-auth policy with `MAIL_INBOUND_TLS=off`;
- password auth without a readable `MAIL_SMTPD_USERS_FILE`.

### Legacy clients without TLS or SSL

SASL without TLS is not supported. PLAIN and LOGIN offer no protection on their
own—they're safe here only because Postfix gates them behind STARTTLS. The managed
config forces `smtpd_tls_auth_only=yes` for SASL. Before STARTTLS, AUTH is absent
from EHLO and early AUTH commands are rejected.

Pick one of these patterns for older printers, scanners, UPS appliances, or other devices:

- `ip`: all permitted clients are admitted by source IP and use no password;
- `ip-or-auth`: a fixed legacy client is admitted by source IP without a
  password, while clients outside the allowlist must use STARTTLS plus SASL.

Don't configure a SASL username or password on the legacy client. Use the narrowest
possible `/32` address (or a tightly controlled VLAN), bind the port to one LAN
address, and enforce the same source restriction in the firewall. The legacy-to-relay
hop is plaintext; the relay-to-Microsoft hop always uses verified TLS. Devices across
untrusted networks need a local TLS-capable SMTP gateway. TLS-before-AUTH is not
negotiable.

`smtp-auth` and `ip-and-auth` won't serve clients without STARTTLS—both require
SASL. `MAIL_INBOUND_TLS=may` doesn't change that: an allowlisted IP can stay
plaintext, but AUTH stays unavailable until STARTTLS completes.

### `off`

```yaml
environment:
  MAIL_INBOUND_AUTH: off
```

For unpublished Docker-network listeners only. `MAIL_TRUSTED_NETWORKS` must be empty.

### `ip`

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip
  MAIL_INBOUND_TLS: off
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32
```

Fits a fixed printer on a controlled VLAN. Device-to-relay is plaintext;
relay-to-Microsoft always uses TLS.

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

Every non-loopback client, including other containers, must STARTTLS and
authenticate. IP doesn't matter here.

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

The printer at `.50` sends plaintext by IP. Roaming devices outside the allowlist
must STARTTLS and authenticate. Pre-STARTTLS EHLO hides AUTH; after STARTTLS it
shows PLAIN and LOGIN only.

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

Both gates must pass. Correct password from the wrong IP fails; correct IP with
no password fails.

## Inbound TLS

`off`, `may`, and `require` map to Postfix `none`, `may`, and `encrypt`. SASL
modes always force `smtpd_tls_auth_only=yes`.

Without BYO files, the container creates an RSA-2048 self-signed pair under
`/var/lib/mail-relay/inbound-tls`. OAuth rotation refuses paths outside
`/var/lib/mail-relay/secrets`, keeping lifecycles separate. It defaults to 3,650
days valid and auto-renews 365 days before expiry, reusing the private key and
running `postfix reload`. Exact-certificate pinning still needs client trust
updates at renewal; use an externally managed CA where seamless trust matters.

For BYO TLS:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /run/secrets/inbound_tls_cert
  MAIL_INBOUND_TLS_KEY: /run/secrets/inbound_tls_key
secrets:
  - inbound_tls_cert
  - inbound_tls_key
```

`MAIL_INBOUND_TLS_CERT` should be a fullchain PEM for issuers with intermediates:
leaf first, then intermediates. Certbot's `fullchain.pem` has that shape. No
separate chain variable intentionally—Postfix's `smtpd_tls_chain_files` expects
private-key material, not just intermediates.

Replace mounted files and restart to validate them. Don't weaken AlmaLinux crypto
policy for TLS-1.0 hardware—use IP policy instead.

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
| `MAIL_VERIFY_SEND` | `no` -- test-only end-to-end probe; see below |
| `MAIL_CA_BUNDLE_MAX_AGE_DAYS` | `90` |
| `MAIL_TOKEN_ALERT_AFTER` | `3` consecutive failures |
| `MAIL_QUEUE_WARN_DEPTH` | `25` deferred messages |
| `MAIL_SASL_FAILURE_WARN_COUNT` | `10` recent failures |
| `MAIL_ALERT_WEBHOOK` | empty; optional independent JSON incident receiver |
| `MAIL_RUNBOOK_URL` | public project runbook URL used in notifications |

Loop timing overrides are for isolated tests. Rotation stages, adds, waits for
replication, proves token and delivery, swaps atomically, re-mints immediately,
and retires the old key on the next run.

### Bringing your own OAuth certificate

By default the container generates its own RSA-2048 OAuth client certificate on
first boot and rotates it automatically. To supply your own instead, mount the
private key and certificate and point these at them:

| Variable | Meaning |
|---|---|
| `MAIL_RELAY_CLIENT_KEY_FILE` | Path to your OAuth client **private key** (PEM). Must be RSA-2048 or stronger. |
| `MAIL_RELAY_CLIENT_CERT_FILE` | Path to the matching **certificate** (PEM). Its public half is what you upload to the app registration. |

They are copied into the state volume once, on first boot, and thereafter the
relay owns and rotates that copy. Provide both or neither.

### `MAIL_VERIFY_SEND` — end-to-end delivery probe (test only, off by default)

`MAIL_VERIFY_SEND` defaults to `no`. **It is a testing tool, not a production
feature, and the relay never emails the administrator on a schedule.** When set
to `yes`, every verify cycle (`MAIL_VERIFY_LOOP_SECONDS`, default hourly) sends
one real message *through the relay* to `MAIL_ADMIN_EMAIL` and then confirms in
Postfix's log that it reached `status=sent`. That is the only check that proves
the entire path — local submission, XOAUTH2 `AUTH` to Microsoft, and upstream
acceptance — actually delivers; no internal check can prove delivery without
sending mail. The cost is an email to the admin on every cycle, which is why it
must never be left on.

Use it deliberately during **bring-up or troubleshooting**: set
`MAIL_VERIFY_SEND=yes` (optionally with a longer `MAIL_VERIFY_LOOP_SECONDS`, or
run `verify-relay.sh` once by hand), watch the probe arrive in the admin inbox,
then set it back to `no`. All other verify checks — token freshness, OAuth
certificate, rotation, queue depth, and SASL failure counts — run on every cycle
regardless of this setting and never send mail.

### What can expire during unattended operation

- The OAuth access token is short-lived. The five-minute loop re-mints it when
  fewer than 30 minutes remain—not a certificate, never renewed on a fixed schedule.
- The OAuth app certificate defaults to 730 days and attempts staged rotation
  halfway through. If it expires or external policy blocks Graph `addKey`,
  recovery needs an Entra admin—alerts are non-optional.
- The inbound STARTTLS certificate follows the independent 3,650/365 lifecycle.
  BYO certificates are never overwritten; their CA/ACME owner must replace and
  restart. The verifier and daily rotation alert inside the renewal window.
- Microsoft owns the `smtp.office365.com` certificate; no leaf to pin here. The
  `secure` default validates chain, hostname, and validity against the image CA
  bundle. `encrypt` is a compatibility mode without server authentication.
- CA roots, distro packages, DNS, tenant permissions, mailbox licenses,
  Conditional Access, SMTP AUTH, webhook creds, disk, and time can all change
  independently. No container runs zero-maintenance for years. Rebuild/pull
  patched images, restart onto the reviewed digest, keep state/spool volumes,
  and monitor rotation alerts and health checks.

The verifier opens one durable incident when the CA bundle exceeds 90 days;
repeated checks update it without duplicates. A tested image replacement clears
it with the same reference and elapsed duration. This doesn't mutate running
images. Raise the threshold only if your org has a different documented patch
cadence.

### Alert webhook and incident data

`MAIL_ALERT_WEBHOOK` receives JSON for each incident open/recovery and one-time
notices. It includes schema version, status, severity, event, stable reference,
relay name, UTC/local timestamps, timezone, duration, count, redacted evidence,
likely causes, remediation, and runbook URL. Use a TLS URL in production and
treat the endpoint as sensitive. The relay never puts the URL in notification
bodies.

Email and webhook delivery are independent. Failed deliveries persist and retry
with bounded backoff. Configure both when possible: email uses the same Postfix/OAuth
route you're watching, while webhooks can still report that route's failure.

### Push health monitors

`MAIL_RELAY_PUSH_BASE` turns on push-style health reporting (for example an
Uptime Kuma push monitor). Set it to the monitor's base URL and mount one token
file per category you want reported — `/run/secrets/push_token_relay`,
`push_token_token`, `push_token_certificate`, `push_token_rotation`. Each verify
cycle the relay calls `BASE/<token>?status=up|down&msg=...` for every category
that has a token. Only the status word and a character-filtered summary are sent;
never a bearer token, mail content, or raw log line. Leave `MAIL_RELAY_PUSH_BASE`
empty to disable.

### Corporate TLS inspection

An inspecting firewall terminates TLS and reads XOAUTH2 tokens and message
bodies. If your org accepts that tradeoff, mount its **public root CA** and
point `MAIL_UPSTREAM_CA_EXTRA_FILE` there. Boot rejects missing, malformed,
expired, not-yet-valid, or private-key files. The bundle contains public roots
and the corporate root; `secure` still requires the leaf to match
`smtp.office365.com`. Without explicit trust, inspection fails closed and mail
defers for the queue lifetime.

```yaml
environment:
  MAIL_UPSTREAM_CA_EXTRA_FILE: /run/secrets/corporate_smtp_ca
secrets:
  - corporate_smtp_ca
```

## Mounted `main.cf` and `POSTFIX_*`

Mount a base configuration at `/etc/postfix-m365-relay/main.cf` to replace the
generated base. Then `POSTFIX_<name>` env vars become lowercased `name = value`
through `postconf`.

The visible `postfix-m365-relay (managed)` block force-asserts upstream OAuth,
relay restrictions, sender guards and rewrites, local-delivery refusal, and all
inbound SASL/TLS policy. A mounted file can't turn the image into an open relay
or expose AUTH before TLS.

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

Tier 2 works because sasldb2 rebuilds in `/run/mail-relay`.

## Images

The default `latest` (Ubuntu) runs on any x86-64 and arm64. For the AlmaLinux
builds use `alma-v3` (AVX2) or `alma-v2` (SSE4.2, amd64 only). Docker Hub is
primary; GHCR mirrors the release. Pin by digest after testing.
