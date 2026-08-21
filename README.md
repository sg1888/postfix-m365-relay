# postfix-m365-relay

A lightweight mail relay for your Docker containers and your internal IoT devices
(printers, NAS boxes, UPSes, scanners, home-lab apps). It connects to a
Microsoft 365 shared mailbox — or a regular user mailbox — and sends email on
their behalf. Authentication uses SASL XOAUTH2 with an app-only OAuth token, so
the relay keeps working after Microsoft sunsets basic SMTP AUTH in December 2026
(tentative date).

It builds on the excellent [`sasl-xoauth2`](https://github.com/tarickb/sasl-xoauth2)
plugin and stands on well-worn parts: [Postfix](https://www.postfix.org/),
[Cyrus SASL](https://www.cyrusimap.org/sasl/), Python
[`cryptography`](https://cryptography.io/), and an
[AlmaLinux 10](https://almalinux.org/) + EPEL base (supported through 2035).

> [!WARNING]
> **Never publish this service to the Internet.** It's built for a trusted LAN
> and must be bound to a specific host interface. If a device has to cross an
> untrusted network to reach it, put a TLS-capable gateway in front. Don't argue
> with this one.

## What this app does

* Uses a single M365 shared mailbox (or user mailbox) to send email on behalf of
  your Docker containers and IoT devices — printers, servers, monitoring stacks,
  and so on.
  - You can send from multiple addresses using
    [aliases](docs/SENDER-REWRITING.md).
  - Each device can carry its own **display name** in the email. You are not
    stuck with the shared mailbox's name.
  - You can rewrite sender names and addresses per device. Some apps won't let
    you set a display name at all (**cough** _Diun_) — this relay handles that
    with Postfix canonical rewriting and display-name renaming. See
    [Sender rewriting](docs/SENDER-REWRITING.md).
* Lets your devices send email **without ever seeing your Microsoft 365
  credentials**. The OAuth secret never leaves the relay.
* Lets you authenticate devices by **source IP, username/password, or both**.
  - Some older devices can't do TLS. Those can still send using source-IP
    authentication — no password required (details below).
* Encrypts the relay-to-Microsoft hop **every time**, verifying Microsoft's
  certificate — even when the sending device itself can't speak TLS.
* Lets you reuse many of your standard Postfix settings via `POSTFIX_*`
  overrides. See the [Configuration reference](docs/CONFIGURATION.md).
* Runs **unprivileged**: it listens on port 2525 so the container needs no
  privileged-port capability.
* Manages its own credentials: it generates the OAuth client certificate on
  first boot and rotates it automatically before expiry. No passwords to babysit.
* Queues mail and retries if Microsoft is briefly unreachable, and emails (or
  webhooks) a designated admin if something goes wrong.
* Lets you use your **existing tenant/subscription** instead of paying a
  third-party email provider (SMTP2Go, SendGrid, and friends).
* Ships as a multi-arch image (amd64 and arm64, including 64-bit Raspberry Pi).

## Why use postfix-m365-relay?

Fair question. There are plenty of other relays out there, and you should go look
at them. I did, none of them solved all of my problems, so I wrote this one.
Here's what sets it apart:

* **Modern OAuth 2.0.** It authenticates through Microsoft's Role-Based Access
  Control (RBAC) for SMTP — not basic SMTP AUTH and not the
  [legacy Application Access Policies](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-access-policies),
  which Microsoft says will be deprecated (no date announced yet).
* **Very restricted access.** The app doesn't need Entra permissions, FullAccess,
  mailbox read permissions, or even sign-in capability. It is limited to sending
  email — nothing else.
* **Works with an unlicensed shared mailbox,** freeing up a license for a real
  user.
* **Password-less.** It uses certificates and tokens that auto-rotate before they
  expire.
* **Tells you when something breaks.** It emails a designated admin on failure,
  and can also fire a webhook in case email itself is the thing that's down.

## What this app is NOT

* **Not a full mail server.** It only relays outbound email for your containers
  and devices through one M365 shared mailbox. It does not receive Internet mail,
  deliver locally, or sign DKIM. Microsoft 365 stays responsible for DKIM, SPF,
  DMARC, reputation, and final delivery.
* **Not compatible with other providers** (Gmail, Outlook.com, etc.). It is
  **only** for Microsoft 365-hosted domains.

## What you need

As the name suggests, it's a relay for Microsoft 365 — and nothing else. To run
it you'll need:

* Admin access to a Microsoft 365 **tenant** (not a consumer M365 account)
* PowerShell, Docker, and a reasonable amount of IT comfort

### Setup at a glance

Start to finish, getting mail flowing is these steps. Each links to its detail
below; do the Microsoft side and the Docker side in either order — they meet at
step 6 (the certificate upload).

1. **Microsoft:** create a dedicated shared mailbox and an Entra app registration;
   record the tenant ID, client ID, and Enterprise App object ID.
   → [One-time Microsoft setup](#one-time-microsoft-setup)
2. **Microsoft:** run `powershell/setup-exchange.ps1` to grant the scoped,
   read-nothing SendAs role. → [same section](#one-time-microsoft-setup)
3. **Docker:** `docker compose up -d`. The relay writes a template config and
   waits. → [Quick start](#quick-start-a-private-docker-relay)
4. **Docker:** fill the three identifiers + mailbox into
   `./mail-relay/mail-relay.conf`. Named senders are optional. The relay starts on
   its own. → [Quick start](#quick-start-a-private-docker-relay)
5. **Docker:** the relay generates its OAuth certificate and writes the public
   half to `./mail-relay/microsoft365-app-public-cert.pem`.
6. **Microsoft:** upload that file to the app registration's **Certificates**.
   The relay accepts the token, deletes the export, and starts sending — and from
   here it rotates the certificate itself, with no further manual steps.
7. **Verify:** run the built-in end-to-end check and watch a real message land.
   → [Test that it actually works](#test-that-it-actually-works)

---

## How it works in 30 seconds

Two ideas kill about 90% of the questions before you ask them:

**1. The port number is not the encryption.** People conflate these constantly.
The relay always listens on `2525` inside the container — a number picked so the
process runs unprivileged, nothing more. Encryption is decided by the auth/TLS
policy you set, not by whether the port happens to be 587.

**2. The relay-to-Microsoft hop is always encrypted.** However a device reaches
the relay — even plaintext on your LAN — the relay opens a *verified* TLS
connection to `smtp.office365.com` to actually deliver. So yes, your ancient
printer that has never heard of SSL is fine: its one plaintext hop stays on your
trusted LAN, and everything past the relay is encrypted whether it likes it or not.

```
  container / device                 relay                      Microsoft 365
  ┌──────────────┐   plaintext or  ┌──────────┐   always TLS  ┌───────────────┐
  │ Grafana,     │──── STARTTLS ──▶│ :2525    │──── XOAUTH2 ─▶│ smtp.office365 │
  │ printer, ... │   (your choice) │          │  (verified)   │     .com:587   │
  └──────────────┘                 └──────────┘               └───────────────┘
```

That second hop is why locking the relay to port 587 would be pointless: it would
shut out the exact plaintext-only devices this project exists for, while making
delivery to Microsoft precisely zero percent more secure than it already is.

---

## Quick start: a private Docker relay

This is how most people will run it — no published port, containers only. Create
a mail-relay directory and bring up the [`compose.yaml`](compose.yaml):

```bash
mkdir -p mail-relay
docker compose up -d
docker compose logs -f postfix-m365-relay
```

> [!NOTE]
> **The default image runs anywhere — nothing to pick.** `:latest` is the
> Ubuntu-based build and works on every x86-64 CPU, including **virtual machines**
> with the default QEMU/KVM CPU and budget chips (Celeron/Atom/N-series, NAS
> boxes), plus arm64. If you specifically want the optimized AlmaLinux builds,
> `:alma-v3` (needs AVX2) and `:alma-v2` (needs SSE4.2, amd64-only) are available.
> See [Base image & CPU compatibility](docs/BASE-IMAGE.md) for the details.

A minimal `compose.yaml` looks like this:

```yaml
services:
  postfix-m365-relay:
    image: docker.io/sg1888/postfix-m365-relay:latest
    container_name: postfix-m365-relay
    restart: unless-stopped

    # `expose` documents the port for other containers. It does NOT open a
    # host/LAN port — nothing outside this Docker network can reach the relay.
    expose:
      - "2525"

    volumes:
      - ./mail-relay:/config                   # human-edited settings live here
      - mail-relay-state:/var/lib/mail-relay   # OAuth key + rotation state
      - mail-relay-spool:/var/spool/postfix    # deferred mail (survives restarts)
    tmpfs:
      - /run/mail-relay:rw,nosuid,noexec,mode=0750  # tokens, sasldb2 (ephemeral)

    networks:
      mail-relay:
        aliases: [postfix-m365-relay]

networks:
  mail-relay:
    name: mail-relay

volumes:
  mail-relay-state:
    name: mail-relay-state
  mail-relay-spool:
    name: mail-relay-spool
```

On first boot the container copies its sample to `./mail-relay/mail-relay.conf`,
locks it down to `0600`, and **waits without opening SMTP** until you fill in the
required values. Edit that file on the host:

```env
MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
MAIL_SEND_MAILBOX=relay-test@example.com
MAIL_ADMIN_EMAIL=relay-admin@example.com
```

Those three identifiers plus the mailbox are **all that is required**. Named
senders are optional: leave them out and every message is sent as
`MAIL_SEND_MAILBOX` while keeping the display name the sending application
supplied. Add a `MAIL_SENDER_<APP>` (and optional `MAIL_SENDER_NAME_<APP>`) only
when you want to pin a specific From display name for one application. See
[Sender modes](#sender-modes) for the sender allowlist.

Save it in place — the waiting container notices and starts on its own. The file
is a bind-mounted host file, not baked into the image; environment variables and
`env_file:` are supported as optional overrides but aren't required. An explicit
environment value wins over the matching file line without rewriting the file.

Once the required values are set, an empty state volume triggers generation of an
RSA-4096 OAuth client certificate. Its **public** half is written to
`./mail-relay/microsoft365-app-public-cert.pem` (with the SHA-1 thumbprint in
`./mail-relay/microsoft365-app-cert-thumbprint.txt`) — a normal file in your
`mail-relay` folder, no `docker logs` needed. Upload that public certificate to
your app registration (see [Microsoft 365 setup](docs/MICROSOFT-SETUP.md)). The
container stays up, retries minting a token every five minutes, and queues mail
until the upload propagates. Once Microsoft accepts it, the relay removes that
export automatically and never needs you again — it rotates the certificate on
its own from then on. The private key never leaves the `mail-relay-state` volume.

Running without a writable `/config` mount (an env-only deployment)? The bootstrap
file has nowhere to land, so dump the public certificate straight to a file
instead — no `docker logs` scraping:

```bash
docker exec postfix-relay export-cert > m365-app-cert.pem
```

`export-cert` (equivalently `relay-admin export-cert`) prints only the public
certificate; the private key is never emitted. It exits non-zero until the relay
has generated the certificate on first boot.

> Prefer `docker run`? See the [full run command](docs/NETWORKING.md). No port is
> published in either local-network path.

## Test that it actually works

Before you wire up a single app, prove the relay reaches Microsoft. One command
runs the same audit the container runs on every verify cycle — listener, token,
certificate, rotation, queue, and SASL checks — all internal, no email sent:

```bash
docker exec postfix-m365-relay /usr/local/libexec/mail-relay/verify-relay.sh
```

To also prove **end-to-end delivery** — a real message travelling localhost
submit → XOAUTH2 `AUTH` → Microsoft **accept**, confirmed by its arrival in your
inbox — opt in for a one-off run:

```bash
docker exec -e MAIL_VERIFY_SEND=yes postfix-m365-relay /usr/local/libexec/mail-relay/verify-relay.sh
```

A healthy run ends with `healthy (0 warning(s))`. With the delivery probe
enabled it also drops a "postfix-m365-relay end-to-end verification" message into
your `MAIL_ADMIN_EMAIL` inbox — that arrival is your proof mail is really
flowing. This is a **test tool**: the relay never emails the admin on a schedule
(`MAIL_VERIFY_SEND` defaults to `no`; see docs/CONFIGURATION.md). Turn it on
while validating, then turn it back off.

If something's wrong, it doesn't just say "failed." It names **which** part broke
and why, so you know exactly what to fix:

```text
FAILED relay:       SMTP listener does not answer on 2525
FAILED token:       token expires too soon (unreadable s)
FAILED certificate: OAuth certificate is expired or unreadable
FAILED rotation:    last rotation event failed: ...
```

The most common first-run result is a **token** failure: the container minted its
OAuth certificate but you haven't uploaded the public half to your Microsoft app
registration yet, so no token can be issued. Upload
`./mail-relay/microsoft365-app-public-cert.pem`, wait for propagation, and re-run.
The command exits `0` when healthy and `1` when any category failed, so you can
drop it into a script or CI check.

## Wiring an application to the relay

There's no special magic on the app side, despite what you may be dreading. Point
its SMTP settings at the relay's container name and port, and — inside the private
Docker network — skip encryption and authentication entirely:

```text
SMTP host:      postfix-m365-relay
SMTP port:      2525
Encryption:     none   (you're on a private Docker network)
Authentication: none
From:           app@relay.example.local
```

The only "special" part is the **port**: most apps default to 25, 465, or 587, so
you type `2525` into the port field. That's the whole trick — it's a text box, not
a custom protocol. The `From` address just has to match one of your
`MAIL_SENDER_*` values.

Here's the same relay wired to Grafana and Gitea in one Compose file
([`examples/compose-with-apps.yaml`](examples/compose-with-apps.yaml) has the
full version with Alertmanager too):

```yaml
  grafana:
    image: docker.io/grafana/grafana:latest
    environment:
      GF_SMTP_ENABLED: "true"
      GF_SMTP_HOST: postfix-m365-relay:2525
      GF_SMTP_FROM_ADDRESS: grafana@relay.example.local
      GF_SMTP_FROM_NAME: Grafana alerts
      GF_SMTP_STARTTLS_POLICY: NoStartTLS   # plaintext inside the private network
    networks: [grafana-internal, mail-relay]

  gitea:
    image: docker.gitea.com/gitea:latest
    environment:
      GITEA__mailer__ENABLED: "true"
      GITEA__mailer__PROTOCOL: smtp
      GITEA__mailer__SMTP_ADDR: postfix-m365-relay
      GITEA__mailer__SMTP_PORT: "2525"
      GITEA__mailer__FROM: Gitea notifications <gitea@relay.example.local>
      # No USER/PASSWD — none is needed in private Docker-network mode.
    networks: [gitea-internal, mail-relay]
```

Only the process that actually sends mail needs to join `mail-relay`; databases
and backends can stay on their own `internal: true` networks. In the default
`collapse` mode, both apps deliver as the one authorized mailbox but keep their
own display names — so the same recipient sees mail from "Grafana alerts" and
"Gitea notifications." Full topologies (same-project, cross-project, isolated
networks, LAN) are in [NETWORKING.md](docs/NETWORKING.md); real app configs are
in [WIRING.md](docs/WIRING.md).

## Letting devices outside Docker use the relay (printers, etc.)

A printer or scanner that isn't a container can't join the Docker network, so you
publish a **host** port for it. This is where the port/encryption split really
pays off, and it answers the two questions everyone asks:

**"2525 is non-standard — will my printer accept it?"** Two options, pick your
device's flavor of stubborn:

* If the device lets you set the SMTP port (most do), set it to `2525`. Done.
* If the device is hard-wired to a "normal" port like `587` or `25`, **map it**.
  Docker will publish any host port you want onto the container's `2525`:

  ```yaml
  ports:
    # HOST_LAN_IP : HOST_PORT : CONTAINER_PORT
    - "192.0.2.10:587:2525"   # device connects to your host on 587; relay stays 2525
  ```

  The device thinks it's talking to a normal `587` server. Internally the relay
  is still `2525` and still unprivileged, and everyone's happy. Never shorten this
  to `587:2525` — that publishes on **every** interface, which is the opposite of
  what you want. Always pin the host LAN IP.

#### Multiple ports, fixed ports, and the port 25 crowd

The container has exactly **one** listener, on `2525`. Everything else is just
host-port publishing aimed at it. So map as many host ports as your fleet
insists on — they all land on the same relay:

```yaml
ports:
  - "192.0.2.10:25:2525"     # copiers hard-wired to port 25
  - "192.0.2.10:587:2525"    # devices that only speak "submission"
  - "192.0.2.10:2525:2525"   # anything sensible enough to use 2525
```

A few things to know before you get clever:

* **Do 587 and 25 *need* to be mapped?** Yes. The relay never listens on 587 or
  25 — only 2525. Nothing reaches it on those ports unless you publish them. Skip
  the mapping and the device connects to nothing. Want *only* 587 and 25 on the
  host? Just list those two and leave 2525 off.
* **Port 25 is privileged, but you don't grant the container anything** — the
  Docker daemon (root) binds the host port. One gotcha: if the host already runs
  a local MTA on 25, that conflict is yours to resolve.
* **One listener, one policy.** Every published port shares the *same*
  `MAIL_INBOUND_AUTH` and `MAIL_INBOUND_TLS`. You can't make 587 require auth
  while 25 is IP-only. Different policy per port means separate relay containers.
* **Don't map 465.** That's implicit TLS (SMTPS) — TLS before any SMTP. This
  relay does STARTTLS on a plaintext listener, so a device expecting SMTPS on 465
  fails the handshake. Stick to 25, 587, or 2525.

**"A lot of my devices can't do SSL — doesn't port 587 force encryption?"** No.
On this relay the port and the encryption are independent. A device with no
TLS support authenticates by **source IP**, with no password:

```yaml
services:
  postfix-m365-relay:
    image: docker.io/sg1888/postfix-m365-relay:latest
    restart: unless-stopped
    ports:
      - "192.0.2.10:587:2525"        # or 2525:2525 if the device can use 2525
    environment:
      MAIL_INBOUND_AUTH: ip          # authenticate by source IP only
      MAIL_INBOUND_TLS: "off"        # legacy device speaks plaintext on the LAN
      MAIL_TRUSTED_NETWORKS: 192.0.2.50/32,192.0.2.51/32   # per-device /32s
    volumes:
      - ./mail-relay:/config
      - mail-relay-state:/var/lib/mail-relay
      - mail-relay-spool:/var/spool/postfix
    tmpfs:
      - /run/mail-relay:rw,nosuid,noexec,mode=0750
    networks:
      mail-relay:

networks:
  mail-relay:
volumes:
  mail-relay-state:
  mail-relay-spool:
```

The plaintext hop stays on your trusted LAN; the relay-to-Microsoft hop is still
encrypted. Use the narrowest CIDRs you can (a `/32` per device), keep those
devices on a dedicated VLAN, and restrict the published port at your firewall.

For devices that **can** do STARTTLS, hand out per-device passwords instead (or
in addition). The full example with a Docker-secret password file is
[`examples/compose.device-relay.yaml`](examples/compose.device-relay.yaml). The
available policies:

| Policy         | What it requires                                    | Good for |
|----------------|-----------------------------------------------------|----------|
| `off`          | nothing (Docker network only)                       | containers |
| `ip`           | source IP on the allowlist                          | fixed legacy printers, no TLS |
| `smtp-auth`    | username + password, **after STARTTLS**             | modern/roaming devices |
| `ip-or-auth`   | allowlisted IP **or** valid credentials             | mixed fleet (old printer + modern device) |
| `ip-and-auth`  | allowlisted IP **and** valid credentials            | managed devices, defense in depth |

> [!IMPORTANT]
> **Never give a password to a device that can't do STARTTLS.** SASL PLAIN/LOGIN
> over plaintext hands your credentials to anyone watching the wire. This image
> only advertises AUTH *after* STARTTLS and rejects an early AUTH attempt. Keep
> no-TLS devices on `ip`, on an isolated VLAN, restricted at the firewall.

The device password file is one `user:password` per line, mounted as a Docker
secret:

```text
printer:use-a-long-unique-password
nas:use-a-different-long-password
```

Read [EXTERNAL-SENDERS.md](docs/EXTERNAL-SENDERS.md) before you publish a port.
For a real STARTTLS certificate from Let's Encrypt, see
[`examples/compose.letsencrypt.yaml`](examples/compose.letsencrypt.yaml).

## Testing that mail actually works

Prove it end to end. "The container started" is not a test. A local `250 OK` only
means the relay *accepted* the message — it says nothing about whether Microsoft
actually delivered it. And after any Exchange permission change, wait two hours
before trusting a result, because Exchange propagation runs on its own schedule
and does not care about yours.

**1. Confirm the listener (and that you didn't over-publish a port):**

```bash
# In Docker-only mode this should print NOTHING:
docker port postfix-m365-relay
# The container answers with a 220 banner on its own port:
docker exec postfix-m365-relay sh -c "printf 'QUIT\r\n' | nc -w3 127.0.0.1 2525"
```

**2. Send a real test message and follow it to the recipient.** The bundled
[`scripts/qualify-relay.py`](scripts/qualify-relay.py) sends a message, prints a
unique Message-ID, and lets you map it to a Postfix queue ID and a `status=sent`:

```bash
./scripts/qualify-relay.py \
  --host postfix-m365-relay --from-address app@relay.example.local \
  --from-name 'MyServer [TestServer]' --to you@example.com
```

Then watch it leave and confirm it landed in the recipient mailbox:

```bash
docker compose logs -f postfix-m365-relay   # look for status=sent + your Message-ID
```

**3. Test the alert path** so you'll actually hear about outages:

```bash
docker exec postfix-m365-relay alert.sh notify info manual-test 'test detail'
```

**4. Test an external device** the way the device will connect — from the real
LAN interface, using its own IP/credentials. [`swaks`](https://github.com/jetmore/swaks)
is handy here:

```bash
# From an allowlisted host, plaintext (ip policy):
swaks --server 192.0.2.10:587 --from app@relay.example.local --to you@example.com
```

The full release-gate matrix — every auth policy, TLS-before-AUTH, revocation,
certificate rotation, upstream-outage recovery — is in
[TESTING.md](docs/TESTING.md).

---

## One-time Microsoft setup

Use a **separate test mailbox and test app registration** first. Do not
experiment against production; future-you will thank present-you. Change any
Exchange permission and you wait two hours before trusting a send test — that's
Exchange, not the relay.

1. Create a dedicated shared mailbox and block its interactive sign-in. Keep it
   only for relay output. Below 50 GB it normally needs no separate license;
   licensed archive, hold, advanced compliance, or larger storage have their own
   Microsoft requirements.
2. In the Microsoft Entra admin center, open **Entra ID → App registrations** and
   create an app registration.
3. Record its Application (client) ID and tenant ID. Under **Enterprise
   applications**, open the matching application and record the Enterprise
   Application Object ID.
4. Leave the app registration's **API permissions empty**. Claims-less Exchange
   App RBAC doesn't use the legacy `SMTP.SendAsApp` Entra permission and needs no
   Graph mail permissions.
5. Create a dedicated Exchange distribution or mail-enabled security group and add
   only the relay shared mailbox as a direct member.
6. Run `powershell/setup-exchange.ps1` from an admin workstation. It creates
   Exchange's service-principal record, a group-backed management scope, and the
   scoped `Application SMTP.SendAsApp` role. It does **not** grant `FullAccess`,
   so the relay can't read mailbox contents.
7. Start the container once. It generates its OAuth certificate and writes the
   **public** half to `./mail-relay/microsoft365-app-public-cert.pem`. Upload that
   file under **App registrations → your app → Certificates & secrets →
   Certificates**. Never upload or copy the private key (it never leaves the
   relay's state volume). The relay removes the export once Microsoft accepts it,
   then rotates the certificate itself — this upload is the only manual cert step,
   ever.
8. Wait two hours after the last permission change, then prove delivery using only
   the test objects.

```powershell
./powershell/setup-exchange.ps1 `
  -Mailbox relay-test@example.com `
  -ScopeGroup postfix-m365-relay-mailboxes@example.com `
  -ClientId 11111111-1111-1111-1111-111111111111 `
  -EnterpriseAppObjectId 22222222-2222-2222-2222-222222222222
```

Pass `-EnableSendFromAlias` only after reading the passthrough warning below —
that switch changes `SendFromAliasEnabled` for your **entire** Exchange
organization.

Read the [full Microsoft 365 setup](docs/MICROSOFT-SETUP.md) before making tenant
changes. It links the Microsoft docs behind each PowerShell command and explains
the no-read security boundary and licensing caveats.

## Sender modes

**Named senders are optional.** With none configured, the relay sends every
message as `MAIL_SEND_MAILBOX` and keeps the display name the sending application
supplied (falling back to `MAIL_SENDER_NAME_FALLBACK` when the app supplies none).
Define a `MAIL_SENDER_<APP>` — and optionally `MAIL_SENDER_NAME_<APP>` — only to
pin a specific From display name for one application.

Envelope-From admission is controlled by `MAIL_SENDER_ALLOWLIST`:

| Value | Behavior |
|-------|----------|
| `off` (default) | Accept any envelope sender from an already-authorized client and collapse it to the mailbox. No per-application registration needed. |
| `on` | Reject any envelope From that is not `MAIL_SEND_MAILBOX` or a configured `MAIL_SENDER_*` address. |

`off` is **not** an open relay: who may connect is always governed separately by
`MAIL_INBOUND_AUTH` and `MAIL_TRUSTED_NETWORKS`. The allowlist only restricts
which From addresses an already-authorized client may use.

`MAIL_SENDER_MODE=collapse` is the proven default. Every permitted sender is
rewritten to the relay mailbox, which avoids Exchange `SendAsDenied` responses
while keeping each device's display name.

`MAIL_SENDER_MODE=passthrough` preserves only the addresses listed in
`MAIL_PASSTHROUGH_SENDERS`; every other sender still collapses. Passthrough is
for proxy addresses on the same mailbox and requires org-wide
`SendFromAliasEnabled`. Don't rely on it until you've watched it work with
dedicated test objects and completed the alias gate in
[TESTING.md](docs/TESTING.md). Foreign-mailbox SendAs is out of scope.

## Corporate TLS inspection

Outbound TLS verifies `smtp.office365.com` by default. If an authorized corporate
firewall re-signs that connection, mount its public inspection root with
`MAIL_UPSTREAM_CA_EXTRA_FILE` — don't turn off server authentication just to make
inspection work. Note that the firewall can then see the bearer token and message
contents. Format, rotation, and a Compose example are in
[SECRETS.md](docs/SECRETS.md#corporate-smtp-inspection-ca-public-not-secret).

## What runs inside the image

Bash is PID 1 and supervises Postfix plus three restartable loops:

- **token refresh** every five minutes, minting only when under 30 minutes remain;
- **certificate rotation** — the OAuth app certificate and, independently, the
  inbound STARTTLS certificate — checked daily;
- **health verification** hourly: listener, token, certificates, queue, and SASL
  failures — all internal. The end-to-end delivery probe (a real email to the
  admin) is off by default and test-only; enable with `MAIL_VERIFY_SEND=yes`.

### Where things are stored, and why

The Compose file uses three kinds of storage on purpose. They aren't
interchangeable and none of them is decoration:

| Mount | Kind | Holds | Survives a container update? |
|---|---|---|---|
| `./mail-relay` | **bind mount** (host folder) | `mail-relay.conf`, device-password file | yes — it's your folder |
| `mail-relay-state` | **named volume** | OAuth private key + cert-rotation state | yes |
| `mail-relay-spool` | **named volume** | Postfix queue / deferred mail | yes |
| `/run/mail-relay` | **tmpfs** (RAM) | access tokens, `sasldb2`, rendered CA | no — wiped every restart, never hits disk |

Quick definitions, since people mix these up:

* **Bind mount** = a real directory on the host. `config` is one because you have
  to *edit* `mail-relay.conf` and drop in the password file. It has to be a path
  you can open.
* **Named volume** = Docker-managed storage the container owns but that must
  **outlive** the container. When you `docker compose pull` a new image, the old
  container is destroyed and replaced — a named volume is how the key and the mail
  queue live through that.
* **tmpfs** = RAM-backed storage, wiped on every restart, mounted `noexec,nosuid`.
  It's where the secrets that should never touch disk go.

> **Named volume vs. bind mount for `state`/`spool`:** both persist — the
> difference is who manages permissions. We default to named volumes because the
> OAuth key wants `0600` and Postfix's spool is famously strict about ownership;
> Docker gets that right for free. Prefer files on a known host path (backups,
> rsync)? Bind-mount them instead — `./state:/var/lib/mail-relay`,
> `./spool:/var/spool/postfix`, drop the top-level `volumes:` block — and you own
> the permission chores. Don't use anonymous volumes for either; they orphan.

Why each one earns its place:

* **`mail-relay-state`** holds the OAuth **private key**. This is the one you do
  *not* skip. Lose it and the container mints a fresh certificate on the next
  update — which means re-uploading the public cert to Entra every single time.
  Keep it, and setup is a one-time thing. Note: `docker compose down` alone keeps
  every volume; only `docker compose down -v` deletes the named volumes, wiping
  the OAuth identity and any queued mail. If you do that, the relay detects the
  empty state on next boot, generates a fresh certificate, and writes a new
  `./mail-relay/microsoft365-app-public-cert.pem` for you to re-upload — a full
  re-bootstrap. Your `./mail-relay` bind-mount folder is never touched by `-v`.
* **`mail-relay-spool`** is the Postfix **queue**. When Microsoft has a bad five
  minutes, deferred mail waits here (12 hours by default). Make it ephemeral and a
  restart quietly eats whatever was queued.
* **`/run/mail-relay`** holds the things that must **never** land on disk: access
  tokens, the `sasldb2` device-password database, rendered CA material. RAM only.

Are we over-engineering? No — run the trim test. Drop `state` and you re-register
with Entra on every update. Drop `spool` and you silently lose mail during any
upstream blip. Drop the `tmpfs` and it still runs, but your tokens and password
database land in the container's writable layer instead of RAM. `config` and
`state` are mandatory; `spool` is "unless you enjoy losing mail"; the `tmpfs` is
cheap hardening you should keep. That's the whole storage story.

## Images and platforms

Docker Hub is primary; GHCR is a mirror. Release CI publishes:

- `latest` / `ubuntu` — Ubuntu base, `linux/amd64` + `linux/arm64`, runs on any CPU;
- `alma-v3` — AlmaLinux (x86-64-v3 / AVX2), `linux/amd64` + `linux/arm64`;
- `alma-v2` — AlmaLinux (x86-64-v2 / SSE4.2), `linux/amd64` only, for older x86.

Use a 64-bit OS on Raspberry Pi. 32-bit platforms are outside the v1 support
contract. Pin a release digest after you evaluate it — tags are mutable.

## Documentation

| Topic | Start here |
|---|---|
| First install and minimal config | This page, above |
| Shared mailbox, claims-less App RBAC, and licensing | [Microsoft 365 setup](docs/MICROSOFT-SETUP.md) |
| Allowlists, address rewriting, fixed names, domains, and aliases | [Sender rewriting](docs/SENDER-REWRITING.md) |
| Connecting Grafana, Gitea, Alertmanager, and Authelia | [Application wiring](docs/WIRING.md) |
| Docker networks, cross-project access, LAN publication, firewalls | [Networking](docs/NETWORKING.md) |
| Legacy printers, IP admission, SASL, and TLS-before-AUTH | [External senders](docs/EXTERNAL-SENDERS.md) |
| OAuth keys, device passwords, inbound TLS keys, inspection CA | [Secrets](docs/SECRETS.md) |
| Every environment variable and Postfix override | [Configuration reference](docs/CONFIGURATION.md) |
| Token refresh, cert rotation, queues, alerts, recovery | [Operator runbook](docs/RUNBOOK.md) |
| Security boundary and supported CPU platforms | [Scope and platforms](docs/SCOPE.md) |
| Offline, live-install, failure, and release qualification | [Testing](docs/TESTING.md) |
| Publishing images and release tags | [Maintainer release procedure](docs/RELEASING.md) |
| GitHub repository and Actions | [GitHub guide](docs/GITHUB.md) |

## License

See [LICENSE](LICENSE).
