# postfix-m365-relay

Microsoft 365 is retiring basic SMTP authentication. This image gives Docker
applications and trusted LAN devices one durable outbound path: Postfix submits
to Microsoft 365 with certificate-based, app-only OAuth (XOAUTH2), while each
application keeps its own display name.

This repository and image are intentionally Microsoft 365-only. Their token
scope, SMTP endpoint, Entra setup, Exchange permissions, certificate rotation,
tests, and failure guidance are designed for Microsoft 365—not as a generic
OAuth-provider abstraction. A future general-purpose relay belongs in a
different repository and image.

This is an outbound submission relay, not a full mail server. It does not receive
Internet mail, deliver locally, or sign DKIM. Microsoft 365 remains responsible
for DKIM, SPF, DMARC, reputation, and final delivery.

> Never publish this service to the Internet. The device posture is for a trusted
> LAN and must be bound to a specific host interface.

## Choose a posture

- **Local Docker network (default):** no published port. Applications share a
  private Compose network and send without credentials.
- **Published device relay:** printers, NAS systems, scanners, and UPS devices
  connect through an interface-bound host port. Use narrow IP ranges, per-device
  SMTP credentials, or both.

Start with the local posture unless a non-Docker device truly needs access.

## Documentation index

| Topic | Start here |
|---|---|
| First installation and minimal configuration | [First installation](#first-installation) |
| Microsoft shared mailbox, claims-less App RBAC, and licensing | [Microsoft 365 setup](docs/MICROSOFT-SETUP.md) |
| Sender allowlists, address rewriting, fixed names, domains, and aliases | [Sender rewriting scenarios](docs/SENDER-REWRITING.md) |
| Connecting Grafana, Gitea, Alertmanager, and Authelia | [Application wiring](docs/WIRING.md) |
| Docker networks, cross-project access, LAN publication, and firewalls | [Networking](docs/NETWORKING.md) |
| Legacy printers, IP admission, SASL, and TLS-before-AUTH | [External senders](docs/EXTERNAL-SENDERS.md) |
| OAuth keys, device passwords, inbound TLS keys, and corporate inspection CA | [Secrets](docs/SECRETS.md) |
| Every environment variable and Postfix override | [Configuration reference](docs/CONFIGURATION.md) |
| Token refresh, certificate rotation, queues, alerts, and recovery | [Operator runbook](docs/RUNBOOK.md) |
| Security boundary and supported CPU platforms | [Scope and platforms](docs/SCOPE.md) |
| Offline, live-install, failure, and release qualification | [Testing](docs/TESTING.md) |
| Existing-install migration | [Migration](docs/MIGRATION.md) |
| Publishing images and release tags | [Maintainer release procedure](docs/RELEASING.md) |

## First installation

The container configuration is deliberately small. Create its persistent host
directory and start the complete root [`compose.yaml`](compose.yaml):

```bash
mkdir -p config
docker compose up -d
docker compose logs postfix-m365-relay
```

On first start, the image copies its sample to
`./config/mail-relay.conf`, applies restrictive permissions, and waits without
opening SMTP. Edit that generated file on the host. You need three identifiers,
one or more sender addresses, and preferably an administrator email:

```env
MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
MAIL_SEND_MAILBOX=relay-test@example.com
MAIL_SENDER_APP=app@relay.example.local
MAIL_SENDER_NAME_APP=Example application
MAIL_ADMIN_EMAIL=relay-admin@example.com
```

If the container created the file as the container administrator, use an editor
with equivalent host privileges. Save the file in place; the waiting container
detects it and starts automatically. Follow its progress with:

```bash
docker compose logs -f postfix-m365-relay
```

The file is not baked into the image. It is a bind-mounted host file under the
persistent `./config` directory. Environment variables are optional overrides,
useful for orchestrators; `env_file:` is supported but is not required. An
explicit environment value wins over the corresponding file line without
rewriting the file.

After required configuration is complete, an empty state volume causes the
container to generate an RSA-4096 OAuth client
certificate. The log prints only its public PEM and SHA-1 thumbprint. Upload the
public certificate to the test app registration. The container stays running,
retries token minting every five minutes, and queues mail until the upload has
propagated.

To use `docker run` instead:

```bash
docker volume create mail-relay-state
docker volume create mail-relay-spool
docker network create mail-relay
mkdir -p config
docker run -d --name postfix-m365-relay --restart unless-stopped \
  --network mail-relay \
  --mount type=bind,source="$(pwd)/config",target=/config \
  --mount source=mail-relay-state,target=/var/lib/mail-relay \
  --mount source=mail-relay-spool,target=/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,noexec,nosuid,mode=0750 \
  docker.io/sg1888/postfix-m365-relay:latest
```

No port is published in either local-network example.

## One-time Microsoft setup

Use a separate test mailbox and test app registration first. Never experiment
against a production relay or mailbox. If any Exchange permission changes, wait
two hours before interpreting a send test.

1. Create a dedicated shared mailbox and block its interactive sign-in. Keep it
   only for relay output, not ordinary email. It normally needs no separate
   license below 50 GB; licensed archive, hold, advanced compliance, or larger
   storage scenarios have separate Microsoft requirements.
2. In the Microsoft Entra admin center, open **Entra ID**, select **App
   registrations**, and create an app registration.
3. Record its Application (client) ID and tenant ID. Under **Enterprise
   applications**, open the corresponding application and separately record the
   Enterprise Application Object ID.
4. Leave the app registration's **API permissions empty**. Claims-less Exchange
   App RBAC does not use the legacy Entra `SMTP.SendAsApp` permission and needs
   no Graph mail permissions.
5. Create a dedicated Exchange distribution or mail-enabled security group and
   add only the relay shared mailbox as a direct member.
6. Run `powershell/setup-exchange.ps1` from an administrator workstation. It
   creates Exchange's service-principal record, a group-backed management scope,
   and the scoped `Application SMTP.SendAsApp` role. It does not grant
   `FullAccess`, so the relay app has no permission to read mailbox contents.
7. Start the container once and copy the public certificate from its log. Upload
   it under **App registrations → your app → Certificates & secrets →
   Certificates**. Never upload or copy the private key.
8. Wait two hours after the last permission change, then prove delivery using
   only the test objects.

Example PowerShell invocation:

```powershell
./powershell/setup-exchange.ps1 `
  -Mailbox relay-test@example.com `
  -ScopeGroup postfix-m365-relay-mailboxes@example.com `
  -ClientId 11111111-1111-1111-1111-111111111111 `
  -EnterpriseAppObjectId 22222222-2222-2222-2222-222222222222
```

Pass `-EnableSendFromAlias` only after reading the passthrough warning below.
That switch changes `SendFromAliasEnabled` for the entire Exchange organization.

Read [the complete Microsoft 365 shared-mailbox and App RBAC setup](docs/MICROSOFT-SETUP.md)
before making tenant changes. It links the Microsoft documentation behind each
PowerShell command, explains the no-read security boundary and licensing
caveats, and includes positive plus out-of-scope negative tests.

## Wire an application

Attach the application to the same `mail-relay` network, then configure:

```text
SMTP host: postfix-m365-relay
SMTP port: 2525
Encryption: none (inside the private Docker network)
Authentication: none
From: app@relay.example.local
```

The `From` address must match a `MAIL_SENDER_*` value. In the default `collapse`
mode, the envelope and header address become `MAIL_SEND_MAILBOX`; the original
display name is retained. This lets two applications send to the same recipient
as, for example, “Backups” and “SSO” while using one authorized mailbox.

See [NETWORKING.md](docs/NETWORKING.md) for complete same-project,
cross-project, isolated-network, and LAN topologies. [WIRING.md](docs/WIRING.md)
contains real Grafana, Gitea, Prometheus Alertmanager, and Authelia examples.

## Sender modes

`MAIL_SENDER_MODE=collapse` is the proven default. Every permitted sender is
rewritten to the relay mailbox, preventing Exchange `SendAsDenied` responses.

`MAIL_SENDER_MODE=passthrough` preserves only addresses listed in
`MAIL_PASSTHROUGH_SENDERS`; every other sender still collapses. Passthrough is
for proxy addresses on the same mailbox and requires org-wide
`SendFromAliasEnabled`.

The SMTP XOAUTH2 app-only alias path is a must-test. Do not rely on passthrough
until you watch it work with dedicated test objects and complete the alias gate
in [TESTING.md](docs/TESTING.md). Foreign-mailbox SendAs is out of scope.

## Device relay

[`examples/compose.device-relay.yaml`](examples/compose.device-relay.yaml) shows
the published posture. It binds one LAN IP and uses a Docker secret containing:

```text
printer:use-a-long-unique-password
nas:use-a-different-long-password
```

Available policies are `off`, `ip`, `smtp-auth`, `ip-or-auth`, and
`ip-and-auth`. Password authentication is offered only after STARTTLS and only
as PLAIN/LOGIN. AlmaLinux 10 requires TLS 1.2 or newer; keep ancient plaintext
devices in an IP-only policy rather than weakening crypto policy.

**A client that cannot use STARTTLS must not be given a SASL password.** Use
`ip` for a fleet of fixed legacy devices, or `ip-or-auth` when the same relay
must also serve modern authenticated clients. In `ip-or-auth`, an allowlisted
legacy device submits without credentials while every non-allowlisted client
must negotiate STARTTLS before AUTH is available. Restrict the published port
and allowlisted addresses at the firewall because the legacy device-to-relay
hop is neither authenticated nor encrypted. If the device is not on a trusted
local network, place a TLS-capable SMTP gateway near it instead.

Read [EXTERNAL-SENDERS.md](docs/EXTERNAL-SENDERS.md) before publishing a port.

## Corporate TLS inspection

Outbound TLS verifies `smtp.office365.com` by default. If an authorized
corporate firewall re-signs that connection, mount its public inspection root
with `MAIL_UPSTREAM_CA_EXTRA_FILE`; do not switch off server authentication just
to make inspection work. The firewall can then see the bearer token and message
contents. The exact file format, safe rotation procedure, and Compose example
are in [SECRETS.md](docs/SECRETS.md#corporate-smtp-inspection-ca-public-not-secret).

## What runs inside the image

Bash is PID 1 and supervises Postfix plus three restartable loops:

- token refresh every five minutes, minting only when less than 30 minutes remain;
- OAuth app-certificate rotation and independent inbound STARTTLS renewal daily;
- local health verification hourly, including listener, token, certificates,
  queue, SASL failures, and optional end-to-end delivery.

The OAuth key and state live in `mail-relay-state`; deferred mail lives in
`mail-relay-spool` for 12 hours by default; tokens and sasldb2 live only under
`/run/mail-relay`.

## Images and platforms

Docker Hub is primary; GHCR is a mirror. Release CI publishes:

- `linux/amd64` (x86-64-v3) and `linux/arm64` under normal tags;
- `linux/amd64/v2` under tags ending `-x86-64-v2`.

Use a 64-bit OS on Raspberry Pi. 32-bit platforms are outside the v1 support
contract. Pin a release digest after evaluating it; tags are mutable.

## Next documents

- [GitHub repository and Actions guide](docs/GITHUB.md)
- [Microsoft 365 shared-mailbox and App RBAC setup](docs/MICROSOFT-SETUP.md)
- [Sender address and display-name rewriting scenarios](docs/SENDER-REWRITING.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Docker and LAN networking](docs/NETWORKING.md)
- [Secrets model](docs/SECRETS.md)
- [Operator runbook](docs/RUNBOOK.md)
- [Scope and platforms](docs/SCOPE.md)
- [Release and live-install qualification](docs/TESTING.md)
- [Maintainer release procedure](docs/RELEASING.md)

## License

See [LICENSE](LICENSE).
