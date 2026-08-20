# Docker and LAN networking

The relay listens on TCP 2525 inside its container. How a sender reaches that
listener decides which topology is safe:

- Docker applications share a user-defined bridge and resolve
  `postfix-m365-relay` through Docker DNS; no host port is published.
- Separate Compose projects share a pre-created external Docker network.
- Printers and LAN devices require an explicitly interface-bound published port
  plus narrow IP allowlist, auth, or both.

Outbound is separate. The relay must reach `smtp.office365.com:587` plus
Microsoft login and Graph HTTPS endpoints. `internal: true` network blocks
egress when it's the relay's only network.

## Complete Docker-only deployment

Use the repository's root `compose.yaml`. First startup creates
`config/mail-relay.conf` from the image sample and waits with SMTP closed.
Edit it; the container detects a complete required block and starts.

```bash
mkdir -p mail-relay
docker compose config
docker compose up -d
docker compose logs postfix-m365-relay
# Edit config/mail-relay.conf, then follow startup:
docker compose logs -f postfix-m365-relay
docker compose ps
docker port postfix-m365-relay
```

Environment variables override config as higher precedence. A Compose `env_file:`
exists for automation but isn't required—it's not part of a normal install.

The last command should print nothing. `expose: 2525` is metadata, not host
publication.

Every sender needs the relay's network. Docker DNS resolves the service
name—don't use container IPs; they change on recreation.

```text
SMTP host       postfix-m365-relay
SMTP port       2525
Authentication  none
TLS             none on the private Docker hop
From            one configured MAIL_SENDER_* address
```

The private hop doesn't weaken upstream. The relay still requires verified
STARTTLS and XOAUTH2 when submitting to Microsoft. For untrusted
infrastructure, enable inbound TLS and auth instead.

## One project with popular notification containers

`examples/compose-with-apps.yaml` has the relay, Grafana, Gitea, and Prometheus
Alertmanager. `examples/authelia.compose.yaml` adds trusted-STARTTLS for
Authelia's security-sensitive notifications. Each app keeps its own private
network plus the mail network. Databases don't belong there.

Add matching relay senders:

```env
MAIL_SENDER_GRAFANA=grafana@relay.example.local
MAIL_SENDER_NAME_GRAFANA=Grafana alerts
MAIL_SENDER_GITEA=gitea@relay.example.local
MAIL_SENDER_NAME_GITEA=Gitea notifications
MAIL_SENDER_ALERTMANAGER=alertmanager@relay.example.local
MAIL_SENDER_NAME_ALERTMANAGER=Prometheus Alertmanager
MAIL_SENDER_AUTHELIA=authelia@relay.example.local
MAIL_SENDER_NAME_AUTHELIA=Authelia
```

A shared bridge lets containers reach each other. For tighter isolation, give
each app its own mail network and attach the relay to all. Either way, sender
admission still applies.

## Separate Compose projects

Create one plain external bridge. Pick a private subnet that doesn't overlap
existing Docker, LAN, or VPN ranges.

```bash
docker network ls
docker network inspect bridge
docker network create --driver bridge --subnet 172.30.50.0/24 mail-relay
```

Use `examples/cross-project/relay.compose.yaml` in the relay project and
`examples/cross-project/application.compose.yaml` in an application project.
Both declare:

```yaml
networks:
  mail-relay:
    external: true
    name: mail-relay
```

Create it first. Services attached to it resolve the relay alias regardless of
Compose project names.

```bash
docker network inspect mail-relay
docker exec application getent hosts postfix-m365-relay
docker exec application nc -vz postfix-m365-relay 2525
```

Minimal images may lack `getent` or `nc`—that's not a network failure. Prefer
the app's built-in SMTP test when it exists.

## One mail network per application

For stronger east-west isolation, create per-app networks like `grafana-mail` and
`gitea-mail`. Attach the relay to both, each app to its own:

```yaml
services:
  postfix-m365-relay:
    networks:
      grafana-mail:
        aliases: [postfix-m365-relay]
      gitea-mail:
        aliases: [postfix-m365-relay]
  grafana:
    networks: [grafana-internal, grafana-mail]
  gitea:
    networks: [gitea-internal, gitea-mail]
```

Don't make both relay networks internal unless it has a separate egress network.
The entrypoint discovers each attached IPv4 subnet and permits those container
sources in Docker-only posture.

## LAN/device publication

Only device topology uses `ports`. Bind one actual host LAN address:

```yaml
ports:
  - "192.0.2.10:2525:2525"
```

Never use `2525:2525` or `0.0.0.0:2525:2525`—they listen on all interfaces.
Enforce sources in host/network firewall and `MAIL_TRUSTED_NETWORKS`. NAT can
alter the observed address, so check logs and test allowed/denied hosts before
trusting IP policy.

```env
# Fixed device: address-based admission, plaintext on the LAN.
MAIL_INBOUND_AUTH=ip
MAIL_INBOUND_TLS=off
MAIL_TRUSTED_NETWORKS=192.0.2.50/32
```

```env
# Modern devices: both allowed subnet and credentials are required.
MAIL_INBOUND_AUTH=ip-and-auth
MAIL_INBOUND_TLS=require
MAIL_TRUSTED_NETWORKS=192.0.2.48/28
MAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users
```

With password policies, AUTH isn't available until after STARTTLS, then
PLAIN/LOGIN. See `EXTERNAL-SENDERS.md` for the full truth table.

No SASL-without-TLS fallback exists. A plaintext-only legacy device must use IP
admission without credentials (`ip` or `ip-or-auth`) on a firewall-restricted
trusted network. Never use `smtp-auth` or `ip-and-auth` for such a device. Put
a TLS-capable gateway beside legacy hardware that can't stay on trusted local
segment.

## Certbot-managed inbound STARTTLS

Use Certbot's `fullchain.pem` (leaf plus intermediates) and `privkey.pem`:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /etc/letsencrypt/live/smtp.example.com/fullchain.pem
  MAIL_INBOUND_TLS_KEY: /etc/letsencrypt/live/smtp.example.com/privkey.pem
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

Mount the full tree—`live/` entries are symlinks into `archive/`. After
renewal, restart the relay so boot validation checks the new pair before
Postfix takes mail:

```bash
certbot renew --deploy-hook 'docker compose restart postfix-m365-relay'
```

OAuth state and Postfix spool persist across restart. This is only the
device-facing identity; Entra app-certificate rotation leaves it alone.

## Troubleshooting path

```bash
docker compose config
docker compose ps
docker network inspect mail-relay
docker exec postfix-m365-relay postconf -h mynetworks
docker exec postfix-m365-relay postqueue -p
docker compose logs --tail 200 postfix-m365-relay
```

- DNS failure: app and relay don't share the same network/alias.
- Connection refused: relay is unhealthy, still starting, or port is wrong.
- `Sender address rejected`: envelope sender is missing from `MAIL_SENDER_*`.
- Local acceptance followed by a queue entry: app networking worked; inspect
  upstream TLS/OAuth logs.
- LAN client denied: compare its logged address with `MAIL_TRUSTED_NETWORKS`
  and firewall/NAT behavior.
