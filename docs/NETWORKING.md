# Docker and LAN networking

The relay listens on TCP 2525 inside its container. How a sender reaches that
listener determines the safe topology:

- Docker applications share a user-defined bridge and resolve
  `postfix-m365-relay` through Docker DNS; no host port is published.
- Separate Compose projects share a pre-created external Docker network.
- Printers and LAN devices require an explicitly interface-bound published port
  plus a narrow IP allowlist, SMTP authentication, or both.

The outbound path is separate. The relay must resolve and reach
`smtp.office365.com:587` plus Microsoft login and Graph HTTPS endpoints. An
`internal: true` network blocks that egress when it is the relay's only network.

## Complete Docker-only deployment

Use the repository's root `compose.yaml`. It bind-mounts `./config` at
`/config`. First startup creates `config/mail-relay.conf` from the image sample
and waits without opening SMTP. Edit the generated host file; the container
detects a complete required block and starts automatically.

```bash
mkdir -p config
docker compose config
docker compose up -d
docker compose logs postfix-m365-relay
# Edit config/mail-relay.conf, then follow startup:
docker compose logs -f postfix-m365-relay
docker compose ps
docker port postfix-m365-relay
```

Environment variables remain optional higher-precedence overrides. A Compose
`env_file:` is therefore available to automation but is not part of the normal
installation and is never required.

The last command must print nothing. `expose: 2525` is metadata, not host
publication.

Any sender must join the relay's network. Docker DNS resolves the service name;
do not use a container IP because it may change on recreation.

```text
SMTP host       postfix-m365-relay
SMTP port       2525
Authentication  none
TLS             none on the private Docker hop
From            one configured MAIL_SENDER_* address
```

The private hop does not weaken the upstream connection. The relay separately
requires verified STARTTLS and XOAUTH2 when submitting to Microsoft. If the
Docker network crosses untrusted infrastructure, deliberately select inbound
TLS and authentication instead.

## One project with popular notification containers

`examples/compose-with-apps.yaml` contains the relay, Grafana, Gitea, and
Prometheus Alertmanager. `examples/authelia.compose.yaml` shows the additional
trusted-STARTTLS configuration appropriate for Authelia's security-sensitive
notifications. Each application retains a private application network and also
joins the mail network. Its database does not need mail membership.

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

A shared bridge allows member containers to initiate connections to other
members. For stricter isolation, attach the relay to a different mail network
for each application. Sender admission remains necessary in either topology.

## Separate Compose projects

Create an ordinary external bridge once. Choose a private subnet that does not
overlap existing Docker, LAN, or VPN ranges.

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

The network must exist first. Services attached to it resolve the relay alias
regardless of their Compose project names.

```bash
docker network inspect mail-relay
docker exec application getent hosts postfix-m365-relay
docker exec application nc -vz postfix-m365-relay 2525
```

Minimal application images may lack `getent` or `nc`; that is not itself a
network failure. Prefer the application's built-in SMTP test when available.

## One mail network per application

For stronger east-west isolation, create networks such as `grafana-mail` and
`gitea-mail`. Attach the relay to both and each application only to its own:

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

Do not make both relay networks internal unless it also has a separate egress
network. The entrypoint discovers each attached IPv4 subnet and permits those
container sources in the Docker-only posture.

## LAN/device publication

Only the device posture uses `ports`. Bind one actual host LAN address:

```yaml
ports:
  - "192.0.2.10:2525:2525"
```

Do not use `2525:2525` or `0.0.0.0:2525:2525`; those listen on every host
interface. Enforce intended sources in the host/network firewall and in
`MAIL_TRUSTED_NETWORKS`. Port-publishing and NAT implementations can influence
the address Postfix observes, so inspect relay logs and test one allowed and one
denied host before trusting IP policy.

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

With password policies, AUTH is absent before STARTTLS and offered afterward as
PLAIN/LOGIN. See `EXTERNAL-SENDERS.md` for every policy truth table.

## Certbot-managed inbound STARTTLS

Use Certbot's `fullchain.pem` (leaf plus intermediates) and `privkey.pem`:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /etc/letsencrypt/live/smtp.example.com/fullchain.pem
  MAIL_INBOUND_TLS_KEY: /etc/letsencrypt/live/smtp.example.com/privkey.pem
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

Mount the full tree because `live/` entries are symlinks into `archive/`. After
a successful renewal, restart only the relay so boot validation checks the new
pair before Postfix accepts mail:

```bash
certbot renew --deploy-hook 'docker compose restart postfix-m365-relay'
```

The OAuth state and Postfix spool persist through restart. This certificate is
only the device-facing server identity; Entra app-certificate rotation never
touches it.

## Troubleshooting path

```bash
docker compose config
docker compose ps
docker network inspect mail-relay
docker exec postfix-m365-relay postconf -h mynetworks
docker exec postfix-m365-relay postqueue -p
docker compose logs --tail 200 postfix-m365-relay
```

- DNS failure from an app: app and relay do not share the same network/alias.
- Connection refused: relay is unhealthy, still starting, or port is wrong.
- `Sender address rejected`: envelope sender is missing from `MAIL_SENDER_*`.
- Local acceptance followed by a queue entry: app networking worked; inspect
  upstream TLS/OAuth logs.
- LAN client denied: compare its logged address with `MAIL_TRUSTED_NETWORKS`
  and firewall/NAT behavior.
