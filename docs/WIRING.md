# Wiring applications to the relay

Sender address and display-name policy live in
[SENDER-REWRITING.md](SENDER-REWRITING.md)—fixed names like `Diun [Server A]`,
multi-host setups, and alias passthrough.

See [NETWORKING.md](NETWORKING.md) for topology options: same-project,
cross-project, per-app isolation, published LAN. This guide shows actual
app-side SMTP settings.

## Shared application settings

For default private Docker topology:

```text
host: postfix-m365-relay
port: 2525
authentication: none
TLS/SSL: none
From: one configured MAIL_SENDER_* address
```

Never use the Microsoft mailbox password or point apps at `smtp.office365.com`—the
relay owns OAuth, verified TLS, sender policy, and the queue. Don't argue with
this one.

The sender keeps its existing network and also joins the relay:

```yaml
services:
  application:
    environment:
      SMTP_HOST: postfix-m365-relay
      SMTP_PORT: "2525"
      SMTP_FROM: application@relay.example.local
    networks: [default, mail-relay]

networks:
  mail-relay:
    external: true
    name: mail-relay
```

## Grafana

Grafana maps `[smtp]` settings to `GF_SMTP_*` variables:

```yaml
services:
  grafana:
    environment:
      GF_SMTP_ENABLED: "true"
      GF_SMTP_HOST: postfix-m365-relay:2525
      GF_SMTP_FROM_ADDRESS: grafana@relay.example.local
      GF_SMTP_FROM_NAME: Grafana alerts
      GF_SMTP_STARTTLS_POLICY: NoStartTLS
    networks: [default, mail-relay]
```

```env
MAIL_SENDER_GRAFANA=grafana@relay.example.local
MAIL_SENDER_NAME_GRAFANA=Grafana alerts
```

Test with Grafana's built-in function. Require `status=sent` in the relay log
and verify the recipient-visible name.

## Gitea

Gitea 1.18+ takes Docker variables `GITEA__section__SETTING`. Plain `smtp`
works only on private Docker; USER and PASSWD are intentionally absent.

```yaml
services:
  gitea:
    environment:
      GITEA__mailer__ENABLED: "true"
      GITEA__mailer__PROTOCOL: smtp
      GITEA__mailer__SMTP_ADDR: postfix-m365-relay
      GITEA__mailer__SMTP_PORT: "2525"
      GITEA__mailer__FROM: Gitea notifications <gitea@relay.example.local>
      GITEA__service__ENABLE_NOTIFY_MAIL: "true"
    networks: [default, mail-relay]
```

```env
MAIL_SENDER_GITEA=gitea@relay.example.local
MAIL_SENDER_NAME_GITEA=Gitea notifications
```

Test from **Site Administration → Configuration → Mailer Configuration**. Older
releases used combined `HOST`; check your version's docs.

## Prometheus Alertmanager

Alertmanager reads SMTP from YAML, not env vars. Mount `examples/alertmanager.yml`
and add the mail network:

```yaml
services:
  alertmanager:
    image: quay.io/prometheus/alertmanager:latest
    command: [--config.file=/etc/alertmanager/alertmanager.yml]
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro
    networks: [monitoring-internal, mail-relay]
```

```yaml
global:
  smtp_smarthost: postfix-m365-relay:2525
  smtp_from: alertmanager@relay.example.local
  smtp_require_tls: false
```

No auth fields. Plaintext is scoped to the private bridge; Microsoft submission
stays verified TLS.

```env
MAIL_SENDER_ALERTMANAGER=alertmanager@relay.example.local
MAIL_SENDER_NAME_ALERTMANAGER=Prometheus Alertmanager
```

## Authelia

Authelia sends identity-verification and password-reset data, so its secure
default must hold. Configure inbound STARTTLS with a trusted cert. Certbot or
an internal CA works; never set `tls.skip_verify`.

Add these variables to an existing Authelia service:

```yaml
services:
  authelia:
    environment:
      AUTHELIA_NOTIFIER_SMTP_ADDRESS: submission://postfix-m365-relay:2525
      AUTHELIA_NOTIFIER_SMTP_SENDER: Authelia <authelia@relay.example.local>
      AUTHELIA_NOTIFIER_SMTP_STARTUP_CHECK_ADDRESS: operator@example.com
      # Docker resolves the service alias, while this is the name in the relay's
      # public/internal-CA certificate.
      AUTHELIA_NOTIFIER_SMTP_TLS_SERVER_NAME: smtp.example.com
    networks: [authelia-internal, mail-relay]
```

Configure the relay with TLS available to IP-authorized Docker senders:

```env
MAIL_INBOUND_AUTH=ip
MAIL_INBOUND_TLS=may
MAIL_INBOUND_TLS_CERT=/etc/letsencrypt/live/smtp.example.com/fullchain.pem
MAIL_INBOUND_TLS_KEY=/etc/letsencrypt/live/smtp.example.com/privkey.pem
MAIL_SENDER_AUTHELIA=authelia@relay.example.local
MAIL_SENDER_NAME_AUTHELIA=Authelia
```

Mount `/etc/letsencrypt:/etc/letsencrypt:ro` into the relay. If an internal CA
is used instead, add its public root to Authelia's `certificates_directory`.
Authelia runs an SMTP startup check; keep it on so broken notifiers surface
before a user needs a reset.

## Generic application

```yaml
environment:
  SMTP_HOST: postfix-m365-relay
  SMTP_PORT: "2525"
  SMTP_TLS: "false"
  SMTP_USERNAME: ""
  SMTP_PASSWORD: ""
  SMTP_FROM: reports@relay.example.local
```

URL-style clients often accept:

```text
smtp://postfix-m365-relay:2525
```

Apps use inconsistent names (SSL, TLS, STARTTLS, encryption), so check their
docs. If one needs STARTTLS, set inbound TLS to `may` or `require`, provide a
trusted cert, and test.

## Add, apply, and verify

Every envelope sender must be independently configured:

```env
MAIL_SENDER_REPORTS=reports@relay.example.local
MAIL_SENDER_NAME_REPORTS=Nightly reports [Primary]
```

Recreate after any change to environment, senders, device users, mounted
Postfix config, or BYO TLS:

```bash
docker compose up -d --force-recreate postfix-m365-relay
docker compose logs --tail 100 postfix-m365-relay
```

For each application:

1. Send a uniquely titled message from its built-in test function.
2. Find the Postfix queue ID.
3. Require `status=sent`, not just local SMTP acceptance.
4. Confirm receipt and the exact display name, including punctuation/brackets.
5. Try an unconfigured sender and confirm local rejection.

```bash
docker exec application getent hosts postfix-m365-relay
docker exec application nc -vz postfix-m365-relay 2525
docker exec postfix-m365-relay postqueue -p
docker logs --tail 200 postfix-m365-relay
```
