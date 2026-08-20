# Secrets

Identifiers are not secrets: tenant ID, client ID, mailbox address, hostnames,
and policy names belong in `/config/mail-relay.conf` or normal environment
variables. Private keys, device passwords, and credential-bearing webhook URLs
are secrets. Never inline them as environment values.

A standard Compose setup separates three persistence tiers:

```text
postfix-m365-relay/
├── compose.yaml
└── config/                         host bind mount at /config
    ├── mail-relay.conf             generated settings; mode 0600
    └── secrets/
        └── smtpd_users             optional device passwords; mode 0600

mail-relay-state                    named volume: OAuth private key and cert state
mail-relay-spool                    named volume: queued messages and recipients
/run/mail-relay                     tmpfs: access token, PIDs, and sasldb2
```

The image and container layers contain none of these values. The simplest
single-host setup uses `/config/secrets/smtpd_users`. Compose secrets or
Swarm secrets are hardened alternatives. The entrypoint rejects known secret
material pasted into environment variables.

## Device credentials

Enable device passwords by setting an auth policy in `/config/mail-relay.conf`:

```env
MAIL_INBOUND_AUTH=smtp-auth
MAIL_INBOUND_TLS=require
MAIL_SMTPD_USERS_FILE=/config/secrets/smtpd_users
```

Create the file in an editor that doesn't log shell history. Format is one
`username:password` record per line:

```text
printer:replace-with-a-long-unique-password
nas:replace-with-a-different-long-password
```

Usernames may contain lowercase letters, digits, `.`, `_`, and `-`. A password
must not be empty and may contain additional colons because only the first colon
separates the username. Blank lines and lines beginning with `#` are ignored.
Protect the directory and file:

```bash
chmod 700 config config/secrets
chmod 600 config/mail-relay.conf config/secrets/smtpd_users
docker compose restart postfix-m365-relay
docker exec postfix-m365-relay relay-users list
```

`relay-users list` reads the ephemeral database and prints principals only—never
passwords. It's the authoritative view of what the running relay loaded.

### Add, change, remove, or revoke a user

The source file is the complete authority. There is no second persistent
database—nothing to drift or decay.

1. Edit `config/secrets/smtpd_users`.
2. Add a user: new line. Change a password: replace that line. Revoke a user: delete it.
3. Run `chmod 600 config/secrets/smtpd_users` and restart the relay.
4. Run `docker exec postfix-m365-relay relay-users list`.
5. Test one retained account, the changed password, and one revoked credential.
   Don't infer revocation from the list alone.

Every boot builds a fresh `/run/mail-relay/sasldb2` in tmpfs—never merging with
the old one. A missing, unreadable, malformed, or empty source file fails the
relay closed instead of reusing stale credentials. Existing SMTP sessions end on restart.

### Docker Compose secret alternative

Move the credential source outside the repository, change
`MAIL_SMTPD_USERS_FILE` in `mail-relay.conf` to `/run/secrets/smtpd_users`, and
add this Compose wiring:

```yaml
services:
  postfix-m365-relay:
    secrets: [smtpd_users]
secrets:
  smtpd_users:
    file: /approved/private/path/smtpd_users
```

User operations are still file edits, not commands. Edit the source file,
then force recreation so Compose mounts the current secret and rebuilds sasldb2:

```bash
docker compose up -d --force-recreate postfix-m365-relay
docker exec postfix-m365-relay relay-users list
```

Compose grants the file only to services that list it and mounts it read-only
at `/run/secrets/smtpd_users`. Host permissions still own the source file. See
<https://docs.docker.com/reference/compose-file/secrets/> for details.

### Docker Swarm secret alternative

Swarm secrets are encrypted in transit and at rest but immutable. Manage users
by versioning the complete source, atomically switching the service, testing it,
then deleting the old version. For a service named `postfix-m365-relay`:

```bash
docker secret create smtpd_users_v2 /approved/private/path/smtpd_users
docker service update \
  --secret-rm smtpd_users_v1 \
  --secret-add source=smtpd_users_v2,target=smtpd_users \
  postfix-m365-relay
docker service ps postfix-m365-relay
docker exec "$(docker ps -q --filter label=com.docker.swarm.service.name=postfix-m365-relay | head -n 1)" relay-users list
docker secret rm smtpd_users_v1
```

Keep `MAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users`; the stable target hides
the versioned name from the container. Don't remove v1 until the updated task
is healthy and auth tests pass. See
<https://docs.docker.com/engine/swarm/secrets/#example-rotate-a-secret>.

Cleartext input is deliberate: an admin must enter the same password into the
device. Treat it like a private key. Securely erase obsolete copies per policy.
Never commit it.

## OAuth client key

Container generation into the named state volume is the recommended path. Only
the public certificate is printed. Back up the state volume securely.

To import an existing test certificate once:

```yaml
environment:
  MAIL_RELAY_CLIENT_KEY_FILE: /run/secrets/oauth_client_key
  MAIL_RELAY_CLIENT_CERT_FILE: /run/secrets/oauth_client_cert
secrets:
  - oauth_client_key
  - oauth_client_cert
```

The entrypoint copies the pair into the state volume's `secrets/` directory so
rotation can own the live files. Don't point rotation at an inbound TLS directory—
it will refuse that path.

## Inbound TLS key

Self-signed generation requires no secret input. For a trusted certificate:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /run/secrets/inbound_tls_cert
  MAIL_INBOUND_TLS_KEY: /run/secrets/inbound_tls_key
secrets:
  inbound_tls_cert:
    file: /secure/path/fullchain.pem
  inbound_tls_key:
    file: /secure/path/privkey.pem
```

The file stays mounted, not copied into OAuth state. Replace it and restart to
rotate. Graph never touches inbound TLS files.

### Certbot / Let's Encrypt

Certbot provides the two inputs the relay needs:

- `fullchain.pem`: the server/leaf certificate followed by intermediate issuers;
- `privkey.pem`: the unencrypted private key, which must remain secret.

There is no separate `MAIL_INBOUND_TLS_CHAIN`. Postfix's similarly named
`smtpd_tls_chain_files` setting is a replacement interface containing key and
certificate objects in a strict order, not a place for Certbot's `chain.pem`.

Mount the entire Certbot tree read-only so `live/` symlinks resolve into
`archive/` after renewal:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /etc/letsencrypt/live/smtp.example.com/fullchain.pem
  MAIL_INBOUND_TLS_KEY: /etc/letsencrypt/live/smtp.example.com/privkey.pem
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

Restart only after Certbot has atomically written both files:

```bash
certbot renew --deploy-hook 'docker compose restart postfix-m365-relay'
```

Boot validates the new leaf against the new key before accepting mail.
State and spool survive. Don't mount individual files—atomic replacement can
leave a bind mount pointing to a stale inode.

## Corporate SMTP inspection CA (public, not secret)

`MAIL_UPSTREAM_CA_EXTRA_FILE` serves a network where a corporate firewall
terminates and re-signs the relay's STARTTLS connection to Microsoft. It is
**not** the Entra app certificate, the relay's inbound server certificate, or
a private key. It's the PEM-encoded public root that signs the firewall's
replacement certificate for `smtp.office365.com`.

The name `EXTRA` means appended to, not substituting for, the normal public CA
store. Microsoft connections outside the inspected network continue to trust
ordinary roots. The `secure` TLS policy still validates that the leaf names
`smtp.office365.com`, chains to either a public root or this corporate root,
and is within its validity window.

Even though it's public, a Docker secret provides a handy read-only mount:

```yaml
services:
  postfix-m365-relay:
    environment:
      MAIL_UPSTREAM_TLS_SECURITY_LEVEL: secure
      MAIL_UPSTREAM_CA_EXTRA_FILE: /run/secrets/corporate_smtp_ca
    secrets: [corporate_smtp_ca]
secrets:
  corporate_smtp_ca:
    file: /approved/pki/corporate-smtp-inspection-root.pem
```

Export only the public CA certificate. Never export or mount the CA private key.
Boot rejects files with private-key markers, malformed PEM, expired certs, or
certs not yet valid. Missing the correct CA fails TLS closed and defers mail
for `MAIL_QUEUE_LIFETIME`.

When the CA rotates, bundle old and new roots in one PEM, replace the mounted
file, recreate the container, and test. Remove the old root only after observing
the firewall cutover. Since the firewall terminates TLS, it reads XOAUTH2 tokens
and message content. Configuring this file is an explicit acceptance of that
inspection policy.

## Webhooks and push monitors

`MAIL_ALERT_WEBHOOK` is an identifier-like endpoint string passed via env. If
the URL embeds a credential, don't use it—stick with email until a webhook
`*_FILE` input lands. Push tokens use files named `/run/secrets/push_token_relay`,
`push_token_token`, `push_token_certificate`, and `push_token_rotation`.

## Permissions and backups

- OAuth private key: `0600`, owned by `postfix` in the state volume.
- Generated inbound private key: `0600 root:root`.
- Corporate inspection CA: public certificate only; no private key.
- sasldb2: `0600 postfix:postfix`, tmpfs, recreated each boot.
- token: `0640 root:postfix`, tmpfs, atomically replaced.

Encrypt backups of `mail-relay-state`. The spool may contain message content
and recipient addresses—protect it the same way.
