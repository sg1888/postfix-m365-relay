# Secrets

Identifiers are not secrets: tenant ID, client ID, mailbox address, hostnames,
and policy names belong in `/config/mail-relay.conf` or normal environment
variables. Private keys, device passwords, and credential-bearing webhook URLs
are secrets and must never be inline environment values.

A normal Compose installation has three different kinds of persistence:

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
single-host installation uses `/config/secrets/smtpd_users`. Compose secrets or
Swarm secrets are hardened alternatives. Known secret material is refused when
pasted directly into environment variables.

## Device credentials

Device passwords are enabled only by an auth-inclusive policy. Set this in
`/config/mail-relay.conf`:

```env
MAIL_INBOUND_AUTH=smtp-auth
MAIL_INBOUND_TLS=require
MAIL_SMTPD_USERS_FILE=/config/secrets/smtpd_users
```

Create the source file with an editor that will not record passwords in shell
history. Its format is one `username:password` record per line:

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

`relay-users list` reads the ephemeral database and prints principals, never
passwords. It is the authoritative view of what the running relay loaded.

### Add, change, remove, or revoke a user

The source file is the complete authority; there is intentionally no second
persistent user database to drift out of sync.

1. Edit `config/secrets/smtpd_users`.
2. To add a user, add one unique line. To change a password, replace that line.
   To revoke a user, delete the entire line.
3. Run `chmod 600 config/secrets/smtpd_users` and restart the relay.
4. Run `docker exec postfix-m365-relay relay-users list`.
5. Test one retained account, the changed password, and one removed or incorrect
   credential. Do not infer revocation from the list alone.

Every boot constructs a brand-new `/run/mail-relay/sasldb2` in tmpfs. It never
merges with the old database. A missing, unreadable, malformed, or empty source
file makes an auth-enabled relay fail closed instead of preserving old access.
Existing SMTP sessions end on restart.

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

The user operations are still file operations, not one-secret-per-user
commands. Edit the complete source file, then force a recreation so Compose
mounts the current secret content and the entrypoint rebuilds sasldb2:

```bash
docker compose up -d --force-recreate postfix-m365-relay
docker exec postfix-m365-relay relay-users list
```

Docker Compose grants this file only to services listing the secret and mounts
it read-only at `/run/secrets/smtpd_users`. The source file must still be
protected by host permissions. The official Compose secret reference is
<https://docs.docker.com/reference/compose-file/secrets/>.

### Docker Swarm secret alternative

Swarm secrets are encrypted in transit and at rest, but are immutable. Add,
change, or delete users by creating a new version of the complete authority,
atomically switching the service, testing it, then deleting the unreferenced old
version. For a service named `postfix-m365-relay`:

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
the versioned Swarm name from the container. Do not remove v1 until the updated
task is healthy and positive/negative SMTP authentication tests pass. See the
official rotation model at
<https://docs.docker.com/engine/swarm/secrets/#example-rotate-a-secret>.

The cleartext input is deliberate: an administrator must enter the same
password into the device. Protect it as carefully as a private key, securely
erase obsolete copies according to local policy, and never commit it.

## OAuth client key

The recommended path is container generation into the named state volume. Only
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
automatic rotation can safely own the live files. Do not point rotation at an
inbound TLS directory; it refuses that path.

## Inbound TLS key

Self-signed generation needs no secret input. For a trusted certificate:

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

The file remains mounted and is not copied into OAuth state. Replace it and
restart to rotate it. Graph never touches inbound TLS files.

### Certbot / Let's Encrypt

Certbot provides the two inputs the relay needs:

- `fullchain.pem`: the server/leaf certificate followed by intermediate issuers;
- `privkey.pem`: the unencrypted private key, which must remain secret.

There is no separate `MAIL_INBOUND_TLS_CHAIN`. Postfix's similarly named
`smtpd_tls_chain_files` setting is a replacement interface containing key and
certificate objects in a strict order, not a place for Certbot's `chain.pem`.

Mount the complete Certbot tree read-only so the `live/` symlinks can still
resolve into `archive/` after renewal:

```yaml
environment:
  MAIL_INBOUND_TLS_CERT: /etc/letsencrypt/live/smtp.example.com/fullchain.pem
  MAIL_INBOUND_TLS_KEY: /etc/letsencrypt/live/smtp.example.com/privkey.pem
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro
```

Restart the relay only after Certbot has atomically completed both files:

```bash
certbot renew --deploy-hook 'docker compose restart postfix-m365-relay'
```

Boot validates that the new leaf matches the new key before accepting mail.
State and spool volumes survive. Mounting individual files is discouraged:
atomic symlink/file replacement can leave a long-lived file bind mount attached
to an old inode.

## Corporate SMTP inspection CA (public, not secret)

`MAIL_UPSTREAM_CA_EXTRA_FILE` is for a network where an authorized corporate
firewall terminates and re-creates the relay's STARTTLS connection to Microsoft.
It is **not** the Entra app certificate, the relay's inbound server certificate,
or a private key. It contains only the PEM-encoded public root CA certificate
that signs the firewall's replacement certificate for `smtp.office365.com`.

The name says `EXTRA` because the file is appended to—not substituted for—the
normal public CA store. Microsoft connections outside the inspected network
therefore continue to trust ordinary public roots. The `secure` TLS policy still
checks that the presented leaf certificate names `smtp.office365.com`, chains to
either a normal root or this explicit corporate root, and is within its validity
period.

Although the certificate is public, a Docker secret is a convenient read-only
mount:

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
Boot refuses files containing private-key markers, malformed PEM, expired
certificates, and certificates that are not valid yet. Without the correct CA,
TLS inspection fails closed and Postfix defers mail for `MAIL_QUEUE_LIFETIME`.

When the corporate inspection CA rotates, overlap old and new public roots in
one PEM bundle, replace the mounted file, recreate the container, and prove a
send. Remove the old root only after the firewall cutover has been observed.
Because the firewall terminates TLS, it can read the XOAUTH2 bearer token and
message contents; configuring this file is an explicit acceptance of that
corporate inspection policy.

## Webhooks and push monitors

`MAIL_ALERT_WEBHOOK` is currently an identifier-like endpoint string and is
passed by env; if its URL embeds a credential, avoid it and use email until a
webhook `*_FILE` input is added. Push tokens use files named
`/run/secrets/push_token_relay`, `push_token_token`,
`push_token_certificate`, and `push_token_rotation`.

## Permissions and backups

- OAuth private key: `0600`, owned by `postfix` in the state volume.
- Generated inbound private key: `0600 root:root`.
- Corporate inspection CA: public certificate only; no private key.
- sasldb2: `0600 postfix:postfix`, tmpfs, recreated each boot.
- token: `0640 root:postfix`, tmpfs, atomically replaced.

Encrypt backups containing `mail-relay-state`. The spool may contain message
content and recipient addresses, so protect it too.
