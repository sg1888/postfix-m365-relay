# Operator runbook

## Safety rules

- Prove changes with a separate test mailbox and app registration.
- Never experiment against the production relay or mailbox.
- After any Exchange permission change, wait two hours before interpreting a
  result.
- Do not mark a behavior verified unless you watched it work.
- Never expose the published-device posture to the Internet.

## Normal state

The container is running; `postfix` plus token, rotation, verify, and log-tail
children exist under the Bash PID 1 supervisor. The SMTP listener answers on
2525. `/run/mail-relay/relay.json` has more than 30 minutes of life soon after a
mint. The deferred queue is normally empty. The OAuth certificate has ample
life and the rotation log has no final `FAILED` outcome.

Quick check:

```bash
docker ps --filter name=postfix-m365-relay
docker logs --tail 100 postfix-m365-relay
docker exec postfix-m365-relay postqueue -p
docker exec postfix-m365-relay postconf -n
```

## First boot

1. Start with an empty `./config` bind and empty state volume.
2. Confirm `config/mail-relay.conf` is generated as `0600`, no SMTP listener is
   open, and the log says which required fields are missing.
3. Edit the generated host file. Watch the container proceed automatically.
4. Observe RSA-4096 certificate generation and copy only the public PEM.
5. Confirm the private key is `0600` in `/var/lib/mail-relay/secrets`.
6. Upload the public certificate to the test app registration.
7. Do not restart merely to get a token; the five-minute loop retries.
8. After required propagation, observe a successful mint and queue drain.
9. Send two messages through different `MAIL_SENDER_*` values to one recipient
   and verify two distinct display names.

Until step 9 is watched, first boot is not verified.

## Lifecycle loops

The token loop runs every five minutes and skips minting while at least 1,800
seconds remain. After consecutive failures it alerts, while Postfix continues to
queue.

Rotation runs once at supervisor startup and daily thereafter. The OAuth path
checks expiry, stages RSA-4096 material, calls Graph `addKey`, waits for
directory and token-service replication, sends a real proof message, swaps
files atomically, re-mints immediately, and records the old key for later
retirement. A separate inbound-TLS path renews only image-generated server
certificates; neither path can touch the other's key directory.

Verification runs hourly. With `MAIL_ADMIN_EMAIL`, it submits an end-to-end probe
through loopback; otherwise it performs local checks only.

## Certificate operations

List app-registration credentials read-only:

```bash
docker exec postfix-m365-relay \
  /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py --list-keys
```

Force rotation only with test objects and an observed proof recipient:

```bash
docker exec postfix-m365-relay \
  /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py --force
```

Before and after, hash the inbound TLS certificate. It must be byte-identical.
Watch addKey, both replication waits, proof send, swap, immediate token mint, and
later removal; a zero exit code alone is insufficient evidence.

If the OAuth certificate is already expired, automated `addKey` cannot recover.
Generate/upload a new first certificate manually using test-safe procedures.

## Queueing and token failures

```bash
docker exec postfix-m365-relay postqueue -p
docker exec postfix-m365-relay python3 -c \
  'import json,time; p=json.load(open("/run/mail-relay/relay.json")); print(int(p["expiry"])-int(time.time()))'
docker logs --since 30m postfix-m365-relay
```

Missing/expired token with AADSTS certificate errors usually means the public
certificate is absent, expired, or not propagated. A token for Graph instead of
`outlook.office365.com/.default` is refused at SMTP AUTH. Do not delete queued
mail while diagnosing.

## Supervisor failure drills

In an isolated test container:

1. Kill one loop child and watch PID 1 restart it after backoff.
2. Kill Postfix and watch the container exit; Docker restart policy should start
   a new container process.
3. Run `docker stop` and confirm clean exit within the grace period.
4. Queue a message, restart, and confirm the spool volume preserved it.

These drills gate the Bash supervisor. If reaping or signal forwarding does not
behave exactly this way, replace it with s6-overlay before release.

## Device credentials

Edit the protected `/config/secrets/smtpd_users` source, then restart. List
usernames:

```bash
docker exec postfix-m365-relay relay-users list
```

After removing one user, prove that credential fails and an untouched user still
works. Confirm no password appears in `docker inspect`, logs, or state volume.
For add/change/delete procedures and Docker Compose/Swarm secret rotation, use
the complete [SECRETS.md](SECRETS.md#device-credentials) procedure.

## Inbound TLS replacement

For self-signed TLS, a missing pair generates at boot and the daily loop renews
the certificate 365 days before its default ten-year expiry. It keeps the same
private key, retains `cert.pem.previous`, atomically replaces `cert.pem`, and
reloads Postfix. For BYO files, the relay alerts inside the configured renewal
window but never overwrites the external owner's files; replace the mounted
cert/key and restart. Use
`openssl s_client -starttls smtp` from a test client to observe the new
certificate.

## Outbound TLS and corporate CA rotation

The default `secure` policy requires the upstream certificate chain, validity,
and `smtp.office365.com` name to verify. A failure here intentionally defers
mail; inspect the queue and look for `certificate verification failed`, name-
match, expiry, or trust errors in the Postfix log. Do not work around a trust
problem by permanently setting `encrypt`.

On a TLS-inspected network, confirm `MAIL_UPSTREAM_CA_EXTRA_FILE` contains only
the approved public inspection root. During corporate CA rollover, place both
old and new public roots in the PEM bundle, replace the mounted file, recreate
the container, and observe `Verified TLS connection established` plus real test
delivery. Remove the retired root only after the firewall cutover is observed.
The relay never needs and will refuse a private CA key.

The public Internet root store comes from the image's `ca-certificates` RPM.
It is not changed inside a running immutable container. When the 90-day image
age warning fires, build or pull a current image, complete offline qualification,
then recreate the container while retaining state and spool volumes.

With TLS `may` and auth enabled, test both sides: plaintext IP-authorized mail
still works, while AUTH is absent before STARTTLS and PLAIN/LOGIN appear after.

## Sender and alias problems

A local `Sender address rejected` means the application's envelope sender is not
one of the `MAIL_SENDER_*` values. Add it and recreate the container.

Wrong display names usually mean the app emits a bare From and needs a matching
`MAIL_SENDER_NAME_<KEY>` override.

Passthrough alias failures must not be hidden by calling the feature verified.
Confirm the alias belongs to the same test mailbox, org-wide alias sending is
enabled, two hours have passed since that change, and the delivery was observed
over SMTP XOAUTH2 app-only submission.

## Rebuild and update

Pull a release by digest, inspect release notes, and test on a separate instance
before changing the pinned production digest. Published CI must observe package
assertions on amd64-v3, amd64-v2, and arm64.

## Decommission

1. Stop application submissions and drain or preserve the queue.
2. `docker compose down` without deleting volumes.
3. Remove Exchange grants with `undo-exchange.ps1`; wait two hours after each
   permission change.
4. Remove state/spool volumes only after deciding how to securely erase keys and
   message content.
5. Disable `SendFromAliasEnabled` only with the explicit org-wide switch and
   only after checking every tenant workload.

## Related

- `CONFIGURATION.md` — complete configuration surface
- `NETWORKING.md` — Docker and published-LAN topology
- `SECRETS.md` — key/password handling
- `EXTERNAL-SENDERS.md` — device posture and tests
- `TESTING.md` — complete offline and live-install release gate
