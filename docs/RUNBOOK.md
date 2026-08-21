# Operator runbook

## Safety rules

- Prove changes with a separate test mailbox and app registration.
- Never experiment against the production relay or mailbox.
- After any Exchange permission change, wait two hours before interpreting a
  result.
- Do not mark a behavior verified unless you watched it work.
- Never expose the published-device posture to the Internet.

Tenant authorization uses a dedicated shared mailbox and claims-less,
group-scoped `Application SMTP.SendAsApp`; no API permissions, no `FullAccess`,
no mail-reading role. Follow [MICROSOFT-SETUP.md](MICROSOFT-SETUP.md)—the
older licensed-user/FullAccess workflow is dead; don't rebuild it.

## Normal state

Container's up: `postfix`, token, rotation, verify, and log-tail children under
Bash PID 1. SMTP listener answers on 2525. `/run/mail-relay/relay.json` shows
>30 minutes of life post-mint. Deferred queue is empty. OAuth cert has life left;
rotation log shows no final `FAILED`.

Quick check:

```bash
docker ps --filter name=postfix-m365-relay
docker logs --tail 100 postfix-m365-relay
docker exec postfix-m365-relay postqueue -p
docker exec postfix-m365-relay postconf -n
```

## First boot

1. Start with an empty `./mail-relay` bind and empty state volume.
2. Confirm `config/mail-relay.conf` is generated as `0600`, no SMTP listener is
   open, and logs name missing required fields.
3. Edit the host file. Container proceeds on its own.
4. Observe RSA-4096 generation; the public half is exported to
   `./mail-relay/microsoft365-app-public-cert.pem`.
5. Confirm the private key is `0600` in `/var/lib/mail-relay/secrets`.
6. Upload `./mail-relay/microsoft365-app-public-cert.pem` to the test app
   registration; the export is removed automatically once Microsoft accepts it.
7. Do not restart merely to get a token; the five-minute loop retries.
8. After propagation, observe successful mint and queue drain.
9. Send two messages through different `MAIL_SENDER_*` values to one recipient
   and verify two distinct display names.

Skip step 9 and first boot isn't verified—logs don't matter here.

## Lifecycle loops

Token loop runs every five minutes, skips minting while ≥1,800 seconds remain.
Alerts after consecutive failures; Postfix keeps queuing.

Rotation runs at startup and daily. OAuth path: check expiry, stage RSA-4096,
call Graph `addKey`, wait for directory/token-service replication, send proof
message, swap files atomically, re-mint immediately, record old key. Inbound-TLS
path renews image-generated certs only; paths don't touch each other's keys.

Verification runs hourly: internal checks only (token, certificate, rotation,
queue, SASL), never sending mail. The end-to-end delivery probe is test-only and
off by default; set `MAIL_VERIFY_SEND=yes` (with `MAIL_ADMIN_EMAIL`) to submit a
real probe via loopback during bring-up, then set it back to `no`.

## Alerts and durable incidents

Failures are incidents, not a mail stream. First failure opens `open` notification
with stable `PMR-*` reference. Later failures bump occurrence count; no re-pages.
First recovery emits `recovered` with reference and total duration. Incident and
delivery records live in `/var/lib/mail-relay/alerts` (persistent volume)—
replacing the container doesn't forget outages.

Each email and webhook carries UTC and configured-`TZ` timestamps, relay
identity, observations, duration, non-secret evidence, likely causes, and
suggested actions. Keep Microsoft error codes, timestamps, Trace IDs, Correlation
IDs. Redact assertions, tokens, passwords, private keys, and credentials.

Email and `MAIL_ALERT_WEBHOOK` retry independently—neither blocks the other.
Failed channels persist in outbox; later health/rotation passes retry with
exponential backoff (30, 60, 120 sec, up to 1 hr). Audit lines always written.

| Condition | Opens | Clears when |
|---|---|---|
| token refresh | configured consecutive-failure threshold (default 3) | token check succeeds |
| SMTP listener, token, OAuth cert, or rotation audit | verifier hard failure | that category passes |
| OAuth or managed inbound-TLS rotation | loop operation fails | later loop operation succeeds |
| BYO inbound TLS | certificate enters renewal window | replacement is outside the window |
| CA bundle age | exceeds `MAIL_CA_BUNDLE_MAX_AGE_DAYS` | current image is within policy |
| deferred queue | exceeds `MAIL_QUEUE_WARN_DEPTH` | returns to/below threshold |
| inbound SASL failures | exceeds `MAIL_SASL_FAILURE_WARN_COUNT` | returns to/below threshold |
| passthrough alias | proof is refused or not observed sent | all enabled alias probes send |
| push monitor | configured endpoint fails | all configured endpoints respond |

Inspect state without printing message bodies or secrets:

```bash
docker exec postfix-m365-relay find /var/lib/mail-relay/alerts -type f -maxdepth 2 -printf '%P\n'
docker logs --since 1h postfix-m365-relay | grep 'alert-event:'
```

An `incidents/<event>.json` file means the condition is still open. An `outbox`
file means at least one configured notification channel hasn't acknowledged
delivery. Do not delete these to silence an alert; fix the condition, or
deliberately remove the affected channel configuration and write down why.

## Certificate operations

List app-registration credentials read-only:

```bash
docker exec postfix-m365-relay relay-admin keys
```

Force rotation only with test objects and an observed proof recipient:

```bash
docker exec postfix-m365-relay relay-admin rotate --force
```

Hash the inbound TLS cert before and after—must be byte-identical. Watch addKey,
replication waits, proof send, swap, token mint, removal; exit code alone proves
nothing.

If OAuth cert is already expired, automated `addKey` can't help. Hand-generate
and upload a new cert using test-safe procedures.

## Queueing and token failures

```bash
docker exec postfix-m365-relay postqueue -p
docker exec postfix-m365-relay python3 -c \
  'import json,time; p=json.load(open("/run/mail-relay/relay.json")); print(int(p["expiry"])-int(time.time()))'
docker logs --since 30m postfix-m365-relay
```

Missing/expired token with AADSTS errors usually means the public cert is absent,
expired, or not propagated. Graph tokens (not `outlook.office365.com/.default`)
are refused at SMTP AUTH. Don't delete queued mail while diagnosing.

Send a one-time channel test from a healthy isolated instance:

```bash
docker exec postfix-m365-relay \
  /usr/local/libexec/mail-relay/alert.sh notify info manual-test \
  'Operator-requested notification channel test'
```

Confirm exact receipt. No incident opens, so no recovery message later.

## Supervisor failure drills

In an isolated test container:

1. Kill one loop child and watch PID 1 restart it after backoff.
2. Kill Postfix and watch the container exit; Docker restart policy should start
   a new container process.
3. Run `docker stop` and confirm clean exit within the grace period.
4. Queue a message, restart, and confirm the spool volume preserved it.

These drills validate the Bash supervisor. If reaping or signal forwarding
deviates, replace with s6-overlay before release.

## Device credentials

Edit the protected `/config/secrets/smtpd_users` source, then restart. List
usernames:

```bash
docker exec postfix-m365-relay relay-users list
```

Prove removed credential fails and untouched users still work. Confirm no
passwords in `docker inspect`, logs, or state. For add/change/delete and rotation,
see [SECRETS.md](SECRETS.md#device-credentials).

## Inbound TLS replacement

Self-signed TLS: missing pair generates at boot, daily loop renews 365 days
before expiry. Keeps same key, retains `cert.pem.previous`, replaces `cert.pem`
atomically, reloads Postfix. BYO files: relay alerts in renewal window but never
overwrites; replace mounted cert/key and restart. Use `openssl s_client -starttls
smtp` to observe.

## Outbound TLS and corporate CA rotation

Default `secure` policy requires upstream chain, validity, and `smtp.office365.com`
match. Failures defer mail intentionally; look for `certificate verification
failed`, name-match, expiry, or trust errors in logs. Don't permanently set
`encrypt` to work around trust problems.

TLS-inspected network: `MAIL_UPSTREAM_CA_EXTRA_FILE` must contain only the
approved public inspection root. CA rollover: place both old and new roots in
PEM, replace mounted file, recreate container, observe `Verified TLS connection
established` and real delivery. Remove retired root only after firewall cutover.
Relay refuses private CA keys.

Public roots come from image's `ca-certificates` RPM; not updated in running
containers. When 90-day warning fires, pull current image, qualify offline,
recreate container (retain state/spool).

With TLS `may` and auth enabled, test both sides: plaintext IP-authorized mail
still works, while AUTH is absent before STARTTLS and PLAIN/LOGIN appear after.

## Sender and alias problems

`Sender address rejected`: application's envelope sender isn't a `MAIL_SENDER_*`.
Add it and recreate.

Wrong display names usually mean the app emits a bare From and needs a matching
`MAIL_SENDER_NAME_<KEY>` override.

Don't hide alias failures by calling the feature verified. Confirm: alias is in
test mailbox, org-wide sending enabled, two hours passed since change, delivery
observed via SMTP XOAUTH2 app-only.

## Rebuild and update

Pull by digest, inspect notes, test separately before updating production. CI must
observe assertions on amd64-v3, amd64-v2, arm64.

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
