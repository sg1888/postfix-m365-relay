# Release and live-install qualification

This is the release gate. Everything runs on a dedicated test mailbox, Entra app registration, isolated relay, test recipients, and disposable device credentials. Don't point these at production.

After **any Exchange permission or organization-setting change, wait two full hours before interpreting a send result**. A probe before then is informational only. Record what you observed yourself; config output, exit codes, and SMTP acceptance prove nothing about Microsoft delivery.

## Evidence record

One row per test. No secrets in the record, ever.

| Field | Record |
|---|---|
| image tag and digest | |
| image platform | |
| test mailbox | |
| test app client ID | |
| test enterprise-app object ID | |
| permission-change UTC time | |
| earliest conclusive-test UTC time (+2h) | |
| test ID | |
| exact non-secret inputs | |
| expected result | |
| observed result and UTC time | |
| Message-ID / Postfix queue ID | |
| recipient receipt or rejection evidence | |
| pass, fail, or blocked | |

Redact access tokens, private keys, passwords, webhook tokens, and message
content from captured logs.

## Phase 1: offline release suite

Run every suite against the candidate image:

```bash
./tests/run-offline.sh postfix-m365-relay:test
```

The runner stops at each named suite; failure pinpoints the problem. CI runs them as separate named steps for visibility.

These cover invalid configuration, malformed secrets, sender-name escaping, collapse/passthrough maps, all five inbound policies, trusted/untrusted networks, right/wrong passwords, authorized/unauthorized senders, TLS-before-AUTH, credential revocation, certificate handling, supervisor behavior, wedged healthcheck, read-only operation, and deferred messages surviving queue ID replacement through recovery. The inbound fullchain test verifies Postfix serves the intermediate, validates hostname, and loads atomically replaced key/fullchain pairs.

Then AST-parse both PowerShell files on a workstation that has PowerShell:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ./powershell/setup-exchange.ps1), [ref]$null, [ref]$errors)
$errors
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ./powershell/undo-exchange.ps1), [ref]$null, [ref]$errors)
$errors
```

Empty errors = pass for each file.

## Phase 2: isolated first boot

1. Start the candidate with an empty `/config` bind and empty state volume.
2. Confirm it creates `mail-relay.conf` as `0600`, prints setup instructions,
   doesn't open SMTP, and auto-proceeds after required test identifiers and sender are saved.
3. Watch generation of the RSA-4096 OAuth certificate and public PEM output.
4. Confirm the private key is `0600`, Postfix stays up, the token loop retries,
   and a locally accepted test message remains deferred without a token.
5. Confirm no host port is published by default.
6. Run the bad-data cases below on disposable instances. Each must exit
   nonzero with the expected diagnostic before accepting mail.

| ID | Bad input | Required result |
|---|---|---|
| B01 | missing tenant, client ID, mailbox, or all senders | setup wait; no SMTP listener |
| B02 | malformed mailbox/sender address | boot refused |
| B03 | newline in display name | boot refused |
| B04 | unsupported sender/auth/TLS mode | boot refused |
| B05 | invalid size or queue lifetime | boot refused |
| B05a | invalid/traversing `TZ` name | boot refused |
| B06 | invalid IPv4/CIDR or all-address network | boot refused |
| B07 | auth enabled with TLS off | boot refused |
| B08 | missing/malformed/empty device credential file | boot refused |
| B09 | secret or PEM placed directly in environment | boot refused |
| B10 | mismatched, expired, or weak OAuth pair | boot refused |
| B11 | mismatched inbound TLS pair or malformed fullchain | boot refused |
| B12 | hostile mounted `main.cf` | managed safe values win |
| B13 | process-control key or shell syntax in config | key refused; values remain literal and execute nothing |

## Phase 3: test Entra and Exchange setup

This phase changes external state, so get explicit approval immediately before
you run it.

1. Create or identify a dedicated test shared mailbox and test app. Keep API
   permissions empty; use scoped Exchange `Application SMTP.SendAsApp`.
2. Record tenant ID, application/client ID, and enterprise-application object ID.
3. Grant only the documented Exchange application permission and mailbox access.
4. Upload only the public certificate printed by first boot.
5. Record the final permission-change time and wait two hours.
6. Without restarting the container, watch the token loop mint a token and the
   deferred queue drain.

Leave alias sending off for now. Collapse mode gets qualified first.

## Phase 4: live collapse-mode delivery and rejection

Use `scripts/qualify-relay.py`; device passwords come from a protected file, never argv. Every accepted run prints a unique Message-ID. Map it to a Postfix queue ID, require `status=sent`, then verify the exact message landed in the test recipient mailbox.

```bash
./scripts/qualify-relay.py \
  --host postfix-m365-relay --from-address app@relay.example.local \
  --from-name 'MyServer [TestServer]' --to test-recipient@example.com
```

Run this matrix:

| ID | Case | Required result |
|---|---|---|
| C01 | configured sender, name `MyServer [TestServer]` | delivered with exact name and main mailbox address |
| C02 | second configured sender and different name | delivered to same recipient with second exact name |
| C03 | quotes, backslash, apostrophe, comma, colon, `$1`, `$5`, Unicode, emoji | each delivered with exact intended display name |
| C04 | configured envelope sender with a preexisting display name | configured name wins |
| C05 | unconfigured envelope sender from a trusted client | local `Sender address rejected`; nothing queued |
| C06 | syntactically invalid recipient | client-side or local rejection; nothing delivered |
| C07 | syntactically valid nonexistent test recipient | upstream permanent failure observed and handled as documented |
| C08 | wrong but syntactically valid send mailbox in a disposable instance | upstream auth/submission failure; no false success alert |
| C09 | temporarily unreachable upstream | message defers, survives restart, then delivers after recovery |

## Phase 5: live inbound policy truth tables

Run isolated two-network automation first. Then repeat the selected published posture with two real test clients: one address inside the allowlist, one outside. Bind the host port to a single explicit test-LAN interface, nowhere else.

| Policy | Trusted, no auth | Untrusted, valid auth | Trusted, valid auth | Neither |
|---|---:|---:|---:|---:|
| `ip` | accept | reject | accept by IP | reject |
| `smtp-auth` | reject | accept | accept | reject |
| `ip-or-auth` | accept | accept | accept | reject |
| `ip-and-auth` | reject | reject | accept | reject |

For every auth-enabled row also prove:

- pre-STARTTLS EHLO contains no AUTH; early AUTH rejected;
- post-STARTTLS EHLO offers exactly PLAIN and LOGIN;
- wrong password returns 535;
- unauthorized sender still fails after valid authentication;
- bare username works and username-with-wrong-realm does not;
- removing one credential and restarting revokes it while another still works;
- no password appears in inspect output, logs, state, or process arguments.

For BYO inbound TLS, record the served fingerprint, swap the mounted pair, restart, confirm the new fingerprint. Mismatched replacement must prevent boot, not serve the wrong cert.

For generated inbound TLS, force a safe artificial renewal window. Confirm the leaf fingerprint changes, the public-key digest stays constant, `cert.pem.previous` exists, replacement extends beyond the threshold, and Postfix still answers after reload. Also inspect `maximal_queue_lifetime` and `bounce_queue_lifetime`: both default to `12h` and must follow explicit override.

For outbound TLS, the real Postfix client must pass all five rows: publicly or explicitly trusted matching cert sends; untrusted CA defers; trusted CA with wrong hostname defers; expired leaf defers; explicitly trusted corporate inspection root with matching replacement leaf sends. Prove also that compatibility mode `encrypt` accepts the otherwise-untrusted endpoint—the documented security difference should be observable, not theoretical.

## Phase 6: verification and notifications

On the healthy test instance:

1. Run `alert.sh notify info manual-test 'test detail'` directly and confirm the
   email arrives.
2. Point the optional webhook at a controlled test receiver; verify valid JSON,
   special-character escaping, success status, and receiver-unreachable handling.
3. Use a disposable instance with intentionally wrong test tenant/client ID,
   set failure threshold to one, observe the token-failure webhook.
4. Restore valid test inputs and observe automatic token and queue recovery.
5. Force a verification run and correlate its Message-ID to `status=sent` and
   recipient receipt.
6. Suspend smtpd and observe the Compose healthcheck fail; resume it and observe
   recovery.
7. Create queue depth and SASL-failure conditions; confirm they're reported
   without exposing credentials.

For every automatic trigger, require all of these—not just a zero exit code: exact email body, exact webhook JSON, one stable reference, duplicate suppression on second failure, recovery with same reference and elapsed duration, persistence across container replacement, configured-local and UTC timestamps, and zero token/assertion/password/key exposure.
Break the email listener while webhook is healthy, reverse it; each channel must be attempted independently and only its own failed delivery may remain queued for bounded retry.

Test both channels separately—email alerts can't escape through a broken OAuth path; webhook is the independent channel.

## Phase 7: live certificate rotation

This mutates only the dedicated test app and requires approval immediately
before execution.

1. Record OAuth and inbound TLS certificate hashes and run `--list-keys`.
2. Induce proof-send failure on `--force` with a disposable bad upstream
   endpoint. Watch `addKey`, replication, token proof, failure, abandon cleanup,
   old-cert continuity, failure notification. Confirm no orphan remains.
3. Run successful `--force`. Watch add, both replication waits, token mint,
   proof delivery, atomic swap, immediate re-mint, success alert.
4. Assert the inbound TLS certificate is byte-identical before and after both
   attempts.
5. Re-run `--list-keys`; identify live and retiring credentials correctly.
6. In a later invocation, use test-only zero-day grace to exercise confirmed
   removal. Prove the live certificate sends afterward.
7. Exercise expired-certificate refusal offline; do not intentionally expire the
   only live test-app credential.

## Phase 8: passthrough/alias gate

`SendFromAliasEnabled` is organization-wide. Get explicit approval, enable only through the guarded PowerShell switch, record the change time, wait two hours before judging results.

| ID | Case | Required result |
|---|---|---|
| P01 | allowlisted proxy alias of the test mailbox | delivered over SMTP XOAUTH2 app-only with alias preserved |
| P02 | configured but unlisted sender | collapses to main mailbox and delivers |
| P03 | allowlisted address that is not a real alias | verifier reports failure and alert fires |
| P04 | foreign-mailbox address | rejected/out of scope; never represented as supported |

P01 gates the feature. Passthrough stays unverified until observed.

## Phase 9: platform and registry release

1. Build and smoke-run arm64, amd64-v3, and the dedicated amd64-v2 image.
2. On every image verify `sasl-xoauth2` 0.27, cryptography import, `saslpasswd2`,
   and package architecture.
3. Push test tags to Docker Hub and GHCR only after approval.
4. Compare manifest platform sets and digests, anonymously pull Docker Hub, and
   run the offline suite against pulled images.
5. Confirm the Docker Hub overview rendered—no secrets or internal development
   details visible.

Only after every applicable row is green should reference deployment migration be considered. Production migration is separate and last.
