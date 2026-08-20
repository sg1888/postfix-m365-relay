# Release and live-install qualification

This is the release gate. Use a dedicated test mailbox, dedicated Entra app
registration, isolated relay instance, test recipients, and disposable device
credentials. Never point these drills at a production relay or mailbox.

After **any Exchange permission or organization-setting change, wait two full
hours before interpreting a send result**. A probe during that window is
informational only. Record only behavior you personally observed; config output,
an exit code, and local SMTP acceptance are not proof of Microsoft delivery.

## Evidence record

Create one row per test. Preserve secrets nowhere in the record.

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

The runner prints and stops at each named suite, so a failure remains directly
traceable. CI keeps the same suites as separate named steps for reviewability.

These cover invalid configuration, malformed secrets, sender-name escaping,
collapse/passthrough maps, all five inbound policies, trusted and untrusted
source networks, correct and wrong passwords, authorized and unauthorized
senders, TLS-before-AUTH, credential revocation, certificate separation and
import, supervisor behavior, a wedged healthcheck, read-only operation, and a
deferred message retaining the same queue ID across forced replacement before
draining through the recovered isolated upstream. The inbound fullchain test
uses a root, intermediate, and leaf to prove Postfix serves the intermediate,
validates the hostname, and loads an atomically replaced key/fullchain pair.

Also AST-parse both PowerShell files on a workstation with PowerShell:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ./powershell/setup-exchange.ps1), [ref]$null, [ref]$errors)
$errors
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ./powershell/undo-exchange.ps1), [ref]$null, [ref]$errors)
$errors
```

An empty error list is the expected result for each file.

## Phase 2: isolated first boot

1. Start the candidate with an empty `/config` bind and empty state volume.
2. Confirm it creates `mail-relay.conf` as `0600`, prints setup instructions,
   does not open SMTP, and automatically proceeds after the required fake test
   identifiers and sender are saved.
3. Watch generation of the RSA-4096 OAuth certificate and public PEM output.
4. Confirm the private key is `0600`, Postfix stays up, the token loop retries,
   and a locally accepted test message remains deferred without a token.
5. Confirm no host port is published in the default posture.
6. Run the bad-data cases below against disposable instances. Each must exit
   nonzero with the expected diagnostic, before accepting mail.

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

This phase changes external state and requires explicit approval immediately
before execution.

1. Create or identify the dedicated licensed test mailbox and test app.
2. Record tenant ID, application/client ID, and enterprise-application object ID.
3. Grant only the documented Exchange application permission and mailbox access.
4. Upload only the public certificate printed by first boot.
5. Record the final permission-change time and wait two hours.
6. Without restarting the container, watch the token loop mint a token and the
   previously deferred queue drain.

Do not enable alias sending yet. Collapse mode is qualified first.

## Phase 4: live collapse-mode delivery and rejection

Use `scripts/qualify-relay.py`; device passwords, when needed, come from a
protected file and never from argv. Every accepted run prints a unique
Message-ID. Map it to a Postfix queue ID, require `status=sent`, and then confirm
the exact message in the test recipient mailbox.

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

First run the isolated two-network automation. Then repeat the selected published
posture using two real test clients: one address inside the allowlist and one
outside it. Bind the host port to one explicit test-LAN interface only.

| Policy | Trusted, no auth | Untrusted, valid auth | Trusted, valid auth | Neither |
|---|---:|---:|---:|---:|
| `ip` | accept | reject | accept by IP | reject |
| `smtp-auth` | reject | accept | accept | reject |
| `ip-or-auth` | accept | accept | accept | reject |
| `ip-and-auth` | reject | reject | accept | reject |

For every auth-enabled row also prove:

- pre-STARTTLS EHLO contains no AUTH and early AUTH is rejected;
- post-STARTTLS EHLO offers exactly PLAIN and LOGIN;
- wrong password returns 535;
- unauthorized sender still fails after valid authentication;
- bare username works and username-with-wrong-realm does not;
- removing one credential and restarting revokes it while another still works;
- no password appears in inspect output, logs, state, or process arguments.

For BYO inbound TLS, record the served fingerprint, replace the mounted pair,
restart, and observe the new fingerprint. A mismatched replacement must prevent
boot rather than serve an unintended certificate.

For generated inbound TLS, force a safe artificial renewal window. Confirm the
leaf fingerprint changes, the public-key digest does not, `cert.pem.previous`
exists, the replacement extends beyond the threshold, and Postfix still answers
after its reload. Also inspect `maximal_queue_lifetime` and
`bounce_queue_lifetime`: both must be `12h` by default and both must follow an
explicit override.

For outbound TLS, the real Postfix client must pass all five rows: publicly or
explicitly trusted matching certificate sends; untrusted CA defers; trusted CA
with the wrong hostname defers; expired leaf defers; and an explicitly trusted
corporate inspection root with a matching replacement leaf sends. Also prove
that compatibility mode `encrypt` accepts the otherwise-untrusted endpoint, so
the documented security difference is observable rather than assumed.

## Phase 6: verification and notifications

On the healthy test instance:

1. Run `alert.sh` directly and confirm the email arrives.
2. Point the optional webhook at a controlled test receiver; verify valid JSON,
   special-character escaping, success status, and receiver-unreachable handling.
3. Use a disposable instance with an intentionally wrong test tenant/client ID,
   set the failure threshold to one, and observe the token-failure webhook.
4. Restore valid test inputs and observe automatic token and queue recovery.
5. Force a verification run and correlate its Message-ID to `status=sent` and
   recipient receipt.
6. Suspend smtpd and observe the Compose healthcheck fail; resume it and observe
   recovery.
7. Create queue depth and SASL-failure warning conditions and confirm they are
   reported without exposing credentials.

Email alerts cannot leave through a deliberately broken OAuth path; the webhook
is the independent channel for that failure. Test both channels separately.

## Phase 7: live certificate rotation

This mutates only the dedicated test app and requires approval immediately
before execution.

1. Record OAuth and inbound TLS certificate hashes and run `--list-keys`.
2. Induce a proof-send failure on `--force` using a disposable bad upstream
   endpoint. Watch `addKey`, replication, token proof, failure, abandon cleanup,
   old-cert continuity, and failure notification. Confirm no orphan remains.
3. Run a successful `--force`. Watch add, both replication waits, token mint,
   real proof delivery, atomic swap, immediate re-mint, and success alert.
4. Assert the inbound TLS certificate is byte-identical before and after both
   attempts.
5. Re-run `--list-keys`; identify live and retiring credentials correctly.
6. In a later invocation, use a test-only zero-day grace to exercise confirmed
   removal. Prove the live certificate still sends afterward.
7. Exercise expired-certificate refusal offline; do not intentionally expire the
   only live test-app credential.

## Phase 8: passthrough/alias gate

`SendFromAliasEnabled` is organization-wide. Obtain explicit approval, enable it
only through the guarded PowerShell switch, record the change time, then wait two
hours before judging a result.

| ID | Case | Required result |
|---|---|---|
| P01 | allowlisted proxy alias of the test mailbox | delivered over SMTP XOAUTH2 app-only with alias preserved |
| P02 | configured but unlisted sender | collapses to main mailbox and delivers |
| P03 | allowlisted address that is not a real alias | verifier reports failure and alert fires |
| P04 | foreign-mailbox address | rejected/out of scope; never represented as supported |

P01 is the feature gate. Passthrough remains unverified until it is watched.

## Phase 9: platform and registry release

1. Build and smoke-run arm64, amd64-v3, and the dedicated amd64-v2 image.
2. On every image assert `sasl-xoauth2` 0.27, cryptography import, `saslpasswd2`,
   and the expected package architecture.
3. Push test tags to Docker Hub and GHCR only after approval.
4. Compare manifest platform sets and digests, anonymously pull Docker Hub, and
   run the offline suite against pulled images.
5. Confirm the Docker Hub overview rendered and contains no secrets or internal
   development details.

Only after every applicable row is green should migration of any reference
deployment be considered. Production migration is a separate, last operation.
