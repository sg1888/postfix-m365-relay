# sasl-xoauth2 code review

A full read of the plugin source in `src/src/` at the vendored commit
(see [`UPSTREAM`](UPSTREAM)), judged against how this relay uses it.

- **Version reviewed:** 0.28 (`release-0.28`, commit `35c732e`)
- **Date:** 2026-10-14
- **Scope:** every non-test source file: `module.cc`, `client.cc`, `token_store.cc`,
  `http.cc`, `config.cc`, `log.cc` and their headers (about 1,600 lines).
  `xoauth2_test.cc` and `test_config.cc` were read for the sanitizer work only.

**Verdict: fit to ship as configured here.** No finding affects the relay. The
plugin's risky parts (its own token refresh and its full-trace log) are
unreachable or disabled by the image's configuration, and a test now enforces
that configuration.

## How the relay uses the plugin

The plugin and libsasl2 log through `syslog()`. A container has no syslog
daemon, so `scripts/syslog-bridge.py` (started first by the supervisor) receives
`/dev/log` and appends those lines to the relay log, which also streams to
`docker logs`.

Postfix's `smtp` client loads the plugin through Cyrus SASL for one mechanism,
XOAUTH2 (`smtp_sasl_mechanism_filter = xoauth2`). Per connection the plugin:

1. Reads the token file named as the "password" in `/etc/postfix/sasl_passwd`.
   The relay's own refresher (`scripts/refresh-smtp-token.py`) writes that file
   with `access_token`, `expiry` and a placeholder `refresh_token`.
2. Sends `user=<mailbox>^Aauth=Bearer <token>^A^A`.
3. If the server answers with a 334 challenge whose JSON `status` is `400` or
   `401`, it tries its own token refresh (step 4), and otherwise fails.
4. Its refresh POSTs `client_id`, `client_secret` and the file's `refresh_token`
   to `token_endpoint`, then rewrites the token file.

The image's `/etc/sasl-xoauth2.conf` points `token_endpoint` at
`http://127.0.0.1:9/...`, where nothing listens, so step 4 always fails at once
with a local connection error. Postfix then defers the message, and the next
retry uses whatever token the relay's refresher has written since.

## Findings

Severity is for this relay as configured. "Upstream" means the issue is in the
plugin and only matters to other deployments.

### 1. Trace log contains the bearer token and refresh secrets (mitigated)

`Client::SendToken` logs the full XOAUTH2 response including the bearer token
(`client.cc:284`). `TokenStore::Read` logs the access and refresh tokens
(`token_store.cc:213`). `TokenStore::Refresh` logs the request body with
`client_secret` and the response with the new token (`token_store.cc:120,136`).

These lines are buffered in memory and written to syslog only when
`always_log_to_syslog` or `log_full_trace_on_failure` is enabled. Otherwise a
failure logs one summary line (`log.cc`, `Log::Flush`): the last line before
the failure, which on every failure path is an error message, not a token.

- **Relay:** both settings are `no`. `tests/container-sasl-plugin.sh` fails if
  either is turned on.
- **Upstream:** fix proposed in [#129](https://github.com/tarickb/sasl-xoauth2/pull/129) (secrets logged as `<redacted, N bytes>`).

### 2. Plugin refresh sends secrets to a configurable URL with no timeout (mitigated)

`HttpPost` (`http.cc`) follows redirects (`CURLOPT_FOLLOWLOCATION`). It sets no
connect or transfer timeout, so a slow endpoint could stall Postfix's `smtp`
process. Its form body is not URL-encoded.

- **Relay:** unreachable. `token_endpoint` is a dead loopback port and
  `client_secret` is empty. `tests/container-sasl-plugin.sh` enforces both, and
  `tests/container-auth-rejected.sh` drives this exact path (a 401 from the
  server) and proves the message is deferred, not bounced, and that Postfix
  keeps running.

### 3. Token expiry parsed as a 32-bit int: fails after January 2038 (low)

`TokenStore::Read` parses `expiry` with `std::stoi` (`token_store.cc:209`). Once
Unix time passes 2,147,483,647 (2038-01-19), a correct expiry is out of `int`
range. `stoi` then throws, the read fails, and every authentication fails.

- **Relay:** no effect until 2038. Upstream will very likely have changed this
  by then, and the watcher will propose that release.
- **Upstream:** fix proposed in [#126](https://github.com/tarickb/sasl-xoauth2/pull/126) (`std::stoll` into `time_t`).

### 4. Case-insensitive yes/no parsing does not work (informational)

`Transform<bool>` (`config.cc`) intends to lower-case the value, but its
`std::for_each` lambda returns the lowered character instead of assigning it.
So `"Yes"` or `"NO"` is rejected as invalid.

- **Relay:** the image writes lower-case values only.
- **Upstream:** fix proposed in [#127](https://github.com/tarickb/sasl-xoauth2/pull/127).

### 5. Server challenge logged with `%s` and no length (low)

`Client::TokenSentStep` logs `from_server` with `%s` (`client.cc:246`), which
relies on the buffer being NUL-terminated, although the code also has its
length.

- **Relay:** Postfix decodes the challenge into a NUL-terminated buffer, and
  the line is formatted even when the trace is not output.
- **Confirmed by fuzzing:** when the fuzz harness passes the challenge without
  a trailing NUL (allowed by the SASL API), AddressSanitizer reports a heap
  over-read at `client.cc:246` within a minute. The harness passes it the way
  Postfix does. Fix proposed upstream: [#128](https://github.com/tarickb/sasl-xoauth2/pull/128).

### 6. Password callback memory (not a defect)

The plugin never frees the secret returned by the `SASL_CB_PASS` callback. That
is correct: under the Cyrus SASL callback contract the application owns that
buffer, and Postfix returns its own. Upstream's test helper `FakeGetPassword`
allocates a new one per call and never frees it, which LeakSanitizer reports.
`tests/sasl-xoauth2-sanitizers.sh` suppresses exactly that test function.

## What was checked and found sound

- **Concurrency.** Each Postfix `smtp` process is single-threaded with its own
  copy of the plugin; the only global state is the config, read once at load.
  The token file is replaced by rename on the container's tmpfs, so a reader
  sees a whole old or new file. `tests/container-token-rotation-load.sh`
  measures this under load.
- **Expiry margin.** The relay renews a token once it has under 30 minutes left
  (checked every 5 minutes); the plugin treats a token as expired only in its
  last 10 seconds (`refresh_window`). A token is always replaced at least 25
  minutes before the plugin would try its own refresh.

- **TLS before token.** The relay only allows `smtp_tls_security_level` of
  `secure` or `encrypt` (`render-config.sh`), so the token is never sent in
  clear text. The plugin also declares `SASL_SEC_NOPLAINTEXT`.
- **Token file writes.** The plugin rewrites the token file only after a
  successful refresh, which cannot happen here. When it does, it writes to a
  temporary file and renames it, so readers never see a partial file.
- **Memory safety.** The plugin uses `std::string`, `std::vector` and
  `unique_ptr`, with no manual buffer arithmetic except `RequestContext::Read`,
  whose copy is bounded by `std::min`. The 0.28 fix (a use-after-free in
  `http.cc`) is in place. Upstream's tests pass under ASan, LSan and UBSan
  (`tests/sasl-xoauth2-sanitizers.sh`, run in CI).
- **Plugin surface.** One client mechanism (XOAUTH2). No server side and no
  global state beyond the read-once config. The config is loaded at plugin
  init, before Postfix would chroot.
- **Failure behaviour.** Every error returns a SASL error code. Postfix treats
  SASL failures as temporary (`smtp_sasl_auth_soft_bounce = yes`, the default),
  so mail is deferred and retried, never bounced.
  `tests/container-auth-rejected.sh` proves this end to end.

## Tests that back this review

| Test | What it proves |
|---|---|
| `tests/sasl-xoauth2-sanitizers.sh` | Upstream unit tests pass under ASan, LSan and UBSan |
| `tests/container-sasl-plugin.sh` | Plugin loads; provenance matches `UPSTREAM`; refresh endpoint dead; trace logging off |
| `tests/container-end-to-end.sh` | Postfix sends exactly the mounted token, over TLS, for the configured mailbox |
| `tests/container-auth-rejected.sh` | A Microsoft-style 401/535 defers the message without bouncing it, and the message delivers once the token is accepted again |
| `tests/sasl-xoauth2-fuzz.sh` | libFuzzer (with ASan and UBSan) on the three inputs the plugin parses: the token file, the server's AUTH challenge, a refresh reply. About 700,000 inputs a minute; no finding on the paths Postfix uses |
| `tests/container-token-rotation-load.sh` | 200 messages from 8 concurrent clients while the token file is replaced ten times a second: every AUTH carries a whole valid token, nothing defers. Fails, as it should, against a rotator that writes in place |
| `tests/container-token-faults.sh` | Expired, missing, empty and malformed token files defer the message without sending AUTH; the plugin's reason reaches the log with no token in it; a read-only root delivers; `smtp` runs outside its chroot |

## Upstream issues checked

Every issue on tarickb/sasl-xoauth2 was read (2026-10-14, 93 issues). Those that
apply to this relay, and what guards against each:

| Upstream issue | Guard |
|---|---|
| #3, #38, #46, #52, #120 token file missing, unreadable or malformed | `container-token-faults.sh` |
| #98, #117 expired token, plugin refresh | `container-token-faults.sh` (refresh fails locally, mail deferred) |
| #125 read-only filesystem (Ubuntu 26.04 `ProtectSystem`) | `container-token-faults.sh` runs with `--read-only` |
| #3, #120 Postfix chroot hides the token file | `container-token-faults.sh` asserts `smtp` chroot is off |
| #28 config syntax error, plugin not loaded | `container-sasl-plugin.sh` (plugin loads, config parses) |
| #50 plugin compiled to read another config path | `container-sasl-plugin.sh` (compiled path is `/etc/sasl-xoauth2.conf`) |
| #91 crash on 16K-page arm64 kernels (Raspberry Pi 5) | `container-sasl-plugin.sh` (64 KiB segment alignment on arm64) |
| #48, #87, #96 wrong user, XOAUTH2 not used | `container-end-to-end.sh` (exact user and token) |
| #71, #110 Microsoft rejects the token | `container-auth-rejected.sh` |
| #115 libcurl 8.17 refresh failure (use-after-free) | fixed in 0.28; `sasl-xoauth2-sanitizers.sh`; refresh unused |
| #96 plugin messages missing from logs | `scripts/syslog-bridge.py`; `container-token-faults.sh` checks the reason is logged |

The rest concern Gmail, Keycloak, personal Outlook.com, the `sasl-xoauth2-tool`
helper, distro packaging, SELinux host policy, or desktop mail clients.

## When re-vendoring

Read `git diff -- vendor/sasl-xoauth2/src/src` for the new release and check it
against the findings above, especially any change to logging, `HttpPost`,
`TokenStore::Refresh` or the config keys. Update this file's version, date and
findings.
