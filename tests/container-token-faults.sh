#!/usr/bin/env bash
# Token-file faults, the most common failures reported against sasl-xoauth2
# upstream, on a relay with a read-only root filesystem:
#   expired    the plugin attempts its own refresh (upstream #98, #117); the
#              image points that at a dead local port, so it fails locally
#   missing    "TokenStore::Read: failed to open file" (upstream #3, #38, #52, #120)
#   empty      a truncated write
#   malformed  invalid JSON (upstream #46)
#
# For each fault a real message must be deferred, never bounced, with no AUTH
# sent upstream, and the plugin's reason must reach the relay log (through
# syslog-bridge.py) without any token in it. Once a valid token is back, every
# deferred message must deliver.
#
# Also proves, on the same relay:
#   - delivery works with a read-only root (Ubuntu 26.04 hardening made the
#     plugin's writes fail on hosts; upstream #125). Nothing in the plugin's
#     authentication path may write to disk.
#   - Postfix's smtp client runs outside its chroot, where the token file is
#     (Ubuntu/Debian ship it chrooted; upstream #3, #120).
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-token-faults-relay
upstream=postfix-m365-relay-token-faults-upstream
network=postfix-m365-relay-token-faults-network
state=postfix-m365-relay-token-faults-state
spool=postfix-m365-relay-token-faults-spool
fixture=$PWD/tests/.tmp-token-faults
good_token=offline-token-faults-good-token
expired_token=offline-token-faults-expired-token

cleanup() {
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
report_failure() {
  rc=$?
  if (( rc != 0 )); then
    echo "token-faults test failed; queue, AUTH log and relay log:" >&2
    docker exec "$relay" postqueue -j >&2 2>&1 || true
    cat "$fixture/auth.jsonl" >&2 2>/dev/null || true
    docker exec "$relay" cat /var/log/mail-relay/postfix.log >&2 2>&1 || true
    docker logs "$relay" >&2 2>&1 || true
  fi
  cleanup
  exit "$rc"
}
trap report_failure EXIT
cleanup

install -d -m 0700 "$fixture"
# A directory mount, not a file mount: replacing the token by rename stays
# visible inside the container.
install -d -m 0755 "$fixture/token"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=upstream \
  -keyout "$fixture/upstream.key" -out "$fixture/upstream.crt" >/dev/null 2>&1
chmod 0600 "$fixture/upstream.key"
: > "$fixture/messages.jsonl"
: > "$fixture/auth.jsonl"

# Replace the token file atomically, as the relay's own refresher does.
put_token() {
  printf '%s' "$1" > "$fixture/token/.relay.json.tmp"
  chmod 0644 "$fixture/token/.relay.json.tmp"
  mv -f "$fixture/token/.relay.json.tmp" "$fixture/token/relay.json"
}
# Wait until the relay sees exactly the host's token file (or its absence).
# Docker Desktop and Colima share host directories through a file-sharing layer
# that can briefly serve a renamed file's old or partial contents; a fault case
# must test the intended file, not that artifact.
sync_token() {
  local want
  if [[ -e $fixture/token/relay.json ]]; then
    want=$(openssl dgst -sha256 -r "$fixture/token/relay.json" | cut -d' ' -f1)
  else
    want=absent
  fi
  for _attempt in {1..50}; do
    [[ $(docker exec "$relay" sh -c 'f=/run/secrets/token/relay.json
      if [ -e "$f" ]; then sha256sum "$f" | cut -d" " -f1; else echo absent; fi') == "$want" ]] && return 0
    sleep 0.2
  done
  echo "relay never saw the new token file" >&2
  return 1
}
token_json() {
  printf '{"access_token":"%s","expiry":"%s","refresh_token":"unused-app-only-flow"}\n' "$1" "$2"
}
put_token "$(token_json "$good_token" $(( $(date +%s) + 3600 )))"
good_sha256=$(printf %s "$good_token" | openssl dgst -sha256 -r | cut -d' ' -f1)

docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null
docker run -d --name "$upstream" --network "$network" --network-alias upstream \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_xoauth2_smtp.py --cert /data/upstream.crt \
  --key /data/upstream.key --output /data/messages.jsonl \
  --expect-token-sha256 "$good_sha256" --auth-log /data/auth.jsonl >/dev/null
for _attempt in {1..20}; do
  docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
  grep -q '^READY ' "$fixture/upstream-ready.log" && break
  sleep 1
done
grep -q '^READY ' "$fixture/upstream-ready.log"

# The read-only layout of tests/container-policy.sh (Tier 2).
docker run -d --name "$relay" --network "$network" --network-alias relay --read-only \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_FAULTS=faults-test@relay.example.local \
  -e MAIL_ADMIN_EMAIL= \
  -e MAIL_UPSTREAM_HOST=upstream -e MAIL_UPSTREAM_PORT=1587 \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/upstream-ca.crt \
  -e MAIL_TOKEN_FILE=/run/secrets/token/relay.json \
  -e MAIL_INBOUND_AUTH=ip -e MAIL_VERIFY_SEND=no \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 \
  -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/token":/run/secrets/token:ro \
  -v "$fixture/upstream.crt":/run/secrets/upstream-ca.crt:ro \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /etc/postfix:rw --tmpfs /run:rw,nosuid,noexec --tmpfs /var/lib/postfix:rw \
  "$image" >/dev/null
for _attempt in {1..40}; do
  [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || exit 1
  docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1

[[ $(docker exec "$relay" postconf -h -F smtp/unix/chroot) == n ]] || {
  echo "Postfix smtp runs chrooted; the token file outside the chroot is unreadable" >&2
  exit 1
}
docker exec "$relay" test -S /dev/log || { echo "syslog bridge socket /dev/log missing" >&2; exit 1; }
echo 'ok smtp runs outside its chroot; syslog bridge is listening'

send() {
  docker run --rm --network "$network" --entrypoint python3 \
    -v "$PWD":/workspace:ro "$image" /workspace/scripts/qualify-relay.py \
    --host relay --from-address faults-test@relay.example.local \
    --from-name 'Token Faults' --to recipient@example.invalid --subject "$1" >/dev/null
}
queue_count() { docker exec "$relay" postqueue -j | grep -c . || true; }
lines() { wc -l < "$1" | tr -d ' '; }
relay_log() { docker exec "$relay" cat /var/log/mail-relay/postfix.log; }

# Baseline: a read-only relay delivers with a valid token.
send token-faults-baseline
docker exec "$relay" postqueue -f
for _attempt in {1..40}; do [[ $(lines "$fixture/messages.jsonl") == 1 ]] && break; sleep 1; done
[[ $(lines "$fixture/messages.jsonl") == 1 ]]
echo 'ok read-only root filesystem delivers through XOAUTH2'

# name | token file content | plugin reason expected in the relay log
cases=(
  "expired|$(token_json "$expired_token" $(( $(date +%s) - 60 )))|TokenStore::Refresh: http error"
  "missing||TokenStore::Read: failed to open file"
  "empty|<empty>|TokenStore::Read"
  "malformed|{\"access_token\": \"truncated|TokenStore::Read: exception"
)
deferred=0
for spec in "${cases[@]}"; do
  IFS='|' read -r name content reason <<<"$spec"
  case "$name" in
    missing) rm -f "$fixture/token/relay.json" ;;
    empty) put_token '' ;;
    *) put_token "$content" ;;
  esac
  sync_token
  auth_before=$(lines "$fixture/auth.jsonl")
  log_before=$(relay_log | grep -c 'sasl-xoauth2' || true)
  send "token-faults-$name"
  deferred=$(( deferred + 1 ))
  docker exec "$relay" postqueue -f
  for _attempt in {1..40}; do
    (( $(relay_log | grep -c 'sasl-xoauth2' || true) > log_before )) && \
      [[ $(docker exec "$relay" postqueue -j | grep -c 'SASL authentication failed' || true) == "$deferred" ]] && break
    sleep 1
  done
  relay_log > "$fixture/relay-$name.log"
  # The plugin's own reason, carried by the syslog bridge.
  grep 'sasl-xoauth2' "$fixture/relay-$name.log" | tail -n 5 | grep -qF "$reason" || {
    echo "$name: plugin reason '$reason' not in relay log" >&2; exit 1;
  }
  # Deferred, not bounced, not delivered: every queued message is ours.
  docker exec "$relay" postqueue -j > "$fixture/queue-$name.jsonl"
  QUEUE=$fixture/queue-$name.jsonl WANT=$deferred python3 - <<'PY'
import json, os
rows = [json.loads(line) for line in open(os.environ["QUEUE"]) if line.strip()]
assert len(rows) == int(os.environ["WANT"]), rows
for row in rows:
    assert row["queue_name"] == "deferred", row
    assert row["sender"] == "relay-test@example.invalid", row
    assert all("SASL authentication failed" in r.get("delay_reason", "") for r in row["recipients"]), row
PY
  # The plugin failed before sending anything upstream.
  [[ $(lines "$fixture/auth.jsonl") == "$auth_before" ]] || { echo "$name: AUTH reached upstream" >&2; exit 1; }
  [[ $(lines "$fixture/messages.jsonl") == 1 ]] || { echo "$name: message delivered" >&2; exit 1; }
  [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]]
  echo "ok $name token: deferred with no AUTH sent; log says '$reason'"
done

# No token, valid or expired, may appear in any log.
relay_log > "$fixture/relay-final.log"
docker logs "$relay" > "$fixture/docker.log" 2>&1
if grep -qF -e "$good_token" -e "$expired_token" "$fixture/relay-final.log" "$fixture/docker.log"; then
  echo "a bearer token appeared in the relay log" >&2
  exit 1
fi
echo 'ok no token value in the relay log or container log'

# A valid token again: every deferred message delivers, none bounced.
put_token "$(token_json "$good_token" $(( $(date +%s) + 3600 )))"
sync_token
docker exec "$relay" postqueue -f
for _attempt in {1..60}; do
  [[ $(lines "$fixture/messages.jsonl") == $(( deferred + 1 )) && $(queue_count) == 0 ]] && break
  sleep 1
done
[[ $(queue_count) == 0 ]]
MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import base64, json, os
from email import policy
from email.parser import BytesParser
records = [json.loads(line) for line in open(os.environ["MESSAGES"])]
subjects = sorted(str(BytesParser(policy=policy.default).parsebytes(
    base64.b64decode(r["message_b64"]))["Subject"]) for r in records)
want = sorted("token-faults-" + n for n in ("baseline", "expired", "missing", "empty", "malformed"))
assert subjects == want, subjects
assert all(r["mail_from"] == "relay-test@example.invalid" for r in records), records
PY
echo 'ok every deferred message delivered once the token file was valid again'
