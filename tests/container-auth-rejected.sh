#!/usr/bin/env bash
# What happens when Microsoft rejects the relay's token (expired, revoked, or
# the application lost its permission): the fake upstream answers AUTH exactly
# as Microsoft does, a 334 challenge carrying {"status":"401"} and then 535.
#
# Proves, offline on an internal network:
#   - the message is deferred and kept, never bounced to the sender;
#   - the XOAUTH2 plugin's 401 handling (it tries its own refresh, which the
#     image points at a dead local port) fails cleanly: Postfix and the
#     container keep running;
#   - once the upstream accepts the token again, the same message is delivered.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-auth-rejected-relay
upstream=postfix-m365-relay-auth-rejected-upstream
network=postfix-m365-relay-auth-rejected-network
state=postfix-m365-relay-auth-rejected-state
spool=postfix-m365-relay-auth-rejected-spool
fixture=$PWD/tests/.tmp-auth-rejected

cleanup() {
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
report_failure() {
  rc=$?
  if (( rc != 0 )); then
    echo "auth-rejected test failed; queue, sink and relay log:" >&2
    docker exec "$relay" postqueue -j >&2 2>&1 || true
    cat "$fixture/auth.jsonl" >&2 2>/dev/null || true
    docker logs "$relay" >&2 2>&1 || true
  fi
  cleanup
  exit "$rc"
}
trap report_failure EXIT
cleanup

install -d -m 0700 "$fixture"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=upstream \
  -keyout "$fixture/upstream.key" -out "$fixture/upstream.crt" >/dev/null 2>&1
chmod 0600 "$fixture/upstream.key"
: > "$fixture/messages.jsonl"
: > "$fixture/auth.jsonl"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-rejected-test-token","expiry":"%s","refresh_token":"unused-app-only-flow"}\n' \
  "$expiry" > "$fixture/relay.json"
chmod 0644 "$fixture/relay.json"
token_sha256=$(printf %s offline-rejected-test-token | openssl dgst -sha256 -r | cut -d' ' -f1)

docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null

start_upstream() {
  docker rm -f "$upstream" >/dev/null 2>&1 || true
  docker run -d --name "$upstream" --network "$network" --network-alias upstream \
    --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
    "$image" /tests/fake_xoauth2_smtp.py --cert /data/upstream.crt \
    --key /data/upstream.key --output /data/messages.jsonl \
    --auth-log /data/auth.jsonl "$@" >/dev/null
  for _attempt in {1..20}; do
    docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
    grep -q '^READY ' "$fixture/upstream-ready.log" && return 0
    sleep 1
  done
  cat "$fixture/upstream-ready.log" >&2
  return 1
}

queue_json() { docker exec "$relay" postqueue -j; }

start_upstream --reject-auth
docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_REJECTED=rejected-test@relay.example.local \
  -e MAIL_UPSTREAM_HOST=upstream -e MAIL_UPSTREAM_PORT=1587 \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/upstream-ca.crt \
  -e MAIL_TOKEN_FILE=/run/secrets/relay.json \
  -e MAIL_INBOUND_AUTH=ip -e MAIL_VERIFY_SEND=no \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 \
  -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/relay.json":/run/secrets/relay.json:ro \
  -v "$fixture/upstream.crt":/run/secrets/upstream-ca.crt:ro \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 \
  "$image" >/dev/null
for _attempt in {1..40}; do
  docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1

docker run --rm --network "$network" --entrypoint python3 \
  -v "$PWD":/workspace:ro "$image" /workspace/scripts/qualify-relay.py \
  --host relay --from-address rejected-test@relay.example.local \
  --from-name 'Rejected Test' --to recipient@example.invalid \
  --subject auth-rejected-then-delivered >/dev/null

# Wait for a real rejected AUTH and a deferral that names SASL as the reason.
docker exec "$relay" postqueue -f
for _attempt in {1..40}; do
  grep -q '"rejected"' "$fixture/auth.jsonl" && \
    queue_json | grep -q 'SASL authentication failed' && break
  sleep 1
done
grep -q '"rejected"' "$fixture/auth.jsonl"
queue_json > "$fixture/deferred.jsonl"

QUEUE=$fixture/deferred.jsonl MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import json, os
rows = [json.loads(line) for line in open(os.environ["QUEUE"]) if line.strip()]
# Exactly the original message: a bounce would add a second message with the
# null sender, and a delivery would empty the queue.
assert len(rows) == 1, rows
row = rows[0]
assert row["queue_name"] == "deferred", row
assert row["sender"] == "relay-test@example.invalid", row
(recipient,) = row["recipients"]
assert recipient["address"] == "recipient@example.invalid", recipient
assert "SASL authentication failed" in recipient["delay_reason"], recipient
assert os.path.getsize(os.environ["MESSAGES"]) == 0, "sink received mail despite rejected AUTH"
PY
[[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]]
docker exec "$relay" postfix status >/dev/null 2>&1
echo 'ok rejected XOAUTH2 (334 status 401, then 535) defers the message; no bounce, relay keeps running'

# Microsoft accepts the token again: the same queued message must deliver.
start_upstream --expect-token-sha256 "$token_sha256"
docker exec "$relay" postqueue -f
for _attempt in {1..40}; do
  [[ -s $fixture/messages.jsonl && -z $(queue_json) ]] && break
  sleep 1
done
[[ -z $(queue_json) ]]
MESSAGES=$fixture/messages.jsonl AUTH=$fixture/auth.jsonl python3 - <<'PY'
import base64, json, os
from email import policy
from email.parser import BytesParser
records = [json.loads(line) for line in open(os.environ["MESSAGES"])]
assert len(records) == 1, records
message = BytesParser(policy=policy.default).parsebytes(base64.b64decode(records[0]["message_b64"]))
assert str(message["Subject"]) == "auth-rejected-then-delivered"
results = [json.loads(line)["result"] for line in open(os.environ["AUTH"])]
assert results[-1] == "accepted" and "rejected" in results, results
PY
echo 'ok deferred message delivered once the upstream accepted the token again'
