#!/usr/bin/env bash
# Prove that a deferred message belongs to the persistent Postfix spool volume,
# not to one container's writable layer.  This is deliberately a black-box
# replacement drill: the first relay accepts mail while its upstream hostname
# does not exist, we forcibly remove that container, and a newly created relay
# must discover the same queue ID and deliver it after the upstream appears.
#
# Everything runs on an internal Docker network with example.invalid identities
# and a fake XOAUTH2 server.  No DNS packet can escape that network and no part
# of this test knows a Microsoft tenant, mailbox, application, or access token.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-spool-test
upstream=postfix-m365-relay-spool-upstream
network=postfix-m365-relay-spool-network
state=postfix-m365-relay-spool-state
spool=postfix-m365-relay-spool-volume
fixture=$PWD/tests/.tmp-spool-recovery

cleanup() {
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup

install -d -m 0700 "$fixture"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=upstream \
  -keyout "$fixture/upstream.key" -out "$fixture/upstream.crt" >/dev/null 2>&1
chmod 0600 "$fixture/upstream.key"
: > "$fixture/messages.jsonl"

# A static, non-secret token keeps this test focused on Postfix's queue.  The
# fake server accepts any syntactically valid XOAUTH2 bearer value and never
# records it.  Its expiry is kept one hour ahead so the refresh helper does not
# try to contact Entra while the replacement drill is in progress.
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-spool-test-token","expiry":"%s","refresh_token":"unused-app-only-flow"}\n' \
  "$expiry" > "$fixture/relay.json"
chmod 0644 "$fixture/relay.json"

docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null

start_relay() {
  # Reuse both named volumes on every invocation.  State preserves the generated
  # OAuth certificate; spool preserves active/deferred mail and queue metadata.
  # The `upstream` network alias is intentionally absent on the first boot.
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker run -d --name "$relay" --network "$network" --network-alias relay \
    -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
    -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
    -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
    -e MAIL_SENDER_QUEUE=queue-test@relay.example.local \
    -e 'MAIL_SENDER_NAME_QUEUE=Queue [Replacement Test]' \
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
    [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || {
      docker logs "$relay"; return 1;
    }
    docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' \
      >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$relay"
  return 1
}

queue_id() {
  # postqueue -j is stable machine-readable output.  Avoid parsing the classic
  # human display because its queue ID gains punctuation while a message is in
  # the active queue, which previously made identity comparisons unreliable.
  docker exec "$relay" bash -c \
    "postqueue -j | python3 -c 'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; assert len(rows)==1, rows; print(rows[0][\"queue_id\"])'"
}

start_relay
docker run --rm --network "$network" --entrypoint python3 \
  -v "$PWD":/workspace:ro "$image" /workspace/scripts/qualify-relay.py \
  --host relay --from-address queue-test@relay.example.local \
  --from-name 'client name must be replaced' --to recipient@example.invalid \
  --subject spool-survives-container-replacement >/dev/null

# Force an immediate attempt so the test observes a real defer before removal,
# rather than merely racing a newly accepted message that has not left active.
docker exec "$relay" postqueue -f
for _attempt in {1..30}; do
  docker exec "$relay" postqueue -j > "$fixture/deferred-queue.jsonl"
  grep -q '"delay_reason"' "$fixture/deferred-queue.jsonl" && break
  sleep 1
done
# Do not match human-readable diagnostic wording here. The exact DNS error is
# resolver-dependent (for example "host not found" versus "name service
# error"). `delay_reason` is Postfix's machine-readable proof that delivery was
# attempted and the recipient is genuinely deferred.
docker exec "$relay" postqueue -j > "$fixture/deferred-queue.jsonl"
if ! grep -q '"delay_reason"' "$fixture/deferred-queue.jsonl"; then
  docker exec "$relay" postqueue -j >&2
  docker logs "$relay" >&2
  echo 'message never entered a genuinely deferred state' >&2
  exit 1
fi
before=$(queue_id)

# `docker rm -f` is intentional here: it models replacement after abrupt loss,
# not a graceful stop.  Removing the named spool volume would be destructive
# operator action and is specifically outside the recovery promise.
docker rm -f "$relay" >/dev/null
start_relay
after=$(queue_id)
[[ $after == "$before" ]] || {
  printf 'queue ID changed across replacement: before=%s after=%s\n' "$before" "$after" >&2
  exit 1
}

# Only now make the isolated upstream available.  A manual flush removes the
# normal retry delay so the regression suite completes promptly; production
# Postfix would also retry automatically according to its queue schedule.
docker run -d --name "$upstream" --network "$network" --network-alias upstream \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_xoauth2_smtp.py --cert /data/upstream.crt \
  --key /data/upstream.key --output /data/messages.jsonl >/dev/null
for _attempt in {1..20}; do
  docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
  grep -q '^READY ' "$fixture/upstream-ready.log" && break
  sleep 1
done
docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
grep -q '^READY ' "$fixture/upstream-ready.log"
docker exec "$relay" postqueue -f

for _attempt in {1..40}; do
  [[ $(wc -l < "$fixture/messages.jsonl" | tr -d ' ') == 1 ]] && \
    [[ -z $(docker exec "$relay" postqueue -j) ]] && break
  sleep 1
done
[[ $(wc -l < "$fixture/messages.jsonl" | tr -d ' ') == 1 ]]
[[ -z $(docker exec "$relay" postqueue -j) ]]

SPOOL_MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import base64
import json
import os
from email import policy
from email.parser import BytesParser

records = [json.loads(line) for line in open(os.environ["SPOOL_MESSAGES"])]
assert len(records) == 1, records
record = records[0]
message = BytesParser(policy=policy.default).parsebytes(
    base64.b64decode(record["message_b64"])
)
assert record["tls"] is True
assert record["authenticated_user"] == "relay-test@example.invalid"
assert record["mail_from"] == "relay-test@example.invalid"
assert str(message["Subject"]) == "spool-survives-container-replacement"
assert message["From"].addresses[0].display_name == "Queue [Replacement Test]"
PY

echo "ok deferred queue ID $before survived forced replacement and drained after recovery"
