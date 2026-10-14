#!/usr/bin/env bash
# Token rotation under concurrent load: the race that could surprise us.
#
# Postfix runs many smtp processes at once, and each one's XOAUTH2 plugin reads
# the token file at every AUTH while the relay's refresher replaces that file.
# The design says a reader always sees a whole token (the refresher writes a
# temporary file and renames it into place on the same tmpfs). This measures it:
#
#   - inside the relay container, as in production, a rotator replaces
#     /run/mail-relay/relay.json about ten times a second, the same way
#     refresh-smtp-token.py does (temp file, mode 0640 root:postfix, rename);
#   - each token is ~1.5 KB, like a real Microsoft token, and derived from a
#     key and a generation number, so the fake upstream accepts only whole,
#     exact tokens (a torn or partial read would be rejected);
#   - 200 messages arrive from 8 concurrent clients while it rotates, with
#     Postfix's connection cache off so every delivery authenticates afresh.
#
# Every message must be delivered with no deferral, every AUTH must carry a
# whole valid token, and deliveries must have used many token generations.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-rotation-load-relay
upstream=postfix-m365-relay-rotation-load-upstream
network=postfix-m365-relay-rotation-load-network
state=postfix-m365-relay-rotation-load-state
spool=postfix-m365-relay-rotation-load-spool
fixture=$PWD/tests/.tmp-rotation-load
key=offline-rotation-load-key
messages=200
clients=8

cleanup() {
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  [[ -n ${KEEP_FIXTURE:-} ]] || rm -rf "$fixture"
}
report_failure() {
  rc=$?
  if (( rc != 0 )); then
    echo "rotation-load test failed; AUTH results, queue and relay log tail:" >&2
    python3 -c 'import collections,json,sys; print(collections.Counter(json.loads(l)["result"] for l in open(sys.argv[1])))' \
      "$fixture/auth.jsonl" >&2 2>/dev/null || true
    docker exec "$relay" postqueue -j 2>/dev/null | head -5 >&2 || true
    docker exec "$relay" tail -n 40 /var/log/mail-relay/postfix.log >&2 2>&1 || true
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

docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null
docker run -d --name "$upstream" --network "$network" --network-alias upstream \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_xoauth2_smtp.py --cert /data/upstream.crt \
  --key /data/upstream.key --output /data/messages.jsonl \
  --rotating-token-key "$key" --auth-log /data/auth.jsonl >/dev/null
for _attempt in {1..20}; do
  docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
  grep -q '^READY ' "$fixture/upstream-ready.log" && break
  sleep 1
done
grep -q '^READY ' "$fixture/upstream-ready.log"

# Default token path: /run/mail-relay/relay.json on the container's tmpfs.
docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_LOAD=load-test@relay.example.local \
  -e MAIL_ADMIN_EMAIL= \
  -e MAIL_UPSTREAM_HOST=upstream -e MAIL_UPSTREAM_PORT=1587 \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/upstream-ca.crt \
  -e MAIL_INBOUND_AUTH=ip -e MAIL_VERIFY_SEND=no \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 \
  -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$PWD/tests":/tests:ro \
  -v "$fixture/upstream.crt":/run/secrets/upstream-ca.crt:ro \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 \
  "$image" >/dev/null
for _attempt in {1..40}; do
  [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || exit 1
  docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1

# Every delivery opens a fresh upstream session and authenticates, instead of
# reusing a cached, already-authenticated connection.
docker exec "$relay" postconf -e 'smtp_connection_cache_on_demand = no'
docker exec "$relay" postfix reload >/dev/null 2>&1

# The rotator, inside the relay container (the same filesystem semantics as
# production). It runs until /run/mail-relay/stop-rotation appears.
docker exec -d "$relay" python3 -c '
import grp, json, os, sys, time
sys.path.insert(0, "/tests")
from fake_xoauth2_smtp import rotating_token
key = sys.argv[1]
path = "/run/mail-relay/relay.json"
gid = grp.getgrnam("postfix").gr_gid
generation = 0
while not os.path.exists("/run/mail-relay/stop-rotation"):
    temporary = f"{path}.tmp.{os.getpid()}"
    with open(temporary, "w") as stream:
        json.dump({"access_token": rotating_token(key, generation),
                   "expiry": str(int(time.time()) + 3600),
                   "refresh_token": "unused-app-only-flow"}, stream)
    os.chown(temporary, 0, gid)
    os.chmod(temporary, 0o640)
    os.replace(temporary, path)
    with open("/run/mail-relay/rotation-generation", "w") as stream:
        stream.write(str(generation))
    generation += 1
    time.sleep(0.1)
' "$key"
for _attempt in {1..50}; do
  docker exec "$relay" test -s /run/mail-relay/relay.json && break
  sleep 0.2
done
docker exec "$relay" test -s /run/mail-relay/relay.json

# 200 messages from 8 concurrent SMTP clients.
docker run --rm --network "$network" --entrypoint python3 "$image" -c '
import smtplib, sys
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
total, clients = int(sys.argv[1]), int(sys.argv[2])
def send(i):
    message = EmailMessage()
    message["From"] = "Load Test <load-test@relay.example.local>"
    message["To"] = "recipient@example.invalid"
    message["Subject"] = f"rotation-load-{i}"
    message.set_content(f"message {i}\n")
    with smtplib.SMTP("relay", 2525, timeout=60) as smtp:
        smtp.send_message(message)
with ThreadPoolExecutor(clients) as pool:
    list(pool.map(send, range(total)))
print(f"submitted {total} messages from {clients} clients")
' "$messages" "$clients"

lines() { wc -l < "$1" | tr -d ' '; }
for _attempt in {1..180}; do
  [[ $(lines "$fixture/messages.jsonl") -ge $messages ]] && break
  sleep 1
done
docker exec "$relay" touch /run/mail-relay/stop-rotation
rotations=$(docker exec "$relay" cat /run/mail-relay/rotation-generation)
docker exec "$relay" cat /var/log/mail-relay/postfix.log > "$fixture/relay.log"

MESSAGES=$fixture/messages.jsonl AUTH=$fixture/auth.jsonl WANT=$messages python3 - <<'PY'
import base64, collections, json, os
from email import policy
from email.parser import BytesParser
want = int(os.environ["WANT"])
records = [json.loads(line) for line in open(os.environ["MESSAGES"])]
subjects = {str(BytesParser(policy=policy.default).parsebytes(
    base64.b64decode(r["message_b64"]))["Subject"]) for r in records}
assert len(records) == want, f"{len(records)} of {want} messages delivered"
assert subjects == {f"rotation-load-{i}" for i in range(want)}, "missing or duplicate subjects"
attempts = [json.loads(line) for line in open(os.environ["AUTH"])]
results = collections.Counter(a["result"] for a in attempts)
assert set(results) == {"accepted"}, f"AUTH results: {dict(results)}"
assert len(attempts) >= want, f"only {len(attempts)} AUTHs for {want} deliveries"
generations = {a["generation"] for a in attempts}
assert len(generations) >= 10, f"deliveries used only {len(generations)} token generations"
print(f"ok {len(attempts)} AUTHs, all whole valid tokens, across {len(generations)} token generations")
PY
if grep -qE 'status=deferred|\[sasl-xoauth2\] auth failed|SASL authentication failed' "$fixture/relay.log"; then
  grep -E 'status=deferred|\[sasl-xoauth2\] auth failed|SASL authentication failed' "$fixture/relay.log" | head -5 >&2
  echo "a delivery deferred or an authentication failed during rotation" >&2
  exit 1
fi
[[ -z $(docker exec "$relay" postqueue -j) ]]
echo "ok $messages messages from $clients clients delivered with no deferral while the token rotated $rotations times"
