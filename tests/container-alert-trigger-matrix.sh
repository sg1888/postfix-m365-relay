#!/usr/bin/env bash
# Focused automatic-trigger matrix. Uses one disposable relay and webhook;
# each verifier fault is opened, repeated, then cleared. No Microsoft access.
set -euo pipefail
image=${1:-postfix-m365-relay:test-v2}
relay=postfix-m365-relay-alert-trigger-relay
webhook=postfix-m365-relay-alert-trigger-webhook
network=postfix-m365-relay-alert-trigger-network
state=postfix-m365-relay-alert-trigger-state
spool=postfix-m365-relay-alert-trigger-spool
fixture=$PWD/tests/.tmp-alert-trigger
cleanup() { docker rm -f "$relay" "$webhook" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true; docker volume rm "$state" "$spool" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
report_failure() {
  rc=$?
  if (( rc != 0 )); then
    echo "automatic alert trigger matrix failed; webhook capture:" >&2
    [[ -f $fixture/webhooks.jsonl ]] && tail -n 20 "$fixture/webhooks.jsonl" >&2 || true
    echo "automatic alert trigger matrix relay log:" >&2
    docker logs "$relay" >&2 2>&1 || true
  fi
  cleanup
  exit "$rc"
}
trap report_failure EXIT
cleanup
install -d -m 0700 "$fixture"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-trigger-token","expiry":"%s"}\n' "$expiry" > "$fixture/token.json"
docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null
docker run -d --name "$webhook" --network "$network" --network-alias webhook --entrypoint python3 \
  -v "$PWD/tests":/tests:ro -v "$fixture":/data "$image" /tests/fake_webhook.py --output /data/webhooks.jsonl >/dev/null
for _ in {1..20}; do docker logs "$webhook" > "$fixture/webhook.log" 2>&1; grep -q '^READY ' "$fixture/webhook.log" && break; sleep 1; done
docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid -e MAIL_SENDER_TEST=test@relay.example.local \
  -e MAIL_ADMIN_EMAIL= -e MAIL_VERIFY_SEND=no -e MAIL_ALERT_WEBHOOK=http://webhook:8080/relay-alert \
  -e MAIL_TOKEN_FILE=/run/secrets/token.json -e MAIL_INBOUND_AUTH=ip \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/token.json":/run/secrets/token.json:ro -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
for _ in {1..40}; do docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break; sleep 1; done
docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1

# The production supervisor intentionally starts its token and verification
# loops immediately, and both send a token-health "recovered" on every healthy
# pass. This test invokes the verifier itself to make one fault at a time, so
# pause those background groups before injecting faults. Without that
# isolation a healthy background recovery can land between the deliberate open
# and the duplicate-suppression assertion, producing a CI timing failure that
# says nothing about the alert implementation.
#
# Order matters: wait for the first background verify pass to finish before
# stopping, so both loops are provably inside their 300-second sleep and
# cannot be frozen mid-pass while holding the alert state lock.
for _ in {1..30}; do
  docker logs "$relay" 2>&1 | grep -q 'verify-relay:' && break; sleep 1
done
docker logs "$relay" 2>&1 | grep -q 'verify-relay:'
for role in token verify; do
  role_pid=$(docker exec "$relay" cat "/run/mail-relay/supervisor/$role.pid")
  docker exec "$relay" kill -STOP -- "-$role_pid"
done
# Fail fast with a clear message if a frozen process somehow still holds the
# alert lock; otherwise every later alert call would hang until the job times
# out with no explanation.
docker exec "$relay" python3 -c '
import fcntl, signal
signal.alarm(10)
fcntl.flock(open("/var/lib/mail-relay/alerts/.lock", "a+"), fcntl.LOCK_EX)
' || { echo "alert state lock is wedged after pausing supervisor loops" >&2; exit 1; }

# Keep the known-good fixture token explicit on every exec.  `docker exec`
# inherits the container's original environment, but the entrypoint may load a
# generated config between checks; making this path explicit prevents a later
# fault injection (for example MAIL_RELAY_CERT_FILE=missing) from accidentally
# turning the token check into a second, unrelated "token absent" incident.
verify() { docker exec "$relay" env MAIL_TOKEN_FILE=/run/secrets/token.json "$@" /usr/local/libexec/mail-relay/verify-relay.sh >/dev/null 2>&1 || true; }
event_seen() { EVENT=$1 STATUS=$2 FILE=$fixture/webhooks.jsonl python3 -c 'import json,os; assert any((d.get("event"),d.get("status"))==(os.environ["EVENT"],os.environ["STATUS"]) for d in map(json.loads,open(os.environ["FILE"])))'; }
wait_event() {
  for _ in {1..20}; do event_seen "$1" "$2" && return; sleep 1; done
  echo "timed out waiting for event=$1 status=$2" >&2
  return 1
}
# Recovery notifications are expected, so duplicate suppression is measured
# only among open incidents for the requested event.
open_event_lines() { EVENT=$1 FILE=$fixture/webhooks.jsonl python3 -c 'import json,os; print(sum(d.get("event")==os.environ["EVENT"] and d.get("status")=="open" for d in map(json.loads, open(os.environ["FILE"]))))'; }

# Token, OAuth certificate, CA age, queue, SASL, inbound TLS, push monitor,
# and listener categories. Each row opens, suppresses duplicate, then clears.
verify MAIL_TOKEN_FILE=/run/secrets/missing
wait_event token-health open; verify MAIL_TOKEN_FILE=/run/secrets/missing; sleep 1; [[ $(open_event_lines token-health) == 1 ]]
verify; wait_event token-health recovered
verify MAIL_RELAY_CERT_FILE=/run/secrets/missing-cert
wait_event oauth-certificate-health open; verify MAIL_RELAY_CERT_FILE=/run/secrets/missing-cert; sleep 1; [[ $(open_event_lines oauth-certificate-health) == 1 ]]
verify; wait_event oauth-certificate-health recovered
verify MAIL_CA_BUNDLE_MAX_AGE_DAYS=0
wait_event ca-bundle-age open; verify MAIL_CA_BUNDLE_MAX_AGE_DAYS=0; sleep 1; [[ $(open_event_lines ca-bundle-age) == 1 ]]
verify MAIL_CA_BUNDLE_MAX_AGE_DAYS=99999; wait_event ca-bundle-age recovered
docker exec "$relay" touch /var/spool/postfix/deferred/alert-trigger-test
verify MAIL_QUEUE_WARN_DEPTH=0; wait_event queue-depth-health open
docker exec "$relay" rm -f /var/spool/postfix/deferred/alert-trigger-test
verify MAIL_QUEUE_WARN_DEPTH=99999; wait_event queue-depth-health recovered
for _ in {1..11}; do docker exec "$relay" bash -c 'echo "warning: SASL authentication failed" >> /var/log/mail-relay/postfix.log'; done
verify MAIL_SASL_FAILURE_WARN_COUNT=10; wait_event sasl-auth-health open
docker exec "$relay" truncate -s 0 /var/log/mail-relay/postfix.log
verify MAIL_SASL_FAILURE_WARN_COUNT=99999; wait_event sasl-auth-health recovered
docker exec "$relay" openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=short \
  -keyout /tmp/short.key -out /tmp/short.crt >/dev/null 2>&1
verify MAIL_INBOUND_TLS=may MAIL_INBOUND_TLS_CERT_EFFECTIVE=/tmp/short.crt; wait_event inbound-tls-expiring open
verify; wait_event inbound-tls-expiring recovered
docker exec "$relay" mkdir -p /run/secrets; docker exec "$relay" sh -c 'printf token > /run/secrets/push_token_relay'
verify MAIL_RELAY_PUSH_BASE=http://missing-push:9; wait_event push-monitor-health open
docker exec "$relay" rm -f /run/secrets/push_token_relay
verify; wait_event push-monitor-health recovered
verify RELAY_PORT=2999; wait_event relay-health open
verify; wait_event relay-health recovered

WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
rows=[json.loads(x) for x in open(os.environ["WEBHOOKS"])]
events=["token-health","oauth-certificate-health","ca-bundle-age","queue-depth-health","sasl-auth-health","inbound-tls-expiring","push-monitor-health","relay-health"]
for event in events:
    pair=[r for r in rows if r["event"]==event]
    opens=[r for r in pair if r["status"]=="open"]
    recovers=[r for r in pair if r["status"]=="recovered"]
    assert opens and recovers, (event, pair)
    assert any(o["reference_id"]==r["reference_id"] for o in opens for r in recovers), event
print("ok automatic trigger matrix:", ", ".join(events))
PY
