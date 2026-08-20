#!/usr/bin/env bash
# Managed inbound-TLS rotation alert. Disposable relay generates its own pair;
# short certificate plus hidden key forces failure, key restore proves renewal
# and same-incident recovery. No Microsoft or Exchange mutation.
set -euo pipefail
image=${1:-postfix-m365-relay:test-v2}
relay=postfix-m365-relay-inbound-alert-relay
webhook=postfix-m365-relay-inbound-alert-webhook
network=postfix-m365-relay-inbound-alert-network
state=postfix-m365-relay-inbound-alert-state
spool=postfix-m365-relay-inbound-alert-spool
fixture=$PWD/tests/.tmp-inbound-tls-alert
cleanup() { docker rm -f "$relay" "$webhook" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true; docker volume rm "$state" "$spool" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-inbound-alert-token","expiry":"%s"}\n' "$expiry" > "$fixture/token.json"
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
  -e MAIL_TOKEN_FILE=/run/secrets/token.json -e MAIL_INBOUND_AUTH=ip -e MAIL_INBOUND_TLS=may \
  -e MAIL_INBOUND_TLS_VALIDITY_DAYS=2 -e MAIL_INBOUND_TLS_RENEW_AT_DAYS=1 \
  -e MAIL_ROTATION_LOOP_SECONDS=1 -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/token.json":/run/secrets/token.json:ro -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
cert=/var/lib/mail-relay/inbound-tls/cert.pem
key=/var/lib/mail-relay/inbound-tls/key.pem
for _ in {1..40}; do docker exec "$relay" test -s "$cert" -a -s "$key" && break; sleep 1; done
docker exec "$relay" test -s "$cert" -a -s "$key"
docker exec "$relay" openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=short-inbound \
  -keyout /tmp/short.key -out /tmp/short.crt >/dev/null 2>&1
docker exec "$relay" mv /tmp/short.crt "$cert"
docker exec "$relay" mv "$key" "${key}.hidden"
for _ in {1..30}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "inbound-tls-health".*"status": "open"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "inbound-tls-health".*"status": "open"' "$fixture/webhooks.jsonl"
docker exec "$relay" mv "${key}.hidden" "$key"
for _ in {1..40}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "inbound-tls-health".*"status": "recovered"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "inbound-tls-health".*"status": "recovered"' "$fixture/webhooks.jsonl"
for _ in {1..40}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "inbound-tls-rotated".*"status": "notification"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "inbound-tls-rotated".*"status": "notification"' "$fixture/webhooks.jsonl"

WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
rows=[json.loads(x) for x in open(os.environ["WEBHOOKS"])]
health=[r for r in rows if r["event"]=="inbound-tls-health"]
renewed=[r for r in rows if r["event"]=="inbound-tls-rotated"]
assert len(health)==2, health
assert health[0]["status"]=="open" and health[1]["status"]=="recovered"
assert health[0]["reference_id"]==health[1]["reference_id"]
assert len(renewed)==1 and renewed[0]["status"]=="notification"
print("ok managed inbound-TLS rotation failure, success, recovery, and notification")
PY
