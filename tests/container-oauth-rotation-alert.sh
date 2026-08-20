#!/usr/bin/env bash
# OAuth rotation alert only. Disposable fake tenant, valid static token, and
# local webhook. Hide generated OAuth cert to force supervisor failure, restore
# it, then require same-reference recovery. No Microsoft call.
set -euo pipefail
image=${1:-postfix-m365-relay:test-v2}
relay=postfix-m365-relay-oauth-alert-relay
webhook=postfix-m365-relay-oauth-alert-webhook
network=postfix-m365-relay-oauth-alert-network
state=postfix-m365-relay-oauth-alert-state
spool=postfix-m365-relay-oauth-alert-spool
fixture=$PWD/tests/.tmp-oauth-rotation-alert
cleanup() { docker rm -f "$relay" "$webhook" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true; docker volume rm "$state" "$spool" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-rotation-alert-token","expiry":"%s"}\n' "$expiry" > "$fixture/token.json"
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
  -e MAIL_ROTATION_LOOP_SECONDS=1 -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/token.json":/run/secrets/token.json:ro -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
for _ in {1..40}; do docker exec "$relay" test -s /var/lib/mail-relay/secrets/mail_relay_client_cert.pem && break; sleep 1; done
cert=/var/lib/mail-relay/secrets/mail_relay_client_cert.pem
key=/var/lib/mail-relay/secrets/mail_relay_client_key.pem
docker exec "$relay" test -s "$cert"
docker exec "$relay" mv "$cert" "${cert}.hidden"
for _ in {1..30}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "oauth-rotation-health".*"status": "open"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "oauth-rotation-health".*"status": "open"' "$fixture/webhooks.jsonl"
docker exec "$relay" mv "${cert}.hidden" "$cert"
for _ in {1..30}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "oauth-rotation-health".*"status": "recovered"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "oauth-rotation-health".*"status": "recovered"' "$fixture/webhooks.jsonl"

WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
rows=[json.loads(x) for x in open(os.environ["WEBHOOKS"])]
pair=[r for r in rows if r["event"]=="oauth-rotation-health"]
assert len(pair)==2, pair
assert pair[0]["status"]=="open" and pair[1]["status"]=="recovered", pair
assert pair[0]["reference_id"]==pair[1]["reference_id"]
assert "certificate" in pair[0]["evidence"].lower()
assert pair[1]["duration_seconds"] >= 0
print("ok OAuth rotation failure and same-reference recovery alert")
PY
