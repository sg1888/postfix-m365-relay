#!/usr/bin/env bash
# Invalid passthrough alias alert. Local sender rejection is intentional: this
# proves verifier alerting without changing Entra alias settings.
set -euo pipefail
image=${1:-postfix-m365-relay:test-v2}
relay=postfix-m365-relay-invalid-alias-relay
webhook=postfix-m365-relay-invalid-alias-webhook
network=postfix-m365-relay-invalid-alias-network
state=postfix-m365-relay-invalid-alias-state
spool=postfix-m365-relay-invalid-alias-spool
fixture=$PWD/tests/.tmp-invalid-alias-alert
cleanup() { docker rm -f "$relay" "$webhook" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true; docker volume rm "$state" "$spool" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-invalid-alias-token","expiry":"%s"}\n' "$expiry" > "$fixture/token.json"
docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null
docker run -d --name "$webhook" --network "$network" --network-alias webhook --entrypoint python3 \
  -v "$PWD/tests":/tests:ro -v "$fixture":/data "$image" /tests/fake_webhook.py --output /data/webhooks.jsonl >/dev/null
for _ in {1..20}; do docker logs "$webhook" > "$fixture/webhook.log" 2>&1; grep -q '^READY ' "$fixture/webhook.log" && break; sleep 1; done
docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid -e MAIL_SENDER_TEST=test@relay.example.local \
  -e MAIL_ADMIN_EMAIL=admin@example.invalid -e MAIL_VERIFY_SEND=no -e MAIL_ALERT_WEBHOOK=http://webhook:8080/relay-alert \
  -e MAIL_TOKEN_FILE=/run/secrets/token.json -e MAIL_INBOUND_AUTH=ip -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/token.json":/run/secrets/token.json:ro -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
for _ in {1..40}; do docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break; sleep 1; done
docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1
verify() { docker exec "$relay" env "$@" /usr/local/libexec/mail-relay/verify-relay.sh >/dev/null 2>&1 || true; }
verify MAIL_SENDER_MODE=passthrough MAIL_PASSTHROUGH_SENDERS=invalid-alias@example.invalid
for _ in {1..20}; do [[ -f $fixture/webhooks.jsonl ]] && grep -q '"event": "alias-health".*"status": "open"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "alias-health".*"status": "open"' "$fixture/webhooks.jsonl"
verify MAIL_SENDER_MODE=collapse MAIL_PASSTHROUGH_SENDERS=
for _ in {1..20}; do grep -q '"event": "alias-health".*"status": "recovered"' "$fixture/webhooks.jsonl" && break; sleep 1; done
grep -q '"event": "alias-health".*"status": "recovered"' "$fixture/webhooks.jsonl"

WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
rows=[r for r in map(json.loads,open(os.environ["WEBHOOKS"])) if r["event"]=="alias-health"]
assert len(rows)==2, rows
assert rows[0]["status"]=="open" and rows[1]["status"]=="recovered"
assert rows[0]["reference_id"]==rows[1]["reference_id"]
assert "invalid-alias@example.invalid" in rows[0]["evidence"]
print("ok invalid passthrough alias alert and same-reference recovery")
PY
