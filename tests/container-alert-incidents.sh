#!/usr/bin/env bash
# Exercise durable incident semantics without Microsoft or an outbound SMTP
# server. Every alert invocation runs in a fresh container against one state
# volume, proving that references and duplicate suppression survive replacement.
# A disposable HTTP receiver captures exact webhook JSON for schema assertions.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
webhook=postfix-m365-relay-alert-test-webhook
network=postfix-m365-relay-alert-test-network
state=postfix-m365-relay-alert-test-state
fixture=$PWD/tests/.tmp-alert-incidents

cleanup() {
  docker rm -f "$webhook" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
: > "$fixture/webhooks.jsonl"
docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker run -d --name "$webhook" --network "$network" --network-alias webhook \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_webhook.py --output /data/webhooks.jsonl >/dev/null
for _attempt in {1..20}; do
  docker logs "$webhook" > "$fixture/webhook-ready.log" 2>&1
  grep -q '^READY ' "$fixture/webhook-ready.log" && break
  sleep 1
done
grep -q '^READY ' "$fixture/webhook-ready.log"

run_alert() {
  docker run --rm --network "$network" --entrypoint /usr/local/libexec/mail-relay/alert.sh \
    -e MAIL_ALERT_WEBHOOK=http://webhook:8080/relay-alert \
    -e MAIL_RELAY_HOSTNAME='Alert Relay [Test]' -e TZ=America/New_York \
    -v "$state":/var/lib/mail-relay "$image" "$@"
}
wait_for_webhooks() {
  local wanted=$1
  for _attempt in {1..20}; do
    [[ $(wc -l < "$fixture/webhooks.jsonl" | tr -d ' ') -ge $wanted ]] && return 0
    sleep 1
  done
  return 1
}

evidence=$'AADSTS900021; Trace ID: safe-trace; Correlation ID: safe-correlation\nBracket [x], quote "x", Unicode Café 🚨; Bearer must-not-leak'
run_alert open error token-health "$evidence" >/dev/null
wait_for_webhooks 1
# A fresh process observes the same open incident and updates its count, but it
# must not page again. This is the container-replacement deduplication proof.
run_alert open error token-health 'same outage, second observation' >/dev/null
sleep 1
[[ $(wc -l < "$fixture/webhooks.jsonl" | tr -d ' ') == 1 ]]
sleep 1
run_alert recover token-health 'A fresh token was minted and its file passed validation' >/dev/null
wait_for_webhooks 2

ALERT_WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
records = [json.loads(line) for line in open(os.environ["ALERT_WEBHOOKS"])]
assert len(records) == 2, records
opened, recovered = records
required = {
    "schema_version", "application", "relay", "status", "severity", "event",
    "reference_id", "first_observed_utc", "observed_utc", "observed_local",
    "timezone", "duration_seconds", "occurrence_count", "summary", "evidence",
    "likely_causes", "remediation", "runbook_url",
}
assert required <= opened.keys(), opened
assert opened["status"] == "open" and recovered["status"] == "recovered"
assert opened["reference_id"] == recovered["reference_id"]
assert opened["timezone"] == recovered["timezone"] == "America/New_York"
assert opened["observed_utc"] != opened["observed_local"]
assert recovered["duration_seconds"] >= 1
assert recovered["occurrence_count"] == 2
assert "safe-correlation" in opened["evidence"]
assert "must-not-leak" not in opened["evidence"]
assert opened["likely_causes"] and opened["remediation"]
assert recovered["recovered_utc"] and recovered["recovered_local"]
PY
echo 'ok incident reference, deduplication, restart persistence, timezone, redaction, and recovery schema'

# There is intentionally no SMTP listener in this one-shot container. Email
# must fail concisely, the independent webhook must still arrive, and the state
# volume must retain only the failed email channel for a later retry.
if docker run --rm --network "$network" --entrypoint /usr/local/libexec/mail-relay/alert.sh \
  -e MAIL_ALERT_WEBHOOK=http://webhook:8080/relay-alert \
  -e MAIL_ADMIN_EMAIL=admin@example.invalid -e MAIL_SEND_MAILBOX=relay@example.invalid \
  -e MAIL_RELAY_HOSTNAME='Alert Relay [Test]' -e TZ=America/New_York \
  -v "$state":/var/lib/mail-relay "$image" open error relay-health \
  'SMTP listener is unavailable' > "$fixture/channel-failure.log" 2>&1; then
  echo 'alert unexpectedly reported complete delivery with its email channel down' >&2
  exit 1
fi
wait_for_webhooks 3
grep -q 'channel=email result=' "$fixture/channel-failure.log"
grep -q 'channel=webhook result=HTTP success' "$fixture/channel-failure.log"
docker run --rm --network none --entrypoint python3 -v "$state":/state "$image" -c \
  'import glob,json; rows=[json.load(open(p)) for p in glob.glob("/state/alerts/outbox/*.json")]; assert len(rows)==1, rows; assert rows[0]["email_pending"] is True; assert rows[0]["webhook_pending"] is False'
echo 'ok failed email did not suppress webhook and only the failed channel remained queued'
