#!/usr/bin/env bash
# Real Postfix-to-upstream integration without external traffic. An internal
# Docker network contains the relay, a TLS/XOAUTH2 protocol sink, and clients.
# This proves queue delivery and rewritten wire messages, not Microsoft policy.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-e2e-test
upstream=postfix-m365-relay-e2e-upstream
webhook=postfix-m365-relay-e2e-webhook
network=postfix-m365-relay-e2e-network
state=postfix-m365-relay-e2e-state
spool=postfix-m365-relay-e2e-spool
fixture=$PWD/tests/.tmp-e2e

cleanup() {
  docker rm -f "$relay" "$upstream" "$webhook" >/dev/null 2>&1 || true
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
: > "$fixture/webhooks.jsonl"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-test-token","expiry":"%s","refresh_token":"unused-app-only-flow"}\n' \
  "$expiry" > "$fixture/relay.json"
chmod 0644 "$fixture/relay.json"

docker network create --internal "$network" >/dev/null
docker run -d --name "$upstream" --network "$network" --network-alias upstream \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_xoauth2_smtp.py --cert /data/upstream.crt \
  --key /data/upstream.key --output /data/messages.jsonl >/dev/null
docker run -d --name "$webhook" --network "$network" --network-alias webhook \
  --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
  "$image" /tests/fake_webhook.py --output /data/webhooks.jsonl >/dev/null
for _attempt in {1..20}; do
  docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
  docker logs "$webhook" > "$fixture/webhook-ready.log" 2>&1
  grep -q '^READY ' "$fixture/upstream-ready.log" && \
    grep -q '^READY ' "$fixture/webhook-ready.log" && break
  sleep 1
done
docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
docker logs "$webhook" > "$fixture/webhook-ready.log" 2>&1
grep -q '^READY ' "$fixture/upstream-ready.log"
grep -q '^READY ' "$fixture/webhook-ready.log"

start_relay() {
  local mode=$1 verify_send=$2
  docker rm -f "$relay" >/dev/null 2>&1 || true
  relay_args=(
    -d --name "$relay" --network "$network" --network-alias relay
    -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
    -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
    -e MAIL_SEND_MAILBOX=relay-test@example.invalid
    -e MAIL_SENDER_BRACKETS=brackets@relay.example.local
    -e 'MAIL_SENDER_NAME_BRACKETS=MyServer [TestServer]'
    -e MAIL_SENDER_DOLLAR=dollar@relay.example.local
    -e 'MAIL_SENDER_NAME_DOLLAR=Price $5 / $1 / ${HOME}'
    -e MAIL_ADMIN_EMAIL=admin@example.invalid
    -e MAIL_ALERT_WEBHOOK=http://webhook:8080/relay-alert
    -e MAIL_UPSTREAM_HOST=upstream -e MAIL_UPSTREAM_PORT=1587
    -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/upstream-ca.crt
    -e MAIL_TOKEN_FILE=/run/secrets/relay.json
    -e MAIL_INBOUND_AUTH=ip -e "MAIL_SENDER_MODE=$mode"
    -e MAIL_SENDER_ALLOWLIST=on
    -e "MAIL_VERIFY_SEND=$verify_send" -e MAIL_VERIFY_DELIVERY_WAIT_SECONDS=20
    -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300
    -v "$fixture/relay.json":/run/secrets/relay.json:ro
    -v "$fixture/upstream.crt":/run/secrets/upstream-ca.crt:ro
    -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix
    --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750
  )
  if [[ $mode == passthrough ]]; then
    relay_args+=(
      -e MAIL_SENDER_ALIAS=alias@example.invalid
      -e 'MAIL_SENDER_NAME_ALIAS=Alias [Test]'
      -e MAIL_PASSTHROUGH_SENDERS=alias@example.invalid
    )
  fi
  docker run "${relay_args[@]}" "$image" >/dev/null
  for _attempt in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || {
      docker logs "$relay"; return 1;
    }
    docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$relay"
  return 1
}

send_message() {
  docker run --rm --network "$network" --entrypoint python3 \
    -v "$PWD":/workspace:ro "$image" /workspace/scripts/qualify-relay.py \
    --host relay --from-address "$1" --from-name "$2" --to recipient@example.invalid \
    --subject "$3"
}

wait_for_messages() {
  local wanted=$1
  for _attempt in {1..40}; do
    count=$(wc -l < "$fixture/messages.jsonl" | tr -d ' ')
    (( count >= wanted )) && return 0
    sleep 1
  done
  docker logs "$relay"
  docker logs "$upstream"
  return 1
}

wait_for_webhooks() {
  local wanted=$1
  for _attempt in {1..30}; do
    count=$(wc -l < "$fixture/webhooks.jsonl" | tr -d ' ')
    (( count >= wanted )) && return 0
    sleep 1
  done
  docker logs "$webhook"
  return 1
}

start_relay collapse no
send_message brackets@relay.example.local 'client supplied name' e2e-brackets
send_message dollar@relay.example.local 'another client name' e2e-dollar
wait_for_messages 2
docker run --rm --network "$network" --entrypoint python3 \
  -v "$PWD/tests":/tests:ro "$image" /tests/smtp-policy-client.py relay \
  --sender unauthorized@relay.example.local --expect sender-reject

E2E_MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import base64, json, os
from email import policy
from email.parser import BytesParser

records = [json.loads(line) for line in open(os.environ["E2E_MESSAGES"])]
assert len(records) == 2, records
expected = {
    "e2e-brackets": "MyServer [TestServer]",
    "e2e-dollar": "Price $5 / $1 / ${HOME}",
}
for record in records:
    message = BytesParser(policy=policy.default).parsebytes(base64.b64decode(record["message_b64"]))
    assert record["tls"] is True
    assert record["authenticated_user"] == "relay-test@example.invalid"
    assert record["mail_from"] == "relay-test@example.invalid"
    assert message["From"].addresses[0].addr_spec == "relay-test@example.invalid"
    assert message["From"].addresses[0].display_name == expected[str(message["Subject"])]
PY
echo 'ok real Postfix TLS/XOAUTH2 delivery preserves exact bracket and dollar display names'
# Save before searching. `docker logs | grep -q` can make the Docker client exit
# with SIGPIPE after grep finds an early match; under pipefail that reported 141
# even though both messages had already reached the verified test endpoint.
docker logs "$relay" > "$fixture/relay-secure.log" 2>&1
grep -q 'Verified TLS connection established to upstream' "$fixture/relay-secure.log"
[[ $(docker exec "$relay" postconf -h smtp_tls_security_level) == secure ]]
echo 'ok outbound TLS verifies the trusted upstream identity under secure default'

# alert.sh submits through the same queue and must also reach the sink.
docker exec "$relay" /usr/local/libexec/mail-relay/alert.sh notify info qualification \
  'Alert JSON/email characters: [test] $5 "quoted"' >/dev/null
wait_for_messages 3
wait_for_webhooks 1
E2E_WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
records = [json.loads(line) for line in open(os.environ["E2E_WEBHOOKS"])]
notice = records[-1]
assert notice["schema_version"] == 1
assert notice["status"] == "notification"
assert notice["severity"] == "info"
assert notice["event"] == "qualification"
assert notice["evidence"] == 'Alert JSON/email characters: [test] $5 "quoted"'
assert notice["reference_id"].startswith("PMR-")
assert notice["likely_causes"] and notice["remediation"]
PY
echo 'ok email and escaped-JSON webhook notifications delivered'

# Induce a real verifier failure by pointing only this invocation at a missing
# token. The running relay remains healthy. Both notification channels must
# carry the failure, proving alerts are wired to a failure path rather than only
# to a direct alert.sh smoke call.
if docker exec -e MAIL_TOKEN_FILE=/run/secrets/intentionally-missing \
  -e MAIL_VERIFY_SEND=no "$relay" /usr/local/libexec/mail-relay/verify-relay.sh \
  > "$fixture/expected-verify-failure.log" 2>&1; then
  echo 'verifier accepted an intentionally missing token' >&2
  exit 1
fi
wait_for_messages 4
wait_for_webhooks 2
# A second observation of the same fault updates durable occurrence state but
# sends neither a second email nor a second webhook.
if docker exec -e MAIL_TOKEN_FILE=/run/secrets/intentionally-missing \
  -e MAIL_VERIFY_SEND=no "$relay" /usr/local/libexec/mail-relay/verify-relay.sh \
  > "$fixture/expected-verify-duplicate.log" 2>&1; then
  echo 'verifier accepted an intentionally missing token on duplicate pass' >&2
  exit 1
fi
sleep 1
[[ $(wc -l < "$fixture/messages.jsonl" | tr -d ' ') == 4 ]]
[[ $(wc -l < "$fixture/webhooks.jsonl" | tr -d ' ') == 2 ]]

# The documented wrapper reloads file configuration for this exec session. A
# healthy token check clears the same incident and emits one correlated recovery.
docker exec "$relay" relay-admin verify > "$fixture/verify-recovered.log" 2>&1
wait_for_messages 5
wait_for_webhooks 3
E2E_WEBHOOKS=$fixture/webhooks.jsonl python3 - <<'PY'
import json, os
records = [json.loads(line) for line in open(os.environ["E2E_WEBHOOKS"])]
opened, recovered = records[-2:]
assert opened["severity"] == "error"
assert opened["event"] == recovered["event"] == "token-health"
assert opened["status"] == "open" and recovered["status"] == "recovered"
assert opened["reference_id"] == recovered["reference_id"]
assert opened["occurrence_count"] == 1
assert recovered["occurrence_count"] == 2
assert "token file is absent" in opened["evidence"]
assert "token valid for" in recovered["evidence"]
PY
E2E_MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import base64, json, os
from email import policy
from email.parser import BytesParser
records = [json.loads(line) for line in open(os.environ["E2E_MESSAGES"])]
alerts = []
for record in records:
    message = BytesParser(policy=policy.default).parsebytes(base64.b64decode(record["message_b64"]))
    if "token-health" in str(message["Subject"]):
        alerts.append(message)
assert len(alerts) == 2, [str(m["Subject"]) for m in alerts]
assert " open:" in str(alerts[0]["Subject"])
assert " recovered:" in str(alerts[1]["Subject"])
opened_body, recovered_body = alerts[0].get_content(), alerts[1].get_content()
for label in ("Reference:", "First observed (UTC):", "Observed (local):", "Duration:", "Likely causes", "Suggested actions", "Runbook"):
    assert label in opened_body, label
open_reference = next(line for line in opened_body.splitlines() if line.startswith("Reference:"))
assert open_reference in recovered_body
PY
echo 'ok verifier incident delivered exact email/webhook schema, suppressed duplicate, and correlated recovery'

# Passthrough remains an Entra must-test, but the local recurring probe can be
# proven against the protocol sink: it must correlate its own queue ID to sent,
# and the wire envelope/header for the alias must remain the alias.
: > "$fixture/messages.jsonl"
start_relay passthrough yes
for _attempt in {1..50}; do
  docker logs "$relay" > "$fixture/relay-alias.log" 2>&1
  grep -q 'alias verified by upstream delivery: alias@example.invalid' "$fixture/relay-alias.log" && break
  sleep 1
done
docker logs "$relay" > "$fixture/relay-alias.log" 2>&1
grep -q 'alias verified by upstream delivery: alias@example.invalid' "$fixture/relay-alias.log"
wait_for_messages 2
E2E_MESSAGES=$fixture/messages.jsonl python3 - <<'PY'
import base64, json, os
from email import policy
from email.parser import BytesParser

records = [json.loads(line) for line in open(os.environ["E2E_MESSAGES"])]
aliases = []
for record in records:
    message = BytesParser(policy=policy.default).parsebytes(base64.b64decode(record["message_b64"]))
    if record["mail_from"] == "alias@example.invalid":
        aliases.append((record, message))
assert aliases, records
record, message = aliases[-1]
assert record["tls"] is True
assert message["From"].addresses[0].addr_spec == "alias@example.invalid"
PY
echo 'ok recurring alias probe correlates status=sent and preserves local passthrough identity'
