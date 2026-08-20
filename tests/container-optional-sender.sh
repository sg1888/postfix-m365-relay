#!/usr/bin/env bash
# Named senders are optional. With none configured the relay must still boot and
# render a valid Postfix configuration that collapses every message to the
# licensed mailbox while preserving the display name the sending application
# supplied. This also proves the MAIL_SENDER_ALLOWLIST knob: off (default)
# accepts any envelope sender from an authorized client; on rejects any envelope
# From that is neither the mailbox nor a configured MAIL_SENDER_* address.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
container=postfix-m365-relay-optional-sender-test
state=postfix-m365-relay-optional-sender-state
spool=postfix-m365-relay-optional-sender-spool
mailbox=relay-test@example.invalid

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

wait_rendered() {
  for _ in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; return 1; }
    docker exec "$container" grep -q '^# <<< postfix-m365-relay (managed) <<<$' \
      /etc/postfix/main.cf >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$container"; return 1
}

# --- No senders at all, default allowlist (off) ------------------------------
docker run -d --name "$container" --network none \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX="$mailbox" \
  -e 'MAIL_SENDER_NAME_FALLBACK=Fallback Name' \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
wait_rendered
echo 'ok relay boots and renders a valid configuration with no MAIL_SENDER_* set'

# Envelope collapse applies to any sender.
collapsed=$(docker exec "$container" postmap -q 'anything@somewhere.example' \
  regexp:/etc/postfix/sender_canonical)
[[ $collapsed == "$mailbox" ]] || { echo "FAILED collapse: $collapsed" >&2; exit 1; }
echo 'ok every envelope sender collapses to the licensed mailbox'

# A From header with a display name keeps that name; only the address is rewritten.
named=$(docker exec "$container" postmap -q 'From: Cool App <svc@internal.example>' \
  regexp:/etc/postfix/header_checks)
[[ $named == "REPLACE From: Cool App <$mailbox>" ]] || { echo "FAILED named From: $named" >&2; exit 1; }
echo 'ok app-supplied display name is preserved when no sender is configured'

# A bare-address From (no display name) receives the configured fallback name.
bare=$(docker exec "$container" postmap -q 'From: svc@internal.example' \
  regexp:/etc/postfix/header_checks)
[[ $bare == "REPLACE From: \"Fallback Name\" <$mailbox>" ]] || { echo "FAILED bare From: $bare" >&2; exit 1; }
echo 'ok bare-address From falls back to MAIL_SENDER_NAME_FALLBACK'

# Default allowlist off: envelope-From admission is permissive.
restr=$(docker exec "$container" postconf -h smtpd_sender_restrictions)
[[ $restr == permit ]] || { echo "FAILED default sender restriction: $restr" >&2; exit 1; }
echo 'ok default MAIL_SENDER_ALLOWLIST=off admits any sender (permit)'

docker rm -f "$container" >/dev/null
docker volume rm "$state" "$spool" >/dev/null 2>&1 || true

# --- Strict allowlist on ------------------------------------------------------
docker run -d --name "$container" --network none \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX="$mailbox" \
  -e MAIL_SENDER_ALLOWLIST=on \
  -e MAIL_SENDER_APP=app@relay.example.local \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
wait_rendered

restr_on=$(docker exec "$container" postconf -h smtpd_sender_restrictions)
[[ $restr_on == 'check_sender_access texthash:/etc/postfix/sender_access, reject' ]] || {
  echo "FAILED strict sender restriction: $restr_on" >&2; exit 1; }
# The mailbox and the one configured sender are admitted; an unlisted sender is not.
[[ $(docker exec "$container" postmap -q "$mailbox" texthash:/etc/postfix/sender_access) == OK ]]
[[ $(docker exec "$container" postmap -q app@relay.example.local texthash:/etc/postfix/sender_access) == OK ]]
if docker exec "$container" postmap -q stranger@nowhere.example texthash:/etc/postfix/sender_access >/dev/null; then
  echo 'FAILED: unlisted sender is present in the allowlist' >&2; exit 1
fi
echo 'ok MAIL_SENDER_ALLOWLIST=on restricts envelope senders to the allowlist'

echo 'ok optional-sender and sender-allowlist matrix'
