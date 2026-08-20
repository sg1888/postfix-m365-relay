#!/usr/bin/env bash
# Exercise the novice first-run contract without environment configuration. An
# empty host directory must receive a restrictive template, the container must
# wait without accepting mail, and editing that same persistent file must start
# the relay automatically. The parser is also attacked with shell syntax and a
# process-control variable to prove the file is data rather than executable code.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
container=postfix-m365-relay-first-run-test
state=postfix-m365-relay-first-run-state
spool=postfix-m365-relay-first-run-spool
fixture=$PWD/tests/.tmp-first-run

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture/config"

start() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run -d --name "$container" --network none "$@" \
    -v "$fixture/config":/config \
    -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
    --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
}

start
for _attempt in {1..20}; do
  [[ -f $fixture/config/mail-relay.conf ]] && break
  sleep 1
done
[[ -f $fixture/config/mail-relay.conf ]]
[[ $(docker exec "$container" stat -c %a /config/mail-relay.conf) == 600 ]]
docker logs "$container" > "$fixture/setup.log" 2>&1
grep -q 'SETUP REQUIRED' "$fixture/setup.log"
if docker exec "$container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1; then
  echo 'setup-mode container accepted SMTP before required configuration' >&2
  exit 1
fi

# Overwrite the generated template as an administrator would edit it. The
# display name contains command substitution syntax and dollar captures that
# previously broke shell/regexp implementations. No marker may be created.
cat > "$fixture/config/mail-relay.conf" <<'EOF'
MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
MAIL_SEND_MAILBOX=file-mailbox@example.invalid
MAIL_SENDER_APP=app@relay.example.local
MAIL_SENDER_NAME_APP=$(touch /config/PWNED) $5 [Config Test]
MAIL_INBOUND_AUTH=ip
MAIL_VERIFY_SEND=no
MAIL_TOKEN_ALERT_AFTER=99
MAIL_TOKEN_LOOP_SECONDS=300
MAIL_ROTATION_LOOP_SECONDS=300
MAIL_VERIFY_LOOP_SECONDS=300
TZ=UTC
EOF
chmod 0600 "$fixture/config/mail-relay.conf"

for _attempt in {1..50}; do
  docker exec "$container" postfix status >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$container" postfix status >/dev/null
[[ ! -e $fixture/config/PWNED ]]
rendered=$(docker exec "$container" postmap -q 'From: app@relay.example.local' \
  regexp:/etc/postfix/header_checks)
[[ $rendered == *'$(touch /config/PWNED) $5 [Config Test]'* ]]
echo 'ok first run generated a 0600 config, waited safely, and loaded literal special characters'

# The host file survives forced replacement. An explicit Docker environment
# value must override only its matching file value while all other file values
# continue to load.
checksum_before=$(openssl dgst -sha256 "$fixture/config/mail-relay.conf")
start -e MAIL_SEND_MAILBOX=environment-override@example.invalid
for _attempt in {1..40}; do
  docker exec "$container" postfix status >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$container" postfix status >/dev/null
target=$(docker exec "$container" postmap -q app@relay.example.local \
  regexp:/etc/postfix/sender_canonical)
[[ $target == environment-override@example.invalid ]]
[[ $(openssl dgst -sha256 "$fixture/config/mail-relay.conf") == "$checksum_before" ]]
echo 'ok persistent config survived replacement and explicit environment won without rewriting the file'

# Process-control names are forbidden even though the line is syntactically a
# normal assignment. This closes a less obvious injection path than `source`:
# accepting PATH or BASH_ENV could change which programs trusted scripts run.
printf '\nPATH=/tmp/attacker\n' >> "$fixture/config/mail-relay.conf"
docker rm -f "$container" >/dev/null
if docker run --rm --name "$container" --network none \
  -v "$fixture/config":/config -v "$state":/var/lib/mail-relay \
  -v "$spool":/var/spool/postfix --tmpfs /run/mail-relay:mode=0750 \
  "$image" > "$fixture/forbidden.log" 2>&1; then
  echo 'configuration parser accepted forbidden PATH assignment' >&2
  exit 1
fi
grep -q 'may set only MAIL_\*, POSTFIX_\*, TZ, or RELAY_PORT' "$fixture/forbidden.log"
echo 'ok persistent configuration refuses process-control variables'
