#!/usr/bin/env bash
# Prove the administrator-facing SASL lifecycle for both supported sources:
# /config/secrets/smtpd_users (simple bind-mounted install) and an explicit
# /run/secrets path (Docker secret pattern). sasldb2 is rebuilt in tmpfs at each
# restart, so deleting a source line must revoke that account completely.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-sasl-lifecycle-test
network=postfix-m365-relay-sasl-lifecycle-network
state=postfix-m365-relay-sasl-lifecycle-state
spool=postfix-m365-relay-sasl-lifecycle-spool
fixture=$PWD/tests/.tmp-sasl-lifecycle

cleanup() {
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture/config/secrets"
cat > "$fixture/config/mail-relay.conf" <<'EOF'
MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
MAIL_SEND_MAILBOX=relay-test@example.invalid
MAIL_SENDER_APP=app@relay.example.local
MAIL_INBOUND_AUTH=smtp-auth
MAIL_INBOUND_TLS=may
MAIL_VERIFY_SEND=no
MAIL_TOKEN_ALERT_AFTER=99
MAIL_TOKEN_LOOP_SECONDS=300
MAIL_ROTATION_LOOP_SECONDS=300
MAIL_VERIFY_LOOP_SECONDS=300
EOF
printf '%s\n' 'printer:printer-old-password' 'scanner:scanner-password' \
  > "$fixture/config/secrets/smtpd_users"
chmod 0600 "$fixture/config/mail-relay.conf" "$fixture/config/secrets/smtpd_users"
docker network create --internal "$network" >/dev/null

start() {
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker run -d --name "$relay" --network "$network" --network-alias relay \
    -v "$fixture/config":/config \
    -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
    --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$@" "$image" >/dev/null
  for _attempt in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || {
      docker logs "$relay"; return 1;
    }
    docker exec "$relay" postfix status >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$relay"; return 1
}

client() {
  docker run --rm --network "$network" --entrypoint python3 \
    -v "$PWD/tests":/tests:ro "$image" /tests/smtp-policy-client.py relay "$@"
}

start
users=$(docker exec "$relay" relay-users list)
[[ $users == *printer* && $users == *scanner* ]]
client --username printer --password printer-old-password --expect accept
client --username scanner --password scanner-password --expect accept

# One edit changes printer's password and removes scanner. Restart terminates
# old authenticated sessions and creates a new database solely from this file.
printf '%s\n' 'printer:printer-new-password' > "$fixture/config/secrets/smtpd_users"
chmod 0600 "$fixture/config/secrets/smtpd_users"
docker restart "$relay" >/dev/null
for _attempt in {1..40}; do
  docker exec "$relay" postfix status >/dev/null 2>&1 && break
  sleep 1
done
users=$(docker exec "$relay" relay-users list)
[[ $users == *printer* && $users != *scanner* ]]
client --username printer --password printer-old-password --expect auth-reject
client --username printer --password printer-new-password --expect accept
client --username scanner --password scanner-password --expect auth-reject
echo 'ok mounted credential file adds, changes, lists, and revokes SASL users after restart'

# Docker Compose secrets are mounted at /run/secrets. Pointing the config at an
# explicit path must behave identically; the image never assumes where the
# orchestrator sourced or encrypted that file.
printf '%s\n' 'docker-secret-user:docker-secret-password' > "$fixture/docker-secret-users"
chmod 0600 "$fixture/docker-secret-users"
printf '\nMAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users\n' \
  >> "$fixture/config/mail-relay.conf"
start -v "$fixture/docker-secret-users":/run/secrets/smtpd_users:ro
users=$(docker exec "$relay" relay-users list)
[[ $users == *docker-secret-user* && $users != *printer* ]]
client --username docker-secret-user --password docker-secret-password --expect accept
echo 'ok explicit Docker-secret path builds the same ephemeral sasldb2'

# An empty authority is a configuration error, not "allow anyone" and not an
# invisible reuse of the previous database.
: > "$fixture/docker-secret-users"
docker rm -f "$relay" >/dev/null
if docker run --rm --name "$relay" --network "$network" \
  -v "$fixture/config":/config \
  -v "$fixture/docker-secret-users":/run/secrets/smtpd_users:ro \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:mode=0750 "$image" > "$fixture/empty.log" 2>&1; then
  echo 'empty SASL source unexpectedly started the relay' >&2
  exit 1
fi
grep -q 'contains no device credentials' "$fixture/empty.log"
echo 'ok empty credential authority is refused instead of retaining old access'
