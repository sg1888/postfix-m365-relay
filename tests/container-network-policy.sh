#!/usr/bin/env bash
# Prove Postfix's AND/OR policy semantics from genuinely different source
# networks. Both networks are internal: fake tenant IDs and test messages can
# never escape to Microsoft or any other external service.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-network-policy-test
trusted=postfix-m365-relay-test-trusted
untrusted=postfix-m365-relay-test-untrusted
state=postfix-m365-relay-network-policy-state
spool=postfix-m365-relay-network-policy-spool
fixture=$PWD/tests/.tmp-network-policy

cleanup() {
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker network rm "$trusted" "$untrusted" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
printf '%s\n' 'device:correct-password' > "$fixture/smtpd_users"
chmod 0600 "$fixture/smtpd_users"
docker network create --internal --subnet 172.31.250.0/24 "$trusted" >/dev/null
docker network create --internal --subnet 172.31.251.0/24 "$untrusted" >/dev/null

start_relay() {
  local policy=$1
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker run -d --name "$relay" --hostname relay --network "$trusted" --ip 172.31.250.10 \
    --network-alias relay \
    -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
    -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
    -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
    -e MAIL_SENDER_APP=app@relay.example.local \
    -e MAIL_SENDER_ALLOWLIST=on \
    -e "MAIL_INBOUND_AUTH=$policy" -e MAIL_SUBNET=172.31.250.0/24 \
    -e MAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users \
    -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
    -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
    -v "$fixture/smtpd_users":/run/secrets/smtpd_users:ro \
    -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
    --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
  docker network connect --ip 172.31.251.10 --alias relay "$untrusted" "$relay"
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

client() {
  local network=$1; shift
  docker run --rm --network "$network" --entrypoint python3 \
    -v "$PWD/tests":/tests:ro "$image" /tests/smtp-policy-client.py relay "$@"
}

# OR: either source network membership or successful AUTH is enough. Sender
# admission remains a separate gate even when the client gate passes.
start_relay ip-or-auth
client "$trusted" --expect accept
client "$untrusted" --expect policy-reject
client "$untrusted" --username device --password correct-password --expect accept
client "$untrusted" --username device --password wrong --expect auth-reject
client "$trusted" --sender unauthorized@relay.example.local --expect sender-reject
echo 'ok ip-or-auth positive, negative, bad-password, and sender gates'

# AND: prove all three truth-table rows, especially authenticated from the wrong
# IP. This is why client and relay restrictions are two independent lists.
# ip-and-auth defaults to mandatory TLS, so the unauthenticated trusted client
# still negotiates STARTTLS before testing RCPT. An initial plaintext attempt
# correctly stopped earlier at MAIL with "Must issue STARTTLS" and never reached
# the AND policy we intended to exercise.
start_relay ip-and-auth
client "$trusted" --starttls --expect policy-reject
client "$untrusted" --username device --password correct-password --expect policy-reject
client "$trusted" --username device --password correct-password --expect accept
echo 'ok ip-and-auth requires both source network and credentials'

# Password-only intentionally ignores trusted network membership.
start_relay smtp-auth
client "$trusted" --expect policy-reject
client "$trusted" --username device --password correct-password --expect accept
echo 'ok smtp-auth requires credentials even on the trusted network'

# IP-only never exposes an AUTH escape hatch.
start_relay ip
client "$trusted" --expect accept
client "$untrusted" --expect policy-reject
echo 'ok ip mode admits only the configured source network'
