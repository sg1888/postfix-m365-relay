#!/usr/bin/env bash
# Exercise Postfix's actual regexp-table expansion, not just generated text.
# This catches characters such as "$5" that Bash prints literally but Postfix
# interprets as capture macros. The initial implementation failed this exact
# case: Postfix skipped the rule because capture group 5 did not exist.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
container=postfix-m365-relay-sender-name-test
state=postfix-m365-relay-sender-name-test-state
spool=postfix-m365-relay-sender-name-test-spool
cleanup() {
  # Names are globally unique and cleanup targets only disposable test objects.
  # Running cleanup before and after makes an interrupted prior run recoverable.
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker run -d --name "$container" --network none \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_BRACKETS=brackets@relay.example.local \
  -e 'MAIL_SENDER_NAME_BRACKETS=MyServer [TestServer]' \
  -e MAIL_SENDER_PARENS=parens@relay.example.local \
  -e 'MAIL_SENDER_NAME_PARENS=Backups (Primary)' \
  -e MAIL_SENDER_APOSTROPHE=apostrophe@relay.example.local \
  -e "MAIL_SENDER_NAME_APOSTROPHE=O'Brien's NAS" \
  -e MAIL_SENDER_PUNCT=punct@relay.example.local \
  -e 'MAIL_SENDER_NAME_PUNCT=Reports, Finance & Ops #42: Green' \
  -e MAIL_SENDER_DOLLAR=dollar@relay.example.local \
  -e 'MAIL_SENDER_NAME_DOLLAR=Price $5 / $1 / ${HOME}' \
  -e MAIL_SENDER_BACKSLASH=backslash@relay.example.local \
  -e 'MAIL_SENDER_NAME_BACKSLASH=Path \ Server' \
  -e MAIL_SENDER_QUOTE=quote@relay.example.local \
  -e 'MAIL_SENDER_NAME_QUOTE=The "Quoted" Server' \
  -e MAIL_SENDER_UNICODE=unicode@relay.example.local \
  -e 'MAIL_SENDER_NAME_UNICODE=Café – Zürich' \
  -e MAIL_SENDER_SYMBOLS=alerts+prod.v2@relay.example.local \
  -e 'MAIL_SENDER_NAME_SYMBOLS=Rack {A/B}; owner=Ops @ NOC — 🚨' \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null

for _ in {1..30}; do
  # Wait on a rendered artifact rather than sleeping a guessed duration. RSA
  # key generation is visibly slower under amd64/v2 emulation on an arm64 host.
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; exit 1; }
  docker exec "$container" grep -q '^# >>> postfix-m365-relay (managed) >>>$' /etc/postfix/main.cf >/dev/null 2>&1 && break
  sleep 1
done

check() {
  # `postmap -q` invokes the same regexp replacement engine used by smtp(8), so
  # the assertion covers regex escaping, replacement escaping, and final syntax.
  local sender=$1 expected=$2 actual
  actual=$(docker exec "$container" postmap -q "From: $sender@relay.example.local" regexp:/etc/postfix/header_checks)
  [[ $actual == "REPLACE From: \"$expected\" <relay-test@example.invalid>" ]] || {
    printf 'FAILED %s\n expected: %s\n actual:   %s\n' "$sender" "$expected" "$actual" >&2
    return 1
  }
  printf 'ok %s => %s\n' "$sender" "$actual"
}

check brackets 'MyServer [TestServer]'
check parens 'Backups (Primary)'
check apostrophe "O'Brien's NAS"
check punct 'Reports, Finance & Ops #42: Green'
check dollar 'Price $5 / $1 / ${HOME}'
check backslash 'Path \\ Server'
check quote 'The \"Quoted\" Server'
check unicode 'Café – Zürich'
check 'alerts+prod.v2' 'Rack {A/B}; owner=Ops @ NOC — 🚨'

# Applications emit several legal From layouts. Verify the address matcher is
# not accidentally limited to a bare address, and that address case does not
# change routing. Postfix regexp tables are case-insensitive unless a rule opts
# out; this test records that dependency explicitly.
check_header() {
  local input=$1 expected=$2 actual
  actual=$(docker exec "$container" postmap -q "$input" regexp:/etc/postfix/header_checks)
  [[ $actual == "$expected" ]] || {
    printf 'FAILED header form\n input:    %s\n expected: %s\n actual:   %s\n' "$input" "$expected" "$actual" >&2
    return 1
  }
  printf 'ok header form %s\n' "$input"
}
check_header 'From: Old Device Name <brackets@relay.example.local>' \
  'REPLACE From: "MyServer [TestServer]" <relay-test@example.invalid>'
check_header 'From:    BRACKETS@RELAY.EXAMPLE.LOCAL   ' \
  'REPLACE From: "MyServer [TestServer]" <relay-test@example.invalid>'
