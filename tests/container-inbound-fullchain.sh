#!/usr/bin/env bash
# Prove the public-CA/ACME input contract with a real TLS handshake.  The relay
# receives only two operator paths: an unencrypted private key and a conventional
# fullchain PEM containing leaf first, then intermediate issuers.  A client that
# trusts only the root must validate the served name and chain successfully.
#
# The second half models Certbot-style renewal. Both files are atomically moved
# inside one bind-mounted directory, the container is restarted, and the served
# leaf fingerprint must change while chain validation continues to succeed.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-fullchain-test
network=postfix-m365-relay-fullchain-network
state=postfix-m365-relay-fullchain-state
spool=postfix-m365-relay-fullchain-spool
fixture=$PWD/tests/.tmp-inbound-fullchain

cleanup() {
  docker rm -f "$relay" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture/live" "$fixture/stage"

# Build a root -> intermediate -> server hierarchy rather than using a single
# self-signed leaf. A self-signed fixture would pass even if Postfix forgot to
# send the intermediate, which is precisely the failure this test must catch.
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
  -subj /CN=Fullchain-Test-Root \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$fixture/root.key" -out "$fixture/root.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj /CN=Fullchain-Test-Intermediate \
  -keyout "$fixture/intermediate.key" -out "$fixture/intermediate.csr" >/dev/null 2>&1
cat > "$fixture/intermediate.ext" <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in "$fixture/intermediate.csr" -days 20 -sha256 \
  -CA "$fixture/root.crt" -CAkey "$fixture/root.key" -CAcreateserial \
  -extfile "$fixture/intermediate.ext" -out "$fixture/intermediate.crt" >/dev/null 2>&1

make_leaf() {
  local generation=$1 directory=$2
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj /CN=smtp.example.invalid \
    -keyout "$directory/privkey.pem.new" -out "$directory/leaf.csr" >/dev/null 2>&1
  cat > "$directory/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:smtp.example.invalid
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -in "$directory/leaf.csr" -days 10 -sha256 \
    -CA "$fixture/intermediate.crt" -CAkey "$fixture/intermediate.key" \
    -CAcreateserial -set_serial "$generation" -extfile "$directory/leaf.ext" \
    -out "$directory/cert.pem" >/dev/null 2>&1
  # Certbot fullchain.pem ordering is leaf first, then intermediate issuer(s).
  # The trusted root is intentionally omitted; clients already own trust roots.
  cp "$directory/cert.pem" "$directory/fullchain.pem.new"
  cat "$fixture/intermediate.crt" >> "$directory/fullchain.pem.new"
  chmod 0600 "$directory/privkey.pem.new"
  chmod 0644 "$directory/fullchain.pem.new"
}

make_leaf 1001 "$fixture/live"
mv "$fixture/live/privkey.pem.new" "$fixture/live/privkey.pem"
mv "$fixture/live/fullchain.pem.new" "$fixture/live/fullchain.pem"

docker network create --internal "$network" >/dev/null
docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_APP=app@relay.example.local \
  -e MAIL_INBOUND_AUTH=ip -e MAIL_INBOUND_TLS=require \
  -e MAIL_INBOUND_TLS_CERT=/run/inbound/fullchain.pem \
  -e MAIL_INBOUND_TLS_KEY=/run/inbound/privkey.pem \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 \
  -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$fixture/live":/run/inbound:ro \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null

wait_for_relay() {
  for _attempt in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || {
      docker logs "$relay"; return 1;
    }
    docker exec "$relay" postfix status >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$relay"
  return 1
}

handshake() {
  local output=$1
  docker run --rm --network "$network" --entrypoint bash \
    -v "$fixture/root.crt":/run/root.crt:ro "$image" -c \
    "openssl s_client -starttls smtp -connect relay:2525 \
      -servername smtp.example.invalid -verify_hostname smtp.example.invalid \
      -verify_return_error -showcerts -CAfile /run/root.crt </dev/null" \
    > "$output" 2>&1
  grep -q 'Verification: OK' "$output"
  [[ $(grep -c -- '-----BEGIN CERTIFICATE-----' "$output") -eq 2 ]]
}

wait_for_relay
handshake "$fixture/first-handshake.log"
first=$(openssl x509 -in "$fixture/live/fullchain.pem" -noout -fingerprint -sha256)

# Generate into a separate staging directory, then move both completed files
# into the mounted directory. The restart is deliberately after both renames:
# it re-runs pair validation and avoids loading half of a renewal transaction.
make_leaf 1002 "$fixture/stage"
mv "$fixture/stage/privkey.pem.new" "$fixture/live/privkey.pem"
mv "$fixture/stage/fullchain.pem.new" "$fixture/live/fullchain.pem"
docker restart "$relay" >/dev/null
wait_for_relay
handshake "$fixture/second-handshake.log"
second=$(openssl x509 -in "$fixture/live/fullchain.pem" -noout -fingerprint -sha256)
[[ $second != "$first" ]]

echo 'ok fullchain leaf+intermediate validates by root and renewed pair loads after restart'
