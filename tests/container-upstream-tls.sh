#!/usr/bin/env bash
# Prove outbound STARTTLS authentication with the real Postfix SMTP client.
# A successful handshake alone is insufficient: `encrypt` also handshakes with
# an impostor. These cases distinguish trusted identity, hostname, validity,
# corporate inspection trust, and the documented compatibility escape hatch.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-upstream-tls-test
upstream=postfix-m365-relay-upstream-tls-server
network=postfix-m365-relay-upstream-tls-network
state=postfix-m365-relay-upstream-tls-state
spool=postfix-m365-relay-upstream-tls-spool
fixture=$PWD/tests/.tmp-upstream-tls

cleanup() {
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"

make_ca() {
  local stem=$1 subject=$2
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$subject" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$fixture/$stem.key" -out "$fixture/$stem.crt" >/dev/null 2>&1
}
make_leaf() {
  local stem=$1 hostname=$2 ca=$3
  openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$hostname" \
    -keyout "$fixture/$stem.key" -out "$fixture/$stem.csr" >/dev/null 2>&1
  printf '%s\n' "subjectAltName=DNS:$hostname" 'extendedKeyUsage=serverAuth' \
    > "$fixture/$stem.ext"
  openssl x509 -req -days 20 -in "$fixture/$stem.csr" \
    -CA "$fixture/$ca.crt" -CAkey "$fixture/$ca.key" -CAcreateserial \
    -extfile "$fixture/$stem.ext" -out "$fixture/$stem.crt" >/dev/null 2>&1
}

make_ca corporate-root 'Authorized inspection test root'
make_ca foreign-root 'Untrusted test root'
make_ca retiring-root 'Overlapping retiring inspection root'
make_leaf trusted upstream corporate-root
make_leaf wrong-name wrong.example.invalid corporate-root
make_leaf untrusted upstream foreign-root
# A rollover bundle deliberately contains an old and a new public root. This
# proves the documented overlap procedure and the entrypoint's multi-PEM parser.
cp "$fixture/retiring-root.crt" "$fixture/corporate-bundle.crt"
cat "$fixture/corporate-root.crt" >> "$fixture/corporate-bundle.crt"

# OpenSSL's simple `x509 -req` interface accepts a duration but not a past end
# time. Generate the intentionally expired leaf with the same cryptography stack
# shipped in the release image. This is test-only material on an internal
# network; it never contacts Microsoft or leaves the fixture directory.
docker run --rm -i --network none --entrypoint python3 -v "$fixture":/data "$image" - <<'PY'
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

root = Path('/data')
ca_key = serialization.load_pem_private_key((root / 'corporate-root.key').read_bytes(), None)
ca_cert = x509.load_pem_x509_certificate((root / 'corporate-root.crt').read_bytes())
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'upstream')])
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=10))
    .not_valid_after(now - datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName('upstream')]), False)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    .sign(ca_key, hashes.SHA256())
)
(root / 'expired.key').write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
(root / 'expired.crt').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
PY
chmod 0600 "$fixture"/*.key
: > "$fixture/messages.jsonl"
expiry=$(( $(date +%s) + 3600 ))
printf '{"access_token":"offline-test-token","expiry":"%s","refresh_token":"unused-app-only-flow"}\n' \
  "$expiry" > "$fixture/relay.json"
chmod 0644 "$fixture/relay.json"
docker network create --internal "$network" >/dev/null

start_case() {
  local certificate=$1 security_level=$2
  docker rm -f "$relay" "$upstream" >/dev/null 2>&1 || true
  docker volume rm "$spool" >/dev/null 2>&1 || true
  : > "$fixture/messages.jsonl"
  docker run -d --name "$upstream" --network "$network" --network-alias upstream \
    --entrypoint python3 -v "$PWD/tests":/tests:ro -v "$fixture":/data \
    "$image" /tests/fake_xoauth2_smtp.py --cert "/data/$certificate.crt" \
    --key "/data/$certificate.key" --output /data/messages.jsonl >/dev/null
  for _attempt in {1..20}; do
    # Save before searching. With `pipefail`, `docker logs | grep -q` can report
    # 141 when grep finds READY and closes while an emulated Docker client is
    # still writing platform notices. That is a harness SIGPIPE, not a failure.
    docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
    grep -q '^READY ' "$fixture/upstream-ready.log" && break
    sleep 1
  done
  docker logs "$upstream" > "$fixture/upstream-ready.log" 2>&1
  grep -q '^READY ' "$fixture/upstream-ready.log"

  docker run -d --name "$relay" --network "$network" \
    -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
    -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
    -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
    -e MAIL_SENDER_TEST=test@relay.example.local \
    -e MAIL_UPSTREAM_HOST=upstream -e MAIL_UPSTREAM_PORT=1587 \
    -e "MAIL_UPSTREAM_TLS_SECURITY_LEVEL=$security_level" \
    -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/corporate-bundle.crt \
    -e MAIL_TOKEN_FILE=/run/secrets/relay.json -e MAIL_INBOUND_AUTH=ip \
    -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_LOOP_SECONDS=300 \
    -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
    -v "$fixture/corporate-bundle.crt":/run/secrets/corporate-bundle.crt:ro \
    -v "$fixture/relay.json":/run/secrets/relay.json:ro \
    -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
    --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null
  for _attempt in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$relay") == true ]] || {
      docker logs "$relay"; return 1;
    }
    docker exec "$relay" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

submit() {
  docker run --rm --network "$network" --entrypoint python3 -v "$PWD":/workspace:ro \
    "$image" /workspace/scripts/qualify-relay.py --host "$relay" \
    --from-address test@relay.example.local --to recipient@example.invalid \
    --subject "upstream TLS case $1" >/dev/null
}

expect_sent() {
  local label=$1
  submit "$label"
  for _attempt in {1..30}; do
    [[ -s $fixture/messages.jsonl ]] && break
    sleep 1
  done
  [[ -s $fixture/messages.jsonl ]]
  docker logs "$relay" > "$fixture/relay-$label.log" 2>&1
  grep -q 'Verified TLS connection established to upstream' "$fixture/relay-$label.log" || \
    [[ $(docker exec "$relay" postconf -h smtp_tls_security_level) == encrypt ]]
  echo "ok outbound TLS sent: $label"
}

expect_deferred() {
  local label=$1
  submit "$label"
  for _attempt in {1..30}; do
    docker exec "$relay" postqueue -p > "$fixture/queue-$label.log" 2>/dev/null
    grep -q 'recipient@example.invalid' "$fixture/queue-$label.log" && break
    sleep 1
  done
  docker exec "$relay" postqueue -p > "$fixture/queue-$label.log"
  if ! grep -q 'recipient@example.invalid' "$fixture/queue-$label.log"; then
    echo "expected a deferred queue entry: $label" >&2
    cat "$fixture/queue-$label.log" >&2
    docker logs "$relay" >&2
    return 1
  fi
  if [[ -s $fixture/messages.jsonl ]]; then
    echo "untrusted/invalid TLS case reached the upstream message sink: $label" >&2
    return 1
  fi
  # Queue state and Docker's log transport become visible independently. Under
  # architecture emulation the queue can be observed just before the TLS error
  # line is readable, so poll the diagnostic rather than racing one snapshot.
  for _attempt in {1..10}; do
    docker logs "$relay" > "$fixture/relay-$label.log" 2>&1
    grep -Eqi 'certificate.*(untrusted|verify|match|valid|expired)|TLS.*(trust|verify|certificate)' \
      "$fixture/relay-$label.log" && break
    sleep 1
  done
  if ! grep -Eqi 'certificate.*(untrusted|verify|match|valid|expired)|TLS.*(trust|verify|certificate)' \
      "$fixture/relay-$label.log"; then
    echo "deferred as expected, but no recognizable TLS diagnostic appeared: $label" >&2
    cat "$fixture/relay-$label.log" >&2
    return 1
  fi
  echo "ok outbound TLS deferred: $label"
}

start_case trusted secure
expect_sent 'trusted corporate root plus matching hostname under secure'
start_case untrusted secure
expect_deferred 'untrusted root under secure'
start_case wrong-name secure
expect_deferred 'trusted root but wrong hostname under secure'
start_case expired secure
expect_deferred 'expired leaf under secure'
start_case untrusted encrypt
expect_sent 'untrusted root under explicit encrypt compatibility mode'

echo 'ok outbound STARTTLS identity, expiry, corporate CA, and compatibility matrix'
