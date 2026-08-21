#!/usr/bin/env bash
# OAuth certificate reset and the repeated "upload required" notice, fully
# offline. No Microsoft call: the relay runs on an internal network so every
# token mint fails, which is exactly the state in which the upload notice must
# persist and repeat. Exercises first-boot export, the docker-exec reset
# subcommand, and the /config sentinel-file reset, and confirms the per-instance
# id is stable in the state volume.
set -euo pipefail
image=${1:-postfix-m365-relay:test}
relay=postfix-m365-relay-reset-relay
network=postfix-m365-relay-reset-network
state=postfix-m365-relay-reset-state
spool=postfix-m365-relay-reset-spool
fixture=$PWD/tests/.tmp-oauth-reset
cleanup() { docker rm -f "$relay" >/dev/null 2>&1 || true; docker network rm "$network" >/dev/null 2>&1 || true; docker volume rm "$state" "$spool" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
cleanup

install -d -m 0700 "$fixture" "$fixture/config"
# A complete config so the relay boots past setup mode AND the relay-admin exec
# session (which re-parses the file, never PID 1's exports) can reset.
cat > "$fixture/config/mail-relay.conf" <<'EOF'
MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
MAIL_SEND_MAILBOX=relay-test@example.invalid
EOF

docker network create --internal "$network" >/dev/null
docker volume create "$state" >/dev/null
docker volume create "$spool" >/dev/null

thumbprint_file=$fixture/config/microsoft365-app-cert-thumbprint.txt
export_file=$fixture/config/microsoft365-app-public-cert.pem

docker run -d --name "$relay" --network "$network" --network-alias relay \
  -e MAIL_ADMIN_EMAIL= -e MAIL_VERIFY_SEND=no -e MAIL_INBOUND_AUTH=ip \
  -e MAIL_TOKEN_LOOP_SECONDS=3 -e MAIL_VERIFY_LOOP_SECONDS=4 -e MAIL_ROTATION_LOOP_SECONDS=3600 \
  -v "$fixture/config":/config -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null

# --- first boot: a certificate is generated and its public half exported ------
for _ in {1..40}; do [[ -s $export_file && -s $thumbprint_file ]] && break; sleep 1; done
[[ -s $export_file ]] || { echo 'FAIL: first-boot public certificate export never appeared in /config' >&2; docker logs "$relay" | tail -20 >&2; exit 1; }
first_thumb=$(tr -d '\r\n' < "$thumbprint_file")
[[ -n $first_thumb ]] || { echo 'FAIL: first-boot thumbprint file is empty' >&2; exit 1; }
echo "ok first boot generated a certificate and exported its public half ($first_thumb)"

# --- the upload notice repeats rather than appearing once ---------------------
# Every mint fails on the internal network, so the notice must persist; count the
# ACTION REQUIRED lines across a few loop cycles.
sleep 14
banner_count=$(docker logs "$relay" 2>&1 | grep -c 'ACTION REQUIRED' || true)
(( banner_count >= 2 )) || { echo "FAIL: upload notice did not repeat (saw $banner_count ACTION REQUIRED lines)" >&2; exit 1; }
echo "ok the upload notice repeats in the logs ($banner_count times) rather than being lost"

# --- a stable per-instance id lives in the state volume -----------------------
instance_id=$(docker exec "$relay" cat /var/lib/mail-relay/instance-id | tr -d '\r\n')
[[ -n $instance_id ]] || { echo 'FAIL: no instance id in the state volume' >&2; exit 1; }
echo "ok a stable per-instance id is present ($instance_id)"

# --- reset via the relay-admin subcommand -------------------------------------
docker exec "$relay" relay-admin reset-oauth-cert >/dev/null
for _ in {1..20}; do [[ "$(tr -d '\r\n' < "$thumbprint_file")" != "$first_thumb" ]] && break; sleep 1; done
subcmd_thumb=$(tr -d '\r\n' < "$thumbprint_file")
[[ -n $subcmd_thumb && $subcmd_thumb != "$first_thumb" ]] || { echo 'FAIL: relay-admin reset did not produce a new certificate' >&2; exit 1; }
docker exec "$relay" test -s /var/lib/mail-relay/secrets/mail_relay_client_key.pem.previous
docker exec "$relay" test -s /var/lib/mail-relay/secrets/mail_relay_client_cert.pem.previous
echo "ok relay-admin reset-oauth-cert regenerated the certificate and kept the previous pair ($subcmd_thumb)"

# --- reset via the /config sentinel file (no docker exec) ---------------------
: > "$fixture/config/reset-oauth-cert"
for _ in {1..20}; do
  current=$(tr -d '\r\n' < "$thumbprint_file")
  [[ $current != "$subcmd_thumb" && ! -e $fixture/config/reset-oauth-cert ]] && break
  sleep 1
done
sentinel_thumb=$(tr -d '\r\n' < "$thumbprint_file")
[[ -n $sentinel_thumb && $sentinel_thumb != "$subcmd_thumb" ]] || { echo 'FAIL: sentinel reset did not produce a new certificate' >&2; exit 1; }
[[ ! -e $fixture/config/reset-oauth-cert ]] || { echo 'FAIL: sentinel file was not consumed' >&2; exit 1; }
echo "ok /config sentinel triggered a reset and was consumed ($sentinel_thumb)"

# --- the instance id is unchanged across resets -------------------------------
instance_id_after=$(docker exec "$relay" cat /var/lib/mail-relay/instance-id | tr -d '\r\n')
[[ $instance_id_after == "$instance_id" ]] || { echo 'FAIL: instance id changed across resets' >&2; exit 1; }
echo "ok the per-instance id is stable across certificate resets"
