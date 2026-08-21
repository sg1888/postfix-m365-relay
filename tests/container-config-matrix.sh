#!/usr/bin/env bash
# Exercise configuration branches that cannot be covered by one running relay.
# Each row boots the real entrypoint and inspects Postfix's effective values,
# which catches differences between intended shell variables and parsed config.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
container=postfix-m365-relay-config-matrix-test
state=postfix-m365-relay-config-matrix-state
spool=postfix-m365-relay-config-matrix-spool
fixture=$PWD/tests/.tmp-config-matrix

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture/config-secrets"
printf '%s\n' 'device:correct:horse:battery:staple' 'other:still-valid' > "$fixture/config-secrets/smtpd_users"
chmod 0600 "$fixture/config-secrets/smtpd_users"

# Reuse the state volume so RSA-2048 generation happens once. Every row still
# gets a clean /etc/postfix and /run, exactly as a real container recreation does.
common=(--network none
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid
  -e MAIL_SENDER_APP=app@relay.example.local
  -e 'MAIL_SENDER_NAME_APP=Application [Primary]'
  -e TZ=America/New_York
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix
  # Exercise the novice/default credential location. Other suites separately
  # prove the explicit /run/secrets path used by Docker secret integrations.
  -v "$fixture/config-secrets":/config/secrets:ro
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750)

wait_for_config() {
  for _attempt in {1..40}; do
    [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || {
      docker logs "$container"; return 1;
    }
    # `postconf` can read the package defaults before entrypoint rendering has
    # finished. The first version of this test waited only for postconf and
    # intermittently observed the package's TLS default (`may`) in off mode.
    # The managed-banner closing line is the actual render commit marker.
    docker exec "$container" grep -q '^# <<< postfix-m365-relay (managed) <<<$' \
      /etc/postfix/main.cf >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo 'container did not render Postfix configuration' >&2
  docker logs "$container"
  return 1
}

assert_postconf() {
  local key=$1 expected=$2 actual
  actual=$(docker exec "$container" postconf -h "$key")
  [[ $actual == "$expected" ]] || {
    printf 'FAILED %s/%s\n expected: %s\n actual:   %s\n' "$current_mode" "$key" "$expected" "$actual" >&2
    return 1
  }
}

# The system trust bundle lives at a distro-specific path (RHEL/AlmaLinux use
# /etc/pki, Debian/Ubuntu use /etc/ssl). Detect it from the running image the
# same way the entrypoint does so the CAfile assertion is not tied to one distro.
system_ca_path() {
  docker exec "$container" sh -c '
    if [ -s /etc/pki/tls/certs/ca-bundle.crt ]; then echo /etc/pki/tls/certs/ca-bundle.crt;
    elif [ -s /etc/ssl/certs/ca-certificates.crt ]; then echo /etc/ssl/certs/ca-certificates.crt; fi'
}

start_mode() {
  current_mode=$1
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run -d --name "$container" "${common[@]}" -e "MAIL_INBOUND_AUTH=$current_mode" \
    "$image" >/dev/null
  wait_for_config
}

# These five rows are the public inbound-auth contract. Test defaults as well
# as restrictions: a correct TLS level with `permit` in the wrong place is still
# an open relay, and correct restrictions with AUTH advertised in cleartext are
# still credential exposure.
start_mode off
assert_postconf smtpd_sasl_auth_enable no
assert_postconf smtpd_tls_security_level none
assert_postconf smtpd_client_restrictions 'permit_mynetworks, reject'
assert_postconf smtpd_relay_restrictions 'permit_mynetworks, reject'
# Both lifetime knobs must move together. A previous operational override
# changed only one side, so this asserts the image's unattended default rather
# than trusting the environment example to match the renderer.
assert_postconf maximal_queue_lifetime 12h
assert_postconf bounce_queue_lifetime 12h
assert_postconf smtp_tls_security_level secure
assert_postconf smtp_tls_CAfile "$(system_ca_path)"
[[ $(docker exec "$container" date +%Z) != UTC ]]
echo 'ok secure upstream TLS, 12-hour queue defaults, and validated TZ are effective'

start_mode ip
assert_postconf smtpd_sasl_auth_enable no
assert_postconf smtpd_tls_security_level none
assert_postconf smtpd_client_restrictions 'permit_mynetworks, reject'
assert_postconf smtpd_relay_restrictions 'permit_mynetworks, reject'

start_mode smtp-auth
assert_postconf smtpd_sasl_auth_enable yes
assert_postconf smtpd_tls_security_level may
assert_postconf smtpd_tls_auth_only yes
assert_postconf smtpd_client_restrictions ''
assert_postconf smtpd_relay_restrictions 'check_client_access cidr:/etc/postfix/loopback_clients, permit_sasl_authenticated, reject'

start_mode ip-or-auth
assert_postconf smtpd_sasl_auth_enable yes
assert_postconf smtpd_tls_security_level may
assert_postconf smtpd_client_restrictions ''
assert_postconf smtpd_relay_restrictions 'permit_mynetworks, permit_sasl_authenticated, reject'

start_mode ip-and-auth
assert_postconf smtpd_sasl_auth_enable yes
assert_postconf smtpd_tls_security_level encrypt
assert_postconf smtpd_client_restrictions 'permit_mynetworks, reject'
assert_postconf smtpd_relay_restrictions 'check_client_access cidr:/etc/postfix/loopback_clients, permit_sasl_authenticated, reject'
echo 'ok all five inbound-auth policies and their TLS defaults'

# A password may contain colons because only the first colon separates the
# username. Proving login here guards against an over-eager split implementation.
# Rendering completes before the supervisor necessarily opens the socket. Wait
# on the protocol endpoint too; using the config marker for both caused a real
# ConnectionRefused race under v2 emulation during development.
for _attempt in {1..20}; do
  docker exec "$container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done
docker exec -i "$container" python3 - <<'PY'
import smtplib, ssl
s = smtplib.SMTP("127.0.0.1", 2525, timeout=10)
s.ehlo(); s.starttls(context=ssl._create_unverified_context()); s.ehlo()
s.login("device", "correct:horse:battery:staple")
s.quit()
PY
echo 'ok device password preserves embedded colons'
# The same banner healthcheck remains valid when TLS is required: SMTP sends its
# 220 greeting before STARTTLS, so health monitoring needs no certificate trust.
docker exec "$container" bash -c \
  "printf 'QUIT\\r\\n' | nc -w 3 127.0.0.1 2525 | grep -q '^220 '"
echo 'ok banner healthcheck passes with mandatory inbound TLS'

# Credentials are rebuilt from the mounted source on restart. Remove one line
# in place (so the bind mount sees the update), recreate the same mode, and
# prove revocation is selective rather than a stale-database or all-users event.
! docker logs "$container" 2>&1 | grep -Fq 'correct:horse:battery:staple'
! docker inspect "$container" | grep -Fq 'correct:horse:battery:staple'
printf '%s\n' 'other:still-valid' > "$fixture/config-secrets/smtpd_users"
docker rm -f "$container" >/dev/null
start_mode ip-and-auth
for _attempt in {1..20}; do
  docker exec "$container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done
docker exec -i "$container" python3 - <<'PY'
import smtplib, ssl

def connect():
    smtp = smtplib.SMTP("127.0.0.1", 2525, timeout=10)
    smtp.ehlo(); smtp.starttls(context=ssl._create_unverified_context()); smtp.ehlo()
    return smtp

revoked = connect()
try:
    revoked.login("device", "correct:horse:battery:staple")
except smtplib.SMTPAuthenticationError:
    pass
else:
    raise AssertionError("removed device credential still authenticates")
finally:
    revoked.close()

retained = connect()
retained.login("other", "still-valid")
retained.quit()
PY
echo 'ok credential removal revokes one device while retaining another'

# Test passthrough as a narrow allowlist. The alias is preserved in both the
# envelope and visible header; a configured but unlisted sender still collapses.
docker rm -f "$container" >/dev/null
current_mode=passthrough
docker run -d --name "$container" "${common[@]}" \
  -e MAIL_INBOUND_AUTH=ip -e MAIL_SENDER_MODE=passthrough \
  -e MAIL_SENDER_ALIAS=alerts+prod@tenant.example.invalid \
  -e 'MAIL_SENDER_NAME_ALIAS=Alerts [Production]' \
  -e MAIL_PASSTHROUGH_SENDERS=alerts+prod@tenant.example.invalid \
  "$image" >/dev/null
wait_for_config
[[ $(docker exec "$container" postmap -q alerts+prod@tenant.example.invalid regexp:/etc/postfix/sender_canonical) == alerts+prod@tenant.example.invalid ]]
[[ $(docker exec "$container" postmap -q app@relay.example.local regexp:/etc/postfix/sender_canonical) == relay-test@example.invalid ]]
[[ $(docker exec "$container" postmap -q 'From: Alerts <alerts+prod@tenant.example.invalid>' regexp:/etc/postfix/header_checks) == DUNNO ]]
[[ $(docker exec "$container" postmap -q 'From: app@relay.example.local' regexp:/etc/postfix/header_checks) == 'REPLACE From: "Application [Primary]" <relay-test@example.invalid>' ]]
echo 'ok passthrough preserves only allowlisted envelope/header identities'

# Explicit network input must normalize a host to /32 and retain a CIDR. This
# assertion also proves the container network is not replaced by user entries.
docker rm -f "$container" >/dev/null
current_mode=trusted-networks
docker run -d --name "$container" "${common[@]}" -e MAIL_INBOUND_AUTH=ip \
  -e 'MAIL_TRUSTED_NETWORKS=192.0.2.50, 198.51.100.0/24' "$image" >/dev/null
wait_for_config
mynetworks=$(docker exec "$container" postconf -h mynetworks)
[[ $mynetworks == *'192.0.2.50/32'* && $mynetworks == *'198.51.100.0/24'* ]]
echo 'ok trusted host/CIDR normalization'

# The image's PID 1 waits on several child process groups. Docker can return a
# stop-timeout status on the hosted runner even after the container is no
# longer running, so capture the diagnostic and verify the actual state before
# the trap removes it. This keeps the test about lifecycle state, not Docker's
# transport timeout behavior.
docker stop --timeout 10 "$container" >/dev/null 2>&1 || true
[[ $(docker inspect -f '{{.State.Running}}' "$container") == false ]]
echo 'ok every configuration-matrix container stopped cleanly'
