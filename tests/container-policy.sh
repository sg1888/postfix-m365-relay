#!/usr/bin/env bash
# Black-box security and lifecycle regression test. It boots real containers,
# talks SMTP over a socket, authenticates against Cyrus sasldb2, kills supervised
# processes, and finally repeats Tier 2 with a read-only root filesystem.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
container=postfix-m365-relay-policy-test
state=postfix-m365-relay-policy-test-state
spool=postfix-m365-relay-policy-test-spool
fixture=$PWD/tests/.tmp-policy
cleanup() {
  # Remove only names owned by this test. Never prune images, volumes, or
  # networks globally; developers may be running unrelated workloads.
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$state" "$spool" >/dev/null 2>&1 || true
  rm -rf "$PWD/tests/.tmp-policy"
}
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"
printf '%s\n' 'printer:correct horse battery staple' > "$fixture/smtpd_users"
chmod 0600 "$fixture/smtpd_users"
printf '%s\n' 'MissingColon' > "$fixture/users-no-colon"
printf '%s\n' 'UpperCase:secret' > "$fixture/users-bad-name"
printf '%s\n' 'empty:' > "$fixture/users-empty-password"
printf '%s\n' 'not a certificate' > "$fixture/not-a-ca"
printf '%s\n' '-----BEGIN PRIVATE KEY-----' 'intentionally-not-a-real-key' \
  '-----END PRIVATE KEY-----' > "$fixture/private-ca"
chmod 0600 "$fixture"/users-*
cat > "$fixture/main.cf" <<'EOF'
compatibility_level = 3.6
mydomain = hostile.example
myorigin = $mydomain
mydestination =
inet_interfaces = all
inet_protocols = ipv4
mynetworks = 0.0.0.0/0
smtpd_relay_restrictions = permit
smtpd_sender_restrictions =
smtpd_tls_auth_only = no
smtp_tls_security_level = none
smtp_tls_CAfile = /tmp/hostile-ca
EOF

common=(--rm --network none
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid
  -e MAIL_SENDER_APP=app@relay.example.local
  -e MAIL_VERIFY_SEND=no
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750)

expect_boot_failure() {
  # Refusal tests assert both nonzero exit and the diagnostic an operator needs.
  # Merely failing somewhere later could mask an unsafe validation regression.
  local needle=$1; shift
  if docker run "${common[@]}" "$@" "$image" > "$fixture/failure.log" 2>&1; then
    echo "expected boot failure: $needle" >&2; return 1
  fi
  grep -Fq "$needle" "$fixture/failure.log" || { cat "$fixture/failure.log"; return 1; }
  echo "ok refused: $needle"
}

expect_boot_failure 'open relay' -e MAIL_TRUSTED_NETWORKS=0.0.0.0/0
expect_boot_failure 'open relay' -e MAIL_TRUSTED_NETWORKS=::/0
expect_boot_failure 'password auth requires' -e MAIL_INBOUND_AUTH=smtp-auth -e MAIL_INBOUND_TLS=off
expect_boot_failure 'contradicts' -e MAIL_INBOUND_AUTH=off -e MAIL_TRUSTED_NETWORKS=192.0.2.50/32
expect_boot_failure 'docs/SECRETS.md' -e MAIL_SMTPD_USERS=printer:visible
expect_boot_failure 'invalid MAIL_INBOUND_AUTH' -e MAIL_INBOUND_AUTH=trust-everyone
expect_boot_failure 'MAIL_INBOUND_TLS must be' -e MAIL_INBOUND_TLS=sometimes
expect_boot_failure 'MAIL_SENDER_MODE must be' -e MAIL_SENDER_MODE=maybe
expect_boot_failure 'MAIL_RELAY_MAX_SIZE must look like' -e MAIL_RELAY_MAX_SIZE=huge
expect_boot_failure 'MAIL_QUEUE_LIFETIME must look like' -e MAIL_QUEUE_LIFETIME=forever
expect_boot_failure 'MAIL_UPSTREAM_TLS_SECURITY_LEVEL must be secure or encrypt' \
  -e MAIL_UPSTREAM_TLS_SECURITY_LEVEL=may
expect_boot_failure 'MAIL_UPSTREAM_CA_EXTRA_FILE must be a readable certificate file' \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/missing-ca
expect_boot_failure 'contains invalid or non-current certificates' \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/not-a-ca \
  -v "$fixture/not-a-ca":/run/secrets/not-a-ca:ro
expect_boot_failure 'must never contain a private key' \
  -e MAIL_UPSTREAM_CA_EXTRA_FILE=/run/secrets/private-ca \
  -v "$fixture/private-ca":/run/secrets/private-ca:ro
expect_boot_failure 'TZ must be an installed IANA timezone' -e TZ=Not/A_Real_Zone
expect_boot_failure 'TZ must be an installed IANA timezone' -e TZ=../../etc/passwd
expect_boot_failure 'MAIL_CA_BUNDLE_MAX_AGE_DAYS must be a whole number' \
  -e MAIL_CA_BUNDLE_MAX_AGE_DAYS=quarterly
expect_boot_failure 'validity and renewal values must be whole days' \
  -e MAIL_INBOUND_TLS=may -e MAIL_INBOUND_TLS_VALIDITY_DAYS=many
expect_boot_failure 'must exceed MAIL_INBOUND_TLS_RENEW_AT_DAYS' \
  -e MAIL_INBOUND_TLS=may -e MAIL_INBOUND_TLS_VALIDITY_DAYS=30 \
  -e MAIL_INBOUND_TLS_RENEW_AT_DAYS=30
expect_boot_failure 'MAIL_SUBNET must be an IPv4 CIDR' -e MAIL_SUBNET=192.0.2.0
# A completely missing sender is the novice first-run state, not malformed
# configuration: entrypoint waits without a listener until one appears. The
# dedicated first-run suite proves that bounded setup behavior. Rows below keep
# a sender and therefore exercise strict post-setup validation failures.
expect_boot_failure 'must not contain a newline' -e $'MAIL_SENDER_NAME_APP=bad\nheader'
expect_boot_failure 'expected user:password' -e MAIL_INBOUND_AUTH=smtp-auth \
  -e MAIL_SMTPD_USERS_FILE=/run/secrets/bad -v "$fixture/users-no-colon":/run/secrets/bad:ro
expect_boot_failure 'invalid device username' -e MAIL_INBOUND_AUTH=smtp-auth \
  -e MAIL_SMTPD_USERS_FILE=/run/secrets/bad -v "$fixture/users-bad-name":/run/secrets/bad:ro
expect_boot_failure 'empty password' -e MAIL_INBOUND_AUTH=smtp-auth \
  -e MAIL_SMTPD_USERS_FILE=/run/secrets/bad -v "$fixture/users-empty-password":/run/secrets/bad:ro

docker run -d --name "$container" --network none \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid \
  -e MAIL_SENDER_APP=app@relay.example.local \
  -e MAIL_INBOUND_AUTH=ip-or-auth -e MAIL_INBOUND_TLS=may \
  -e MAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users \
  -e POSTFIX_smtp_dns_support_level=disabled \
  -e POSTFIX_smtp_tls_security_level=encrypt \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -e MAIL_LOOP_RESTART_BACKOFF=1 \
  -e MAIL_TOKEN_LOOP_SECONDS=300 -e MAIL_ROTATION_LOOP_SECONDS=300 -e MAIL_VERIFY_LOOP_SECONDS=300 \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  -v "$fixture/smtpd_users":/run/secrets/smtpd_users:ro \
  -v "$fixture/main.cf":/etc/postfix-m365-relay/main.cf:ro \
  --tmpfs /run/mail-relay:rw,nosuid,noexec,mode=0750 "$image" >/dev/null

for _ in {1..30}; do
  # Probe the listener instead of assuming startup time. This test exposed the
  # verifier's former one-shot startup race and motivated its bounded retry.
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; exit 1; }
  docker exec "$container" bash -c 'exec 3<>/dev/tcp/127.0.0.1/2525' >/dev/null 2>&1 && break
  sleep 1
done

[[ $(docker exec "$container" postconf -h smtpd_relay_restrictions) == 'permit_mynetworks, permit_sasl_authenticated, reject' ]]
[[ $(docker exec "$container" postconf -h smtpd_sender_restrictions) == 'check_sender_access texthash:/etc/postfix/sender_access, reject' ]]
[[ $(docker exec "$container" postconf -h smtpd_tls_auth_only) == yes ]]
[[ $(docker exec "$container" postconf -h smtpd_sasl_auth_enable) == yes ]]
[[ $(docker exec "$container" postconf -h smtp_dns_support_level) == disabled ]]
[[ $(docker exec "$container" postconf -h smtp_tls_security_level) == secure ]]
[[ $(docker exec "$container" postconf -h smtp_tls_CAfile) == /etc/pki/tls/certs/ca-bundle.crt ]]
[[ $(docker exec "$container" postconf -h mynetworks) != *0.0.0.0/0* ]]
[[ $(docker exec "$container" stat -c '%a %U:%G' /run/mail-relay/sasldb2) == '600 postfix:postfix' ]]
docker exec "$container" relay-users list > "$fixture/relay-users.log"
grep -q 'printer@relay.example.local' "$fixture/relay-users.log"
echo 'ok managed block overrides hostile main.cf and sasldb2 is protected'

docker exec -i "$container" python3 - <<'PY'
import base64, smtplib, ssl
s = smtplib.SMTP("127.0.0.1", 2525, timeout=10)
s.ehlo()
assert "auth" not in s.esmtp_features, s.esmtp_features
early = base64.b64encode(b"\0printer\0correct horse battery staple").decode()
code, _ = s.docmd("AUTH", "PLAIN " + early)
assert code >= 500, code
s.starttls(context=ssl._create_unverified_context())
s.ehlo()
assert set(s.esmtp_features.get("auth", "").split()) == {"PLAIN", "LOGIN"}, s.esmtp_features
s.login("printer", "correct horse battery staple")
assert s.mail("app@relay.example.local")[0] == 250
assert s.rcpt("recipient@example.invalid")[0] == 250
s.rset(); s.quit()
PY
# This is the hard TLS-before-AUTH contract: AUTH is neither advertised nor
# accepted in cleartext, and only the two documented password mechanisms appear
# after STARTTLS. The final MAIL/RCPT proves auth grants relay permission.
echo 'ok AUTH absent before STARTTLS, PLAIN/LOGIN only after, sasldb login succeeds'

# Exercise the exact Compose health command while the supervised Postfix master
# remains alive. Suspending only the master was tried first, but an already
# running smtpd worker could still serve a 220 banner. Instead, temporarily move
# the disposable container's smtpd executable and retire existing workers; the
# master keeps its listener but cannot service a new connection. A TCP-connect-
# only healthcheck would falsely pass this condition.
health_command="printf 'QUIT\\r\\n' | nc -w 3 127.0.0.1 2525 | grep -q '^220 '"
docker exec "$container" timeout 5 bash -c "$health_command"
daemon_directory=$(docker exec "$container" postconf -h daemon_directory)
docker exec "$container" mv "$daemon_directory/smtpd" "$daemon_directory/smtpd.health-test-disabled"
# The minimal image intentionally has no procps (`ps`, `pgrep`, or `pkill`). An
# early version silently ignored command-not-found behind `|| true`, leaving the
# old worker alive and producing another false pass. Read /proc directly and
# kill only processes whose kernel comm name is exactly smtpd.
docker exec "$container" bash -c '
  for comm in /proc/[0-9]*/comm; do
    read -r name < "$comm" || continue
    if [[ $name == smtpd ]]; then
      pid=${comm#/proc/}; pid=${pid%/comm}; kill -KILL "$pid"
    fi
  done'
if docker exec "$container" timeout 5 bash -c "$health_command"; then
  docker exec "$container" mv "$daemon_directory/smtpd.health-test-disabled" "$daemon_directory/smtpd"
  echo 'health command accepted a wedged Postfix process' >&2
  exit 1
fi
docker exec "$container" mv "$daemon_directory/smtpd.health-test-disabled" "$daemon_directory/smtpd"
# TODO(revisit): smtpd recovery latency after the wedge is variable and not yet
# fully understood. On the AlmaLinux postfix it lands ~10s; on the Ubuntu postfix
# (same 3.8.x) it has been observed anywhere from ~3s to ~15s. The mechanism
# (postfix master throttle after a signal-killed / failed-exec service) needs a
# proper investigation. Window bumped 10 -> 15 to cover the observed range; if it
# still flakes, do the deep dive rather than widening further.
for _ in {1..15}; do
  docker exec "$container" timeout 5 bash -c "$health_command" && break
  sleep 1
done
docker exec "$container" timeout 5 bash -c "$health_command"
echo 'ok health command passes normally and fails while smtpd is wedged'

openssl_bits=$(docker exec "$container" openssl x509 -in /var/lib/mail-relay/inbound-tls/cert.pem -noout -text | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
[[ $openssl_bits == 2048 ]]
if docker exec -e MAIL_RELAY_KEY_FILE=/var/lib/mail-relay/inbound-tls/key.pem \
  -e MAIL_RELAY_CERT_FILE=/var/lib/mail-relay/inbound-tls/cert.pem "$container" \
  /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py --dry-run > "$fixture/rotation-path.log" 2>&1; then
  echo 'rotation accepted an inbound TLS path' >&2; exit 1
fi
grep -Fq 'never inbound-tls' "$fixture/rotation-path.log"
echo 'ok inbound TLS cert is RSA-2048 and OAuth rotation refuses its path'

# Kill each restartable loop with SIGKILL, not TERM. SIGKILL deliberately skips
# shell cleanup traps and reproduces the live SUP-001 failure where the loop's
# `sleep` survived under PID 1. Each role is a process-group leader now; PID 1
# must clean the entire old group before publishing a replacement PID.
for role in token rotation verify; do
  old_pid=$(docker exec "$container" cat "/run/mail-relay/supervisor/$role.pid")
  [[ $(docker exec "$container" awk '{print $5}' "/proc/$old_pid/stat") == "$old_pid" ]]

  # Wait until the loop has a child in its group. Otherwise killing immediately
  # would prove only leader restart, not descendant cleanup.
  for _ in {1..15}; do
    group_count=$(docker exec "$container" bash -c '
      wanted=$1; count=0
      for stat_file in /proc/[0-9]*/stat; do
        pgid=$(awk "{print \$5}" "$stat_file" 2>/dev/null) || continue
        [[ $pgid == "$wanted" ]] && count=$((count + 1))
      done
      printf "%s\n" "$count"' _ "$old_pid")
    (( group_count >= 2 )) && break
    sleep 1
  done
  (( group_count >= 2 ))

  docker exec "$container" kill -KILL "$old_pid"
  for _ in {1..15}; do
    new_pid=$(docker exec "$container" cat "/run/mail-relay/supervisor/$role.pid")
    [[ $new_pid != "$old_pid" ]] && break
    sleep 1
  done
  [[ $new_pid != "$old_pid" ]]
  docker exec "$container" kill -0 "$new_pid"
  if docker exec "$container" bash -c '
    wanted=$1
    for stat_file in /proc/[0-9]*/stat; do
      pgid=$(awk "{print \$5}" "$stat_file" 2>/dev/null) || continue
      [[ $pgid == "$wanted" ]] && exit 0
    done
    exit 1' _ "$old_pid"; then
    echo "$role left a process in old group $old_pid" >&2
    exit 1
  fi
  echo "ok $role process group restarted without descendants ($old_pid -> $new_pid)"
done

postfix_pid=$(docker exec "$container" cat /run/mail-relay/supervisor/postfix.pid)
docker exec "$container" kill -TERM "$postfix_pid"
for _ in {1..15}; do
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == false ]] && break
  sleep 1
done
[[ $(docker inspect -f '{{.State.Running}}' "$container") == false ]]
[[ $(docker inspect -f '{{.State.ExitCode}}' "$container") != 0 ]]
echo 'ok Postfix death exits the container nonzero'

docker rm "$container" >/dev/null
# The hardened deployment provides writable tmpfs only where packages genuinely
# need mutation. Reusing the state volume also verifies first-boot material is
# durable and is not regenerated merely because /etc/postfix is ephemeral.
docker run -d --name "$container" --network none --read-only \
  -e MAIL_RELAY_TENANT=00000000-0000-0000-0000-000000000000 \
  -e MAIL_RELAY_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e MAIL_SEND_MAILBOX=relay-test@example.invalid -e MAIL_SENDER_APP=app@relay.example.local \
  -e MAIL_INBOUND_AUTH=ip-or-auth -e MAIL_INBOUND_TLS=may \
  -e MAIL_SMTPD_USERS_FILE=/run/secrets/smtpd_users \
  -e MAIL_VERIFY_SEND=no -e MAIL_TOKEN_ALERT_AFTER=99 \
  -v "$state":/var/lib/mail-relay -v "$spool":/var/spool/postfix \
  -v "$fixture/smtpd_users":/run/secrets/smtpd_users:ro \
  --tmpfs /etc/postfix:rw --tmpfs /run:rw,nosuid,noexec --tmpfs /var/lib/postfix:rw \
  "$image" >/dev/null
for _ in {1..30}; do
  [[ $(docker inspect -f '{{.State.Running}}' "$container") == true ]] || { docker logs "$container"; exit 1; }
  docker exec "$container" test -f /run/mail-relay/sasldb2 >/dev/null 2>&1 && break
  sleep 1
done
[[ $(docker exec "$container" stat -c '%a %U:%G' /run/mail-relay/sasldb2) == '600 postfix:postfix' ]]
# Docker's hosted runner can report a stop timeout while the supervisor has
# already processed TERM and the container has stopped. Assert the observable
# lifecycle state instead of treating Docker's client-side timeout code as a
# relay failure; a still-running container remains a hard test failure.
docker stop --timeout 10 "$container" >/dev/null 2>&1 || true
[[ $(docker inspect -f '{{.State.Running}}' "$container") == false ]]
echo 'ok Tier 2 runs read-only with /etc/postfix, /run, and /var/lib/postfix tmpfs'
