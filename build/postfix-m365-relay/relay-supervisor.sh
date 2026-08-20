#!/usr/bin/env bash
# Minimal Bash PID-1 supervisor. We intentionally do not depend on systemd or a
# second init package: all child roles and restart rules fit here, and their PIDs
# are exposed under /run for black-box tests and incident inspection.
set -uo pipefail

log() { printf '%s relay-supervisor: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
declare -A role_by_pid pid_by_role
stopping=0
exit_code=0

run_token_loop() {
  # Refresh at a short cadence but let the Python helper skip a healthy token.
  # Consecutive failures are counted so one transient network error is logged
  # while a sustained outage becomes an alert.
  local failures=0
  while :; do
    if /usr/local/libexec/mail-relay/refresh-smtp-token.py --min-remaining 1800; then failures=0
    else
      failures=$((failures + 1)); log "token refresh failed ($failures consecutive)"
      if (( failures == ${MAIL_TOKEN_ALERT_AFTER:-3} )); then /usr/local/libexec/mail-relay/alert.sh error token-refresh "Token refresh failed $failures consecutive times" || true; fi
    fi
    sleep "${MAIL_TOKEN_LOOP_SECONDS:-300}" & wait $!
  done
}
run_rotation_loop() {
  # Both rotations perform their own due checks, so daily invocation is cheap.
  # They remain separate programs and separate key directories: the local SMTP
  # server certificate must never become the Microsoft app credential.
  while :; do
    if ! /usr/local/libexec/mail-relay/rotate-inbound-tls.sh; then
      /usr/local/libexec/mail-relay/alert.sh error inbound-tls-rotation \
        'Inbound STARTTLS certificate renewal failed' || true
    fi
    if ! /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py \
      --validity "${MAIL_CERT_VALIDITY_DAYS:-730}" \
      --renew-at "${MAIL_CERT_RENEW_AT_DAYS:-$(( ${MAIL_CERT_VALIDITY_DAYS:-730} / 2 ))}" \
      --grace-days "${MAIL_CERT_GRACE_DAYS:-7}"; then
      /usr/local/libexec/mail-relay/alert.sh error certificate-rotation 'Certificate rotation failed; inspect cert-rotation.log' || true
    fi
    sleep "${MAIL_ROTATION_LOOP_SECONDS:-86400}" & wait $!
  done
}
run_verify_loop() {
  while :; do
    /usr/local/libexec/mail-relay/verify-relay.sh || true
    sleep "${MAIL_VERIFY_LOOP_SECONDS:-3600}" & wait $!
  done
}
spawn() {
  # Capture $! immediately. Writing the PID file is part of the observable
  # contract used by tests and operators; it also avoids fragile `pgrep`
  # matching when several Python loops have similar command lines.
  local role=$1
  case "$role" in
    postfix) /usr/sbin/postfix start-fg & ;;
    token) run_token_loop & ;;
    rotation) run_rotation_loop & ;;
    verify) run_verify_loop & ;;
    log) tail -n 0 -F /var/log/mail-relay/postfix.log & ;;
  esac
  local pid=$!
  role_by_pid[$pid]=$role; pid_by_role[$role]=$pid
  install -d -m 0755 /run/mail-relay/supervisor
  printf '%s\n' "$pid" > "/run/mail-relay/supervisor/$role.pid"
  log "started $role (pid $pid)"
}
shutdown() {
  # Idempotence matters because Postfix stopping can wake wait -n while the TERM
  # trap is already running. Stop accepting mail first, then terminate helpers.
  (( stopping == 0 )) || return
  stopping=1; log 'stopping children'
  postfix stop >/dev/null 2>&1 || true
  for pid in "${!role_by_pid[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
}
trap shutdown TERM INT

touch /var/log/mail-relay/postfix.log
for role in postfix token rotation verify log; do spawn "$role"; done

while (( stopping == 0 )); do
  # wait -n reports that *a* child exited; associative maps identify which one.
  # Helper-loop death is recoverable. Postfix death is not: keeping the
  # container "healthy" with no SMTP listener would defeat orchestrator restart.
  if wait -n; then status=0; else status=$?; fi
  (( stopping == 0 )) || break
  dead=''
  for pid in "${!role_by_pid[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then dead=$pid; break; fi
  done
  [[ -n $dead ]] || continue
  role=${role_by_pid[$dead]}; unset 'role_by_pid[$dead]' 'pid_by_role[$role]'
  if [[ $role == postfix ]]; then
    log "postfix exited ($status); container will exit"
    exit_code=$status; (( exit_code != 0 )) || exit_code=1
    shutdown; break
  fi
  log "$role exited ($status); restarting after ${MAIL_LOOP_RESTART_BACKOFF:-5}s"
  # The sleep itself is waited on so TERM interrupts the supervisor cleanly.
  # An earlier implementation used an uninterruptible foreground sleep; a
  # stop arriving during backoff could race into respawning a helper.
  sleep "${MAIL_LOOP_RESTART_BACKOFF:-5}" & wait $!
  (( stopping == 0 )) && spawn "$role"
done

for pid in "${!role_by_pid[@]}"; do wait "$pid" 2>/dev/null || true; done
exit "$exit_code"
