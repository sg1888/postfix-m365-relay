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
  local failures=0 token_result
  while :; do
    # Capture the concise helper diagnostic so safe Entra error codes, Trace ID,
    # Correlation ID, and timestamp can accompany the incident. The helper never
    # prints the assertion or access token, and alert-event applies an additional
    # credential-shaped redaction pass before persistence or delivery.
    if token_result=$(/usr/local/libexec/mail-relay/refresh-smtp-token.py --min-remaining 1800 2>&1); then
      [[ -z $token_result ]] || printf '%s\n' "$token_result"
      # Recovery is harmless when no incident is open. Calling it on every
      # healthy pass also clears an incident that survived container restart,
      # when this process-local failure counter necessarily starts again at 0.
      /usr/local/libexec/mail-relay/alert.sh recover token-health \
        'Token check succeeded and the token file is current' || true
      failures=0
    else
      failures=$((failures + 1))
      [[ -z $token_result ]] || printf '%s\n' "$token_result" >&2
      log "token refresh failed ($failures consecutive)"
      if (( failures >= ${MAIL_TOKEN_ALERT_AFTER:-3} )); then
        /usr/local/libexec/mail-relay/alert.sh open error token-health \
          "Token refresh failed $failures consecutive times. Last safe diagnostic: ${token_result:-none}" || true
      fi
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
      /usr/local/libexec/mail-relay/alert.sh open error inbound-tls-health \
        'Inbound STARTTLS certificate renewal failed' || true
    else
      /usr/local/libexec/mail-relay/alert.sh recover inbound-tls-health \
        'Inbound STARTTLS certificate check or renewal completed successfully' || true
    fi
    if ! /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py \
      --validity "${MAIL_CERT_VALIDITY_DAYS:-730}" \
      --renew-at "${MAIL_CERT_RENEW_AT_DAYS:-$(( ${MAIL_CERT_VALIDITY_DAYS:-730} / 2 ))}" \
      --grace-days "${MAIL_CERT_GRACE_DAYS:-7}"; then
      /usr/local/libexec/mail-relay/alert.sh open error oauth-rotation-health \
        'OAuth application certificate rotation failed' || true
    else
      /usr/local/libexec/mail-relay/alert.sh recover oauth-rotation-health \
        'OAuth application certificate rotation check completed successfully' || true
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
run_role() {
  # Restartable roles run in their own session/process group.  The first live
  # supervisor used ordinary background functions.  Killing the function shell
  # while it waited left `sleep 300` reparented to PID 1; repeated crashes could
  # therefore accumulate invisible timers.  A dedicated process group gives
  # PID 1 one stable cleanup target even after the group's original leader has
  # already died.  This also handles SIGKILL, which no shell trap can catch.
  case "$1" in
    token) run_token_loop ;;
    rotation) run_rotation_loop ;;
    verify) run_verify_loop ;;
    log) tail -n 0 -F /var/log/mail-relay/postfix.log ;;
    *) log "unknown restartable role: $1"; return 64 ;;
  esac
}
spawn() {
  # Capture $! immediately. Writing the PID file is part of the observable
  # contract used by tests and operators; it also avoids fragile `pgrep`
  # matching when several Python loops have similar command lines.
  local role=$1
  case "$role" in
    postfix) /usr/sbin/postfix start-fg & ;;
    token|rotation|verify|log)
      # Re-enter this script instead of exporting Bash functions. Exported
      # functions are process-wide input interpreted by Bash and are needlessly
      # difficult to audit. `setsid` makes the returned PID both leader and PGID.
      setsid "$0" --run-role "$role" &
      ;;
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
  local pid role
  (( stopping == 0 )) || return
  stopping=1; log 'stopping children'
  postfix stop >/dev/null 2>&1 || true
  for pid in "${!role_by_pid[@]}"; do
    role=${role_by_pid[$pid]}
    if [[ $role == postfix ]]; then
      kill -TERM "$pid" 2>/dev/null || true
    else
      # Negative PID means process group. This terminates a role's current
      # sleep or subprocess as well as its shell, leaving nothing for PID 1 to
      # inherit and reap later.
      kill -TERM -- "-$pid" 2>/dev/null || true
    fi
  done
}
trap shutdown TERM INT

# Internal entry point used only by `spawn` above. A TERM trap makes a normal
# container stop quiet; group signalling still reaches the foreground sleep or
# helper, so the role cannot remain behind after this shell exits.
if [[ ${1:-} == --run-role ]]; then
  [[ -n ${2:-} ]] || exit 64
  trap 'exit 0' TERM INT
  run_role "$2"
  exit $?
fi

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
  # The leader is gone, but its process group can still contain a sleep or a
  # helper process. Clean that group before the replacement is created. This
  # ordering is the regression-critical part of SUP-001.
  kill -TERM -- "-$dead" 2>/dev/null || true
  log "$role exited ($status); restarting after ${MAIL_LOOP_RESTART_BACKOFF:-5}s"
  # The sleep itself is waited on so TERM interrupts the supervisor cleanly.
  # An earlier implementation used an uninterruptible foreground sleep; a
  # stop arriving during backoff could race into respawning a helper.
  sleep "${MAIL_LOOP_RESTART_BACKOFF:-5}" & wait $!
  (( stopping == 0 )) && spawn "$role"
done

for pid in "${!role_by_pid[@]}"; do wait "$pid" 2>/dev/null || true; done
exit "$exit_code"
