#!/usr/bin/env bash
# Periodic health audit. Checks are grouped by operator-facing failure domain so
# push monitors can report relay, token, certificate, and rotation separately.
# Warnings (queue depth, inbound cert age) do not declare the relay down.
set -uo pipefail

failures=() warnings=()
declare -A category_failed=([relay]=0 [token]=0 [certificate]=0 [rotation]=0)
declare -A category_message=([relay]='listener not checked' [token]='token not checked' [certificate]='certificate not checked' [rotation]='rotation not checked')
declare -A category_event=([relay]=relay-health [token]=token-health [certificate]=oauth-certificate-health [rotation]=oauth-rotation-health)
say() { printf '%s verify-relay: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
bad() { local category=$1; shift; failures+=("$*"); category_failed[$category]=1; category_message[$category]="$*"; say "FAILED $category: $*"; }
warn() { warnings+=("$*"); say "warning: $*"; }
submit_probe() {
  local from=$1 subject=$2 message_id=$3
  VERIFY_FROM=$from VERIFY_TO=$MAIL_ADMIN_EMAIL VERIFY_SUBJECT=$subject VERIFY_ID=$message_id python3 - <<'PY'
import os, smtplib
from email.message import EmailMessage
m = EmailMessage()
m["From"] = os.environ["VERIFY_FROM"]
m["To"] = os.environ["VERIFY_TO"]
m["Subject"] = os.environ["VERIFY_SUBJECT"]
m["Message-ID"] = "<" + os.environ["VERIFY_ID"] + ">"
m.set_content("Automated end-to-end relay verification.\n")
with smtplib.SMTP("127.0.0.1", int(os.environ.get("RELAY_PORT", "2525")), timeout=15) as smtp:
    smtp.send_message(m)
PY
}
wait_for_sent_message() {
  local message_id=$1 wait_seconds=${2:-15} queue_id=''
  # Correlate cleanup's Message-ID to its Postfix queue ID, then require the
  # same queue ID on status=sent. Looking for these independently caused a
  # false positive whenever an older unrelated message had been delivered.
  for ((_second=0; _second<wait_seconds; _second++)); do
    queue_id=$(grep -F "message-id=<$message_id>" "$log_file" 2>/dev/null | tail -n 1 | \
      sed -n 's/.*: \([A-F0-9][A-F0-9]*\): message-id=.*/\1/p')
    if [[ -n $queue_id ]] && grep -Eq "${queue_id}: .*status=sent" "$log_file"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

port=${RELAY_PORT:-2525}; token=${MAIL_TOKEN_FILE:-/run/mail-relay/relay.json}
# Postfix and the verifier start concurrently. The first implementation checked
# once and emitted a false alarm during normal startup; a bounded ten-second
# readiness window retains fast failure reporting without racing the listener.
listener_ready=0
for _attempt in {1..10}; do
  if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port; read -r -t 2 line <&3; [[ \$line == 220* ]]" 2>/dev/null; then listener_ready=1; break; fi
  sleep 1
done
if (( listener_ready )); then
  category_message[relay]="SMTP listener answers on $port"
else bad relay "SMTP listener does not answer on $port"; fi

if [[ -s $token ]]; then
  # Parse JSON in Python instead of grepping bearer-token material. Only the
  # derived lifetime crosses back into the shell or appears in logs.
  token_reading=$(TOKEN_PATH=$token python3 - <<'PY' 2>/dev/null
import json, os, time
p=json.load(open(os.environ["TOKEN_PATH"])); print(int(p.get("expiry",0))-int(time.time()))
PY
)
  if [[ $token_reading =~ ^-?[0-9]+$ ]] && (( token_reading > 900 )); then category_message[token]="token valid for ${token_reading}s"
  else bad token "token expires too soon (${token_reading:-unreadable}s)"; fi
else bad token "token file is absent"; fi

oauth_cert=${MAIL_RELAY_CERT_FILE:-/var/lib/mail-relay/secrets/mail_relay_client_cert.pem}
if [[ -s $oauth_cert ]]; then
  if openssl x509 -checkend $((30*86400)) -noout -in "$oauth_cert" >/dev/null 2>&1; then
    expiry=$(openssl x509 -enddate -noout -in "$oauth_cert" | cut -d= -f2-); category_message[certificate]="OAuth certificate expires $expiry"
  elif openssl x509 -checkend 0 -noout -in "$oauth_cert" >/dev/null 2>&1; then bad certificate 'OAuth certificate expires within 30 days'
  else bad certificate 'OAuth certificate is expired or unreadable'; fi
else bad certificate 'OAuth certificate is absent'; fi

# Repeat the "upload a certificate to Entra" banner at the verifier's cadence
# (hourly by default) whenever an upload is still outstanding, so the notice
# stays legible and does not drown in failed-delivery lines. No-op when none.
/usr/local/libexec/mail-relay/cert-action.sh remind || true

if [[ ${MAIL_INBOUND_TLS:-off} != off && -n ${MAIL_INBOUND_TLS_CERT_EFFECTIVE:-} ]]; then
  if openssl x509 -checkend $((30*86400)) -noout -in "$MAIL_INBOUND_TLS_CERT_EFFECTIVE" >/dev/null 2>&1; then
    /usr/local/libexec/mail-relay/alert.sh recover inbound-tls-expiring \
      'The inbound STARTTLS certificate is outside the 30-day warning window' || true
  else
    warn 'inbound TLS certificate expires within 30 days'
    /usr/local/libexec/mail-relay/alert.sh open warning inbound-tls-expiring \
      'Inbound STARTTLS certificate expires within 30 days' || true
  fi
else
  # If an operator disables inbound TLS after an expiry warning, that warning
  # no longer describes an active condition. Clear it explicitly instead of
  # leaving a stale incident in the persistent state volume.
  /usr/local/libexec/mail-relay/alert.sh recover inbound-tls-expiring \
    'Inbound STARTTLS is disabled; no server certificate requires renewal' || true
fi

# A running image is immutable: its public root store does not receive distro
# updates in place. This age check is intentionally based on package install time,
# not individual root expiry dates; trust stores also remove distrusted roots
# and add new intermediates, neither of which an expiry-only scan can detect.
if command -v rpm >/dev/null 2>&1; then
  ca_install_epoch=$(rpm -q --qf '%{INSTALLTIME}' ca-certificates 2>/dev/null || true)
elif command -v dpkg-query >/dev/null 2>&1; then
  # Debian/Ubuntu carry no package install-time field. Approximate the trust
  # store's vintage with the mtime of the package changelog, which dpkg preserves
  # from the .deb (the package build date, not our install moment) and which
  # advances whenever ca-certificates is updated — matching the intent of
  # flagging a stale bundle rather than a freshly rebuilt image.
  ca_doc=$(ls -t /usr/share/doc/ca-certificates/changelog*.gz 2>/dev/null | head -n1)
  ca_install_epoch=$(stat -c %Y "$ca_doc" 2>/dev/null || true)
else
  ca_install_epoch=
fi
ca_max_age_days=${MAIL_CA_BUNDLE_MAX_AGE_DAYS:-90}
if [[ $ca_install_epoch =~ ^[0-9]+$ && $ca_max_age_days =~ ^[0-9]+$ ]]; then
  ca_age_days=$(( ($(date +%s) - ca_install_epoch) / 86400 ))
  if (( ca_age_days > ca_max_age_days )); then
    ca_detail="image CA bundle is ${ca_age_days} days old; rebuild, test, pull, and recreate the container"
    warn "$ca_detail"
    /usr/local/libexec/mail-relay/alert.sh open warning ca-bundle-age "$ca_detail" || true
  else
    /usr/local/libexec/mail-relay/alert.sh recover ca-bundle-age \
      "Image CA bundle age is within the configured ${ca_max_age_days}-day limit" || true
  fi
else
  bad certificate 'could not determine CA-bundle package age or MAIL_CA_BUNDLE_MAX_AGE_DAYS is invalid'
fi

rotation_log=${MAIL_ROTATION_LOG_FILE:-/var/lib/mail-relay/cert-rotation.log}
# Rotation writes JSON Lines atomically by event. The last event is the current
# actionable state and is safe to include in an alert (it contains no key/token).
if [[ -s $rotation_log ]]; then
  last_rotation=$(tail -n 1 "$rotation_log")
  if grep -q '"outcome": "FAILED"' <<<"$last_rotation"; then bad rotation "last rotation event failed: $last_rotation"
  else category_message[rotation]="last event: $last_rotation"; fi
else category_message[rotation]='no rotation has been required yet'; fi

queue_depth=$(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l | tr -d ' ')
if (( queue_depth > ${MAIL_QUEUE_WARN_DEPTH:-25} )); then
  warn "deferred queue has $queue_depth messages"
  /usr/local/libexec/mail-relay/alert.sh open warning queue-depth-health \
    "Deferred queue has $queue_depth messages; warning threshold is ${MAIL_QUEUE_WARN_DEPTH:-25}" || true
else
  /usr/local/libexec/mail-relay/alert.sh recover queue-depth-health \
    "Deferred queue recovered to $queue_depth messages" || true
fi
log_file=/var/log/mail-relay/postfix.log
if [[ -r $log_file ]]; then
  sasl_failures=$(tail -n 2000 "$log_file" | grep -Eci 'SASL.*(fail|authentication failed)|authentication failure' || true)
  if (( sasl_failures > ${MAIL_SASL_FAILURE_WARN_COUNT:-10} )); then
    warn "$sasl_failures recent SASL failures"
    /usr/local/libexec/mail-relay/alert.sh open warning sasl-auth-health \
      "$sasl_failures recent SASL failures exceed threshold ${MAIL_SASL_FAILURE_WARN_COUNT:-10}" || true
  else
    /usr/local/libexec/mail-relay/alert.sh recover sasl-auth-health \
      "Recent SASL failures are within threshold (${sasl_failures:-0})" || true
  fi
fi

# End-to-end delivery probe. OFF by default: when enabled it sends one real
# email through the relay to MAIL_ADMIN_EMAIL every verify cycle
# (MAIL_VERIFY_LOOP_SECONDS, default hourly), so leaving it on would mail the
# administrator on a fixed interval forever -- unacceptable in production. It
# exists purely as a TEST: a bring-up or troubleshooting tool that proves the
# whole path (local submit -> XOAUTH2 AUTH -> Microsoft accept) actually
# delivers, which no internal check can confirm. The other verify checks (token
# freshness, certificate, rotation, queue, SASL failures) always run regardless
# and never send mail. Turn this on deliberately (MAIL_VERIFY_SEND=yes) while
# validating a deployment, watch for the probe to arrive, then turn it back off.
if [[ -n ${MAIL_ADMIN_EMAIL:-} && ${MAIL_VERIFY_SEND:-no} == yes ]]; then
  # Acceptance by localhost is not delivery. Correlate a unique Message-ID with
  # Postfix's log and require a sent result before claiming end-to-end success.
  sender=$MAIL_SEND_MAILBOX
  message_id="verify-$(date +%s)-$$@${MAIL_RELAY_DOMAIN:-relay.example.local}"
  if submit_probe "$sender" 'postfix-m365-relay end-to-end verification (test probe)' "$message_id"
  then
    if wait_for_sent_message "$message_id" "${MAIL_VERIFY_DELIVERY_WAIT_SECONDS:-15}"; then category_message[relay]="end-to-end probe accepted and its delivery was sent"
    else warn 'end-to-end probe was accepted but delivery was not observed yet'; fi
  else bad relay 'end-to-end probe was refused at local submission'; fi
fi

alias_failed=0
alias_evidence='All configured passthrough alias probes were observed sent'
if [[ ${MAIL_SENDER_MODE:-collapse} == passthrough && -n ${MAIL_PASSTHROUGH_SENDERS:-} && -n ${MAIL_ADMIN_EMAIL:-} ]]; then
  # This is the recurring tenant-side validity check for passthrough aliases.
  # Local map tests cannot prove Exchange accepts an alias with app-only OAuth;
  # only a queue-correlated status=sent does. An invalid allowlist entry therefore
  # alerts rather than bouncing application mail or silently collapsing it.
  IFS=$',; \t\n' read -ra alias_candidates <<<"$MAIL_PASSTHROUGH_SENDERS"
  for alias in "${alias_candidates[@]}"; do
    [[ -n $alias ]] || continue
    alias_id="verify-alias-$(date +%s)-$RANDOM-$$@${MAIL_RELAY_DOMAIN:-relay.example.local}"
    if ! submit_probe "$alias" "postfix-m365-relay alias verification: $alias" "$alias_id"; then
      alias_failed=1; alias_evidence="passthrough alias $alias was refused at local submission"
      failures+=("$alias_evidence"); say "FAILED alias: $alias_evidence"
    elif ! wait_for_sent_message "$alias_id" "${MAIL_VERIFY_DELIVERY_WAIT_SECONDS:-15}"; then
      alias_failed=1; alias_evidence="passthrough alias $alias was not observed delivered"
      failures+=("$alias_evidence"); say "FAILED alias: $alias_evidence"
    else
      say "alias verified by upstream delivery: $alias"
    fi
  done
fi
if (( alias_failed )); then
  /usr/local/libexec/mail-relay/alert.sh open error alias-health "$alias_evidence" || true
else
  /usr/local/libexec/mail-relay/alert.sh recover alias-health "$alias_evidence" || true
fi

push_base=${MAIL_RELAY_PUSH_BASE:-}
push_failed=0
push_evidence='All configured push monitors accepted their current status'
# Push tokens are individual mounted files so exposing one monitor does not
# expose the others. The status message is character-filtered before entering a
# URL; bearer tokens, mail content, and raw log lines are never transmitted.
if [[ -n $push_base ]]; then
  for category in relay token certificate rotation; do
    secret=/run/secrets/push_token_${category}
    [[ -s $secret ]] || continue
    push_token=$(tr -d '\r\n' < "$secret"); status=up; (( category_failed[$category] == 0 )) || status=down
    message=$(printf %s "${category_message[$category]}" | tr ' ' '+' | tr -cd 'A-Za-z0-9+._:;,()-')
    if ! curl -fsS --max-time 15 "$push_base/$push_token?status=$status&msg=$message" >/dev/null; then
      push_failed=1; push_evidence="could not reach $category push monitor"
      warn "$push_evidence"
    fi
  done
fi
if (( push_failed )); then
  /usr/local/libexec/mail-relay/alert.sh open warning push-monitor-health "$push_evidence" || true
else
  /usr/local/libexec/mail-relay/alert.sh recover push-monitor-health "$push_evidence" || true
fi

# Every hard-failure category owns one durable incident. The token verifier and
# token refresh loop intentionally share token-health, preventing the same Entra
# outage from producing competing threshold and "token absent" notifications.
for category in relay token certificate rotation; do
  event=${category_event[$category]}
  if (( category_failed[$category] )); then
    /usr/local/libexec/mail-relay/alert.sh open error "$event" \
      "${category_message[$category]}" || true
  else
    /usr/local/libexec/mail-relay/alert.sh recover "$event" \
      "${category_message[$category]}" || true
  fi
done

(( ${#failures[@]} == 0 )) || exit 1
say "healthy (${#warnings[@]} warning(s))"
