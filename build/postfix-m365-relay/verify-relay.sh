#!/usr/bin/env bash
# Periodic health audit. Checks are grouped by operator-facing failure domain so
# push monitors can report relay, token, certificate, and rotation separately.
# Warnings (queue depth, inbound cert age) do not declare the relay down.
set -uo pipefail

failures=() warnings=()
declare -A category_failed=([relay]=0 [token]=0 [certificate]=0 [rotation]=0)
declare -A category_message=([relay]='listener not checked' [token]='token not checked' [certificate]='certificate not checked' [rotation]='rotation not checked')
say() { printf '%s verify-relay: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
bad() { local category=$1; shift; failures+=("$*"); category_failed[$category]=1; category_message[$category]="$*"; say "FAILED $category: $*"; }
warn() { warnings+=("$*"); say "warning: $*"; }
warn_and_alert_periodically() {
  # Warnings such as an aging CA bundle should not mark SMTP unhealthy, but a
  # log-only warning can remain invisible for years. Persist one tiny timestamp
  # per event so email/webhook notification repeats weekly without firing on
  # every hourly verifier pass. The marker contains no credential or mail data.
  local event=$1 detail=$2 repeat_days=${3:-7} now marker last=0 temporary
  now=$(date +%s)
  marker=${STATE_DIR:-/var/lib/mail-relay}/.warning-$event-epoch
  [[ -r $marker ]] && read -r last < "$marker"
  [[ $last =~ ^[0-9]+$ ]] || last=0
  if (( now - last >= repeat_days * 86400 )); then
    /usr/local/libexec/mail-relay/alert.sh warning "$event" "$detail" || true
    temporary=$marker.tmp.$$
    printf '%s\n' "$now" > "$temporary"
    mv -f -- "$temporary" "$marker"
  fi
}
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

if [[ ${MAIL_INBOUND_TLS:-off} != off && -n ${MAIL_INBOUND_TLS_CERT_EFFECTIVE:-} ]]; then
  openssl x509 -checkend $((30*86400)) -noout -in "$MAIL_INBOUND_TLS_CERT_EFFECTIVE" >/dev/null 2>&1 || warn 'inbound TLS certificate expires within 30 days'
fi

# A running image is immutable: its public root store does not receive distro
# updates in place. This age check is intentionally based on RPM install time,
# not individual root expiry dates; trust stores also remove distrusted roots
# and add new intermediates, neither of which an expiry-only scan can detect.
ca_install_epoch=$(rpm -q --qf '%{INSTALLTIME}' ca-certificates 2>/dev/null || true)
ca_max_age_days=${MAIL_CA_BUNDLE_MAX_AGE_DAYS:-90}
if [[ $ca_install_epoch =~ ^[0-9]+$ && $ca_max_age_days =~ ^[0-9]+$ ]]; then
  ca_age_days=$(( ($(date +%s) - ca_install_epoch) / 86400 ))
  if (( ca_age_days > ca_max_age_days )); then
    ca_detail="image CA bundle is ${ca_age_days} days old; rebuild, test, pull, and recreate the container"
    warn "$ca_detail"
    warn_and_alert_periodically ca-bundle-age "$ca_detail" 7
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
(( queue_depth <= ${MAIL_QUEUE_WARN_DEPTH:-25} )) || warn "deferred queue has $queue_depth messages"
log_file=/var/log/mail-relay/postfix.log
if [[ -r $log_file ]]; then
  sasl_failures=$(tail -n 2000 "$log_file" | grep -Eci 'SASL.*(fail|authentication failed)|authentication failure' || true)
  (( sasl_failures <= ${MAIL_SASL_FAILURE_WARN_COUNT:-10} )) || warn "$sasl_failures recent SASL failures"
fi

if [[ -n ${MAIL_ADMIN_EMAIL:-} && ${MAIL_VERIFY_SEND:-yes} == yes ]]; then
  # Acceptance by localhost is not delivery. Correlate a unique Message-ID with
  # Postfix's log and require a sent result before claiming end-to-end success.
  sender=$MAIL_SEND_MAILBOX
  message_id="verify-$(date +%s)-$$@${MAIL_RELAY_DOMAIN:-relay.example.local}"
  if submit_probe "$sender" 'postfix-m365-relay hourly verification' "$message_id"
  then
    if wait_for_sent_message "$message_id" "${MAIL_VERIFY_DELIVERY_WAIT_SECONDS:-15}"; then category_message[relay]="end-to-end probe accepted and its delivery was sent"
    else warn 'end-to-end probe was accepted but delivery was not observed yet'; fi
  else bad relay 'end-to-end probe was refused at local submission'; fi
fi

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
      bad relay "passthrough alias $alias was refused at local submission"
    elif ! wait_for_sent_message "$alias_id" "${MAIL_VERIFY_DELIVERY_WAIT_SECONDS:-15}"; then
      bad relay "passthrough alias $alias was not observed delivered"
    else
      say "alias verified by upstream delivery: $alias"
    fi
  done
fi

push_base=${MAIL_RELAY_PUSH_BASE:-}
# Push tokens are individual mounted files so exposing one monitor does not
# expose the others. The status message is character-filtered before entering a
# URL; bearer tokens, mail content, and raw log lines are never transmitted.
if [[ -n $push_base ]]; then
  for category in relay token certificate rotation; do
    secret=/run/secrets/push_token_${category}
    [[ -s $secret ]] || continue
    push_token=$(tr -d '\r\n' < "$secret"); status=up; (( category_failed[$category] == 0 )) || status=down
    message=$(printf %s "${category_message[$category]}" | tr ' ' '+' | tr -cd 'A-Za-z0-9+._:;,()-')
    curl -fsS --max-time 15 "$push_base/$push_token?status=$status&msg=$message" >/dev/null || warn "could not reach $category push monitor"
  done
fi

if (( ${#failures[@]} > 0 )); then
  /usr/local/libexec/mail-relay/alert.sh error verification "${failures[*]}" || true
  exit 1
fi
say "healthy (${#warnings[@]} warning(s))"
