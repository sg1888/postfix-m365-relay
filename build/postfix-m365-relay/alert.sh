#!/usr/bin/env bash
# Deliver a small operational alert through the relay and/or an HTTP webhook.
# Arguments are data, never shell-evaluated. JSON is produced by the standard
# library so quotes, backslashes, Unicode, and newlines cannot corrupt payloads.
set -euo pipefail
severity=${1:-info}; event=${2:-relay}; detail=${3:-No detail supplied}
subject="[$severity] postfix-m365-relay: $event"

if [[ -n ${MAIL_ADMIN_EMAIL:-} ]]; then
  # Use localhost rather than Microsoft directly. This exercises the same queue
  # and OAuth transport as application mail and preserves deferred delivery.
  ALERT_SUBJECT=$subject ALERT_DETAIL=$detail python3 - <<'PY'
import os, smtplib
from email.message import EmailMessage
m = EmailMessage()
m["From"] = os.environ["MAIL_SEND_MAILBOX"]
m["To"] = os.environ["MAIL_ADMIN_EMAIL"]
m["Subject"] = os.environ["ALERT_SUBJECT"]
m.set_content(os.environ["ALERT_DETAIL"] + "\n")
with smtplib.SMTP("127.0.0.1", int(os.environ.get("RELAY_PORT", "2525")), timeout=15) as s:
    s.send_message(m)
PY
fi

if [[ -n ${MAIL_ALERT_WEBHOOK:-} ]]; then
  payload=$(SEVERITY=$severity EVENT=$event DETAIL=$detail python3 - <<'PY'
import json, os
print(json.dumps({"severity": os.environ["SEVERITY"], "event": os.environ["EVENT"], "detail": os.environ["DETAIL"]}))
PY
)
  curl -fsS --max-time 15 -X POST -H 'Content-Type: application/json' --data "$payload" "$MAIL_ALERT_WEBHOOK" >/dev/null
fi
