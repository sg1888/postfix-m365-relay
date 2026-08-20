#!/usr/bin/env python3
"""Create durable, operator-readable relay incidents and deliver notifications.

The state volume is the authority for incident identity and delivery retries.
That is important in a container: PID 1, Postfix, or the whole container may be
restarted while the underlying outage is still active.  A process-local counter
would forget the incident and page the administrator again after every restart.

No caller supplies prose for causes or remediation.  Those fields come from the
audited catalog below, while caller detail is treated as untrusted evidence and
redacted before it reaches disk, email, a webhook, or stdout.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import secrets
import smtplib
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


RUNBOOK_URL = os.environ.get(
    "MAIL_RUNBOOK_URL",
    "https://github.com/sg1888/postfix-m365-relay/blob/main/docs/RUNBOOK.md",
)
EVENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

# Event-specific guidance keeps messages useful without exposing raw config.
# The lists are deliberately short enough to read on a phone during an outage.
GUIDANCE: dict[str, dict[str, list[str]]] = {
    "token-health": {
        "causes": [
            "Entra or network connectivity is unavailable.",
            "The tenant, application ID, certificate, or Exchange scope is incorrect.",
            "A newly added application credential has not propagated yet.",
        ],
        "remediation": [
            "Check relay logs for the safe Microsoft error code and correlation IDs.",
            "Confirm the app certificate is current and authorized for the relay mailbox.",
            "Leave the persistent spool mounted; queued mail will retry after recovery.",
        ],
    },
    "relay-health": {
        "causes": [
            "Postfix is stopped, starting, or unable to create its SMTP listener.",
            "A generated configuration, filesystem, or port conflict blocked startup.",
        ],
        "remediation": [
            "Inspect container health and recent relay logs.",
            "Validate the persistent config, mounted secrets, and writable spool volume.",
        ],
    },
    "oauth-certificate-health": {
        "causes": [
            "The OAuth application certificate is missing, expired, or unreadable.",
            "Graph credential rotation or Microsoft propagation did not complete.",
        ],
        "remediation": [
            "Inspect the certificate-rotation audit log and list application keys.",
            "Do not delete an old credential until the new certificate mints a token and sends proof mail.",
        ],
    },
    "oauth-rotation-health": {
        "causes": [
            "Graph addKey/removeKey, propagation, proof delivery, or local atomic swap failed.",
            "The application certificate files or persistent state are unavailable.",
        ],
        "remediation": [
            "Inspect the rotation audit log and durable pending-key state.",
            "Keep the old credential active until a retry proves the replacement end to end.",
        ],
    },
    "inbound-tls-health": {
        "causes": [
            "The device-facing STARTTLS key or certificate is missing or mismatched.",
            "Managed certificate generation, validation, swap, or Postfix reload failed.",
        ],
        "remediation": [
            "Inspect the inbound-tls state directory and confirm the key/certificate pair matches.",
            "Restore the prior certificate if clients cannot negotiate STARTTLS.",
        ],
    },
    "inbound-tls-expiring": {
        "causes": [
            "A user-supplied STARTTLS certificate entered its configured renewal window.",
        ],
        "remediation": [
            "Renew the mounted certificate with its external ACME or certificate-management process.",
            "Recreate or signal the container, then verify the certificate served over STARTTLS.",
        ],
    },
    "ca-bundle-age": {
        "causes": ["The immutable image has not received current public root-CA updates."],
        "remediation": [
            "Pull a current image and recreate the container after normal testing.",
            "Do not update CA files manually inside the disposable container layer.",
        ],
    },
    "queue-depth-health": {
        "causes": ["Upstream delivery has failed long enough for the deferred queue to grow."],
        "remediation": [
            "Inspect postqueue output and safe Postfix delivery diagnostics.",
            "Correct the upstream cause; do not delete the persistent spool.",
        ],
    },
    "sasl-auth-health": {
        "causes": ["A device has repeatedly supplied a wrong username/password or an obsolete configuration."],
        "remediation": [
            "Identify the source IP in local logs and correct or revoke that device credential.",
            "Confirm AUTH is attempted only after STARTTLS.",
        ],
    },
    "alias-health": {
        "causes": ["An allowlisted passthrough address is not accepted by Microsoft 365 as a mailbox alias."],
        "remediation": [
            "Confirm the address is an actual alias of the scoped relay mailbox.",
            "Use collapse mode until SMTP XOAUTH2 app-only alias submission is proven.",
        ],
    },
    "push-monitor-health": {
        "causes": [
            "The configured external push-monitor endpoint is unavailable or rejected the request.",
            "Its per-category token, URL, DNS, TLS trust, or firewall route changed.",
        ],
        "remediation": [
            "Check the independent monitor service and network path without printing its secret token.",
            "Keep email and the incident webhook configured as separate notification paths.",
        ],
    },
}
GENERIC_GUIDANCE = {
    "causes": ["The affected component reported the evidence shown below."],
    "remediation": ["Inspect the referenced component logs and follow the relay runbook."],
}


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    """Publish private JSON without ever exposing a partially written record."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
        return value if isinstance(value, dict) else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def redact(value: str) -> str:
    """Retain useful Microsoft references while removing credential-shaped text."""
    text = value.replace("\x00", "")[:8000]
    patterns = (
        (r"(?i)(bearer\s+)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)((?:access_token|client_assertion|client_secret|password)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]"),
        (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED-JWT]"),
        (r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[REDACTED-PEM]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    return text


def timestamp(epoch: float, zone: timezone | ZoneInfo) -> str:
    return datetime.fromtimestamp(epoch, zone).isoformat(timespec="seconds")


def configured_zone() -> timezone | ZoneInfo:
    try:
        return ZoneInfo(os.environ.get("TZ", "UTC"))
    except ZoneInfoNotFoundError:
        return timezone.utc


def reference_id(now: float) -> str:
    return f"PMR-{datetime.fromtimestamp(now, timezone.utc):%Y%m%d}-{secrets.token_hex(4).upper()}"


def build_payload(
    incident: dict[str, Any], status: str, now: float, detail: str
) -> dict[str, Any]:
    zone = configured_zone()
    guidance = GUIDANCE.get(incident["event"], GENERIC_GUIDANCE)
    first = float(incident["first_observed_epoch"])
    payload: dict[str, Any] = {
        "schema_version": 1,
        "application": "postfix-m365-relay",
        "relay": os.environ.get("MAIL_RELAY_HOSTNAME") or socket.gethostname(),
        "status": status,
        "severity": incident["severity"],
        "event": incident["event"],
        "reference_id": incident["reference_id"],
        "first_observed_utc": timestamp(first, timezone.utc),
        "observed_utc": timestamp(now, timezone.utc),
        "observed_local": timestamp(now, zone),
        "timezone": str(getattr(zone, "key", "UTC")),
        "duration_seconds": max(0, int(now - first)),
        "occurrence_count": int(incident.get("occurrence_count", 1)),
        "summary": f"{incident['event']} is {status}",
        "evidence": redact(detail),
        "likely_causes": guidance["causes"],
        "remediation": guidance["remediation"],
        "runbook_url": RUNBOOK_URL,
    }
    if status == "recovered":
        payload["recovered_utc"] = timestamp(now, timezone.utc)
        payload["recovered_local"] = timestamp(now, zone)
    return payload


def email_body(payload: dict[str, Any]) -> str:
    causes = "\n".join(f"- {item}" for item in payload["likely_causes"])
    remedies = "\n".join(f"- {item}" for item in payload["remediation"])
    recovered = ""
    if payload["status"] == "recovered":
        recovered = f"Recovered (UTC): {payload['recovered_utc']}\nRecovered (local): {payload['recovered_local']}\n"
    return (
        f"Status: {payload['status']}\nSeverity: {payload['severity']}\n"
        f"Event: {payload['event']}\nReference: {payload['reference_id']}\n"
        f"Relay: {payload['relay']}\nFirst observed (UTC): {payload['first_observed_utc']}\n"
        f"Observed (UTC): {payload['observed_utc']}\nObserved (local): {payload['observed_local']} "
        f"[{payload['timezone']}]\n{recovered}Duration: {payload['duration_seconds']} seconds\n"
        f"Occurrences: {payload['occurrence_count']}\n\nEvidence\n{payload['evidence']}\n\n"
        f"Likely causes\n{causes}\n\nSuggested actions\n{remedies}\n\nRunbook\n{payload['runbook_url']}\n"
    )


def deliver_email(payload: dict[str, Any]) -> tuple[bool, str]:
    recipient = os.environ.get("MAIL_ADMIN_EMAIL", "")
    if not recipient:
        return True, "disabled"
    message = EmailMessage()
    message["From"] = os.environ.get("MAIL_SEND_MAILBOX", "postfix-m365-relay@localhost")
    message["To"] = recipient
    subject_marker = "recovered" if payload["status"] == "recovered" else payload["severity"]
    message["Subject"] = (
        f"[{subject_marker}] postfix-m365-relay {payload['status']}: "
        f"{payload['event']} ({payload['reference_id']})"
    )
    message.set_content(email_body(payload))
    try:
        with smtplib.SMTP("127.0.0.1", int(os.environ.get("RELAY_PORT", "2525")), timeout=15) as smtp:
            smtp.send_message(message)
        return True, "accepted by local Postfix"
    except (OSError, smtplib.SMTPException) as error:
        return False, f"{type(error).__name__}: {error}"


def deliver_webhook(payload: dict[str, Any]) -> tuple[bool, str]:
    target = os.environ.get("MAIL_ALERT_WEBHOOK", "")
    if not target:
        return True, "disabled"
    request = urllib.request.Request(
        target,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if not 200 <= response.status < 300:
                return False, f"HTTP {response.status}"
        return True, "HTTP success"
    except Exception as error:  # urllib wraps DNS, timeout, TLS, and HTTP failures differently.
        return False, f"{type(error).__name__}: {error}"


def audit(message: str) -> None:
    print(f"{timestamp(time.time(), timezone.utc)} alert-event: {message}", flush=True)


def attempt_outbox(outbox: Path) -> bool:
    """Try each pending channel independently; never let one suppress the other."""
    record = read_json(outbox)
    if not record:
        return True
    payload = record["payload"]
    all_ok = True
    now = time.time()
    for channel, function in (("email", deliver_email), ("webhook", deliver_webhook)):
        pending_key = f"{channel}_pending"
        if not record.get(pending_key, False):
            continue
        # A dead SMTP listener or webhook must not make every verifier category
        # wait on another network timeout. Persist exponential retry timing per
        # channel; a newly created notification still gets one immediate try.
        if now < float(record.get(f"{channel}_next_attempt_epoch", 0)):
            all_ok = False
            continue
        ok, result = function(payload)
        audit(f"reference={payload['reference_id']} status={payload['status']} channel={channel} result={redact(result)}")
        if ok:
            record[pending_key] = False
        else:
            attempts_key = f"{channel}_attempts"
            attempts = int(record.get(attempts_key, 0)) + 1
            record[attempts_key] = attempts
            record[f"{channel}_next_attempt_epoch"] = now + min(3600, 30 * (2 ** min(attempts - 1, 7)))
            all_ok = False
    if record.get("email_pending") or record.get("webhook_pending"):
        atomic_json(outbox, record)
    else:
        outbox.unlink(missing_ok=True)
    return all_ok


def queue_notification(root: Path, payload: dict[str, Any], now: float) -> Path | None:
    email_enabled = bool(os.environ.get("MAIL_ADMIN_EMAIL"))
    webhook_enabled = bool(os.environ.get("MAIL_ALERT_WEBHOOK"))
    if not email_enabled and not webhook_enabled:
        audit(f"reference={payload['reference_id']} status={payload['status']} channels=none local-audit-only")
        return None
    safe_status = payload["status"].replace("-", "_")
    path = root / "outbox" / f"{int(now * 1000)}-{payload['reference_id']}-{safe_status}.json"
    atomic_json(
        path,
        {
            "payload": payload,
            "email_pending": email_enabled,
            "webhook_pending": webhook_enabled,
            "email_attempts": 0,
            "webhook_attempts": 0,
            "email_next_attempt_epoch": 0,
            "webhook_next_attempt_epoch": 0,
        },
    )
    return path


def retry_outbox(root: Path) -> bool:
    ok = True
    for path in sorted((root / "outbox").glob("*.json")):
        ok = attempt_outbox(path) and ok
    return ok


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    opened = commands.add_parser("open")
    opened.add_argument("severity", choices=("info", "warning", "error"))
    opened.add_argument("event")
    opened.add_argument("detail")
    recovered = commands.add_parser("recover")
    recovered.add_argument("event")
    recovered.add_argument("validation")
    notice = commands.add_parser("notify")
    notice.add_argument("severity", choices=("info", "warning", "error"))
    notice.add_argument("event")
    notice.add_argument("detail")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not EVENT_RE.fullmatch(args.event):
        raise SystemExit("event must contain only lowercase letters, digits, and hyphens")
    root = Path(os.environ.get("MAIL_ALERT_STATE_DIR", "/var/lib/mail-relay/alerts"))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = root / ".lock"
    now = time.time()
    with lock_path.open("a+") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        delivery_ok = retry_outbox(root)
        incident_path = root / "incidents" / f"{args.event}.json"
        incident = read_json(incident_path)

        if args.command == "open":
            if incident:
                incident["occurrence_count"] = int(incident.get("occurrence_count", 1)) + 1
                incident["last_observed_epoch"] = now
                incident["last_evidence"] = redact(args.detail)
                atomic_json(incident_path, incident)
                audit(
                    f"reference={incident['reference_id']} status=open event={args.event} "
                    f"duplicate-suppressed count={incident['occurrence_count']}"
                )
                return 0 if delivery_ok else 1
            incident = {
                "event": args.event,
                "severity": args.severity,
                "reference_id": reference_id(now),
                "first_observed_epoch": now,
                "last_observed_epoch": now,
                "occurrence_count": 1,
                "last_evidence": redact(args.detail),
            }
            atomic_json(incident_path, incident)
            payload = build_payload(incident, "open", now, args.detail)
        elif args.command == "recover":
            if not incident:
                return 0 if delivery_ok else 1
            payload = build_payload(incident, "recovered", now, args.validation)
            incident_path.unlink(missing_ok=True)
        else:
            incident = {
                "event": args.event,
                "severity": args.severity,
                "reference_id": reference_id(now),
                "first_observed_epoch": now,
                "occurrence_count": 1,
            }
            payload = build_payload(incident, "notification", now, args.detail)

        outbox = queue_notification(root, payload, now)
        if outbox is not None:
            delivery_ok = attempt_outbox(outbox) and delivery_ok
        return 0 if delivery_ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Operational failures must be concise. A traceback can contain request
        # bodies or paths and obscured the actionable Entra error in live tests.
        print(f"alert-event: FAILED: {redact(str(error))}", file=sys.stderr)
        raise SystemExit(1)
