#!/usr/bin/env python3
"""Rotate the mail relay's certificate before it expires, without a human.

The certificate is the only credential the relay has, and it lasts two years.
Renewing it by hand means a diary entry that has to survive two years and a
person who remembers what to do. This does it on a timer instead.

WHY THIS IS POSSIBLE AT ALL

Microsoft documents that "an application doesn't need any specific permission to
roll its own keys". Authorisation comes from a proof-of-possession JWT signed by
a certificate the application already holds, not from a Graph permission. So the
relay can replace its own credential without being granted a general-purpose
application-management permission. The implementation confirms every add and
remove by reading the application state instead of trusting one HTTP response.

THE ONE-WAY DOOR

  "Applications that don't have any existing valid certificates (no certificates
   have been added yet, or all certificates have expired), won't be able to use
   this service action."

If every certificate expires, self-rotation is permanently dead and recovery is
a human in a browser. That is why this rotates early rather than near the wire,
and why a failure is an alert rather than a log line.

HOW EARLY, AND WHY HALF

--renew-at defaults to half of --validity: a 730-day certificate is replaced
after roughly 365 days.

Half is chosen because the cost of rotating early is one Graph call, and the
cost of rotating late is unbounded -- past expiry there is no automated recovery
at all. Half also leaves a full year of retries: the timer runs daily, so a
rotation that fails every single day for a year still has not put the credential
at risk, and the supervised verifier has been alerting since the first failure.
A 90-day margin gave 90 attempts; half gives 365, for the same work.

Set --renew-at explicitly to override. Keeping it derived from --validity means
changing the validity cannot silently leave the threshold behind.

THE ORDER, AND WHY

Each step is reversible until the one after it. Nothing is swapped until the new
certificate has been proven to work end to end, and the old certificate is not
removed in the same run that adds the new one -- a problem found the next day can
still be rolled back by putting the old thumbprint back.

  1. check days remaining; do nothing if there is time
  2. generate a new key and certificate to a staging path; live files untouched
  3. addKey, authorised by the current certificate
  4. wait for the directory to catch up (writes are eventually consistent, about
     20 seconds observed; an immediate read shows nothing and looks like failure)
  5. prove the new certificate: mint a token with it and send a real message
  6. only now swap the files and update the thumbprint
  7. removeKey for the old certificate happens on a LATER run, after the grace
     period, never in this one

Run by the container's rotation loop. Every outcome is appended to the rotation
log and surfaced by verify-relay.sh, because a rotation that fails silently is
indistinguishable from one that never needed to run.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import smtplib
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

LOGIN = "https://login.microsoftonline.com"
GRAPH = "https://graph.microsoft.com"
OUTLOOK_SCOPE = "https://outlook.office365.com/.default"
# Fixed by Microsoft for proof-of-possession tokens. Not the Graph resource ID,
# and not the application's own ID; one of the easier things to get wrong here.
PROOF_AUDIENCE = "00000002-0000-0000-c000-000000000000"
# Defaults only; overridden by loaded configuration or environment variables.
SMTP_HOST = "smtp.office365.com"
SMTP_PORT = 587


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def credential_thumbprint(credential: dict) -> str:
    """SHA-1 thumbprint of a keyCredential, whatever encoding Graph used.

    customKeyIdentifier is documented as base64 of the thumbprint, but this
    tenant returns the hex string. Both have been seen. Getting it wrong means
    comparing a thumbprint against something that can never match, which is how
    the live certificate once got labelled an orphan.
    """
    identifier = credential.get("customKeyIdentifier") or ""
    candidate = identifier.strip().replace(":", "").upper()
    if len(candidate) == 40 and all(c in "0123456789ABCDEF" for c in candidate):
        return candidate
    try:
        return base64.b64decode(identifier).hex().upper()
    except Exception:  # noqa: BLE001
        return ""


class Rotation:
    def __init__(self, project: Path, env: dict[str, str], log_path: Path, dry_run: bool):
        self.project = project
        self.env = env
        self.log_path = log_path
        self.dry_run = dry_run
        self.tenant = env["MAIL_RELAY_TENANT"]
        self.client_id = env["MAIL_RELAY_CLIENT_ID"]
        self.mailbox = env["MAIL_SEND_MAILBOX"]
        self.key_path = Path(env.get("MAIL_RELAY_KEY_FILE", "/var/lib/mail-relay/secrets/mail_relay_client_key.pem"))
        self.cert_path = Path(env.get("MAIL_RELAY_CERT_FILE", "/var/lib/mail-relay/secrets/mail_relay_client_cert.pem"))
        if not self.key_path.is_absolute():
            self.key_path = project / self.key_path
        if not self.cert_path.is_absolute():
            self.cert_path = project / self.cert_path
        self.state_path = Path(env.get("MAIL_ROTATION_STATE_FILE", "/var/lib/mail-relay/cert-rotation-state.json"))
        for path in (self.key_path, self.cert_path):
            resolved = path.resolve(strict=False)
            if "/inbound-tls/" in f"{resolved}/" or resolved.parent.name != "secrets":
                raise ValueError(f"OAuth rotation path must be inside a secrets/ directory, never inbound-tls: {path}")

    # --- reporting ----------------------------------------------------------

    def log(self, step: str, outcome: str, detail: str = "") -> None:
        """Append one structured line, and echo it.

        The in-container verifier reads the last entry, so "rotation failed at
        step 3" can be alerted on as a distinct condition from "the certificate
        is expiring". Conflating those two hides the one that matters.
        """
        record = {
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "step": step,
            "outcome": outcome,
            "detail": detail,
        }
        line = json.dumps(record)
        print(f"{outcome:8} {step}" + (f": {detail}" if detail else ""))
        if not self.dry_run:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a") as handle:
                handle.write(line + "\n")

    # --- credentials --------------------------------------------------------

    def _sign(self, header: dict, claims: dict, key) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
        signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{b64url(signature)}"

    def _load(self, key_path: Path, cert_path: Path):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return key, cert

    def _header(self, cert) -> dict:
        from cryptography.hazmat.primitives import hashes

        return {"alg": "RS256", "typ": "JWT", "x5t": b64url(cert.fingerprint(hashes.SHA1()))}

    def token(self, scope: str, key, cert) -> str:
        now = int(time.time())
        assertion = self._sign(
            self._header(cert),
            {
                "aud": f"{LOGIN}/{self.tenant}/oauth2/v2.0/token",
                "iss": self.client_id,
                "sub": self.client_id,
                "jti": str(uuid.uuid4()),
                "nbf": now - 60,
                "exp": now + 600,
            },
            key,
        )
        body = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "scope": scope,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
                "grant_type": "client_credentials",
            }
        ).encode()
        request = urllib.request.Request(
            f"{LOGIN}/{self.tenant}/oauth2/v2.0/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)["access_token"]

    def proof(self, key, cert) -> str:
        now = int(time.time())
        return self._sign(
            self._header(cert),
            # Microsoft requires exp to be exactly nbf + 10 minutes.
            {"aud": PROOF_AUDIENCE, "iss": self.client_id, "nbf": now, "exp": now + 600},
            key,
        )

    def graph(self, method: str, path: str, token: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{GRAPH}/v1.0{path}",
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace")[:600]

    # --- state --------------------------------------------------------------

    def read_state(self) -> dict:
        if self.state_path.is_file():
            try:
                return json.loads(self.state_path.read_text())
            except ValueError:
                pass
        return {}

    def write_state(self, state: dict) -> None:
        if self.dry_run:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2) + "\n")
        os.replace(temporary, self.state_path)


def days_remaining(cert) -> int:
    not_after = cert.not_valid_after_utc
    return (not_after - datetime.datetime.now(datetime.timezone.utc)).days


def make_certificate(days: int, key_bits: int = 4096, subject_name: str = "postfix-m365-relay", key=None):
    """Return a self-signed identity with explicit validity and RSA strength.

    The same well-tested primitive creates two intentionally different roles:
    RSA-4096 for the long-lived Entra client credential and RSA-2048 for local
    inbound TLS. Callers choose the role; path guards prevent rotation from ever
    treating the inbound key as the OAuth identity.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Inbound STARTTLS renewal deliberately reuses its existing private key.
    # That avoids needless pin churn and lets the cert file be swapped without
    # a non-atomic two-file key/cert transition. OAuth rotation never supplies
    # a key here: app credentials need an actually new proof-of-possession key.
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def send_proof_message(mailbox: str, token: str, recipient: str, thumbprint: str,
                       host: str = SMTP_HOST, port: int = SMTP_PORT) -> tuple[bool, str]:
    """Prove the new certificate can actually send, not merely authenticate.

    Authentication alone is not enough: a token can be issued and still be
    refused at submission, which is exactly the failure that cost this project a
    whole evening in August 2026.
    """
    message = EmailMessage()
    message["From"] = formataddr(("the relay certificate rotation", mailbox))
    message["To"] = recipient
    message["Subject"] = "Mail relay certificate rotated"
    message.set_content(
        "The mail relay's certificate was replaced automatically.\n\n"
        f"New thumbprint: {thumbprint}\n\n"
        "This message was sent with the new certificate, before it was made live,\n"
        "which is what proves the rotation worked. No action is needed.\n"
    )
    auth = base64.b64encode(f"user={mailbox}\x01auth=Bearer {token}\x01\x01".encode()).decode()
    try:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            code, response = server.docmd("AUTH", "XOAUTH2 " + auth)
            if code != 235:
                return False, f"AUTH refused: {code} {response.decode(errors='replace')[:200]}"
            server.send_message(message)
        return True, "sent"
    except Exception as error:  # noqa: BLE001 - the reason is reported, not handled
        return False, f"{type(error).__name__}: {error}"


def read_env(env_file: Path) -> dict[str, str]:
    env = {}
    if not env_file.is_file():
        return env
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip()
    return env


def main() -> int:
    project = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", default=str(project / ".env"))
    parser.add_argument("--renew-at", type=int, default=None,
                        help="Rotate when fewer days than this remain (default: half of --validity)")
    parser.add_argument("--validity", type=int, default=730, help="Validity of the new certificate, in days")
    parser.add_argument("--key-bits", type=int, default=4096, choices=(2048, 3072, 4096))
    parser.add_argument("--generate-only", action="store_true",
                        help="Generate a self-signed pair without contacting Microsoft")
    parser.add_argument("--reuse-key", action="store_true",
                        help="With --generate-only, renew only the certificate using --key-path")
    parser.add_argument("--key-path", default=None)
    parser.add_argument("--cert-path", default=None)
    parser.add_argument("--subject", default="postfix-m365-relay")
    parser.add_argument("--grace-days", type=int, default=7, help="Days to keep the old certificate after a swap")
    parser.add_argument("--to", default=None, help="Where the proof message goes")
    parser.add_argument("--force", action="store_true", help="Rotate regardless of days remaining")
    parser.add_argument("--dry-run", action="store_true", help="Report what would happen and change nothing")
    parser.add_argument("--list-keys", action="store_true",
                        help="Read-only: list the certificates on the app registration and flag orphans")
    parser.add_argument("--remove-key", default=None, metavar="KEY_ID",
                        help="Remove one key credential by keyId, confirming it is gone")
    args = parser.parse_args()

    # Half the validity, so changing --validity moves the threshold with it
    # rather than leaving it behind at a number that used to make sense.
    if args.renew_at is None:
        args.renew_at = args.validity // 2

    from cryptography.hazmat.primitives import hashes, serialization

    if args.generate_only:
        # This offline path powers first boot and inbound TLS generation. It must
        # not require tenant variables, an admin recipient, or network access.
        # Keeping it in this module prevents two certificate implementations
        # from drifting on permissions or crypto defaults.
        if not args.key_path or not args.cert_path:
            parser.error("--generate-only requires --key-path and --cert-path")
        key_path = Path(args.key_path)
        cert_path = Path(args.cert_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        if args.validity < 1:
            parser.error("--validity must be at least one day")
        if args.reuse_key:
            # Load before touching cert_path. A malformed/missing key therefore
            # leaves the currently served certificate completely untouched.
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = make_certificate(args.validity, args.key_bits, args.subject, key)[1]
        else:
            key, cert = make_certificate(args.validity, args.key_bits, args.subject)
            handle = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "wb") as stream:
                stream.write(key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        cert_path.chmod(0o644)
        print(cert.fingerprint(hashes.SHA1()).hex().upper())
        return 0

    env_file = Path(args.env_file)
    env = read_env(env_file)
    env.update(os.environ)
    for required in ("MAIL_RELAY_TENANT", "MAIL_RELAY_CLIENT_ID", "MAIL_SEND_MAILBOX"):
        if not env.get(required) or env[required] == "replace_me":
            print(f"{required} is not set", file=sys.stderr)
            return 1
    log_path = Path(env.get("MAIL_ROTATION_LOG_FILE", "/var/lib/mail-relay/cert-rotation.log"))
    try:
        rotation = Rotation(project, env, log_path, args.dry_run)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    recipient = args.to or env.get("MAIL_ROTATION_TEST_RECIPIENT") or env.get("MAIL_ADMIN_EMAIL")

    current_key, current_cert = rotation._load(rotation.key_path, rotation.cert_path)
    remaining = days_remaining(current_cert)
    app_path = f"/applications(appId='{rotation.client_id}')"

    def remove_key(key_id: str) -> tuple[bool, str]:
        """Remove a key credential, and confirm it rather than trusting the reply.

        Directory writes and reads land on different replicas, so removeKey can
        answer "No credentials found to be removed" for a key that a read showed
        seconds earlier -- and the removal can still take effect. This behavior
        was observed during failure-path qualification and is why the re-read is
        part of the algorithm rather than optional logging.

        So the response code is treated as a hint and the absence of the key as
        the answer. Anything else would report a false failure and leave a human
        hunting for a key that is not there.
        """
        graph_token = rotation.token(f"{GRAPH}/.default", current_key, current_cert)
        status, result = rotation.graph(
            "POST",
            f"{app_path}/removeKey",
            graph_token,
            {"keyId": key_id, "proof": rotation.proof(current_key, current_cert)},
        )
        already_gone = status == 400 and "No credentials found" in str(result)
        if status not in (200, 204) and not already_gone:
            return False, f"HTTP {status}: {result}"

        for attempt in range(1, 13):
            time.sleep(5)
            read_status, app = rotation.graph("GET", app_path, graph_token)
            if read_status == 200 and not any(k["keyId"] == key_id for k in app.get("keyCredentials", [])):
                return True, f"confirmed gone after {attempt * 5}s"
        return False, "still present 60s after removal was accepted"


    # --- read-only: what is actually on the app registration -----------------
    #
    # The rotation log says what this script believes it did. This says what the
    # tenant thinks, which is the only thing that decides whether a token can be
    # minted. They can disagree: a rotation that died between addKey and the
    # proof leaves a key behind, and before the abandon path existed it left it
    # there silently. Changes nothing.
    if args.list_keys:
        graph_token = rotation.token(f"{GRAPH}/.default", current_key, current_cert)
        status, app = rotation.graph("GET", app_path, graph_token)
        if status != 200 or not app:
            print(f"Graph GET failed: HTTP {status}: {app}", file=sys.stderr)
            return 1

        # customKeyIdentifier is documented as base64 of the SHA-1 thumbprint,
        # while Graph responses have also been observed using a plain hex
        # thumbprint. Getting this wrong labels the live
        # certificate an orphan and invites someone to delete it. So normalise
        # whatever arrives to hex and compare that.
        live_digest = current_cert.fingerprint(hashes.SHA1())
        live_thumbprint = live_digest.hex().upper()

        pending_record = rotation.read_state().get("pending_removal") or {}
        pending_key_id = pending_record.get("key_id")

        def classify(credential: dict) -> str:
            if credential_thumbprint(credential) == live_thumbprint:
                return "live"
            if credential.get("keyId") == pending_key_id:
                return "retiring"
            return "orphan"

        credentials = app.get("keyCredentials", [])
        print(f"{len(credentials)} key credential(s) on {rotation.client_id}")
        print(f"live certificate thumbprint {live_thumbprint}\n")
        for credential in credentials:
            kind = classify(credential)
            if kind == "live":
                role = "LIVE      the certificate on disk, in use now"
            elif kind == "retiring":
                age = (time.time() - pending_record.get("rotated_at", 0)) / 86400
                role = f"RETIRING  scheduled, {args.grace_days - age:.1f} days left"
            else:
                role = "ORPHAN    not live and not scheduled -- remove it"
            print(f"  {role}")
            print(f"    displayName {credential.get('displayName')}")
            print(f"    keyId       {credential.get('keyId')}")
            print(f"    identifier  {credential.get('customKeyIdentifier')}")
            print(f"    expires     {credential.get('endDateTime')}\n")

        orphans = [c.get("keyId") for c in credentials if classify(c) == "orphan"]
        if orphans:
            print("Remove each orphan with:")
            for key_id in orphans:
                print(f"  sudo python3 ./scripts/rotate-smtp-relay-cert.py --remove-key {key_id}")
        return 0

    # --- read-only's counterpart: remove one key by id ------------------------
    if args.remove_key:
        removed, note = remove_key(args.remove_key)
        rotation.log("remove-key-by-hand", "ok" if removed else "FAILED",
                     f"{args.remove_key}: {note}")
        return 0 if removed else 1

    # --- housekeeping: retire an old certificate whose grace period is over ---
    #
    # Done first, and in a different run from the swap that created it. If this
    # ran immediately after a swap there would be no way back from a rotation
    # that turned out to be broken.
    state = rotation.read_state()
    pending = state.get("pending_removal")
    if pending and not args.dry_run:
        age_days = (time.time() - pending.get("rotated_at", 0)) / 86400
        if age_days >= args.grace_days:
            removed, note = remove_key(pending["key_id"])
            if removed:
                rotation.log("retire-old-key", "ok",
                             f"removed {pending['key_id']} after {age_days:.1f} days: {note}")
                state.pop("pending_removal")
                rotation.write_state(state)
            else:
                rotation.log("retire-old-key", "FAILED", note)
        else:
            rotation.log(
                "retire-old-key",
                "waiting",
                f"{pending['key_id']} retires in {args.grace_days - age_days:.1f} days",
            )

    # --- 1. is it time? ------------------------------------------------------
    if remaining > args.renew_at and not args.force:
        rotation.log("check-expiry", "ok", f"{remaining} days remaining, threshold {args.renew_at}")
        return 0
    rotation.log("check-expiry", "due", f"{remaining} days remaining, threshold {args.renew_at}")

    if remaining <= 0:
        # addKey needs a valid certificate to sign the proof. Past expiry there
        # is nothing to sign with and no way back except a human.
        rotation.log(
            "check-expiry",
            "FAILED",
            "certificate has already expired; self-rotation is no longer possible, see docs/RUNBOOK.md part D",
        )
        return 1

    if args.dry_run:
        rotation.log("dry-run", "ok", f"would rotate now and issue a {args.validity}-day certificate")
        return 0

    if not recipient:
        rotation.log("prove-send", "FAILED",
                     "rotation is due but no proof recipient is configured; set MAIL_ADMIN_EMAIL")
        return 1

    # --- 2. stage a new certificate; nothing live is touched -----------------
    new_key, new_cert = make_certificate(args.validity, args.key_bits, args.subject)
    new_thumbprint = new_cert.fingerprint(hashes.SHA1()).hex().upper()
    staging_key = rotation.key_path.with_suffix(".pem.new")
    staging_cert = rotation.cert_path.with_suffix(".pem.new")
    # 0600 before any bytes are written, not after.
    handle = os.open(staging_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as stream:
        stream.write(
            new_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    staging_cert.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))
    staging_cert.chmod(0o644)
    rotation.log("stage-certificate", "ok", f"thumbprint {new_thumbprint}, {args.validity} days")

    # --- 3. addKey, authorised by the certificate we already hold ------------
    graph_token = rotation.token(f"{GRAPH}/.default", current_key, current_cert)
    status, result = rotation.graph(
        "POST",
        f"{app_path}/addKey",
        graph_token,
        {
            "keyCredential": {
                "type": "AsymmetricX509Cert",
                "usage": "Verify",
                "key": base64.b64encode(new_cert.public_bytes(serialization.Encoding.DER)).decode(),
                "displayName": f"the relay mail relay (rotated {datetime.date.today().isoformat()})",
            },
            "passwordCredential": None,
            "proof": rotation.proof(current_key, current_cert),
        },
    )
    if status != 200:
        rotation.log("add-key", "FAILED", f"HTTP {status}: {result}")
        staging_key.unlink(missing_ok=True)
        staging_cert.unlink(missing_ok=True)
        return 1
    added_key_id = result["keyId"]
    rotation.log("add-key", "ok", f"keyId {added_key_id}")

    # --- 4. wait for the directory to catch up -------------------------------
    #
    # Graph directory writes are eventually consistent. During qualification, a
    # read immediately after successful addKey still showed only the old
    # certificate before the new one appeared. Treating
    # the first read as authoritative would abort a rotation that had in fact
    # succeeded, leaving a key behind and no record of it.
    for attempt in range(1, 25):
        time.sleep(5)
        status, app = rotation.graph("GET", app_path, graph_token)
        if status == 200 and any(k["keyId"] == added_key_id for k in app.get("keyCredentials", [])):
            rotation.log("await-replication", "ok", f"visible after {attempt * 5}s")
            break
    else:
        rotation.log("await-replication", "FAILED", f"{added_key_id} not visible after 120s")
        staging_key.unlink(missing_ok=True)
        staging_cert.unlink(missing_ok=True)
        rotation.log("await-replication", "note",
                     f"the key may still appear later; remove {added_key_id} by hand if it does")
        return 1


    def abandon(step: str, detail: str) -> int:
        """Give up cleanly: no swap, no orphan key, no staging files left behind.

        The certificate that is live keeps working -- nothing has been changed
        yet -- but the key added at step 3 has to come off the app registration,
        or every failed attempt leaves another one there.
        """
        rotation.log(step, "FAILED", detail)
        removed, note = remove_key(added_key_id)
        if removed:
            rotation.log("abandon", "ok", f"removed the unused key {added_key_id}: {note}")
        else:
            rotation.log("abandon", "FAILED",
                         f"could not remove {added_key_id}: {note}; remove it by hand")
        staging_key.unlink(missing_ok=True)
        staging_cert.unlink(missing_ok=True)
        rotation.log(step, "note", "old certificate is still live and unchanged")
        return 1

    # --- 5. prove the new certificate before trusting it ---------------------
    #
    # There are two replication delays here, not one, and they are of different
    # lengths. Step 4 waited for the directory to serve the new key on a read.
    # The token service is separate and can be slower: a key visible to Graph
    # may still temporarily produce "HTTP 401 Unauthorized"
    # when used to sign a client assertion. Treating the first 401 as failure
    # aborts a rotation that would have succeeded a minute later.
    smtp_token = None
    last_error = ""
    for attempt in range(1, 21):
        try:
            smtp_token = rotation.token(OUTLOOK_SCOPE, new_key, new_cert)
            rotation.log("prove-token", "ok",
                         f"new certificate minted an SMTP token after {(attempt - 1) * 30}s")
            break
        except Exception as error:  # noqa: BLE001
            last_error = f"{type(error).__name__}: {error}"
            if attempt == 1:
                rotation.log("prove-token", "waiting",
                             "token service has not accepted the new key yet; retrying for 10 minutes")
            time.sleep(30)
    if smtp_token is None:
        return abandon("prove-token", f"still refused after 10 minutes: {last_error}")

    sent, detail = send_proof_message(
        rotation.mailbox, smtp_token, recipient, new_thumbprint,
        env.get("MAIL_UPSTREAM_HOST", SMTP_HOST), int(env.get("MAIL_UPSTREAM_PORT", SMTP_PORT)))
    if not sent:
        return abandon("prove-send", detail)
    rotation.log("prove-send", "ok", f"proof message accepted for {recipient}")

    # --- 6. swap, only now ---------------------------------------------------
    backup_key = rotation.key_path.with_suffix(".pem.previous")
    backup_cert = rotation.cert_path.with_suffix(".pem.previous")
    os.replace(rotation.key_path, backup_key)
    os.replace(rotation.cert_path, backup_cert)
    os.replace(staging_key, rotation.key_path)
    os.replace(staging_cert, rotation.cert_path)
    rotation.log("swap", "ok", f"thumbprint now {new_thumbprint}; previous kept alongside")

    # --- 7. schedule the old key's removal for a later run -------------------
    old_thumbprint = current_cert.fingerprint(hashes.SHA1()).hex().upper()
    status, app = rotation.graph("GET", app_path, graph_token)
    # Match the key by the thumbprint of the certificate this run replaced.
    #
    # This used to take "the first key that is not the one just added", which is
    # correct only when the app registration holds exactly two keys. It holds
    # more whenever a failed rotation has left an orphan behind, or whenever a
    # second project shares this app registration with its own certificate --
    # and then it schedules somebody else's live credential for deletion, which
    # surfaces as mail stopping a week later with nothing in the log to explain
    # it. Match on identity, never on position.
    old_key_id = None
    if status == 200:
        for credential in app.get("keyCredentials", []):
            if credential["keyId"] == added_key_id:
                continue
            if credential_thumbprint(credential) == old_thumbprint:
                old_key_id = credential["keyId"]
                break
    if old_key_id:
        state["pending_removal"] = {
            "key_id": old_key_id,
            "thumbprint": old_thumbprint,
            "rotated_at": int(time.time()),
        }
        rotation.write_state(state)
        rotation.log("schedule-retire", "ok", f"{old_key_id} retires in {args.grace_days} days")
    else:
        rotation.log("schedule-retire", "note",
                     f"no key on the app registration matches the replaced certificate "
                     f"{old_thumbprint}; nothing scheduled for retirement. If that "
                     f"certificate is still registered, remove it with --remove-key")

    refresh_script = Path(__file__).with_name("refresh-smtp-token.py")
    refreshed = subprocess.run([str(refresh_script), "--quiet"], check=False).returncode == 0
    if not refreshed:
        rotation.log("refresh-token", "FAILED", "certificate swapped but immediate token mint failed")
        return 1
    rotation.log("rotate", "ok", "new certificate is live and the token was re-minted")
    alert = Path(__file__).with_name("alert.sh")
    if alert.is_file():
        subprocess.run([str(alert), "info", "certificate-rotation",
                        f"Certificate rotation succeeded; new thumbprint {new_thumbprint}"], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
