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
import re
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


def remove_key_already_gone(status, result) -> bool:
    """Whether a removeKey response means the key is already absent.

    graph() returns the error body as a raw string on an HTTPError, so the
    envelope is parsed defensively here (dict or JSON text, with a plain-text
    fallback). A live tenant answers this case with HTTP 400 and the GENERIC
    code "Request_BadRequest" -- the same code it uses for a malformed proof or
    a bad payload -- so the code alone cannot mean "already gone". The specific
    "No credentials found to be removed" message is the discriminator, read from
    the structured error rather than a loose match over the whole blob. Both are
    required so a different Request_BadRequest never masquerades as success.
    """
    if status != 400:
        return False
    phrase = "No credentials found"
    if isinstance(result, dict):
        error = result.get("error") or {}
        return str(error.get("code", "")) == "Request_BadRequest" and \
            phrase in str(error.get("message", ""))
    try:
        error = (json.loads(result) or {}).get("error") or {}
    except (ValueError, TypeError):
        # Non-JSON body: preserve the original substring behaviour so a future
        # wire format never silently turns a real "already gone" into a failure.
        return phrase in str(result)
    return str(error.get("code", "")) == "Request_BadRequest" and \
        phrase in str(error.get("message", ""))


def rotation_window_error(validity: int, renew_at: int) -> str:
    """Return a human error if the validity/renew window is unsafe, else "".

    Thresholds are whole days (renew_at defaults to validity // 2). The renewal
    point must fall strictly inside the certificate's life:

      * renew_at >= validity makes every freshly issued certificate instantly
        "due" -- rotation fires on every run, churning credentials and hammering
        Graph addKey.
      * renew_at <= 0 waits until the certificate is already expired, leaving no
        lead time to add, replicate, and prove a replacement before an outage.

    A one-day certificate cannot satisfy 0 < validity // 2 < validity, so it is
    rejected here rather than silently rotating only after expiry. Mirrors the
    inbound-TLS window the entrypoint already enforces.
    """
    if validity < 1:
        return f"--validity must be at least one day (got {validity})"
    if not 0 < renew_at < validity:
        return (f"--renew-at ({renew_at}) must be greater than 0 and less than "
                f"--validity ({validity}); otherwise rotation would trigger at or "
                f"after the certificate has already expired")
    return ""


# --- instance identity and credential ownership -----------------------------
#
# One Entra App Registration may be shared by several relay instances, each
# holding its OWN certificate. To stop one instance from ever treating a
# sibling's live credential as a deletable orphan, every key this instance adds
# is stamped with a stable per-instance identifier in its Graph displayName, and
# ownership is read back from that stamp. Certificates uploaded by a human (the
# first credential, or a recovery credential) carry no stamp and are reported as
# ownership-unknown rather than guessed at.
INSTANCE_TAG = "inst:"
# The default id is a UUID, but an operator may pin MAIL_INSTANCE_ID to a
# readable name, so the stamp accepts letters, digits, and the usual separators
# (never a space, which terminates the token in the displayName).
_INSTANCE_TAG_RE = re.compile(r"inst:([A-Za-z0-9._-]{1,128})")

# Ownership labels. Only SUPERSEDED and RETIRING are ever this instance's to
# remove; FOREIGN and UNMONITORED must never be auto-suggested or hand-removed
# without a deliberate, purpose-named override.
OWN_LIVE = "live"
OWN_RETIRING = "retiring"
OWN_SUPERSEDED = "superseded"
OWN_FOREIGN = "foreign"
OWN_UNMONITORED = "unmonitored"


def rotation_display_name(instance_id: str, when: "datetime.date | None" = None) -> str:
    """Graph displayName for a key this instance adds, carrying its owner stamp."""
    day = (when or datetime.date.today()).isoformat()
    stamp = f" {INSTANCE_TAG}{instance_id}" if instance_id else ""
    return f"postfix-m365-relay mail relay{stamp} (rotated {day})"


def instance_id_of(display_name: str) -> str:
    """Return the instance id stamped into a displayName, or '' if unstamped."""
    match = _INSTANCE_TAG_RE.search(display_name or "")
    return match.group(1) if match else ""


def classify_credential(credential: dict, live_thumbprint: str,
                        my_instance_id: str, retiring_key_id: "str | None") -> str:
    """Classify one app keyCredential from THIS instance's point of view.

    The classification decides, above all, what may be removed. Erring in the
    permissive direction lets an operator delete another instance's live
    certificate, so anything not provably this instance's own is reported as
    FOREIGN or UNMONITORED and never offered for removal. A live certificate is
    identified by thumbprint regardless of who uploaded it, so an instance always
    recognises its own in-use credential even when it was added by hand.
    """
    if credential_thumbprint(credential) == live_thumbprint and live_thumbprint:
        return OWN_LIVE
    if retiring_key_id and credential.get("keyId") == retiring_key_id:
        return OWN_RETIRING
    stamped = instance_id_of(credential.get("displayName") or "")
    if stamped and my_instance_id:
        return OWN_SUPERSEDED if stamped == my_instance_id else OWN_FOREIGN
    # Either unstamped (human-uploaded) or this instance has no identity to
    # compare against: ownership cannot be proven, so treat it as hands-off.
    return OWN_UNMONITORED


def classify_token_failure(status: "int | None", body: str) -> str:
    """Classify a failed OAuth token mint into an actionable category.

    The recovery path acts only on a DEFINITIVE certificate fault. A transient
    network or Entra outage must never be mistaken for one, or the relay would
    demand a fresh certificate during an outage that clears on its own. A missing
    Exchange role is a certificate-irrelevant configuration fault and must not
    trigger regeneration either.

      * "transient"  -- no HTTP status (network/DNS/TLS) or a 5xx from Entra.
      * "cert-fault" -- the certificate is expired, revoked, or no longer on the
                        app registration (AADSTS700027 and its kin).
      * "scope"      -- authentication works but the Exchange role/resource
                        principal is missing; a new certificate cannot fix it.
      * "unknown"    -- a 4xx that matches none of the above; treated as NOT a
                        definitive cert fault so recovery never fires on a guess.
    """
    text = (body or "").lower()
    if status is None or status >= 500:
        return "transient"
    if ("aadsts700027" in text
            or ("certificate" in text
                and ("not valid" in text or "not found" in text
                     or "expired" in text or "revoked" in text
                     or "no longer" in text))):
        return "cert-fault"
    if ("resource principal" in text or "sendasapp" in text
            or "aadsts501051" in text or "aadsts500011" in text):
        return "scope"
    return "unknown"


class Rotation:
    def __init__(self, project: Path, env: dict[str, str], log_path: Path, dry_run: bool):
        self.project = project
        self.env = env
        self.log_path = log_path
        self.dry_run = dry_run
        self.tenant = env["MAIL_RELAY_TENANT"]
        self.client_id = env["MAIL_RELAY_CLIENT_ID"]
        self.mailbox = env["MAIL_SEND_MAILBOX"]
        # Stable per-instance identity, stamped into every key this instance adds
        # so a shared app registration never confuses one instance's certificate
        # for another's. Empty is tolerated (legacy state); ownership then falls
        # back to the on-disk live thumbprint only. Normalise to the stamp's
        # charset so stamping and comparison always agree, even for an operator
        # value that contained a space or other stray character.
        self.instance_id = re.sub(r"[^A-Za-z0-9._-]", "-", env.get("MAIL_INSTANCE_ID", "").strip())
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
    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42 (e.g. Ubuntu 24.04 ships 41.x)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return (not_after - datetime.datetime.now(datetime.timezone.utc)).days


def make_certificate(days: int, key_bits: int = 2048, subject_name: str = "postfix-m365-relay", key=None):
    """Return a self-signed identity with explicit validity and RSA strength.

    The same well-tested primitive creates two intentionally different roles:
    RSA-2048 for the long-lived Entra client credential and RSA-2048 for local
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


def pending_addition_is_live(pending: dict, current_cert) -> bool:
    """Return whether crash-recovery state identifies the local live cert."""
    from cryptography.hazmat.primitives import hashes

    return pending.get("thumbprint") == current_cert.fingerprint(hashes.SHA1()).hex().upper()


def run_immediate_token_refresh(
    refresh_script: Path, env_file: Path, env: dict[str, str]
) -> bool:
    """Re-mint with the newly swapped pair and preserve file-loaded config.

    A child process cannot inherit variables held only in this Python mapping.
    Supplying them through ``env`` mirrors the entrypoint's exported process
    environment without exposing identifiers or file paths in the process
    command line. Secret bytes never enter this mapping; only key/cert paths do.
    """
    refresh_environment = os.environ.copy()
    refresh_environment.update(env)
    return subprocess.run(
        [str(refresh_script), "--quiet", "--env-file", str(env_file)],
        check=False,
        env=refresh_environment,
    ).returncode == 0


# --- automatic recovery from a live certificate Entra no longer trusts -------
#
# When the live certificate is deleted at Entra or expires, self-rotation is a
# one-way door: addKey needs a trusted certificate to sign its proof, and the
# dead one cannot. Recovery therefore cannot re-register itself; it stages a NEW
# certificate and asks a human to upload it, exactly like first boot -- but does
# so WITHOUT disturbing the live certificate, which may yet come back (a transient
# Exchange outage, or an admin re-adding the key). The governing invariant: the
# live on-disk pair is never removed or swapped until a new certificate has
# proven it can send AND the old one is confirmed still failing. The old
# certificate is tested first on every pass, so a healed outage always wins.


def _recovery_disabled(env: dict) -> bool:
    return env.get("MAIL_CERT_RECOVERY_ENABLED", "yes").strip().lower() in (
        "no", "0", "false", "off")


def _token_is_fresh(env: dict, margin: int = 300) -> bool:
    """True when the live token file still has comfortable life; a cheap proxy
    for "the live certificate is working" that avoids an extra token request."""
    token_file = Path(env.get("MAIL_TOKEN_FILE") or "/run/mail-relay/relay.json")
    try:
        data = json.loads(token_file.read_text())
        return int(data.get("expiry", 0)) - int(time.time()) >= margin
    except (OSError, ValueError):
        return False


def _try_mint(rotation: "Rotation", key, cert) -> "tuple[bool, int | None, str]":
    """Attempt an Outlook-scope token mint; return (ok, http_status, body).

    A network failure yields status None (transient); an HTTP error yields its
    code and body so the AADSTS reason can be classified. No token is returned or
    logged -- only whether the certificate could mint one.
    """
    try:
        rotation.token(OUTLOOK_SCOPE, key, cert)
        return True, 200, ""
    except urllib.error.HTTPError as error:
        return False, error.code, error.read().decode("utf-8", "replace")[:600]
    except urllib.error.URLError as error:
        return False, None, str(getattr(error, "reason", error))
    except Exception as error:  # noqa: BLE001 - reported, not raised, so a loop continues
        return False, None, f"{type(error).__name__}: {error}"


def _cert_action(rotation: "Rotation", *argv: str) -> None:
    script = Path(__file__).with_name("cert-action.sh")
    if script.is_file():
        subprocess.run([str(script), *argv], check=False)


def _recovery_paths(rotation: "Rotation") -> "tuple[Path, Path]":
    return (rotation.key_path.with_suffix(".pem.recovery"),
            rotation.cert_path.with_suffix(".pem.recovery"))


def _discard_standby(rotation: "Rotation") -> None:
    for path in _recovery_paths(rotation):
        path.unlink(missing_ok=True)


def _generate_standby(rotation: "Rotation", env: dict, args) -> int:
    """Stage ONE new certificate and expose its public half for upload."""
    from cryptography.hazmat.primitives import hashes, serialization

    new_key, new_cert = make_certificate(args.validity, args.key_bits, args.subject)
    thumbprint = new_cert.fingerprint(hashes.SHA1()).hex().upper()
    staging_key, staging_cert = _recovery_paths(rotation)
    handle = os.open(staging_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "wb") as stream:
        stream.write(new_key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    staging_cert.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))
    staging_cert.chmod(0o644)
    state = rotation.read_state()
    state["recovery"] = {"thumbprint": thumbprint, "generated_at": int(time.time())}
    rotation.write_state(state)
    rotation.log("recover", "ok",
                 f"generated a standby certificate {thumbprint}; awaiting operator upload")
    _cert_action(rotation, "require", "recovery-standby-awaiting-upload",
                 thumbprint, str(staging_cert))
    return 0


def _adopt_standby(rotation: "Rotation", env: dict, args, state: dict,
                   current_cert, new_key, new_cert) -> int:
    """Swap a proven standby into the live slot and retire the old credential.

    Reached only after the standby minted a token AND (when a recipient exists)
    sent a real proof message, and only while the old certificate is still
    failing. The old pair is preserved as .previous; the old Entra key is
    scheduled for best-effort retirement rather than removed inline.
    """
    from cryptography.hazmat.primitives import hashes

    old_thumbprint = current_cert.fingerprint(hashes.SHA1()).hex().upper()
    new_thumbprint = new_cert.fingerprint(hashes.SHA1()).hex().upper()
    staging_key, staging_cert = _recovery_paths(rotation)
    os.replace(rotation.key_path, rotation.key_path.with_suffix(".pem.previous"))
    os.replace(rotation.cert_path, rotation.cert_path.with_suffix(".pem.previous"))
    os.replace(staging_key, rotation.key_path)
    os.replace(staging_cert, rotation.cert_path)
    rotation.log("recover", "ok",
                 f"adopted the standby certificate; live thumbprint now {new_thumbprint}")
    for stale in ("recovery", "cert_fault_streak", "cert_fault_since"):
        state.pop(stale, None)
    # Best-effort: if the old key still lingers on the app, schedule its removal
    # through the normal grace-period path. It is often already gone (deleted at
    # Entra), in which case the later removeKey is a confirmed no-op.
    try:
        graph_token = rotation.token(f"{GRAPH}/.default", new_key, new_cert)
        app_path = f"/applications(appId='{rotation.client_id}')"
        gstatus, app = rotation.graph("GET", app_path, graph_token)
        if gstatus == 200:
            for cred in app.get("keyCredentials", []):
                if credential_thumbprint(cred) == old_thumbprint:
                    state["pending_removal"] = {
                        "key_id": cred["keyId"], "thumbprint": old_thumbprint,
                        "rotated_at": int(time.time())}
                    rotation.log("recover", "ok",
                                 f"scheduled the old key {cred['keyId']} for retirement")
                    break
    except Exception as error:  # noqa: BLE001 - scheduling is best-effort
        rotation.log("recover", "note",
                     f"could not schedule old-key retirement now: {type(error).__name__}")
    rotation.write_state(state)
    _cert_action(rotation, "clear")
    refresh_script = Path(__file__).with_name("refresh-smtp-token.py")
    run_immediate_token_refresh(refresh_script, Path(args.env_file), env)
    return 0


def _advance_pending_standby(rotation: "Rotation", env: dict, args, state: dict,
                             current_cert) -> int:
    """Test whether the staged standby is trusted yet; adopt it if it proves out."""
    staging_key, staging_cert = _recovery_paths(rotation)
    if not staging_key.is_file() or not staging_cert.is_file():
        state.pop("recovery", None)
        rotation.write_state(state)
        rotation.log("recover", "note",
                     "standby files missing; will regenerate on the next definitive fault")
        return 0
    try:
        new_key, new_cert = rotation._load(staging_key, staging_cert)
    except Exception as error:  # noqa: BLE001
        rotation.log("recover", "note", f"standby unreadable ({type(error).__name__})")
        return 0
    ok, _status, _body = _try_mint(rotation, new_key, new_cert)
    if not ok:
        rotation.log("recover", "waiting",
                     "standby certificate not yet accepted by Entra; upload still required")
        _cert_action(rotation, "remind")
        return 0
    # Trusted. Prove it can actually SEND before adopting, when a recipient exists.
    recipient = args.to or env.get("MAIL_ROTATION_TEST_RECIPIENT") or env.get("MAIL_ADMIN_EMAIL")
    if recipient:
        try:
            from cryptography.hazmat.primitives import hashes
            smtp_token = rotation.token(OUTLOOK_SCOPE, new_key, new_cert)
            new_thumbprint = new_cert.fingerprint(hashes.SHA1()).hex().upper()
            sent, detail = send_proof_message(
                rotation.mailbox, smtp_token, recipient, new_thumbprint,
                env.get("MAIL_UPSTREAM_HOST", SMTP_HOST),
                int(env.get("MAIL_UPSTREAM_PORT", SMTP_PORT)))
        except Exception as error:  # noqa: BLE001
            sent, detail = False, f"{type(error).__name__}: {error}"
        if not sent:
            rotation.log("recover", "waiting",
                         f"standby accepted but proof send not yet succeeding: {detail}")
            return 0
    else:
        rotation.log("recover", "note",
                     "no proof recipient configured; adopting the standby on token trust alone")
    return _adopt_standby(rotation, env, args, state, current_cert, new_key, new_cert)


def run_recovery(rotation: "Rotation", env: dict, args) -> int:
    if _recovery_disabled(env):
        return 0
    state = rotation.read_state()
    recovery = state.get("recovery")

    # Healthy-path shortcut: no recovery in flight and a fresh live token means
    # the live certificate is plainly working. Clear any stale fault streak and
    # avoid an extra token request every loop.
    if not recovery and _token_is_fresh(env):
        if state.pop("cert_fault_streak", None) is not None \
                or state.pop("cert_fault_since", None) is not None:
            rotation.write_state(state)
        return 0

    if not rotation.key_path.is_file() or not rotation.cert_path.is_file():
        rotation.log("recover", "note",
                     "no live certificate on disk; run relay-admin reset-oauth-cert")
        return 0
    try:
        current_key, current_cert = rotation._load(rotation.key_path, rotation.cert_path)
    except Exception as error:  # noqa: BLE001
        rotation.log("recover", "note",
                     f"live certificate unreadable ({type(error).__name__}); consider a reset")
        return 0

    # Step 1: does the OLD (live) certificate work right now?
    old_ok, old_status, old_body = _try_mint(rotation, current_key, current_cert)
    if old_ok:
        if recovery:
            _discard_standby(rotation)
            for stale in ("recovery", "cert_fault_streak", "cert_fault_since"):
                state.pop(stale, None)
            rotation.write_state(state)
            _cert_action(rotation, "clear")
            rotation.log("recover", "ok",
                         "original certificate is working again; standby discarded")
        elif state.pop("cert_fault_streak", None) is not None \
                or state.pop("cert_fault_since", None) is not None:
            rotation.write_state(state)
        return 0

    # The live certificate is failing. Classify why before doing anything.
    fault = classify_token_failure(old_status, old_body)
    if days_remaining(current_cert) <= 0:
        fault = "cert-fault"  # a locally expired certificate is definitive
    if fault == "transient":
        rotation.log("recover", "waiting",
                     "token mint failing transiently (network/Entra); not a certificate fault")
        return 0
    if fault == "scope":
        rotation.log("recover", "note",
                     "authentication fails on Exchange authorization, not the certificate; "
                     "a new certificate will not help (check the SMTP.SendAsApp role)")
        return 0
    if fault == "unknown":
        rotation.log("recover", "waiting",
                     f"token mint failing (HTTP {old_status}) but not a recognised certificate "
                     f"fault; holding rather than generating a certificate on a guess")
        return 0

    # Definitive certificate fault.
    if recovery:
        return _advance_pending_standby(rotation, env, args, state, current_cert)

    streak = int(state.get("cert_fault_streak", 0)) + 1
    since = int(state.get("cert_fault_since") or time.time())
    state["cert_fault_streak"] = streak
    state["cert_fault_since"] = since
    rotation.write_state(state)
    try:
        need_streak = int(env.get("MAIL_CERT_RECOVERY_FAULT_STREAK", "6") or 6)
        need_seconds = int(env.get("MAIL_CERT_RECOVERY_AFTER_SECONDS", "21600") or 21600)
    except ValueError:
        need_streak, need_seconds = 6, 21600
    waited = int(time.time()) - since
    if streak < need_streak or waited < need_seconds:
        rotation.log("recover", "waiting",
                     f"definitive certificate fault (streak {streak}/{need_streak}, "
                     f"{waited}s/{need_seconds}s) before generating a standby")
        return 0
    return _generate_standby(rotation, env, args)


def main() -> int:
    project = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", default=str(project / ".env"))
    parser.add_argument("--renew-at", type=int, default=None,
                        help="Rotate when fewer days than this remain (default: half of --validity)")
    parser.add_argument("--validity", type=int, default=730, help="Validity of the new certificate, in days")
    parser.add_argument("--key-bits", type=int, default=2048, choices=(2048, 3072, 4096))
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
    parser.add_argument("--reset", action="store_true",
                        help="Regenerate the live OAuth certificate from scratch and require re-upload")
    parser.add_argument("--recover", action="store_true",
                        help="Non-destructive self-recovery check for a live certificate Entra no longer trusts")
    parser.add_argument("--yes", action="store_true",
                        help="Confirm a destructive action (--reset, or removing an unmonitored key)")
    parser.add_argument("--yes-remove-another-instances-cert", action="store_true",
                        help="Deliberately override the guard that protects another instance's certificate")
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

    # Network rotation only: the offline --generate-only path above has no
    # renewal semantics, so the window guard applies from here on.
    window_error = rotation_window_error(args.validity, args.renew_at)
    if window_error:
        parser.error(window_error)

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

    # --- operator reset: regenerate the live certificate from scratch ---------
    #
    # Deliberately destructive and offline: it replaces the live key/cert with a
    # brand new self-signed pair and requires the operator to upload the public
    # half again, exactly like first boot. It must work even when the current
    # pair is missing or corrupt (that is a reason to reset), so it runs before
    # the current-certificate load below. The outgoing pair is kept as .previous
    # so an accidental reset is recoverable.
    if args.reset:
        if not args.yes:
            print("--reset regenerates the live OAuth certificate and requires re-upload to "
                  "Entra; pass --yes to confirm", file=sys.stderr)
            return 1
        old_thumbprint = ""
        if rotation.key_path.is_file() and rotation.cert_path.is_file():
            try:
                _, old_cert = rotation._load(rotation.key_path, rotation.cert_path)
                old_thumbprint = old_cert.fingerprint(hashes.SHA1()).hex().upper()
            except Exception:  # noqa: BLE001 - a corrupt pair is exactly a reset reason
                old_thumbprint = ""
            os.replace(rotation.key_path, rotation.key_path.with_suffix(".pem.previous"))
            os.replace(rotation.cert_path, rotation.cert_path.with_suffix(".pem.previous"))
        new_key, new_cert = make_certificate(args.validity, args.key_bits, args.subject)
        new_thumbprint = new_cert.fingerprint(hashes.SHA1()).hex().upper()
        handle = os.open(rotation.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(handle, "wb") as stream:
            stream.write(new_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        rotation.cert_path.write_bytes(new_cert.public_bytes(serialization.Encoding.PEM))
        rotation.cert_path.chmod(0o644)
        try:  # match the entrypoint's ownership posture where the account exists
            import grp
            import pwd
            uid = pwd.getpwnam("postfix").pw_uid
            gid = grp.getgrnam("postfix").gr_gid
            os.chown(rotation.key_path, uid, gid)
            os.chown(rotation.cert_path, uid, gid)
        except (KeyError, PermissionError, ImportError):
            pass
        # Drop half-finished rotation/recovery bookkeeping; the credentials those
        # referenced are gone now. Record the replaced thumbprint so --list-keys
        # shows the old Entra key as this instance's own superseded certificate.
        state = rotation.read_state()
        for stale in ("pending_addition", "pending_removal", "recovery"):
            state.pop(stale, None)
        if old_thumbprint:
            state["reset_replaced"] = {"thumbprint": old_thumbprint, "at": int(time.time())}
        rotation.write_state(state)
        rotation.log("reset", "ok",
                     f"generated a fresh OAuth certificate {new_thumbprint}; upload required")
        _cert_action(rotation, "require", "reset-fresh-certificate",
                     new_thumbprint, str(rotation.cert_path))
        print(new_thumbprint)
        return 0

    # --- non-destructive self-recovery ---------------------------------------
    # Runs its own certificate load with failure handling, so it is dispatched
    # before the strict load below.
    if args.recover:
        return run_recovery(rotation, env, args)

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
        try:
            graph_token = rotation.token(f"{GRAPH}/.default", current_key, current_cert)
        except Exception as error:  # noqa: BLE001 - retry is persisted by caller
            # Graph and Outlook token audiences were observed accepting a newly
            # rotated certificate at different times. Treat that as a retryable
            # operation result, not an uncaught traceback that loses the key ID
            # the next invocation still needs to clean up.
            return False, f"Graph token unavailable: {type(error).__name__}: {error}"
        status, result = rotation.graph(
            "POST",
            f"{app_path}/removeKey",
            graph_token,
            {"keyId": key_id, "proof": rotation.proof(current_key, current_cert)},
        )
        already_gone = remove_key_already_gone(status, result)
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

        credentials = app.get("keyCredentials", [])
        print(f"{len(credentials)} key credential(s) on {rotation.client_id}")
        print(f"this instance  {rotation.instance_id or '(no MAIL_INSTANCE_ID set)'}")
        print(f"live thumbprint {live_thumbprint}\n")
        removable = []
        seen_foreign = False
        for credential in credentials:
            kind = classify_credential(credential, live_thumbprint,
                                       rotation.instance_id, pending_key_id)
            if kind == OWN_LIVE:
                role = "LIVE        the certificate on disk, in use now"
            elif kind == OWN_RETIRING:
                age = (time.time() - pending_record.get("rotated_at", 0)) / 86400
                role = f"RETIRING    this instance, {args.grace_days - age:.1f} days left"
            elif kind == OWN_SUPERSEDED:
                role = "SUPERSEDED  this instance's old certificate -- safe to remove"
                removable.append(credential.get("keyId"))
            elif kind == OWN_FOREIGN:
                role = "FOREIGN     ANOTHER instance's certificate -- not yours, do not remove"
                seen_foreign = True
            else:
                role = "UNMONITORED ownership unknown (uploaded by hand) -- not removed automatically"
                seen_foreign = True
            print(f"  {role}")
            print(f"    displayName {credential.get('displayName')}")
            print(f"    keyId       {credential.get('keyId')}")
            print(f"    identifier  {credential.get('customKeyIdentifier')}")
            print(f"    expires     {credential.get('endDateTime')}\n")

        if removable:
            print("Remove this instance's OWN superseded certificate(s) with:")
            for key_id in removable:
                print(f"  sudo python3 ./scripts/rotate-smtp-relay-cert.py --remove-key {key_id}")
        else:
            print("Nothing on this app registration is this instance's to remove.")
        if seen_foreign:
            print("FOREIGN/UNMONITORED certificates belong to other instances or were "
                  "uploaded by hand.\nRemove them only from the instance that owns "
                  "them; this tool will refuse to delete them.")
        return 0

    # --- read-only's counterpart: remove one key by id ------------------------
    if args.remove_key:
        # Classify the target before touching it. A shared app registration may
        # hold another instance's LIVE credential; deleting it stops that other
        # relay a week later with nothing to explain it. This instance's own live
        # certificate must be equally undeletable by hand. So removal is gated on
        # ownership, and crossing an ownership boundary needs a deliberate,
        # purpose-named override rather than the generic --force habit.
        graph_token = rotation.token(f"{GRAPH}/.default", current_key, current_cert)
        status, app = rotation.graph("GET", app_path, graph_token)
        if status != 200 or not app:
            print(f"Graph GET failed: HTTP {status}: {app}", file=sys.stderr)
            return 1
        live_thumbprint = current_cert.fingerprint(hashes.SHA1()).hex().upper()
        pending_key_id = (rotation.read_state().get("pending_removal") or {}).get("key_id")
        target = next((c for c in app.get("keyCredentials", [])
                       if c.get("keyId") == args.remove_key), None)
        if target is None:
            rotation.log("remove-key-by-hand", "ok",
                         f"{args.remove_key}: not present on the app registration")
            return 0
        kind = classify_credential(target, live_thumbprint, rotation.instance_id, pending_key_id)
        if kind == OWN_LIVE:
            rotation.log("remove-key-by-hand", "REFUSED",
                         f"{args.remove_key} is this instance's LIVE certificate; refusing")
            return 1
        if kind == OWN_FOREIGN and not args.yes_remove_another_instances_cert:
            owner = instance_id_of(target.get("displayName") or "") or "unknown"
            rotation.log("remove-key-by-hand", "REFUSED",
                         f"{args.remove_key} belongs to another instance ({owner}); refusing. "
                         f"Remove it from that instance, or pass "
                         f"--yes-remove-another-instances-cert to override.")
            return 1
        if kind == OWN_UNMONITORED and not (args.yes or args.yes_remove_another_instances_cert):
            rotation.log("remove-key-by-hand", "REFUSED",
                         f"{args.remove_key} has no instance-owner stamp (uploaded by hand); "
                         f"pass --yes to confirm.")
            return 1
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

    # A key added for a rotation that never reached the local swap is not merely
    # an inventory curiosity: repeated failures would consume credential slots
    # and make it unclear which key is safe to remove. Record the exact key ID
    # immediately after addKey, and retry cleanup on every later invocation.
    #
    # There is one unavoidable cross-system crash window: the local pair can be
    # swapped just before state is updated. Comparing the recorded thumbprint to
    # the certificate currently on disk closes that window. A matching record
    # was adopted successfully and must never be removed; a nonmatching record
    # is an abandoned staged credential and is safe to remove by exact ID.
    pending_addition = state.get("pending_addition")
    if pending_addition and not args.dry_run:
        if pending_addition_is_live(pending_addition, current_cert):
            rotation.log(
                "cleanup-added-key",
                "ok",
                f"{pending_addition.get('key_id')} is the live local certificate; marked adopted",
            )
            state.pop("pending_addition", None)
            rotation.write_state(state)
        else:
            removed, note = remove_key(pending_addition["key_id"])
            if removed:
                rotation.log(
                    "cleanup-added-key",
                    "ok",
                    f"removed abandoned key {pending_addition['key_id']}: {note}",
                )
                state.pop("pending_addition", None)
                rotation.write_state(state)
            else:
                rotation.log(
                    "cleanup-added-key",
                    "FAILED",
                    f"{pending_addition['key_id']} remains pending: {note}",
                )
                # Do not add another credential while the exact previous one is
                # still unresolved. This turns eventual consistency into a
                # bounded retry queue instead of an accumulating orphan set.
                return 1
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
                "displayName": rotation_display_name(rotation.instance_id),
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

    # Persist before the first eventual-consistency read. The original
    # implementation attempted removal for only 60 seconds on failure and then
    # forgot the ID; live Graph behavior left that accepted removal visible and
    # required a later exact-ID retry. This record survives a crash, restart, or
    # stale read and is cleared only after confirmed removal or local adoption.
    state["pending_addition"] = {
        "key_id": added_key_id,
        "thumbprint": new_thumbprint,
        "added_at": int(time.time()),
    }
    rotation.write_state(state)

    def abandon(step: str, detail: str) -> int:
        """Leave the old pair live and durably retire the unused added key.

        Cleanup is attempted immediately for fast recovery. If Graph remains
        stale or unavailable, pending_addition is intentionally retained; the
        next normal loop retries the same exact key before adding anything else.
        """
        rotation.log(step, "FAILED", detail)
        removed, note = remove_key(added_key_id)
        if removed:
            rotation.log("abandon", "ok", f"removed the unused key {added_key_id}: {note}")
            state.pop("pending_addition", None)
            rotation.write_state(state)
        else:
            rotation.log(
                "abandon",
                "FAILED",
                f"could not yet remove {added_key_id}: {note}; cleanup is recorded for retry",
            )
        staging_key.unlink(missing_ok=True)
        staging_cert.unlink(missing_ok=True)
        rotation.log(step, "note", "old certificate is still live and unchanged")
        return 1

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
        return abandon("await-replication", f"{added_key_id} not visible after 120s")

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

    # If the process dies before this write, next invocation recognizes the
    # pending addition's thumbprint as the local live certificate and clears it
    # without removal. Clearing immediately here keeps the normal state simple.
    state.pop("pending_addition", None)

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
        rotation.log("schedule-retire", "ok", f"{old_key_id} retires in {args.grace_days} days")
    else:
        rotation.log("schedule-retire", "note",
                     f"no key on the app registration matches the replaced certificate "
                     f"{old_thumbprint}; nothing scheduled for retirement. If that "
                     f"certificate is still registered, remove it with --remove-key")
    rotation.write_state(state)

    refresh_script = Path(__file__).with_name("refresh-smtp-token.py")
    # `--env-file` populated this process's local dictionary; subprocesses do
    # not inherit Python variables. The first live forced rotation swapped the
    # certificate and then failed with "MAIL_RELAY_TENANT is not set" here.
    # Pass the validated non-secret configuration in the child environment and
    # retain the env-file fallback for off-host diagnostics. No secret value is
    # placed in argv (the private key is referenced only by its file path).
    refreshed = run_immediate_token_refresh(refresh_script, env_file, env)
    if not refreshed:
        rotation.log("refresh-token", "FAILED", "certificate swapped but immediate token mint failed")
        return 1
    rotation.log("rotate", "ok", "new certificate is live and the token was re-minted")
    alert = Path(__file__).with_name("alert.sh")
    if alert.is_file():
        subprocess.run([str(alert), "notify", "info", "certificate-rotation",
                        f"Certificate rotation succeeded; new thumbprint {new_thumbprint}"], check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
