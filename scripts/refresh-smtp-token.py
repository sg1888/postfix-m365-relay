#!/usr/bin/env python3
"""Mint an app-only OAuth token for SMTP submission and write it where Postfix reads it.

This is the only genuinely new moving part of the relay. Everything else is
packaged software with a configuration file.

The plugin (sasl-xoauth2) implements only the delegated refresh-token flow,
which dies on ninety days of inactivity, a password change, or a
conditional-access revocation, and recovers only through a human at a browser.
That fragility is why an earlier version of this project rejected Postfix
outright. We avoid it by never letting the plugin refresh: this script mints a
token from the certificate and writes it to the token file, and the plugin finds
a valid token every time it looks.

Measured behaviour that this design depends on (2026-08-17, sasl-xoauth2 0.27):

  * With a future ``expiry`` the plugin reads the file and sends the token. It
    does not contact the token endpoint at all -- confirmed with a recording
    server and with ``refresh_window`` forced to 7200 against a token that had
    3571 seconds left.
  * With a past ``expiry`` it logs "token expired. refreshing.", attempts the
    delegated refresh, and on failure returns err=-5. It does **not** fall back
    to the access token it is holding.

So the expiry written here must be the truth. Padding it would keep Postfix
sending a token Microsoft has already rejected, turning a clean local failure
into a 535 from the far end.

If this script stops running, mail defers in the queue rather than bouncing, and
delivers itself once the script runs again. That is the intended failure mode,
but it is invisible, which is why the in-container verifier watches this file's
remaining lifetime.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import grp
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

LOGIN = "https://login.microsoftonline.com"
# SMTP AUTH is authorised against Outlook, not Graph. A Graph-scoped token is
# refused at AUTH time with a bare 535 that says nothing about the scope.
OUTLOOK_SCOPE = "https://outlook.office365.com/.default"


class TokenFileError(RuntimeError):
    """A concise, already-redacted failure while replacing the token file."""


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def client_assertion(tenant: str, client_id: str, key_pem: bytes, cert_pem: bytes) -> str:
    """Sign the JWT that stands in for a client secret."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)

    header = {"alg": "RS256", "typ": "JWT", "x5t": b64url(cert.fingerprint(hashes.SHA1()))}
    now = int(time.time())
    claims = {
        "aud": f"{LOGIN}/{tenant}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now - 60,
        "exp": now + 600,
    }
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(signature)}"


def request_token(tenant: str, client_id: str, assertion: str) -> tuple[str, int]:
    """Return the access token and the number of seconds it is good for."""
    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "scope": OUTLOOK_SCOPE,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "grant_type": "client_credentials",
        }
    ).encode()
    request = urllib.request.Request(
        f"{LOGIN}/{tenant}/oauth2/v2.0/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:400]
        raise SystemExit(
            f"Token request refused ({error.code}).\n"
            f"  AADSTS700027 or 'certificate is not valid' means the certificate has expired or\n"
            f"  is no longer on the app registration -- see docs/RUNBOOK.md part D.\n"
            f"  'resource principal not found' means SMTP.SendAsApp is not granted.\n{detail}"
        )
    except urllib.error.URLError as error:
        raise SystemExit(f"Token endpoint unreachable: {error.reason}")

    token = payload.get("access_token")
    if not token:
        raise SystemExit("Token endpoint returned no access_token")
    # expires_in is what the issuer says, so it is preferred over decoding the
    # JWT ourselves. Microsoft currently returns about an hour.
    return token, int(payload.get("expires_in", 3600))


def write_token_file(path: Path, token: str, expires_in: int, group: int | None = None) -> int:
    """Write the token file atomically, without ever truncating a good one.

    The rename is what makes this safe: Postfix reads this file on every
    authentication, and a partially written file would fail authentication for
    however long the write took.
    """
    expiry = int(time.time()) + expires_in
    payload = {
        "access_token": token,
        # The plugin compares this against the clock and refreshes only when it
        # has passed. It must be true; see the module docstring.
        "expiry": str(expiry),
        # The plugin requires the key to be present but must never use it. Its
        # refresh path is delegated-only and cannot work with our credential, so
        # the token endpoint is also pointed at a dead port by
        # image's /etc/sasl-xoauth2.conf. A recognisable value makes it obvious in a
        # log that something has gone wrong if it ever appears in a request.
        "refresh_token": "unused-app-only-flow-see-docs-18",
    }

    # Include the PID in the staging name. The supervisor normally runs only
    # one minter, but an administrator may invoke a diagnostic concurrently;
    # sharing `relay.tmp` would let one process replace or delete the other's
    # staging file. Both names remain in the destination directory so rename is
    # atomic on every supported filesystem.
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(handle, "w") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        # Postfix runs as its own account inside the container and has to read
        # this file. Applying ownership before rename ensures there is never a
        # live 0600 root:root token, even for a fraction of a second. A previous
        # host-timer implementation changed ownership after the helper exited;
        # manual runs consequently produced a generic SASL failure.
        if group is not None:
            os.chown(temporary, -1, group)
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        os.replace(temporary, path)
    except OSError as error:
        # Expected storage failures are operator problems, not Python debugging
        # events. Remove only our staging file, preserve any existing good live
        # token, and report the exact destination plus the OS reason without a
        # traceback (or, importantly, any token bytes).
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        reason = error.strerror or str(error)
        raise TokenFileError(f"could not atomically replace token file {path}: {reason}") from None
    except BaseException:
        # Keep the same no-partial-file invariant for an unexpected exception,
        # while retaining its traceback because that path represents a code bug.
        temporary.unlink(missing_ok=True)
        raise
    return expiry


def read_env(env_file: Path) -> dict[str, str]:
    """Read the retained KEY=value diagnostic format without executing shell.

    Quoting and interpolation are intentionally unsupported. The container uses
    its real environment; this parser exists only for the off-host probe and
    treating an env file as shell would turn configuration into executable code.
    """
    env: dict[str, str] = {}
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
    parser.add_argument(
        "--token-file",
        default=None,
        help="Defaults to MAIL_TOKEN_FILE, or /run/mail-relay/relay.json",
    )
    parser.add_argument(
        "--min-remaining",
        type=int,
        default=0,
        help="Skip the mint if the existing token still has at least this many seconds left",
    )
    parser.add_argument("--quiet", action="store_true", help="Print nothing unless something fails")
    parser.add_argument("--no-chown", action="store_true",
                        help="Leave the token 0600 and owned by the caller, for testing")
    args = parser.parse_args()

    # Process environment is authoritative in the container. A .env file is a
    # compatibility fallback for the retained off-host diagnostic workflow.
    env = read_env(Path(args.env_file))
    env.update(os.environ)
    for key in ("MAIL_RELAY_TENANT", "MAIL_RELAY_CLIENT_ID"):
        if not env.get(key) or env[key] == "replace_me":
            print(f"{key} is not set", file=sys.stderr)
            return 1

    token_file = Path(
        args.token_file
        or env.get("MAIL_TOKEN_FILE")
        or "/run/mail-relay/relay.json"
    )

    # Lets the supervisor loop run often without minting every time, which keeps the
    # number of tokens issued proportionate to how long they actually last.
    if args.min_remaining and token_file.exists():
        try:
            existing = json.loads(token_file.read_text())
            remaining = int(existing.get("expiry", 0)) - int(time.time())
            if remaining >= args.min_remaining:
                if not args.quiet:
                    print(f"existing token still valid for {remaining}s; not minting")
                return 0
        except (ValueError, OSError):
            # An unreadable token file is a reason to mint, not to stop.
            pass

    key_path = Path(env.get("MAIL_RELAY_KEY_FILE") or "/var/lib/mail-relay/secrets/mail_relay_client_key.pem")
    cert_path = Path(env.get("MAIL_RELAY_CERT_FILE") or "/var/lib/mail-relay/secrets/mail_relay_client_cert.pem")
    if not key_path.is_absolute():
        key_path = project / key_path
    if not cert_path.is_absolute():
        cert_path = project / cert_path
    for path in (key_path, cert_path):
        if not path.is_file():
            print(f"Missing {path}; start the container once to generate its certificate", file=sys.stderr)
            return 1

    assertion = client_assertion(
        env["MAIL_RELAY_TENANT"],
        env["MAIL_RELAY_CLIENT_ID"],
        key_path.read_bytes(),
        cert_path.read_bytes(),
    )
    group = None
    if not args.no_chown:
        try:
            group = grp.getgrnam("postfix").gr_gid
        except KeyError:
            print("postfix group does not exist", file=sys.stderr)
            return 1

    token, expires_in = request_token(env["MAIL_RELAY_TENANT"], env["MAIL_RELAY_CLIENT_ID"], assertion)
    try:
        expiry = write_token_file(token_file, token, expires_in, group)
    except TokenFileError as error:
        print(f"Token file update failed: {error}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"wrote {token_file} (valid {expires_in}s, until {time.strftime('%H:%M:%S', time.localtime(expiry))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
