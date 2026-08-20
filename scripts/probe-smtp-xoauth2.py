#!/usr/bin/env python3
"""Prove that SMTP AUTH with OAuth client credentials preserves the sender name.

Graph is closed: nine tests established that it stamps the sending mailbox's
directory display name and discards whatever the application set (docs/DESIGN.md).
Basic-auth SMTP does preserve the name -- observed in this tenant, in production,
for as long as the stack has existed -- but Microsoft turns basic auth off by
default at the end of December 2026.

The whole Postfix plan rests on one claim: that swapping the credential from a
password to an OAuth token changes nothing about the submission pipeline, so the
header survives exactly as it does today. That is documented and plausible and
nobody here has watched it happen. This script watches it happen, in about a
hundred lines, before anyone builds a custom image with sasl-xoauth2 in it and a
timer to refresh tokens.

It sends one message per candidate sender with a display name in the From header.
If those names arrive intact, the architecture is proven and Postfix becomes an
implementation detail. If they do not, the build was going to fail anyway and
this cost an evening instead of a week.

Two things worth knowing before running it:

- The token audience is Outlook, not Graph. SMTP AUTH is authorised by the
  `SMTP.SendAsApp` permission on **Office 365 Exchange Online**, a different
  resource with a different `.default` scope. The existing certificate and app
  registration are reused; only that permission is added.
- Delivery is not the question. Basic auth already proves mail flows. The only
  question is whether the display name in the header reaches the inbox, which
  means a human has to read it -- the app registration cannot read mail, and
  keeping it that way is deliberate.
"""

from __future__ import annotations

import argparse
import base64
import json
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage
from email.utils import formataddr

LOGIN = "https://login.microsoftonline.com"
# SMTP AUTH is authorised against Outlook, not Graph. Using Graph's scope here
# yields a token Exchange rejects at AUTH time with an unhelpful 535.
OUTLOOK_SCOPE = "https://outlook.office365.com/.default"
SMTP_HOST = "smtp.office365.com"
SMTP_PORT = 587


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def client_assertion(tenant: str, client_id: str, key_pem: bytes, cert_pem: bytes) -> str:
    """Sign the JWT that stands in for a client secret.

    Identical in shape to the one in probe-graph-sender-name.py. Deliberately
    duplicated rather than shared: these are throwaway diagnostics, and a common
    module between them would outlive both and have to be maintained.
    """
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


def access_token(tenant: str, client_id: str, assertion: str) -> str:
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
            f"Token request refused ({error.code}). If this says the resource principal "
            f"was not found, SMTP.SendAsApp has not been granted on Office 365 Exchange "
            f"Online yet.\n{detail}"
        )
    token = payload.get("access_token")
    if not token:
        raise SystemExit("Token endpoint returned no access_token")
    return token


def xoauth2_token(mailbox: str, token: str) -> str:
    """Build the SASL XOAUTH2 initial response.

    The format is fixed by the mechanism: user, then the bearer token, separated
    and terminated by ^A bytes. Exchange rejects anything else with a 535 that
    does not say why.
    """
    return base64.b64encode(
        f"user={mailbox}\x01auth=Bearer {token}\x01\x01".encode()
    ).decode()


def send_one(mailbox: str, token: str, sender: str, name: str, recipient: str) -> tuple[bool, str]:
    message = EmailMessage()
    message["From"] = formataddr((name, sender))
    message["To"] = recipient
    message["Subject"] = f"XOAUTH2 PROBE - {name}"
    message.set_content(
        "Sent over SMTP AUTH XOAUTH2 with an app-only OAuth token.\n"
        f"Authenticated as: {mailbox}\n"
        f"From address:     {sender}\n"
        f"Display name set: {name}\n\n"
        "If this arrives showing the display name above, SMTP submission still "
        "preserves headers when the credential is a token rather than a password, "
        "and the Postfix M365 relay will restore per-application sender names."
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            # smtplib has no XOAUTH2 helper, so the mechanism is driven directly.
            code, response = server.docmd("AUTH", "XOAUTH2 " + xoauth2_token(mailbox, token))
            if code != 235:
                return False, f"AUTH refused ({code}): {response.decode(errors='replace')[:200]}"
            server.send_message(message, from_addr=sender, to_addrs=[recipient])
    except smtplib.SMTPException as error:
        return False, f"{type(error).__name__}: {error}"

    return True, message["From"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--cert-file", required=True)
    parser.add_argument(
        "--mailbox",
        required=True,
        help="The mailbox to authenticate as, e.g. other@example.com",
    )
    parser.add_argument(
        "--sender",
        required=True,
        help="The From address, e.g. donotreply@example.com (may be an alias of --mailbox)",
    )
    parser.add_argument("--to", required=True, help="Inbox that will read the result")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be sent and acquire no token. Use this first.",
    )
    args = parser.parse_args()

    # Two names, so a partial result is still informative: if the bracketed one
    # fails and the plain one survives, the problem is header quoting rather than
    # the pipeline.
    names = ["Backups [Example]", "your monitoring system Example"]

    if args.dry_run:
        print(f"Would authenticate as {args.mailbox} via XOAUTH2 at {SMTP_HOST}:{SMTP_PORT}")
        print(f"Token scope: {OUTLOOK_SCOPE}")
        for name in names:
            print(f"  From: {formataddr((name, args.sender))}  ->  {args.to}")
        print("Nothing was sent and no token was requested.")
        return 0

    with open(args.key_file, "rb") as handle:
        key_pem = handle.read()
    with open(args.cert_file, "rb") as handle:
        cert_pem = handle.read()

    token = access_token(
        args.tenant,
        args.client_id,
        client_assertion(args.tenant, args.client_id, key_pem, cert_pem),
    )
    print(f"Token acquired for {OUTLOOK_SCOPE}")

    sent = 0
    for name in names:
        ok, detail = send_one(args.mailbox, token, args.sender, name, args.to)
        print(("sent: " if ok else "FAILED: ") + detail)
        sent += ok

    if not sent:
        print(
            "\nNothing was sent. A 535 at AUTH means the token is valid but Exchange will "
            "not accept it for this mailbox -- check that the Exchange role "
            "'Application SMTP.SendAsApp' is assigned to this app, that "
            "Test-ServicePrincipalAuthorization reports InScope=True for the mailbox, "
            "and that SMTP AUTH is enabled on the mailbox itself "
            "(Set-CASMailbox -SmtpClientAuthenticationDisabled $false). Do not add the "
            "legacy Entra SMTP.SendAsApp API permission to claims-less App RBAC."
        )
        return 1

    print(
        f"\n{sent} message(s) accepted. Read the inbox: if the display names arrived "
        "intact, SMTP submission preserves headers under OAuth exactly as it does "
        "under basic auth, and the Postfix M365 relay is worth building."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
