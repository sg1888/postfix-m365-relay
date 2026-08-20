#!/usr/bin/env python3
"""Submit one auditable positive or negative message through a test relay.

This is a qualification client, not part of the container runtime. Passwords are
read from a protected file, never accepted on the command line. Each accepted
message gets a unique Message-ID that can be correlated with relay logs and the
recipient mailbox; local SMTP acceptance alone is not reported as delivery.
"""

from __future__ import annotations

import argparse
import smtplib
import ssl
import sys
import uuid
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--from-address", required=True)
    parser.add_argument("--from-name", default="postfix-m365-relay qualification")
    parser.add_argument("--to", required=True)
    parser.add_argument("--subject", default="postfix-m365-relay qualification")
    parser.add_argument("--starttls", action="store_true")
    parser.add_argument("--username")
    parser.add_argument("--password-file", type=Path)
    parser.add_argument(
        "--expect",
        choices=("accepted", "rejected", "auth-rejected"),
        default="accepted",
    )
    args = parser.parse_args()

    if bool(args.username) != bool(args.password_file):
        parser.error("--username and --password-file must be supplied together")
    if args.username and not args.starttls:
        parser.error("credential tests require --starttls; plaintext AUTH is never supported")
    if args.password_file and not args.password_file.is_file():
        parser.error("--password-file must name a readable regular file")

    message_id = f"qualification-{uuid.uuid4()}@relay.example.local"
    message = EmailMessage()
    message["From"] = formataddr((args.from_name, args.from_address))
    message["To"] = args.to
    message["Subject"] = args.subject
    message["Message-ID"] = f"<{message_id}>"
    message.set_content(
        "postfix-m365-relay qualification message\n\n"
        f"Message-ID: <{message_id}>\n"
        "Acceptance must be confirmed in relay logs and the test recipient mailbox.\n"
    )

    try:
        with smtplib.SMTP(args.host, args.port, timeout=20) as smtp:
            smtp.ehlo()
            if args.starttls:
                # Qualification commonly uses the generated self-signed inbound
                # certificate. Certificate identity is tested separately; this
                # connection still proves encryption and AUTH ordering.
                smtp.starttls(context=ssl._create_unverified_context())
                smtp.ehlo()
            if args.username:
                password = args.password_file.read_text().rstrip("\r\n")
                smtp.login(args.username, password)
            smtp.send_message(message)
    except smtplib.SMTPAuthenticationError as error:
        if args.expect == "auth-rejected":
            print(f"EXPECTED AUTH REJECTION {error.smtp_code}: {error.smtp_error!r}")
            return 0
        raise
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as error:
        if args.expect == "rejected":
            print(f"EXPECTED SMTP REJECTION: {error}")
            return 0
        raise

    if args.expect != "accepted":
        print(f"FAILED: expected {args.expect}, but SMTP accepted the message", file=sys.stderr)
        return 1
    print(f"SMTP ACCEPTED Message-ID=<{message_id}>")
    print("Now require status=sent for this queue ID and visible receipt in the test mailbox.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
