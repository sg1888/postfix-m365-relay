#!/usr/bin/env python3
"""One remote SMTP policy assertion used by container-network tests."""

from __future__ import annotations

import argparse
import smtplib
import ssl


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--sender", default="app@relay.example.local")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--starttls", action="store_true", help="Negotiate TLS without authenticating")
    parser.add_argument(
        "--expect",
        required=True,
        choices=("accept", "policy-reject", "sender-reject", "auth-reject"),
    )
    args = parser.parse_args()

    smtp = smtplib.SMTP(args.host, 2525, timeout=10)
    smtp.ehlo()
    if args.username or args.starttls:
        smtp.starttls(context=ssl._create_unverified_context())
        smtp.ehlo()
    if args.username:
        try:
            smtp.login(args.username, args.password or "")
        except smtplib.SMTPAuthenticationError as error:
            smtp.close()
            if args.expect == "auth-reject":
                print(f"ok AUTH rejected: {error.smtp_code}")
                return 0
            raise
        if args.expect == "auth-reject":
            raise AssertionError("bad credentials authenticated")

    mail_code, mail_reply = smtp.mail(args.sender)
    if mail_code != 250:
        raise AssertionError(f"MAIL unexpectedly failed: {mail_code} {mail_reply!r}")
    rcpt_code, rcpt_reply = smtp.rcpt("recipient@example.invalid")
    reply = rcpt_reply.decode(errors="replace")
    smtp.close()

    if args.expect == "accept":
        assert rcpt_code == 250, (rcpt_code, reply)
    elif args.expect == "policy-reject":
        # Postfix may attribute the same policy denial to client, relay, or
        # recipient restrictions because this image intentionally renders the
        # relay list into smtpd_recipient_restrictions too. The first network
        # test observed "Recipient address rejected", so assert the security
        # outcome and known policy diagnostics rather than one presentation.
        assert rcpt_code >= 500 and (
            "Relay access denied" in reply
            or "Client host rejected" in reply
            or "Recipient address rejected" in reply
        ), (rcpt_code, reply)
    elif args.expect == "sender-reject":
        assert rcpt_code >= 500 and "Sender address rejected" in reply, (rcpt_code, reply)
    else:
        raise AssertionError("AUTH succeeded when auth-reject was expected")
    print(f"ok {args.expect}: RCPT {rcpt_code} {reply}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
