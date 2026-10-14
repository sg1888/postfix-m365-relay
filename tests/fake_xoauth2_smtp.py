#!/usr/bin/env python3
"""Small TLS/XOAUTH2 SMTP sink for isolated end-to-end container tests.

It records envelopes and message bytes but deliberately never records the bearer
token. This is protocol test infrastructure, not a general SMTP server.

--expect-token-sha256 accepts only the bearer token with that SHA-256, so a
plugin that sent a stale, empty or wrong token fails delivery instead of
passing. --reject-auth answers every AUTH the way Microsoft rejects a bad
token: a 334 challenge carrying {"status":"401",...}, then 535 after the
client's empty reply. --auth-log records each AUTH outcome (never the token).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import ssl
import threading
from pathlib import Path


class Sink:
    # What Microsoft sends in its 334 challenge when it rejects a token.
    REJECTION = base64.b64encode(
        b'{"status":"401","schemes":"bearer","scope":"https://outlook.office365.com/.default"}'
    ).decode()

    def __init__(self, output: Path, expect_token_sha256: str | None = None,
                 reject_auth: bool = False, auth_log: Path | None = None):
        self.output = output
        self.expect_token_sha256 = expect_token_sha256
        self.reject_auth = reject_auth
        self.auth_log = auth_log
        self.lock = threading.Lock()

    @staticmethod
    def send(stream, line: str) -> None:
        stream.write((line + "\r\n").encode())
        stream.flush()

    def record(self, record: dict, output: Path | None = None) -> None:
        with self.lock, (output or self.output).open("a") as handle:
            handle.write(json.dumps(record) + "\n")

    def authenticate(self, stream, argument: str) -> str | None:
        """Answer one AUTH command; return the authenticated user or None."""
        mechanism, _, encoded = argument.partition(" ")
        try:
            decoded = base64.b64decode(encoded).decode(errors="replace")
        except ValueError:
            decoded = ""
        fields = dict(
            field.split("=", 1) for field in decoded.split("\x01")
            if "=" in field
        )
        auth = fields.get("auth", "")
        token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else None
        if mechanism.upper() != "XOAUTH2" or not fields.get("user") or not token:
            result = "malformed"
        elif self.reject_auth:
            result = "rejected"
        elif self.expect_token_sha256 and \
                hashlib.sha256(token.encode()).hexdigest() != self.expect_token_sha256:
            result = "wrong-token"
        else:
            result = "accepted"
        if self.auth_log:
            self.record({"result": result, "user": fields.get("user")}, self.auth_log)
        if result == "accepted":
            self.send(stream, "235 2.7.0 Authentication successful")
            return fields["user"]
        if result == "rejected":
            # XOAUTH2 failure exchange: error JSON in a 334 challenge, the client
            # answers with an empty line (or aborts with "*"), then 535.
            self.send(stream, f"334 {self.REJECTION}")
            stream.readline()
        self.send(stream, "535 5.7.8 Authentication credentials invalid")
        return None

    @staticmethod
    def path_argument(argument: str, prefix: str) -> str:
        """Extract an SMTP path without mistaking ESMTP parameters for it."""
        value = argument.removeprefix(prefix).strip()
        if value.startswith("<") and ">" in value:
            return value[1:].split(">", 1)[0]
        return value.split(None, 1)[0]

    def handle(self, connection: socket.socket, context: ssl.SSLContext) -> None:
        stream = connection.makefile("rwb", buffering=0)
        tls = False
        authenticated_user = None
        mail_from = None
        recipients: list[str] = []
        try:
            self.send(stream, "220 fake-upstream ESMTP qualification sink")
            while line := stream.readline():
                command = line.decode(errors="replace").rstrip("\r\n")
                verb, _, argument = command.partition(" ")
                verb = verb.upper()
                if verb in ("EHLO", "HELO"):
                    self.send(stream, "250-fake-upstream")
                    if not tls:
                        self.send(stream, "250-STARTTLS")
                    else:
                        self.send(stream, "250-AUTH XOAUTH2")
                    self.send(stream, "250 SIZE 10485760")
                elif verb == "STARTTLS" and not tls:
                    self.send(stream, "220 Ready to start TLS")
                    # Re-wrap the accepted socket and replace the buffered stream.
                    # The client must EHLO again before AUTH, as Postfix does.
                    stream.close()
                    connection = context.wrap_socket(connection, server_side=True)
                    stream = connection.makefile("rwb", buffering=0)
                    tls = True
                elif verb == "AUTH" and tls:
                    authenticated_user = self.authenticate(stream, argument)
                elif verb == "MAIL" and authenticated_user:
                    mail_from = self.path_argument(argument, "FROM:")
                    recipients = []
                    self.send(stream, "250 2.1.0 Ok")
                elif verb == "RCPT" and mail_from is not None:
                    recipients.append(self.path_argument(argument, "TO:"))
                    self.send(stream, "250 2.1.5 Ok")
                elif verb == "DATA" and recipients:
                    self.send(stream, "354 End data with <CR><LF>.<CR><LF>")
                    content = bytearray()
                    while data_line := stream.readline():
                        if data_line in (b".\r\n", b".\n"):
                            break
                        if data_line.startswith(b".."):
                            data_line = data_line[1:]
                        content.extend(data_line)
                    self.record(
                        {
                            "tls": tls,
                            "authenticated_user": authenticated_user,
                            "mail_from": mail_from,
                            "recipients": recipients,
                            "message_b64": base64.b64encode(content).decode(),
                        }
                    )
                    mail_from = None
                    recipients = []
                    self.send(stream, "250 2.0.0 queued by qualification sink")
                elif verb == "RSET":
                    mail_from = None
                    recipients = []
                    self.send(stream, "250 2.0.0 Reset")
                elif verb == "NOOP":
                    self.send(stream, "250 2.0.0 Ok")
                elif verb == "QUIT":
                    self.send(stream, "221 2.0.0 Bye")
                    break
                else:
                    self.send(stream, "503 5.5.1 Bad command sequence")
        except (BrokenPipeError, ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=1587)
    parser.add_argument("--expect-token-sha256")
    parser.add_argument("--reject-auth", action="store_true")
    parser.add_argument("--auth-log", type=Path)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    sink = Sink(args.output, args.expect_token_sha256, args.reject_auth, args.auth_log)
    with socket.create_server(("0.0.0.0", args.port), reuse_port=True) as listener:
        print(f"READY fake XOAUTH2 SMTP sink on {args.port}", flush=True)
        while True:
            connection, _address = listener.accept()
            threading.Thread(target=sink.handle, args=(connection, context), daemon=True).start()


if __name__ == "__main__":
    main()
