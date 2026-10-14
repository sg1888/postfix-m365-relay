#!/usr/bin/env python3
"""Receive syslog() messages on /dev/log and append them to the relay's log.

Postfix itself writes /var/log/mail-relay/postfix.log (maillog_file), and the
supervisor streams that file to the container log. Two libraries inside
Postfix's smtp process do not use Postfix's logger: the sasl-xoauth2 plugin and
Cyrus libsasl2 call syslog(), which writes to /dev/log. A container has no
syslog daemon, so without this bridge their messages are silently dropped and a
failed authentication shows only Postfix's "SASL authentication failed ...
generic failure", never the plugin's reason (for example "TokenStore::Read:
failed to open file").

Each datagram becomes one or more lines in postfix.log, formatted like
Postfix's own lines, so `docker logs`, the log file and verify-relay.sh all see
them. Started by relay-supervisor.sh (role "syslog") before Postfix.

The plugin's configuration keeps its token-revealing trace off
(/etc/sasl-xoauth2.conf, enforced by tests/container-sasl-plugin.sh), so these
messages are one-line failure summaries, never tokens.
"""

from __future__ import annotations

import os
import re
import socket
import sys
from datetime import datetime, timezone

SOCKET_PATH = "/dev/log"
LOG_PATH = "/var/log/mail-relay/postfix.log"
MAX_DATAGRAM = 8192
MAX_LINE = 2048
# "<PRI>" plus the optional RFC 3164 timestamp that glibc and musl prepend.
HEADER = re.compile(rb"^<\d{1,3}>(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?")
# Control characters would let a message forge extra log lines or hide text.
CONTROL = re.compile(rb"[\x00-\x08\x0b-\x1f\x7f]")


def lines_of(datagram: bytes) -> list[bytes]:
    """The printable log lines carried by one syslog datagram."""
    body = HEADER.sub(b"", datagram, count=1)
    lines = []
    for line in body.replace(b"\r", b"").split(b"\n"):
        line = CONTROL.sub(b"?", line).rstrip()
        if line:
            lines.append(line[:MAX_LINE])
    return lines


def main() -> int:
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(SOCKET_PATH)
    # Postfix's smtp process runs as the postfix user and must be able to send.
    os.chmod(SOCKET_PATH, 0o666)
    host = socket.gethostname()
    print("syslog-bridge: listening on /dev/log", flush=True)
    # O_APPEND: each line is appended atomically even while Postfix's postlogd
    # writes the same file, and a truncated file is simply appended to again.
    with open(LOG_PATH, "ab", buffering=0) as out:
        while True:
            datagram = sock.recv(MAX_DATAGRAM)
            for line in lines_of(datagram):
                stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
                out.write(stamp.encode() + b" " + host.encode() + b" " + line + b"\n")


if __name__ == "__main__":
    sys.exit(main())
