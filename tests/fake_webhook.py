#!/usr/bin/env python3
"""Record JSON POST bodies for the isolated notification integration test."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API name
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            with lock, args.output.open("a") as handle:
                handle.write(json.dumps(payload) + "\n")
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"READY fake webhook receiver on {args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
