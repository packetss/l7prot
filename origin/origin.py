#!/usr/bin/env python3
"""
Minimal origin server for the L7 protection POC.

Runs on 127.0.0.1:8080 ONLY. Its whole job is to be a real origin behind
Envoy so you can prove:
  - traffic actually flows through Envoy
  - Envoy's cache/rate-limit/WAF are doing something
  - the origin is NOT reachable from outside

Endpoints:
  GET  /healthz          -> 200, cheap, used by Envoy health check
  GET  /                 -> the site
  GET  /api/echo         -> echoes request metadata as JSON (great for testing
                            that headers/JA4/logs all line up)
  POST /api/submit       -> POST endpoint, never cached
"""

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"          # deliberately loopback-only
PORT = int(os.environ.get("ORIGIN_PORT", "8080"))
SITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "origin/1.0"
    sys_version = ""

    # quiet by default; set ORIGIN_VERBOSE=1 to see every request
    def log_message(self, fmt, *args):
        if os.environ.get("ORIGIN_VERBOSE"):
            print("[origin] " + (fmt % args), flush=True)

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/healthz":
            self._send(200, "ok\n", "text/plain")
            return

        if path == "/api/echo":
            payload = {
                "path": self.path,
                "method": "GET",
                "client": self.client_address[0],
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "ts": time.time(),
            }
            self._send(200, json.dumps(payload, indent=2), "application/json")
            return

        if path == "/":
            try:
                with open(os.path.join(SITE, "index.html"), "rb") as fh:
                    self._send(200, fh.read())
            except OSError:
                self._send(200, "<h1>origin ok</h1><p>index.html missing</p>")
            return

        self._send(404, "<h1>404</h1>\n")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""

        if path == "/api/submit":
            payload = {
                "received": len(body),
                "content_type": self.headers.get("Content-Type"),
                "ts": time.time(),
            }
            self._send(200, json.dumps(payload), "application/json")
            return

        self._send(404, "<h1>404</h1>\n")


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    print(f"[origin] listening on {HOST}:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
