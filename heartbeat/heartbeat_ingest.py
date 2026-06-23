#!/usr/bin/env python3
"""heartbeat_ingest.py — HTTP(S) server that receives heartbeat POSTs and writes to engagement state.

Writes heartbeats to: ~/.umbra/engagements/{engagement}/heartbeats/{hostname}.json

Usage:
    python heartbeat_ingest.py <engagement> [--port 8443] [--bind 127.0.0.1]
    python heartbeat_ingest.py <engagement> --tls --cert cert.pem --key key.pem
    python heartbeat_ingest.py <engagement> --auth-token SECRET
"""

import argparse
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import sys
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler

UMBRA_HOME = os.path.expanduser("~/.umbra")
ENGAGEMENTS_DIR = os.path.join(UMBRA_HOME, "engagements")

# Will be set by main()
_engagement_name = ""
_heartbeat_dir = ""
_auth_token = ""


class HeartbeatHandler(BaseHTTPRequestHandler):
    """Handle POST /hb with JSON heartbeat payload."""

    def _check_auth(self):
        """Validate auth token if configured."""
        if not _auth_token:
            return True
        token = self.headers.get("X-Auth-Token", "")
        return hmac.compare_digest(token, _auth_token)

    def do_POST(self):
        if not self._check_auth():
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)

            hostname = data.get("hostname", "unknown").replace("/", "_").replace("..", "_")
            hb_path = os.path.join(_heartbeat_dir, f"{hostname}.json")

            with open(hb_path, "w") as f:
                json.dump(data, f, indent=2)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            print(f"  [+] {data.get('ts', '?')} heartbeat from {hostname} ({data.get('ip', '?')})")

        except (json.JSONDecodeError, KeyError) as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(f"bad request: {e}".encode())

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"error: {e}".encode())

    def do_GET(self):
        """Health check endpoint."""
        if not self._check_auth():
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok", "engagement": _engagement_name}).encode())

    def log_message(self, fmt, *args):
        """Suppress default access logging."""
        pass


def generate_self_signed_cert(cert_path, key_path):
    """Generate a self-signed certificate for TLS."""
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", "/CN=heartbeat-ingest",
        ], check=True, capture_output=True)
    except FileNotFoundError:
        raise RuntimeError("openssl not found — install it or provide --cert/--key manually")
    print(f"[*] Generated self-signed cert: {cert_path}")


def main():
    global _engagement_name, _heartbeat_dir, _auth_token

    parser = argparse.ArgumentParser(description="Heartbeat ingest server")
    parser.add_argument("engagement", help="Engagement name")
    parser.add_argument("--port", "-p", type=int, default=8443, help="Listen port (default: 8443)")
    parser.add_argument("--bind", "-b", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--auth-token", default=os.environ.get("UMBRA_HB_TOKEN", ""),
                        help="Shared secret for auth (X-Auth-Token header)")
    parser.add_argument("--tls", action="store_true", help="Enable TLS")
    parser.add_argument("--cert", default="", help="TLS certificate path (PEM)")
    parser.add_argument("--key", default="", help="TLS private key path (PEM)")
    args = parser.parse_args()

    _engagement_name = args.engagement.strip().replace(" ", "_")
    _heartbeat_dir = os.path.join(ENGAGEMENTS_DIR, _engagement_name, "heartbeats")
    os.makedirs(_heartbeat_dir, exist_ok=True)
    _auth_token = args.auth_token

    # Also ensure engagement dir exists
    eng_dir = os.path.join(ENGAGEMENTS_DIR, _engagement_name)
    os.makedirs(eng_dir, exist_ok=True)

    server = HTTPServer((args.bind, args.port), HeartbeatHandler)

    # TLS setup
    if args.tls:
        cert_path = args.cert
        key_path = args.key

        # Auto-generate self-signed cert if none provided
        if not cert_path or not key_path:
            cert_dir = os.path.join(eng_dir, "tls")
            os.makedirs(cert_dir, exist_ok=True)
            cert_path = os.path.join(cert_dir, "heartbeat.crt")
            key_path = os.path.join(cert_dir, "heartbeat.key")
            if not os.path.exists(cert_path):
                generate_self_signed_cert(cert_path, key_path)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = "https"
    else:
        proto = "http"

    print(f"[*] Heartbeat ingest listening on {args.bind}:{args.port} ({proto})")
    print(f"[*] Engagement: {_engagement_name}")
    print(f"[*] Writing to: {_heartbeat_dir}")
    print(f"[*] Auth: {'enabled' if _auth_token else 'disabled'}")
    print(f"[*] Endpoint: POST {proto}://<this-host>:{args.port}/hb")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
        server.server_close()


if __name__ == "__main__":
    main()
