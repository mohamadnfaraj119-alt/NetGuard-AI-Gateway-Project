#!/usr/bin/env python3
"""
Minimal read-only Gateway Status API + Dashboard server.
"""

import argparse
import http.server
import json
import pathlib
import subprocess


BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD_INDEX = BASE_DIR / "dashboard" / "index.html"
GATEWAY_DOCTOR = BASE_DIR / "scripts" / "gateway_doctor.py"


class GatewayStatusHandler(http.server.BaseHTTPRequestHandler):
    server_version = "NetGuardGatewayStatus/0.1"

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            self.serve_dashboard(send_body=True)
        elif path == "/api/status":
            self.serve_status()
        elif path == "/healthz":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_HEAD(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            self.serve_dashboard(send_body=False)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        self.method_not_allowed()

    def do_PUT(self):
        self.method_not_allowed()

    def do_DELETE(self):
        self.method_not_allowed()

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")

    def method_not_allowed(self):
        self.send_json(405, {"error": "method not allowed"})

    def serve_dashboard(self, send_body):
        try:
            body = DASHBOARD_INDEX.read_bytes()
        except OSError:
            self.send_json(503, {"error": "dashboard unavailable"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def serve_status(self):
        try:
            result = subprocess.run(
                ["python3", str(GATEWAY_DOCTOR), "--json"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=10,
                cwd=BASE_DIR,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.send_json(503, {"error": "gateway doctor timed out"})
            return
        except OSError as exc:
            self.send_json(503, {"error": "gateway doctor failed", "detail": str(exc)})
            return

        if result.returncode != 0:
            self.send_json(503, {
                "error": "gateway doctor exited non-zero",
                "returncode": result.returncode,
            })
            return

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            self.send_json(503, {"error": "gateway doctor returned invalid JSON"})
            return

        self.send_json(200, payload)

    def send_json(self, status_code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetGuard-AI Gateway read-only status API and dashboard"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    return parser.parse_args()


def main():
    args = parse_args()
    server = http.server.ThreadingHTTPServer(
        (args.host, args.port),
        GatewayStatusHandler,
    )
    print(f"Gateway Status API listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
