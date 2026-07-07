#!/usr/bin/env python3
"""
Minimal read-only Gateway Status API + Dashboard server.
"""

import argparse
import http.server
import json
import pathlib
import subprocess
import sys


BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD_INDEX = BASE_DIR / "dashboard" / "index.html"
GATEWAY_DOCTOR = BASE_DIR / "scripts" / "gateway_doctor.py"
DEMO_SNAPSHOT_DATE = "2026-06-20"
DEMO_EVIDENCE_CACHE = None

if str(BASE_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "scripts"))

import attack_classifier  # noqa: E402
import post_training_day_audit  # noqa: E402


class GatewayStatusHandler(http.server.BaseHTTPRequestHandler):
    server_version = "NetGuardGatewayStatus/0.1"

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            self.serve_dashboard(send_body=True)
        elif path == "/api/status":
            self.serve_status()
        elif path == "/api/demo-summary":
            self.serve_demo_summary()
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

    def do_PATCH(self):
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

    def get_gateway_status(self):
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
            return None, {"error": "gateway doctor timed out"}
        except OSError as exc:
            return None, {"error": "gateway doctor failed", "detail": str(exc)}

        if result.returncode != 0:
            return None, {
                "error": "gateway doctor exited non-zero",
                "returncode": result.returncode,
            }

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None, {"error": "gateway doctor returned invalid JSON"}

        return payload, None

    def serve_status(self):
        payload, error = self.get_gateway_status()
        if error:
            self.send_json(503, error)
            return

        self.send_json(200, payload)

    def build_audit_summary(self):
        training_dt = post_training_day_audit.load_training_datetime()
        dates = post_training_day_audit.default_dates(training_dt)
        summaries = [
            post_training_day_audit.audit_day(day, 3)
            for day in dates
        ]
        payload = post_training_day_audit.audit_export_payload(
            training_dt,
            dates,
            summaries,
            summary_only=True,
        )
        return {
            "available": True,
            "trained_at": payload["trained_at"],
            "dates": payload["selected_dates"],
            "recommendation": payload["retraining_recommendation"],
            "labels": payload["label_summary"],
            "note": payload["preliminary_label_note"],
        }

    def build_classification_summary(self):
        training_dt = attack_classifier.load_training_datetime()
        day_summary = attack_classifier.audit_day(DEMO_SNAPSHOT_DATE, set())
        events = attack_classifier.all_events([day_summary])
        top_events = attack_classifier.top_display_events(events, 5)
        return {
            "available": True,
            "date": DEMO_SNAPSHOT_DATE,
            "trained_at": training_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "risk_rows": day_summary["risk_rows"],
            "suspicious_rows": day_summary["suspicious_rows"],
            "classified_rows": day_summary["classified_rows"],
            "attack_type_counts": day_summary["attack_type_counts"],
            "high_confidence_counts": attack_classifier.high_confidence_counts(events),
            "likely_actionable_events": len(attack_classifier.likely_actionable_events(events)),
            "top_events": top_events,
            "note": attack_classifier.CLASSIFICATION_NOTE,
            "calibration_note": attack_classifier.CALIBRATION_NOTE,
            "retraining_note": attack_classifier.RETRAINING_NOTE,
        }

    def serve_demo_summary(self):
        global DEMO_EVIDENCE_CACHE

        gateway_status, gateway_error = self.get_gateway_status()

        if DEMO_EVIDENCE_CACHE is None:
            try:
                audit = self.build_audit_summary()
            except Exception as exc:
                audit = {
                    "available": False,
                    "error": str(exc),
                    "recommendation": "Audit summary unavailable from saved reports.",
                    "labels": {},
                }

            try:
                classification = self.build_classification_summary()
            except Exception as exc:
                classification = {
                    "available": False,
                    "error": str(exc),
                    "date": DEMO_SNAPSHOT_DATE,
                    "attack_type_counts": {},
                    "high_confidence_counts": {},
                    "likely_actionable_events": 0,
                    "top_events": [],
                    "note": "Run attack_classifier.py to generate detailed classification evidence.",
                }

            DEMO_EVIDENCE_CACHE = {
                "audit": audit,
                "classification": classification,
            }

        self.send_json(200, {
            "project": "NetGuard-AI Gateway",
            "release": "v10.1-professional-demo-dashboard",
            "read_only": True,
            "local_only": True,
            "demo_snapshot_date": DEMO_SNAPSHOT_DATE,
            "gateway_status": gateway_status,
            "gateway_status_available": gateway_status is not None,
            "gateway_status_error": gateway_error,
            "audit": DEMO_EVIDENCE_CACHE["audit"],
            "classification": DEMO_EVIDENCE_CACHE["classification"],
            "safety": {
                "allowed_methods": ["GET", "HEAD"],
                "rejected_methods": ["POST", "PUT", "PATCH", "DELETE"],
                "writes_files": False,
                "changes_detection_logic": False,
            },
        })

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
