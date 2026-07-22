#!/usr/bin/env python3
"""
Minimal read-only Gateway Status API + Dashboard server.
"""

import argparse
import csv
import http.server
import ipaddress
import json
import pathlib
import subprocess
import sys
from datetime import datetime


BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD_INDEX = BASE_DIR / "dashboard" / "index.html"
GATEWAY_DOCTOR = BASE_DIR / "scripts" / "gateway_doctor.py"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
REPORTS_DIR = BASE_DIR / "data" / "reports"
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
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
        elif path == "/api/live-summary":
            self.serve_live_summary()
        elif path == "/api/live-threats":
            self.serve_live_threats()
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

    def today(self):
        return datetime.now().strftime("%Y-%m-%d")

    def live_paths(self, day):
        return {
            "processed_today": PROCESSED_DIR / f"baseline_{day}.csv",
            "windows_today": WINDOWS_DIR / f"windows_{day}.csv",
            "risk_today": REPORTS_DIR / f"risk_{day}.csv",
        }

    def csv_row_count(self, path):
        if not path.exists():
            return 0
        try:
            with path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.reader(fh)
                next(reader, None)
                return sum(1 for _row in reader)
        except OSError:
            return 0

    def live_file_times(self, paths):
        times = {}
        for key, path in paths.items():
            if path.exists():
                try:
                    times[key] = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
                except OSError:
                    pass
        return times

    def configured_local_networks(self):
        networks = []
        try:
            profile = json.loads(NETWORK_PROFILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [ipaddress.ip_network("192.168.0.0/16")]

        candidates = []
        for key in ("monitored_networks", "trusted_networks"):
            value = profile.get(key)
            if isinstance(value, list):
                candidates.extend(str(item) for item in value)

        lan = profile.get("lan")
        if isinstance(lan, dict) and lan.get("cidr"):
            candidates.append(str(lan["cidr"]))

        for raw_network in candidates:
            try:
                network = ipaddress.ip_network(raw_network, strict=False)
            except ValueError:
                continue
            if network.is_private and network not in networks:
                networks.append(network)

        return networks or [ipaddress.ip_network("192.168.0.0/16")]

    def is_configured_local_ip(self, value, networks=None):
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        if networks is None:
            networks = self.configured_local_networks()
        return any(address in network for network in networks)

    def local_source_ips(self, path):
        if not path.exists():
            return []
        values = set()
        networks = self.configured_local_networks()
        try:
            with path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    src_ip = attack_classifier.row_value(row, "src_ip")
                    if src_ip and self.is_configured_local_ip(src_ip, networks):
                        values.add(src_ip)
        except OSError:
            return []
        return sorted(values)

    def suspicious_count(self, path):
        if not path.exists():
            return 0
        count = 0
        try:
            with path.open("r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if attack_classifier.is_suspicious_row(row):
                        count += 1
        except OSError:
            return 0
        return count

    def live_status_message(self, files_available, suspicious_rows):
        if not any(files_available.values()):
            return "Waiting for live pipeline output"
        if files_available.get("risk_today"):
            if suspicious_rows:
                return "Live monitoring active"
            return "Monitoring active - no live threats detected yet"
        return "Live monitoring active"

    def serve_live_summary(self):
        day = self.today()
        paths = self.live_paths(day)
        files_available = {key: path.exists() for key, path in paths.items()}
        processed_rows = self.csv_row_count(paths["processed_today"])
        windows_rows = self.csv_row_count(paths["windows_today"])
        risk_rows = self.csv_row_count(paths["risk_today"])
        suspicious_rows = self.suspicious_count(paths["risk_today"])
        local_ips = self.local_source_ips(paths["risk_today"])
        if not local_ips:
            local_ips = self.local_source_ips(paths["processed_today"])

        self.send_json(200, {
            "current_date": day,
            "live_mode": True,
            "files_available": files_available,
            "latest_file_times": self.live_file_times(paths),
            "traffic_summary": {
                "processed_rows": processed_rows,
                "windows_rows": windows_rows,
                "risk_rows": risk_rows,
                "suspicious_rows": suspicious_rows,
                "local_source_ips": local_ips,
            },
            "status_message": self.live_status_message(files_available, suspicious_rows),
            "read_only": True,
            "local_only": True,
        })

    def serve_live_threats(self):
        day = self.today()
        risk_file = REPORTS_DIR / f"risk_{day}.csv"

        if not risk_file.exists():
            self.send_json(200, {
                "current_date": day,
                "available": False,
                "message": "Waiting for live pipeline output",
                "events": [],
                "summary": {
                    "risk_rows": 0,
                    "suspicious_rows": 0,
                    "classified_rows": 0,
                    "attack_type_counts": {},
                    "high_confidence_counts": {},
                    "likely_actionable_events": 0,
                },
                "read_only": True,
                "local_only": True,
            })
            return

        try:
            day_summary = attack_classifier.audit_day(day, set())
            events = attack_classifier.top_display_events(
                attack_classifier.all_events([day_summary]),
                10,
            )
            message = (
                "Live monitoring active"
                if events
                else "Monitoring active - no live threats detected yet"
            )
            all_events = attack_classifier.all_events([day_summary])
            self.send_json(200, {
                "current_date": day,
                "available": True,
                "message": message,
                "events": events,
                "summary": {
                    "risk_rows": day_summary["risk_rows"],
                    "suspicious_rows": day_summary["suspicious_rows"],
                    "classified_rows": day_summary["classified_rows"],
                    "attack_type_counts": day_summary["attack_type_counts"],
                    "high_confidence_counts": attack_classifier.high_confidence_counts(all_events),
                    "likely_actionable_events": len(attack_classifier.likely_actionable_events(all_events)),
                    "top_src_ip_counts": day_summary["top_src_ip_counts"],
                },
                "classification_note": attack_classifier.CLASSIFICATION_NOTE,
                "read_only": True,
                "local_only": True,
            })
        except Exception as exc:
            self.send_json(200, {
                "current_date": day,
                "available": False,
                "message": f"Live risk report is present but could not be classified: {exc}",
                "events": [],
                "summary": {},
                "read_only": True,
                "local_only": True,
            })

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
            "release": "v10.2-soc-dashboard-redesign",
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
