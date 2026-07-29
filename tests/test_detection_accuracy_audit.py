#!/usr/bin/env python3

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import detection_accuracy_audit as audit


HEADERS = [
    "ts",
    "datetime",
    "src_ip",
    "connections_30s",
    "unique_dst_ports_30s",
    "unique_dst_ips_30s",
    "failed_conn_rate_30s",
    "dns_rate_30s",
    "burst_score_30s",
    "bytes_per_sec_30s",
    "flag_port_scan",
    "flag_brute_force",
    "flag_burst",
    "flag_dns_flood",
    "flag_any",
    "anomaly_score",
    "risk_score",
    "dst_port",
    "service",
    "proto",
]


def row(
    index,
    src_ip="192.168.50.10",
    connections=1,
    unique_ports=1,
    unique_ips=1,
    failed=0.0,
    dns=0.0,
    burst=0.0,
    bytes_rate=0.0,
    flag_port_scan=0,
    flag_brute_force=0,
    flag_burst=0,
    flag_dns_flood=0,
    anomaly=0.0,
    risk=1.0,
    dst_port="443",
    service="-",
    proto="tcp",
):
    return {
        "ts": str(1785055200 + index),
        "datetime": f"2026-07-26 12:{index // 60:02d}:{index % 60:02d}",
        "src_ip": src_ip,
        "connections_30s": str(connections),
        "unique_dst_ports_30s": str(unique_ports),
        "unique_dst_ips_30s": str(unique_ips),
        "failed_conn_rate_30s": str(failed),
        "dns_rate_30s": str(dns),
        "burst_score_30s": str(burst),
        "bytes_per_sec_30s": str(bytes_rate),
        "flag_port_scan": str(flag_port_scan),
        "flag_brute_force": str(flag_brute_force),
        "flag_burst": str(flag_burst),
        "flag_dns_flood": str(flag_dns_flood),
        "flag_any": "1" if any([flag_port_scan, flag_brute_force, flag_burst, flag_dns_flood]) else "0",
        "anomaly_score": str(anomaly),
        "risk_score": str(risk),
        "dst_port": str(dst_port),
        "service": service,
        "proto": proto,
    }


def write_csv(path, rows, headers=HEADERS):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DetectionAccuracyAuditTests(unittest.TestCase):
    def make_tree(self, risk_rows, processed_rows=None, window_rows=None):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        date = "2026-07-26"
        write_csv(root / "data" / "reports" / f"risk_{date}.csv", risk_rows)
        write_csv(root / "data" / "processed" / f"baseline_{date}.csv", processed_rows or risk_rows)
        write_csv(root / "data" / "windows" / f"windows_{date}.csv", window_rows or risk_rows)
        return tmp, root, date

    def run_temp_audit(self, risk_rows, label="normal"):
        tmp, root, date = self.make_tree(risk_rows)
        self.addCleanup(tmp.cleanup)
        summary, paths = audit.run_audit(date, label, top=5, base_dir=root)
        return root, date, summary, paths

    def test_known_normal_rows_counted_as_false_positives(self):
        _root, _date, summary, _paths = self.run_temp_audit(
            [
                row(1, risk=1),
                row(2, src_ip="192.168.50.95", connections=90, unique_ips=12, failed=0.4, risk=35),
            ],
            label="normal",
        )

        self.assertEqual(summary["ground_truth"], "normal")
        self.assertEqual(summary["risk_row_count"], 2)
        self.assertEqual(summary["suspicious_row_count"], 1)
        self.assertEqual(summary["estimated_false_positive_rate"], 50.0)
        self.assertEqual(summary["top_false_positive_class"], "UNKNOWN_SUSPICIOUS")

    def test_empty_suspicious_set(self):
        _root, _date, summary, _paths = self.run_temp_audit([row(1, risk=1), row(2, risk=2)])

        self.assertEqual(summary["suspicious_row_count"], 0)
        self.assertEqual(summary["suspicious_window_percentage"], 0.0)
        self.assertEqual(summary["normal_window_percentage"], 100.0)

    def test_missing_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            summary, paths = audit.run_audit("2026-07-26", "unknown", base_dir=root)
            self.assertTrue(paths["audit_summary"].exists())

        self.assertEqual(summary["risk_row_count"], 0)
        self.assertEqual(sorted(summary["missing_files"]), ["processed", "risk", "windows"])

    def test_anomaly_score_zero_handling(self):
        _root, _date, summary, _paths = self.run_temp_audit(
            [
                row(1, risk=1, anomaly=0),
                row(2, connections=130, risk=45, anomaly=0),
                row(3, risk=35, anomaly=0.4),
            ]
        )

        self.assertEqual(summary["anomaly_score_zero_rows"], 2)
        self.assertEqual(summary["suspicious_rows_anomaly_score_zero"], 1)

    def test_heuristic_only_classifications(self):
        _root, _date, summary, _paths = self.run_temp_audit(
            [row(1, connections=130, risk=45, anomaly=0)]
        )

        self.assertEqual(summary["suspicious_row_count"], 1)
        self.assertEqual(summary["suspicious_rows_heuristic_only"], 1)

    def test_repeated_sequences(self):
        _root, _date, summary, _paths = self.run_temp_audit(
            [
                row(1, src_ip="192.168.50.95", connections=90, unique_ips=12, failed=0.4, risk=35),
                row(2, src_ip="192.168.50.95", connections=91, unique_ips=12, failed=0.4, risk=36),
                row(3, src_ip="192.168.50.20", risk=1),
                row(4, src_ip="192.168.50.95", connections=92, unique_ips=12, failed=0.4, risk=37),
            ]
        )

        sequences = summary["repeated_sequences"]
        self.assertEqual(len(sequences), 1)
        self.assertEqual(sequences[0]["src_ip"], "192.168.50.95")
        self.assertEqual(sequences[0]["classification"], "BOT_LIKE_BEHAVIOR")
        self.assertEqual(sequences[0]["count"], 3)
        self.assertEqual(sequences[0]["longest_consecutive_sequence"], 2)

    def test_quantile_calculations(self):
        self.assertEqual(audit.quantile_summary([1, 2, 3, 4])["p50"], 2.5)
        self.assertEqual(audit.quantile_summary([1, 2, 3, 4])["p75"], 3.25)
        self.assertEqual(audit.quantile_summary([1, 2, 3, 4])["max"], 4)

    def test_output_files_creation(self):
        _root, _date, _summary, paths = self.run_temp_audit(
            [row(1, connections=130, risk=45, anomaly=0)]
        )

        expected = {
            "audit_summary",
            "audit_report",
            "suspicious_rows",
            "classification_breakdown",
            "trigger_reason_breakdown",
            "repeated_sequences",
            "feature_quantiles",
        }
        self.assertEqual(set(paths), expected)
        for path in paths.values():
            self.assertTrue(path.exists())

        payload = json.loads(paths["audit_summary"].read_text(encoding="utf-8"))
        self.assertEqual(payload["suspicious_row_count"], 1)

    def test_source_files_remain_unchanged(self):
        risk_rows = [row(1, connections=130, risk=45, anomaly=0)]
        tmp, root, date = self.make_tree(risk_rows)
        self.addCleanup(tmp.cleanup)
        source_paths = [
            root / "data" / "reports" / f"risk_{date}.csv",
            root / "data" / "processed" / f"baseline_{date}.csv",
            root / "data" / "windows" / f"windows_{date}.csv",
        ]
        before = {path: file_hash(path) for path in source_paths}

        audit.run_audit(date, "normal", base_dir=root)

        after = {path: file_hash(path) for path in source_paths}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
