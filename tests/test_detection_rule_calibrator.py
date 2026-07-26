#!/usr/bin/env python3

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts import detection_rule_calibrator as calibrator


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


def make_row(
    index,
    src_ip="192.168.50.60",
    connections=1,
    unique_ports=1,
    unique_ips=1,
    failed=0.0,
    dns=0.0,
    burst=0.0,
    bytes_rate=0.0,
    risk=1.0,
    anomaly=0.0,
    dst_port="443",
    service="-",
    proto="tcp",
):
    return {
        "ts": str(1785055200 + index * 30),
        "datetime": f"2026-07-26 12:{index // 2:02d}:{(index % 2) * 30:02d}",
        "src_ip": src_ip,
        "connections_30s": str(connections),
        "unique_dst_ports_30s": str(unique_ports),
        "unique_dst_ips_30s": str(unique_ips),
        "failed_conn_rate_30s": str(failed),
        "dns_rate_30s": str(dns),
        "burst_score_30s": str(burst),
        "bytes_per_sec_30s": str(bytes_rate),
        "flag_port_scan": "0",
        "flag_brute_force": "0",
        "flag_burst": "0",
        "flag_dns_flood": "0",
        "flag_any": "0",
        "anomaly_score": str(anomaly),
        "risk_score": str(risk),
        "dst_port": dst_port,
        "service": service,
        "proto": proto,
    }


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DetectionRuleCalibratorTests(unittest.TestCase):
    def make_tree(self, rows):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        date = "2026-07-26"
        write_rows(root / "data" / "reports" / f"risk_{date}.csv", rows)
        write_rows(root / "data" / "windows" / f"windows_{date}.csv", rows)
        return tmp, root, date

    def test_exact_reproduction_of_synthetic_current_policy(self):
        rows = [
            make_row(1, failed=1.0),
            make_row(2, failed=1.0),
            make_row(3, failed=1.0),
            make_row(4, failed=1.0),
            make_row(5, failed=1.0),
            make_row(6, src_ip="192.168.50.95", unique_ips=12, connections=50, failed=0.3, risk=25),
        ]
        tmp, root, date = self.make_tree(rows)
        self.addCleanup(tmp.cleanup)

        summary, _paths = calibrator.run_calibration(date, base_dir=root)

        self.assertTrue(summary["offline_reproduction_matches_production"])
        self.assertEqual(summary["current_suspicious_rows"], 6)
        self.assertEqual(summary["current_classification_counts"]["FAILED_CONNECTION_PATTERN"], 5)
        self.assertEqual(summary["current_classification_counts"]["PORT_SCAN"], 1)

    def test_high_failed_rate_with_one_connection_does_not_pass_stricter_candidate(self):
        rows = [make_row(index, failed=1.0, connections=1) for index in range(1, 6)]
        current = calibrator.current_policy_rows(rows)
        policy = next(
            item for item in calibrator.candidate_policies()
            if item.name == "failed_abs_ge_5_connections_ge_10"
        )

        retained, removed = calibrator.apply_candidate(current, policy)

        self.assertEqual(len(retained), 0)
        self.assertEqual(len(removed), 5)

    def test_sustained_high_absolute_failures_can_pass(self):
        rows = [make_row(index, failed=0.9, connections=10) for index in range(1, 4)]
        current = calibrator.current_policy_rows(rows)
        policy = next(
            item for item in calibrator.candidate_policies()
            if item.name == "failed_abs_ge_5_connections_ge_10"
        )

        retained, removed = calibrator.apply_candidate(current, policy)

        self.assertEqual(len(retained), 3)
        self.assertEqual(len(removed), 0)

    def test_persistence_logic(self):
        rows = [
            make_row(1, failed=0.9, connections=10),
            make_row(2, failed=0.9, connections=10),
            make_row(3, failed=0.9, connections=10),
            make_row(20, src_ip="192.168.50.95", failed=0.9, connections=10),
        ]
        current = calibrator.current_policy_rows(rows)
        policy = next(
            item for item in calibrator.candidate_policies()
            if item.name == "failed_persistent_3_abs_ge_5"
        )

        retained, removed = calibrator.apply_candidate(current, policy)

        self.assertEqual(len(retained), 3)
        self.assertEqual(len(removed), 1)

    def test_consecutive_window_grouping(self):
        rows = [
            {"row_index": 1, "src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:00:00"},
            {"row_index": 2, "src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:00:30"},
            {"row_index": 3, "src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:05:00"},
        ]

        sequences = calibrator.group_sequences(rows)

        self.assertEqual([len(item) for item in sequences], [2, 1])

    def test_cooldown_deduplication(self):
        rows = [
            {"src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:00:00"},
            {"src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:00:30"},
            {"src_ip": "a", "classification": "FAILED_CONNECTION_PATTERN", "datetime": "2026-07-26 12:11:00"},
        ]

        self.assertEqual(calibrator.cooldown_alert_count(rows, 600), 2)

    def test_independent_signal_definition(self):
        row = make_row(1, failed=1.0, connections=10, risk=25, anomaly=0.0)
        row["classification"] = "FAILED_CONNECTION_PATTERN"

        signals = calibrator.independent_signal_groups(row, persistence_count=1, current_repeated_count=5)

        self.assertIn("direct_failed_connection_behavior", signals)
        self.assertIn("risk_evidence", signals)
        self.assertNotIn("model_evidence", signals)
        self.assertEqual(
            len([item for item in signals if item == "direct_failed_connection_behavior"]),
            1,
        )

    def test_normal_false_positive_calculation(self):
        policy = calibrator.CandidatePolicy("test", "test")
        retained = [make_row(1), make_row(2)]
        for index, row in enumerate(retained):
            row["classification"] = "FAILED_CONNECTION_PATTERN"
            row["row_index"] = index

        metrics = calibrator.candidate_metrics(10, 5, policy, retained)

        self.assertEqual(metrics["false_positive_rows"], 2)
        self.assertEqual(metrics["false_positive_rate"], 20.0)

    def test_attack_recall_unavailable_without_manifest(self):
        tmp, root, date = self.make_tree([make_row(1, failed=1.0)])
        self.addCleanup(tmp.cleanup)

        summary, _paths = calibrator.run_calibration(date, base_dir=root)

        self.assertFalse(summary["attack_validation_available"])
        self.assertEqual(summary["attack_validation"][0]["detection_rate_recall"], "unavailable")

    def test_no_production_files_modified_and_outputs_created(self):
        rows = [make_row(index, failed=1.0) for index in range(1, 6)]
        tmp, root, date = self.make_tree(rows)
        self.addCleanup(tmp.cleanup)
        sources = [
            root / "data" / "reports" / f"risk_{date}.csv",
            root / "data" / "windows" / f"windows_{date}.csv",
        ]
        before = {path: hash_file(path) for path in sources}

        _summary, paths = calibrator.run_calibration(date, base_dir=root)

        after = {path: hash_file(path) for path in sources}
        self.assertEqual(before, after)
        expected_outputs = {
            "calibration_summary",
            "calibration_report",
            "current_policy_reproduction",
            "candidate_comparison",
            "candidate_classification_breakdown",
            "false_positive_examples",
            "retained_and_removed_rows",
            "attack_validation",
            "ground_truth_gaps",
        }
        self.assertEqual(set(paths), expected_outputs)
        for path in paths.values():
            self.assertTrue(path.exists())

        payload = json.loads(paths["calibration_summary"].read_text(encoding="utf-8"))
        self.assertTrue(payload["offline_reproduction_matches_production"])


if __name__ == "__main__":
    unittest.main()
