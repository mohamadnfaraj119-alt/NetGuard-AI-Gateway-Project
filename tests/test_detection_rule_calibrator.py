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
    "unique_dst_ports_1m",
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
    unique_ports_1m=None,
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
        "unique_dst_ports_1m": "" if unique_ports_1m is None else str(unique_ports_1m),
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


def write_manifest(path, sessions):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sessions": sessions}, indent=2), encoding="utf-8")


def session(
    label,
    date,
    start,
    stop,
    source_ips=None,
    expected_classes=None,
    scenario="scenario",
):
    return {
        "date": date,
        "label": label,
        "expected_classes": expected_classes or [],
        "source_ips": source_ips or [],
        "time_start": "2026-07-26T12:00:00",
        "time_end": "2026-07-26T12:30:00",
        "scenario": scenario,
        "notes": "",
        "row_boundaries": {
            "risk": {
                "start_row": start,
                "stop_row": stop,
                "rows_added": stop - start,
            }
        },
    }


def old_session_without_boundaries(
    label,
    date,
    source_ips=None,
    expected_classes=None,
    scenario="old_manifest_session",
    time_start="2026-07-26T12:00:00+03:00",
    time_end="2026-07-26T12:30:00+03:00",
):
    return {
        "date": date,
        "label": label,
        "expected_classes": expected_classes or [],
        "source_ips": source_ips or [],
        "time_start": time_start,
        "time_end": time_end,
        "scenario": scenario,
        "notes": "",
    }


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

    def test_mixed_date_manifest_scoping_uses_only_labeled_normal_boundaries(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        date_a = "2026-07-26"
        date_b = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{date_a}.csv", [
            make_row(0, src_ip="10.0.0.1"),
            make_row(1, src_ip="10.0.0.1", failed=1.0),
            make_row(2, src_ip="10.0.0.1", failed=1.0),
            make_row(3, src_ip="10.0.0.1"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{date_b}.csv", [
            make_row(4, src_ip="10.0.0.2", failed=1.0),
            make_row(5, src_ip="10.0.0.2"),
        ])
        write_rows(root / "data" / "windows" / f"windows_{date_a}.csv", [])
        write_rows(root / "data" / "windows" / f"windows_{date_b}.csv", [])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", date_a, 1, 3, ["10.0.0.1"], scenario="normal_a"),
            session("normal", date_b, 0, 1, ["10.0.0.2"], scenario="normal_b"),
        ])

        summary, _paths = calibrator.run_calibration(normal_manifest=manifest, base_dir=root)

        self.assertEqual(summary["normal_risk_rows"], 3)
        self.assertEqual(summary["normal_sessions_used"], 2)
        self.assertEqual(summary["normal_sessions_excluded"], 0)
        self.assertEqual(summary["normal_dates"], [date_a, date_b])

    def test_manifest_source_ip_filtering(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        date = "2026-07-26"
        write_rows(root / "data" / "reports" / f"risk_{date}.csv", [
            make_row(0, src_ip="10.0.0.1", failed=1.0),
            make_row(1, src_ip="10.0.0.2", failed=1.0),
            make_row(2, src_ip="10.0.0.1", failed=1.0),
            make_row(3, src_ip="10.0.0.2", failed=1.0),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", date, 0, 4, ["10.0.0.1"], scenario="source_filtered"),
        ])

        summary, _paths = calibrator.run_calibration(normal_manifest=manifest, base_dir=root)

        self.assertEqual(summary["normal_risk_rows"], 2)
        self.assertEqual(summary["normal_source_rows"], 2)

    def test_zero_row_normal_session_excluded(self):
        tmp, root, date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("normal", date, 1, 1, ["10.0.0.2"], scenario="zero_risk_ap_normal"),
        ])

        summary, _paths = calibrator.run_calibration(normal_manifest=manifest, base_dir=root)

        self.assertEqual(summary["normal_sessions_used"], 1)
        self.assertEqual(summary["normal_sessions_excluded"], 1)
        self.assertEqual(summary["excluded_session_details"][0]["scenario"], "zero_risk_ap_normal")
        self.assertEqual(summary["excluded_session_details"][0]["reason"], "risk.rows_added <= 0")

    def test_invalid_boundary_normal_session_excluded(self):
        tmp, root, date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("normal", date, 0, 99, ["10.0.0.1"], scenario="invalid_bounds"),
        ])

        summary, _paths = calibrator.run_calibration(normal_manifest=manifest, base_dir=root)

        self.assertEqual(summary["normal_sessions_used"], 1)
        self.assertEqual(summary["normal_sessions_excluded"], 1)
        self.assertIn("exceeds CSV rows", summary["excluded_session_details"][0]["reason"])

    def test_overlapping_normal_sessions_are_deduplicated_by_original_row(self):
        tmp, root, date = self.make_tree([
            make_row(0, src_ip="10.0.0.1"),
            make_row(1, src_ip="10.0.0.1"),
            make_row(2, src_ip="10.0.0.1"),
            make_row(3, src_ip="10.0.0.1"),
        ])
        self.addCleanup(tmp.cleanup)
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", date, 0, 3, ["10.0.0.1"], scenario="overlap_one"),
            session("normal", date, 1, 4, ["10.0.0.1"], scenario="overlap_two"),
        ])

        summary, _paths = calibrator.run_calibration(normal_manifest=manifest, base_dir=root)

        self.assertEqual(summary["normal_risk_rows"], 4)
        self.assertEqual(summary["normal_sessions_used"], 2)

    def test_seven_session_manifest_uses_valid_sessions_and_excludes_zero_risk_attacks(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-06-20"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="192.168.50.60"),
            make_row(1, src_ip="192.168.50.61"),
            make_row(2, src_ip="192.168.50.70"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(
                0,
                src_ip="192.168.50.95",
                unique_ips=12,
                connections=50,
                failed=0.3,
                risk=25,
            )
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["192.168.50.60"], scenario="phone_active_web_video_normal"),
            session("normal", normal_date, 1, 2, ["192.168.50.61"], scenario="desktop_active_web_office_normal"),
            session("normal", normal_date, 2, 2, ["192.168.50.1"], scenario="ap_idle_normal_zero_risk"),
            session("normal", normal_date, 2, 2, ["192.168.50.2"], scenario="ap_background_normal_zero_risk"),
            session(
                "attack",
                attack_date,
                0,
                1,
                ["192.168.50.95"],
                ["PORT_SCAN"],
                "controlled_port_scan_windows_to_gateway_validated",
            ),
            session("attack", attack_date, 1, 1, ["192.168.50.95"], ["DNS_ANOMALY"], "zero_risk_attack_dns"),
            session(
                "attack",
                attack_date,
                1,
                1,
                ["192.168.50.95"],
                ["SSH_BRUTE_FORCE_OR_LOGIN_PATTERN"],
                "zero_risk_attack_ssh",
            ),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        self.assertEqual(
            summary["normal_session_names_used"],
            ["phone_active_web_video_normal", "desktop_active_web_office_normal"],
        )
        self.assertEqual(
            summary["attack_session_names_used"],
            ["controlled_port_scan_windows_to_gateway_validated"],
        )
        self.assertEqual(summary["normal_sessions_total"], 4)
        self.assertEqual(summary["normal_sessions_excluded"], 2)
        self.assertEqual(summary["attack_sessions_total"], 3)
        self.assertEqual(summary["attack_sessions_excluded"], 2)
        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == "current_policy"
        ][0]
        self.assertEqual(current_attack["missed_expected_attacks"], "")

    def test_attack_session_exclusion_without_recall_penalty_for_no_expected_classes(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-06-20"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.2", failed=1.0),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 0, 1, ["10.0.0.2"], [], "attack_without_expected_class"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        self.assertFalse(summary["attack_validation_available"])
        self.assertEqual(summary["attack_sessions_total"], 1)
        self.assertEqual(summary["attack_sessions_used"], 0)
        self.assertEqual(summary["attack_sessions_excluded"], 1)
        self.assertEqual(summary["attack_validation"][0]["detection_rate_recall"], "unavailable")

    def test_backward_compatible_normal_date_mode(self):
        tmp, root, date = self.make_tree([make_row(0), make_row(1, failed=1.0)])
        self.addCleanup(tmp.cleanup)

        summary, _paths = calibrator.run_calibration(normal_date=date, base_dir=root)

        self.assertEqual(summary["normal_date"], date)
        self.assertEqual(summary["normal_risk_rows"], 2)
        self.assertEqual(summary["normal_sessions_total"], 0)
        self.assertEqual(summary["normal_source_rows"], 2)

    def test_aware_manifest_timestamps_with_naive_risk_timestamps_do_not_raise(self):
        row = make_row(0, src_ip="10.0.0.9")
        row["datetime"] = "2026-07-27 14:29:47"
        manifest_session = old_session_without_boundaries(
            "attack",
            "2026-07-27",
            ["10.0.0.9"],
            ["PORT_SCAN"],
            time_start="2026-07-27T14:29:00+03:00",
            time_end="2026-07-27T14:30:08+03:00",
        )

        self.assertTrue(calibrator.row_in_session(row, manifest_session))

    def test_attack_selection_uses_exact_risk_row_boundaries(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25),
            make_row(1, src_ip="10.0.0.9"),
            make_row(2, src_ip="10.0.0.9"),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 1, 3, ["10.0.0.9"], ["PORT_SCAN"], "bounded_attack"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == "current_policy"
        ][0]
        self.assertEqual(current_attack["detected_classifications"], "")
        self.assertEqual(current_attack["missed_expected_attacks"], "PORT_SCAN")

    def test_attack_source_ip_filtering_inside_boundaries(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.8", unique_ips=12, connections=50, failed=0.3, risk=25),
            make_row(1, src_ip="10.0.0.9"),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 0, 2, ["10.0.0.9"], ["PORT_SCAN"], "source_filtered_attack"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == "current_policy"
        ][0]
        self.assertEqual(current_attack["detected_classifications"], "")
        self.assertEqual(current_attack["missed_expected_attacks"], "PORT_SCAN")

    def test_attack_rows_outside_boundaries_are_not_included(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25),
            make_row(1, src_ip="10.0.0.9"),
            make_row(2, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 1, 2, ["10.0.0.9"], ["PORT_SCAN"], "middle_only_attack"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == "current_policy"
        ][0]
        self.assertEqual(current_attack["detected_classifications"], "")
        self.assertEqual(current_attack["missed_expected_attacks"], "PORT_SCAN")

    def test_invalid_attack_boundaries_are_excluded(self):
        tmp, root, normal_date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 0, 5, ["10.0.0.9"], ["PORT_SCAN"], "invalid_attack_bounds"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        self.assertFalse(summary["attack_validation_available"])
        self.assertEqual(summary["attack_sessions_excluded"], 1)
        self.assertIn("exceeds CSV rows", summary["excluded_session_details"][-1]["reason"])

    def test_zero_row_attack_session_excluded_without_recall_penalty(self):
        tmp, root, normal_date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [
            make_row(0, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25),
        ])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 0, 0, ["10.0.0.9"], ["PORT_SCAN"], "zero_row_attack"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        self.assertFalse(summary["attack_validation_available"])
        self.assertEqual(summary["attack_sessions_excluded"], 1)
        self.assertEqual(summary["attack_validation"][0]["detection_rate_recall"], "unavailable")

    def test_timestamp_fallback_for_old_manifest_without_row_boundaries(self):
        tmp, root, normal_date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        attack_date = "2026-07-27"
        before = make_row(0, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25)
        before["datetime"] = "2026-07-27 14:28:30"
        inside = make_row(1, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25)
        inside["datetime"] = "2026-07-27 14:29:47"
        after = make_row(2, src_ip="10.0.0.9", unique_ips=12, connections=50, failed=0.3, risk=25)
        after["datetime"] = "2026-07-27 14:31:00"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [before, inside, after])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            old_session_without_boundaries(
                "attack",
                attack_date,
                ["10.0.0.9"],
                ["PORT_SCAN"],
                "old_manifest_attack",
                "2026-07-27T14:29:00+03:00",
                "2026-07-27T14:30:08+03:00",
            ),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == "current_policy"
        ][0]
        self.assertEqual(current_attack["detected_classifications"], "PORT_SCAN")
        self.assertEqual(current_attack["missed_expected_attacks"], "")

    def test_portscan_classification_without_flag_is_review_only(self):
        row = make_row(0, unique_ports=25, connections=50, failed=0.3, risk=25)
        current = calibrator.current_policy_rows([row])

        self.assertEqual(current[0]["classification"], "PORT_SCAN")
        self.assertFalse(calibrator.is_actionable_portscan_alert(current[0]))

    def test_normal_cdn_fanout_with_few_ports_is_not_actionable(self):
        row = make_row(0, unique_ports=6, unique_ips=30, connections=50, risk=25)
        row["flag_port_scan"] = "0"
        current = calibrator.current_policy_rows([row])

        self.assertEqual(current[0]["classification"], "PORT_SCAN")
        self.assertFalse(calibrator.is_actionable_portscan_alert(current[0]))

    def test_validated_attack_with_flag_and_101_ports_is_actionable(self):
        row = make_row(0, unique_ports=101, connections=120, failed=0.3, risk=40)
        row["flag_port_scan"] = "1"
        current = calibrator.current_policy_rows([row])

        self.assertEqual(current[0]["classification"], "PORT_SCAN")
        self.assertTrue(calibrator.is_actionable_portscan_alert(current[0]))

    def test_unique_dst_ports_1m_can_satisfy_actionable_portscan_condition(self):
        row = make_row(0, unique_ports=6, unique_ports_1m=102, unique_ips=30, connections=50, risk=25)
        row["flag_port_scan"] = "1"
        current = calibrator.current_policy_rows([row])

        self.assertEqual(current[0]["classification"], "PORT_SCAN")
        self.assertTrue(calibrator.is_actionable_portscan_alert(current[0]))

    def test_missing_actionable_evidence_fields_fail_closed(self):
        row = {"classification": "PORT_SCAN", "src_ip": "10.0.0.1", "datetime": "2026-07-26 12:00:00"}

        self.assertFalse(calibrator.is_actionable_portscan_alert(row))

    def test_unvalidated_attack_classes_remain_review_only(self):
        tmp, root, normal_date = self.make_tree([make_row(0, src_ip="10.0.0.1")])
        self.addCleanup(tmp.cleanup)
        attack_date = "2026-07-27"
        attack_row = make_row(0, src_ip="10.0.0.9", connections=130, risk=30)
        attack_row["flag_burst"] = "1"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [attack_row])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session("attack", attack_date, 0, 1, ["10.0.0.9"], ["DOS_LIKE_BURST"], "burst_attack"),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )

        current_attack = [
            row for row in summary["attack_validation"]
            if row["candidate_policy"] == calibrator.VALIDATED_ALERT_TIER_POLICY
        ][0]
        self.assertEqual(current_attack["detected_classifications"], "DOS_LIKE_BURST")
        self.assertEqual(current_attack["detected_actionable_classifications"], "")
        self.assertEqual(current_attack["actionable_attack_recall"], "unavailable")

    def test_actionable_false_positive_rate_and_cooldown_calculations(self):
        policy = calibrator.CandidatePolicy("test", "test")
        retained = []
        for index, time_text in enumerate(["2026-07-26 12:00:00", "2026-07-26 12:00:30"]):
            row = make_row(index, src_ip="10.0.0.1", unique_ports=101, connections=80, failed=0.3, risk=30)
            row["flag_port_scan"] = "1"
            row["classification"] = "PORT_SCAN"
            row["datetime"] = time_text
            retained.append(row)
        review = make_row(3, failed=1.0)
        review["classification"] = "FAILED_CONNECTION_PATTERN"
        retained.append(review)

        metrics = calibrator.candidate_metrics(100, 3, policy, retained)

        self.assertEqual(metrics["review_rows"], 3)
        self.assertEqual(metrics["actionable_false_positive_rows"], 2)
        self.assertEqual(metrics["actionable_false_positive_rate"], 2.0)
        self.assertEqual(metrics["actionable_alerts_after_cooldown"], 1)

    def test_staged_alerting_ready_acceptance_conditions(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        attack_row = make_row(0, src_ip="10.0.0.9", unique_ports=101, connections=120, failed=0.3, risk=40)
        attack_row["flag_port_scan"] = "1"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [attack_row])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session(
                "attack",
                attack_date,
                0,
                1,
                ["10.0.0.9"],
                ["PORT_SCAN"],
                "controlled_port_scan_windows_to_gateway_validated",
            ),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )
        tier = [
            row for row in summary["candidate_comparison"]
            if row["candidate_policy"] == calibrator.VALIDATED_ALERT_TIER_POLICY
        ][0]

        self.assertTrue(tier["staged_alerting_ready"])
        self.assertFalse(tier["production_ready"])
        self.assertEqual(tier["actionable_attack_recall"], 100.0)

    def test_row_level_false_positive_metrics_remain_unchanged_for_alert_tier(self):
        rows = [
            make_row(0, failed=1.0),
            make_row(1, failed=1.0),
            make_row(2, unique_ports=25, connections=50, failed=0.3, risk=25),
        ]
        tmp, root, date = self.make_tree(rows)
        self.addCleanup(tmp.cleanup)

        summary, _paths = calibrator.run_calibration(normal_date=date, base_dir=root)
        comparison = {row["candidate_policy"]: row for row in summary["candidate_comparison"]}

        self.assertEqual(
            comparison["combined_conservative"]["false_positive_rows"],
            comparison[calibrator.VALIDATED_ALERT_TIER_POLICY]["false_positive_rows"],
        )
        self.assertEqual(
            comparison["combined_conservative"]["normal_target_met"],
            comparison[calibrator.VALIDATED_ALERT_TIER_POLICY]["normal_target_met"],
        )

    def test_valid_attack_manifest_changes_stale_report_wording(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        normal_date = "2026-07-26"
        attack_date = "2026-07-27"
        write_rows(root / "data" / "reports" / f"risk_{normal_date}.csv", [
            make_row(0, src_ip="10.0.0.1"),
        ])
        attack_row = make_row(0, src_ip="10.0.0.9", unique_ports=101, connections=120, failed=0.3, risk=40)
        attack_row["flag_port_scan"] = "1"
        write_rows(root / "data" / "reports" / f"risk_{attack_date}.csv", [attack_row])
        manifest = root / "manifest.json"
        write_manifest(manifest, [
            session("normal", normal_date, 0, 1, ["10.0.0.1"], scenario="valid_normal"),
            session(
                "attack",
                attack_date,
                0,
                1,
                ["10.0.0.9"],
                ["PORT_SCAN"],
                "controlled_port_scan_windows_to_gateway_validated",
            ),
        ])

        summary, _paths = calibrator.run_calibration(
            normal_manifest=manifest,
            attack_manifest=manifest,
            base_dir=root,
        )
        report = calibrator.markdown_report(summary)
        gaps = calibrator.ground_truth_gaps_markdown(summary)

        self.assertNotIn("attack recall remains unavailable", report)
        self.assertNotIn("Build a scoped attack ground-truth manifest", report)
        self.assertIn("Valid bounded attack sessions used", gaps)
        self.assertIn("controlled_port_scan_windows_to_gateway_validated", gaps)

    def test_negative_21_second_delay_is_overlapping_window(self):
        row = make_row(0, src_ip="10.0.0.9", unique_ports=101, connections=120, failed=0.3, risk=40)
        row["datetime"] = "2026-07-27 14:29:47"
        row["flag_port_scan"] = "1"
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        write_rows(root / "data" / "reports" / "risk_2026-07-27.csv", [row])
        manifest_session = session(
            "attack",
            "2026-07-27",
            0,
            1,
            ["10.0.0.9"],
            ["PORT_SCAN"],
            "portscan_overlap",
        )
        manifest_session["time_start"] = "2026-07-27T14:30:08+03:00"

        attack_rows = calibrator.attack_validation_rows(
            [manifest_session],
            [calibrator.CandidatePolicy("current_policy", "current")],
            root,
        )

        self.assertEqual(attack_rows[0]["detection_delay_seconds_raw"], -21)
        self.assertEqual(attack_rows[0]["detection_delay_seconds"], 0)
        self.assertEqual(attack_rows[0]["detection_timing_note"], "overlapping_30s_window")

    def test_negative_delay_below_30_seconds_is_invalid_unavailable(self):
        row = make_row(0, src_ip="10.0.0.9", unique_ports=101, connections=120, failed=0.3, risk=40)
        row["datetime"] = "2026-07-27 14:29:36"
        row["flag_port_scan"] = "1"
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        self.addCleanup(tmp.cleanup)
        write_rows(root / "data" / "reports" / "risk_2026-07-27.csv", [row])
        manifest_session = session(
            "attack",
            "2026-07-27",
            0,
            1,
            ["10.0.0.9"],
            ["PORT_SCAN"],
            "portscan_invalid_negative",
        )
        manifest_session["time_start"] = "2026-07-27T14:30:08+03:00"

        attack_rows = calibrator.attack_validation_rows(
            [manifest_session],
            [calibrator.CandidatePolicy("current_policy", "current")],
            root,
        )

        self.assertEqual(attack_rows[0]["detection_delay_seconds_raw"], -32)
        self.assertEqual(attack_rows[0]["detection_delay_seconds"], "unavailable")
        self.assertEqual(attack_rows[0]["detection_timing_note"], "invalid_negative_delay")


if __name__ == "__main__":
    unittest.main()
