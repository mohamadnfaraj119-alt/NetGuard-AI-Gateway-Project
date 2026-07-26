#!/usr/bin/env python3

import argparse
import csv
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock

from scripts import ground_truth_session as session


HEADERS = ["ts", "datetime", "src_ip", "risk_score"]


def today() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d")


def rows(count: int) -> list[dict[str, str]]:
    return [
        {
            "ts": str(1785055200 + index),
            "datetime": f"{today()} 12:00:{index:02d}",
            "src_ip": "192.168.50.95",
            "risk_score": str(index),
        }
        for index in range(count)
    ]


def write_csv(path: Path, data: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(data)


def append_csv(path: Path, data: list[dict[str, str]]) -> None:
    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADERS)
        writer.writerows(data)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start_args(label="normal", expected_class=None, source_ip="192.168.50.95"):
    return argparse.Namespace(
        command="start",
        label=label,
        expected_class=([expected_class] if expected_class else []),
        source_ip=([source_ip] if source_ip else []),
        scenario="unit_test",
        notes="synthetic test",
    )


def stop_args():
    return argparse.Namespace(command="stop")


def export_args(output):
    return argparse.Namespace(command="export", output=Path(output))


class GroundTruthSessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.date = today()
        self.risk = self.root / "data" / "reports" / f"risk_{self.date}.csv"
        self.windows = self.root / "data" / "windows" / f"windows_{self.date}.csv"
        self.processed = self.root / "data" / "processed" / f"baseline_{self.date}.csv"
        for path in (self.risk, self.windows, self.processed):
            write_csv(path, rows(2))
        self.runtime_patch = mock.patch(
            "scripts.ground_truth_session.runtime_metadata",
            return_value={
                "network_profile": {
                    "path": str(self.root / "config" / "network_profile.json"),
                    "exists": False,
                    "wan_interface": "wan0",
                    "lan_interface": "lan0",
                },
                "git": {"commit": "abc123", "branch": "test"},
                "model_metadata": {},
                "classification_policy": {"source_sha256": "policyhash"},
                "services": {
                    "zeek": "inactive",
                    "collector": "inactive",
                    "pipeline": "inactive",
                    "gateway": "unknown",
                    "telegram": "inactive",
                },
                "telegram_alerts_active": False,
            },
        )
        self.runtime_patch.start()

    def tearDown(self):
        self.runtime_patch.stop()
        self.tmp.cleanup()

    def test_normal_session_start_stop(self):
        with redirect_stdout(io.StringIO()):
            session.command_start(start_args(label="normal"), self.root)
            session.command_stop(stop_args(), self.root)

        completed = list((self.root / "data" / "ground_truth" / "sessions").glob("*.json"))
        self.assertEqual(len(completed), 1)
        payload = json.loads(completed[0].read_text(encoding="utf-8"))
        self.assertTrue(payload["completed"])
        self.assertEqual(payload["label"], "normal")
        self.assertGreaterEqual(payload["duration_seconds"], 0)
        self.assertFalse((self.root / "data" / "ground_truth" / "active_session.json").exists())

    def test_attack_session_requires_expected_class(self):
        with self.assertRaises(session.SessionError):
            session.command_start(start_args(label="attack", expected_class=None), self.root)

    def test_invalid_source_ip(self):
        with self.assertRaises(session.SessionError):
            session.command_start(start_args(source_ip="not-an-ip"), self.root)

    def test_preventing_concurrent_sessions(self):
        with redirect_stdout(io.StringIO()):
            session.command_start(start_args(), self.root)

        with self.assertRaises(session.SessionError):
            session.command_start(start_args(), self.root)

    def test_stop_with_no_active_session(self):
        with self.assertRaises(session.SessionError):
            session.command_stop(stop_args(), self.root)

    def test_exact_row_boundary_capture(self):
        with redirect_stdout(io.StringIO()):
            session.command_start(start_args(), self.root)
        append_csv(self.risk, rows(3)[2:])
        append_csv(self.windows, rows(3)[2:])
        append_csv(self.processed, rows(3)[2:])
        with redirect_stdout(io.StringIO()):
            session.command_stop(stop_args(), self.root)

        completed = next((self.root / "data" / "ground_truth" / "sessions").glob("*.json"))
        payload = json.loads(completed.read_text(encoding="utf-8"))
        boundary = session.row_boundary(payload["start_snapshot"], payload["stop_snapshot"], "risk")
        self.assertEqual(boundary["start_row"], 2)
        self.assertEqual(boundary["stop_row"], 3)
        self.assertEqual(boundary["rows_added"], 1)

    def test_file_hash_capture(self):
        before = digest(self.risk)
        snapshot = session.evidence_snapshot(self.root, self.date)

        self.assertEqual(snapshot["risk"]["sha256"], before)
        self.assertEqual(snapshot["risk"]["file_size"], self.risk.stat().st_size)

    def test_malformed_state_handling(self):
        active = self.root / "data" / "ground_truth" / "active_session.json"
        active.parent.mkdir(parents=True, exist_ok=True)
        active.write_text("{bad json", encoding="utf-8")

        with self.assertRaises(session.SessionError):
            session.command_status(argparse.Namespace(command="status"), self.root)

    def test_manifest_export_excludes_incomplete_sessions(self):
        sessions_dir = self.root / "data" / "ground_truth" / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        complete = {
            "session_id": "complete-1",
            "completed": True,
            "local_date": self.date,
            "label": "attack",
            "expected_classes": ["PORT_SCAN"],
            "source_ips": ["192.168.50.95"],
            "local_start": f"{self.date}T12:00:00+00:00",
            "local_end": f"{self.date}T12:01:00+00:00",
            "scenario": "controlled_port_scan",
            "notes": "verified",
            "start_snapshot": {},
            "stop_snapshot": {},
        }
        incomplete = dict(complete)
        incomplete["session_id"] = "incomplete-1"
        incomplete["completed"] = False
        (sessions_dir / "complete-1.json").write_text(json.dumps(complete), encoding="utf-8")
        (sessions_dir / "incomplete-1.json").write_text(json.dumps(incomplete), encoding="utf-8")
        output = self.root / "manifest.local.json"

        with redirect_stdout(io.StringIO()):
            session.command_export(export_args(output), self.root)

        manifest = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["sessions"]), 1)
        self.assertEqual(manifest["sessions"][0]["session_id"], "complete-1")

    def test_source_evidence_remains_unchanged(self):
        before = {path: digest(path) for path in (self.risk, self.windows, self.processed)}

        with redirect_stdout(io.StringIO()):
            session.command_start(start_args(), self.root)
            session.command_stop(stop_args(), self.root)

        after = {path: digest(path) for path in (self.risk, self.windows, self.processed)}
        self.assertEqual(before, after)

    def test_all_expected_outputs_are_created(self):
        output = self.root / "config" / "detection_ground_truth_manifest.local.json"

        with redirect_stdout(io.StringIO()):
            session.command_start(
                start_args(label="attack", expected_class="PORT_SCAN"),
                self.root,
            )
            session.command_stop(stop_args(), self.root)
            session.command_export(export_args(output), self.root)

        self.assertTrue((self.root / "data" / "ground_truth" / "manifest.json").exists())
        self.assertTrue(output.exists())
        self.assertEqual(
            len(list((self.root / "data" / "ground_truth" / "sessions").glob("*.json"))),
            1,
        )


if __name__ == "__main__":
    unittest.main()
