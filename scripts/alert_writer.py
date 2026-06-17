#!/usr/bin/env python3
"""
alert_writer.py - Shared JSONL alert writer for NetGuard-AI Gateway.

This module is standalone and does not alter existing pipeline behavior.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "data" / "reports"
ALERTS_LOG = LOG_DIR / "alerts.log"

DEFAULT_SOURCE = "netguard-ai"
DEFAULT_SEVERITY = "info"
DEFAULT_ALERT_TYPE = "generic"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _report_path(alert_time: str) -> Path:
    try:
        date_part = datetime.fromisoformat(alert_time.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        date_part = datetime.now(timezone.utc).date().isoformat()
    return REPORT_DIR / f"alerts_{date_part}.jsonl"


def _normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(alert)
    normalized.setdefault("time", _utc_now())
    normalized.setdefault("source", DEFAULT_SOURCE)
    normalized.setdefault("severity", DEFAULT_SEVERITY)
    normalized.setdefault("alert_type", DEFAULT_ALERT_TYPE)
    return normalized


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def write_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize and append an alert to both JSONL alert destinations.

    Required fields are added when missing:
      - time
      - source
      - severity
      - alert_type

    Returns the normalized alert that was written.
    """
    if not isinstance(alert, dict):
        raise TypeError("alert must be a dict")

    normalized = _normalize_alert(alert)
    _append_jsonl(ALERTS_LOG, normalized)
    _append_jsonl(_report_path(str(normalized["time"])), normalized)
    return normalized


def run_test() -> int:
    alert = write_alert({
        "source": "alert_writer",
        "severity": "info",
        "alert_type": "demo_test",
        "message": "demo alert_writer test alert",
    })
    print("[OK] demo alert written")
    print(f"[OK] log: {ALERTS_LOG.relative_to(BASE_DIR)}")
    print(f"[OK] report: {_report_path(str(alert['time'])).relative_to(BASE_DIR)}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write NetGuard-AI JSONL alerts.")
    parser.add_argument(
        "--test",
        action="store_true",
        help="write one safe demo alert to the configured alert outputs",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.test:
        return run_test()

    print("No action selected. Use --test to write one demo alert.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
