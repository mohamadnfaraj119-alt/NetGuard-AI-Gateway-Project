#!/usr/bin/env python3
"""
demo_reset.py - Prepare a fresh local demo session.

This script only manages demo log/session files. It does not change system
configuration, pipeline files, ML files, or data/reports alert history.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
ALERTS_LOG = LOG_DIR / "alerts.log"
ARCHIVE_DIR = LOG_DIR / "demo_archives"
SESSION_FILE = LOG_DIR / "demo_session.json"
MODE = "demo"


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def ok(message: str) -> None:
    print(f"[OK] {message}")


def archive_alerts_log(now: datetime) -> Path | None:
    if not ALERTS_LOG.exists() or ALERTS_LOG.stat().st_size == 0:
        ok("no non-empty alerts log to archive")
        return None

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = ARCHIVE_DIR / f"alerts_{now.strftime('%Y%m%d_%H%M%S')}.log"
    shutil.move(str(ALERTS_LOG), str(archive_path))
    ok(f"archived alerts log to {_relative(archive_path)}")
    return archive_path


def reset_alerts_log() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    ALERTS_LOG.write_text("", encoding="utf-8")
    ok(f"created empty {_relative(ALERTS_LOG)}")


def write_session_metadata(start_time: datetime) -> None:
    metadata = {
        "start_time": start_time.isoformat(),
        "project_root": str(BASE_DIR),
        "mode": MODE,
    }
    SESSION_FILE.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ok(f"wrote demo session metadata to {_relative(SESSION_FILE)}")


def main() -> int:
    start_time = datetime.now(timezone.utc).replace(microsecond=0)
    archive_alerts_log(start_time)
    reset_alerts_log()
    write_session_metadata(start_time)
    ok("demo reset complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
