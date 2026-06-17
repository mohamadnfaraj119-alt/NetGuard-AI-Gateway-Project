#!/usr/bin/env python3
"""
demo_healthcheck.py - Read-only NetGuard-AI Gateway v7.6 demo healthcheck.

The healthcheck reports clear status lines and exits non-zero only when a
critical local readiness check fails. Service status checks are informational
because demo environments may not run systemd or install project services.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"

CRITICAL_FAILURES = 0


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def _line(status: str, message: str) -> None:
    print(f"[{status}] {message}")


def ok(message: str) -> None:
    _line("OK", message)


def warn(message: str) -> None:
    _line("WARN", message)


def fail(message: str, critical: bool = True) -> None:
    global CRITICAL_FAILURES
    _line("FAIL", message)
    if critical:
        CRITICAL_FAILURES += 1


def check_project_root() -> None:
    expected = [
        BASE_DIR / "README.md",
        SCRIPTS_DIR,
        BASE_DIR / "data",
        BASE_DIR / "models",
    ]
    missing = [_relative(path) for path in expected if not path.exists()]

    if missing:
        fail(f"project root incomplete at {BASE_DIR}: missing {', '.join(missing)}")
        return

    ok(f"project root detected: {BASE_DIR}")


def check_config_validity() -> None:
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        import config_loader
    except Exception as exc:
        fail(f"config loader import failed: {exc}")
        return

    try:
        config_loader.validate_network_profile()
        ok("config/network_profile.json is valid")
    except Exception as exc:
        fail(f"config/network_profile.json invalid: {exc}")

    try:
        config_loader.validate_thresholds_profile()
        ok("config/thresholds_profile.json is valid")
    except Exception as exc:
        fail(f"config/thresholds_profile.json invalid: {exc}")


def check_required_folders() -> None:
    required_dirs = [
        BASE_DIR / "config",
        BASE_DIR / "logs",
        BASE_DIR / "data",
        BASE_DIR / "data" / "baselines",
        BASE_DIR / "models",
        BASE_DIR / "models" / "anomaly",
        SCRIPTS_DIR,
    ]

    for path in required_dirs:
        if path.is_dir():
            ok(f"folder exists: {_relative(path)}")
        else:
            fail(f"folder missing: {_relative(path)}")


def _check_json_file(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"JSON file invalid: {_relative(path)} ({exc})")
    except OSError as exc:
        fail(f"JSON file unreadable: {_relative(path)} ({exc})")
    else:
        ok(f"JSON file readable: {_relative(path)}")


def check_important_files() -> None:
    required_files = [
        BASE_DIR / "models" / "anomaly" / "isolation_forest.pkl",
        BASE_DIR / "models" / "anomaly" / "scaler.pkl",
        BASE_DIR / "models" / "anomaly" / "feature_names.json",
        BASE_DIR / "models" / "anomaly" / "baseline_stats.json",
        BASE_DIR / "models" / "anomaly" / "if_scaler.json",
        BASE_DIR / "data" / "baselines" / "ip_baselines.json",
    ]

    for path in required_files:
        if not path.is_file():
            fail(f"required file missing: {_relative(path)}")
            continue
        if not os.access(path, os.R_OK):
            fail(f"required file unreadable: {_relative(path)}")
            continue

        if path.suffix == ".json":
            _check_json_file(path)
        else:
            ok(f"file readable: {_relative(path)}")


def _systemctl_status(service_name: str) -> tuple[str, str]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "WARN", "systemctl not found"

    try:
        result = subprocess.run(
            [systemctl, "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "WARN", "status check timed out"
    except OSError as exc:
        return "WARN", f"status check unavailable: {exc}"

    state = result.stdout.strip() or result.stderr.strip() or "unknown"
    if result.returncode == 0 and state == "active":
        return "OK", "active"
    return "WARN", state


def check_service_statuses() -> None:
    service_names = [
        "zeek",
        "netguard-collector",
        "netguard-pipeline",
        "netguard-window-engine",
        "netguard-risk-engine",
    ]

    for service_name in service_names:
        status, detail = _systemctl_status(service_name)
        _line(status, f"service {service_name}: {detail}")


def check_alerts_log_writability() -> None:
    alerts_log = BASE_DIR / "logs" / "alerts.log"

    if alerts_log.exists():
        if alerts_log.is_file() and os.access(alerts_log, os.W_OK):
            ok(f"alerts log is writable: {_relative(alerts_log)}")
        elif alerts_log.is_file():
            fail(f"alerts log is not writable: {_relative(alerts_log)}")
        else:
            fail(f"alerts log path is not a file: {_relative(alerts_log)}")
        return

    logs_dir = alerts_log.parent
    if logs_dir.is_dir() and os.access(logs_dir, os.W_OK):
        warn(f"alerts log missing, but logs directory can create it: {_relative(alerts_log)}")
        return

    fail(f"alerts log missing and logs directory is not writable: {_relative(alerts_log)}")


def main() -> int:
    print("NetGuard-AI Gateway v7.6 demo healthcheck")
    check_project_root()
    check_config_validity()
    check_required_folders()
    check_important_files()
    check_service_statuses()
    check_alerts_log_writability()

    if CRITICAL_FAILURES:
        print(f"Status: FAIL ({CRITICAL_FAILURES} critical check(s) failed)")
        return 1

    print("Status: OK (critical checks passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
