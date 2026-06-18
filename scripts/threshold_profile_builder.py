#!/usr/bin/env python3
"""
threshold_profile_builder.py - Build NetGuard-AI threshold profiles safely.

Usage examples:
  python scripts/threshold_profile_builder.py --print
  python scripts/threshold_profile_builder.py
  python scripts/threshold_profile_builder.py --apply
  python scripts/threshold_profile_builder.py --source data/baselines/ip_baselines.json --output config/thresholds_profile.json --apply
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = BASE_DIR / "data" / "baselines" / "ip_baselines.json"
DEFAULT_OUTPUT = BASE_DIR / "config" / "thresholds_profile.json"

PROFILE_NAME = "netguard-ai-thresholds-v7.7"
PROFILE_VERSION = "7.7"
RISK_SCORE_BANDS = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}

BASELINE_TO_TRAFFIC_LIMIT = {
    "connections_30s_max": "max_connections_30s",
    "unique_dst_ports_30s_max": "max_unique_dst_ports_30s",
    "dns_rate_1m_max": "max_dns_rate_1m",
}


class ProfileBuildError(Exception):
    """Raised when the threshold profile cannot be built safely."""


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(BASE_DIR))
    except ValueError:
        return str(path)


def _line(status: str, message: str, *, stream: Any = sys.stdout) -> None:
    print(f"[{status}] {message}", file=stream)


def ok(message: str, *, stream: Any = sys.stdout) -> None:
    _line("OK", message, stream=stream)


def warn(message: str, *, stream: Any = sys.stdout) -> None:
    _line("WARN", message, stream=stream)


def dry_run(message: str, *, stream: Any = sys.stdout) -> None:
    _line("DRY-RUN", message, stream=stream)


def error(message: str, *, stream: Any = sys.stderr) -> None:
    _line("ERROR", message, stream=stream)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ProfileBuildError(f"source file missing: {_relative(path)}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ProfileBuildError(f"invalid JSON in {_relative(path)}: {exc}") from exc
    except OSError as exc:
        raise ProfileBuildError(f"unable to read {_relative(path)}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProfileBuildError(f"{_relative(path)} must contain a JSON object")
    return data


def require_object(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ProfileBuildError(f"missing or invalid object: {key}")
    return value


def require_number(data: dict[str, Any], key: str, *, minimum: float | None = None,
                   maximum: float | None = None) -> int | float:
    value = data.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ProfileBuildError(f"missing or invalid number: global_baseline.{key}")

    numeric_value = float(value)
    if minimum is not None and numeric_value < minimum:
        raise ProfileBuildError(f"global_baseline.{key} must be >= {minimum}")
    if maximum is not None and numeric_value > maximum:
        raise ProfileBuildError(f"global_baseline.{key} must be <= {maximum}")

    return value


def build_profile(source: Path) -> dict[str, Any]:
    baseline_data = load_json(source)
    global_baseline = require_object(baseline_data, "global_baseline")

    traffic_limits = {
        output_key: require_number(global_baseline, source_key, minimum=0)
        for source_key, output_key in BASELINE_TO_TRAFFIC_LIMIT.items()
    }

    return {
        "profile_name": PROFILE_NAME,
        "profile_version": PROFILE_VERSION,
        "risk_score_bands": dict(RISK_SCORE_BANDS),
        "traffic_limits": traffic_limits,
        "anomaly": {
            "p99_baseline": require_number(global_baseline, "P99_BASELINE", minimum=0, maximum=1),
            "max_score": 1.0,
        },
    }


def write_profile(profile: dict[str, Any], output: Path) -> Path | None:
    output.parent.mkdir(parents=True, exist_ok=True)

    backup_path: Path | None = None
    if output.exists():
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = output.with_name(f"{output.name}.bak.{timestamp}")
        shutil.copy2(output, backup_path)

    with output.open("w", encoding="utf-8") as handle:
        json.dump(profile, handle, indent=2)
        handle.write("\n")

    return backup_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build config/thresholds_profile.json from global baseline values."
    )
    parser.add_argument(
        "--print",
        dest="print_profile",
        action="store_true",
        help="print the generated threshold profile JSON and exit without writing unless --apply is also set",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write the generated profile to the output path after backing up any existing file",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="source ip_baselines.json path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="thresholds_profile.json output path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    message_stream = sys.stderr if args.print_profile else sys.stdout
    source = args.source.expanduser()
    output = args.output.expanduser()

    if not source.is_absolute():
        source = BASE_DIR / source
    if not output.is_absolute():
        output = BASE_DIR / output

    try:
        profile = build_profile(source)
    except ProfileBuildError as exc:
        error(str(exc))
        return 1

    ok(f"loaded global_baseline from {_relative(source)}", stream=message_stream)
    warn("per-IP baselines are intentionally ignored for v1", stream=message_stream)

    if args.print_profile:
        print(json.dumps(profile, indent=2))

    if not args.apply:
        dry_run(f"would write {_relative(output)}; use --apply to make changes", stream=message_stream)
        return 0

    try:
        backup_path = write_profile(profile, output)
    except OSError as exc:
        error(f"unable to write {_relative(output)}: {exc}")
        return 1

    if backup_path is None:
        warn(f"no existing output to back up at {_relative(output)}")
    else:
        ok(f"backed up existing profile to {_relative(backup_path)}")
    ok(f"wrote threshold profile to {_relative(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
