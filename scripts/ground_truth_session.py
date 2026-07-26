#!/usr/bin/env python3
"""
Read-only ground-truth session recorder for NetGuard-AI lab calibration.

The recorder captures timestamps, metadata, and file row boundaries only. It
never generates traffic, executes attacks, modifies detection logic, or rewrites
processed/window/risk evidence.
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
ACTIVE_SESSION = BASE_DIR / "data" / "ground_truth" / "active_session.json"
SESSIONS_DIR = BASE_DIR / "data" / "ground_truth" / "sessions"
GROUND_TRUTH_MANIFEST = BASE_DIR / "data" / "ground_truth" / "manifest.json"
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
MODEL_METADATA_FILES = (
    BASE_DIR / "models" / "anomaly" / "baseline_stats.json",
    BASE_DIR / "models" / "anomaly" / "feature_names.json",
)
SUPPORTED_CLASSES = {
    "PORT_SCAN",
    "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
    "FAILED_CONNECTION_PATTERN",
    "DNS_ANOMALY",
    "DOS_LIKE_BURST",
    "BOT_LIKE_BEHAVIOR",
    "UNKNOWN_SUSPICIOUS",
    "LOW_SIGNAL_REVIEW",
}
SERVICE_NAMES = {
    "zeek": "zeek",
    "collector": "netguard-collector",
    "pipeline": "netguard-pipeline",
    "gateway": "netguard-gateway",
    "telegram": "netguard-telegram-alerts",
}


class SessionError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record read-only ground-truth session boundaries."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start", help="Start a labeled ground-truth session.")
    start.add_argument("--label", required=True, choices=("normal", "attack"))
    start.add_argument("--expected-class", action="append", default=[])
    start.add_argument("--source-ip", action="append", default=[])
    start.add_argument("--scenario", required=True)
    start.add_argument("--notes", default="")

    subparsers.add_parser("stop", help="Stop the active ground-truth session.")
    subparsers.add_parser("status", help="Show active session status.")
    subparsers.add_parser("list", help="List completed sessions.")

    export = subparsers.add_parser("export", help="Export calibrator-compatible manifest.")
    export.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def now_pair() -> tuple[datetime, datetime]:
    utc_now = datetime.now(timezone.utc)
    local_now = utc_now.astimezone()
    return utc_now, local_now


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise SessionError(f"invalid source IP: {value}") from exc


def validate_start_args(args: argparse.Namespace) -> None:
    expected = args.expected_class or []
    for classification in expected:
        if classification not in SUPPORTED_CLASSES:
            raise SessionError(
                f"unsupported expected class: {classification}; supported: {', '.join(sorted(SUPPORTED_CLASSES))}"
            )
    for source_ip in args.source_ip or []:
        validate_ip(source_ip)
    if args.label == "attack" and not expected:
        raise SessionError("attack sessions require --expected-class")
    if args.label == "normal" and expected:
        raise SessionError("normal sessions must not set --expected-class")


def paths_for_date(base_dir: Path, date_text: str) -> dict[str, Path]:
    return {
        "processed": base_dir / "data" / "processed" / f"baseline_{date_text}.csv",
        "windows": base_dir / "data" / "windows" / f"windows_{date_text}.csv",
        "risk": base_dir / "data" / "reports" / f"risk_{date_text}.csv",
    }


def csv_row_count_and_latest(path: Path) -> tuple[int, str | None]:
    if not path.exists():
        return 0, None
    latest = None
    rows = 0
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows += 1
            latest = row.get("datetime") or row.get("time") or row.get("timestamp") or row.get("ts") or latest
    return rows, latest


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_snapshot(base_dir: Path, date_text: str) -> dict[str, dict[str, Any]]:
    snapshot = {}
    for kind, path in paths_for_date(base_dir, date_text).items():
        rows, latest = csv_row_count_and_latest(path)
        snapshot[kind] = {
            "path": str(path),
            "exists": path.exists(),
            "file_size": path.stat().st_size if path.exists() else 0,
            "row_count": rows,
            "latest_timestamp": latest,
            "sha256": sha256_file(path),
        }
    return snapshot


def git_value(base_dir: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=base_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value or None


def hash_file(path: Path) -> str | None:
    return sha256_file(path)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def model_metadata() -> dict[str, Any]:
    metadata = {}
    for path in MODEL_METADATA_FILES:
        item: dict[str, Any] = {
            "path": str(path),
            "exists": path.exists(),
            "sha256": hash_file(path),
        }
        if path.exists() and path.name == "baseline_stats.json":
            try:
                stats = read_json(path)
                item["trained_at"] = stats.get("trained_at")
            except (OSError, json.JSONDecodeError):
                item["read_error"] = True
        metadata[path.name] = item
    return metadata


def source_policy_hash(base_dir: Path) -> dict[str, Any]:
    source = base_dir / "scripts" / "attack_classifier.py"
    return {
        "source_path": str(source),
        "source_sha256": hash_file(source),
        "policy_version": "attack_classifier.py source hash",
    }


def service_state(service_name: str) -> str:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "unknown"
    try:
        result = subprocess.run(
            [systemctl, "is-active", service_name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    status = result.stdout.strip()
    return status or "unknown"


def network_profile(base_dir: Path) -> dict[str, Any]:
    path = base_dir / "config" / "network_profile.json"
    result: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return result
    try:
        profile = read_json(path)
    except (OSError, json.JSONDecodeError):
        result["read_error"] = True
        return result
    gateway = profile.get("gateway") if isinstance(profile, dict) else {}
    gateway = gateway if isinstance(gateway, dict) else {}
    result.update(
        {
            "configured_wan_interface": gateway.get("wan_interface"),
            "configured_lan_interface": gateway.get("lan_interface"),
            "detected_wan_interface": detect_default_route_interface(),
            "detected_lan_interface": detect_configured_lan_interface(gateway.get("lan_interface")),
            "profile_name": profile.get("profile_name") if isinstance(profile, dict) else None,
            "profile_version": profile.get("profile_version") if isinstance(profile, dict) else None,
        }
    )
    return result


def detect_default_route_interface() -> str | None:
    ip_cmd = shutil.which("ip")
    if not ip_cmd:
        return None
    try:
        result = subprocess.run(
            [ip_cmd, "route", "show", "default"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    parts = result.stdout.split()
    if "dev" not in parts:
        return None
    index = parts.index("dev") + 1
    return parts[index] if index < len(parts) else None


def detect_configured_lan_interface(configured: Any) -> str | None:
    if isinstance(configured, str) and configured and configured != "auto":
        return configured
    return None


def runtime_metadata(base_dir: Path) -> dict[str, Any]:
    services = {name: service_state(service) for name, service in SERVICE_NAMES.items()}
    return {
        "network_profile": network_profile(base_dir),
        "git": {
            "commit": git_value(base_dir, "rev-parse", "HEAD"),
            "branch": git_value(base_dir, "rev-parse", "--abbrev-ref", "HEAD"),
        },
        "model_metadata": model_metadata(),
        "classification_policy": source_policy_hash(base_dir),
        "services": services,
        "telegram_alerts_active": services.get("telegram") == "active",
    }


def session_id(local_now: datetime, label: str, scenario: str) -> str:
    safe_scenario = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in scenario.lower()).strip("-")
    safe_scenario = safe_scenario or "session"
    return f"{local_now.strftime('%Y%m%d-%H%M%S')}-{label}-{safe_scenario}-{uuid.uuid4().hex[:8]}"


def active_path(base_dir: Path) -> Path:
    return base_dir / "data" / "ground_truth" / "active_session.json"


def sessions_dir(base_dir: Path) -> Path:
    return base_dir / "data" / "ground_truth" / "sessions"


def manifest_path(base_dir: Path) -> Path:
    return base_dir / "data" / "ground_truth" / "manifest.json"


def load_active_session(base_dir: Path) -> dict[str, Any] | None:
    path = active_path(base_dir)
    if not path.exists():
        return None
    try:
        data = read_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"malformed active session state at {path}: {exc}") from exc
    if not isinstance(data, dict) or not data.get("session_id"):
        raise SessionError(f"malformed active session state at {path}: missing session_id")
    return data


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


def remove_active(base_dir: Path) -> None:
    path = active_path(base_dir)
    if path.exists():
        path.unlink()


def update_local_manifest(base_dir: Path) -> dict[str, Any]:
    sessions = []
    for path in sorted(sessions_dir(base_dir).glob("*.json")):
        try:
            session = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(session, dict) and session.get("completed"):
            sessions.append(manifest_session(session))
    manifest = {"sessions": sessions}
    write_json(manifest_path(base_dir), manifest)
    return manifest


def manifest_session(session: dict[str, Any]) -> dict[str, Any]:
    start_snapshot = session.get("start_snapshot", {})
    stop_snapshot = session.get("stop_snapshot", {})
    return {
        "date": session.get("local_date"),
        "label": session.get("label"),
        "expected_classes": session.get("expected_classes", []),
        "source_ips": session.get("source_ips", []),
        "time_start": session.get("local_start"),
        "time_end": session.get("local_end"),
        "scenario": session.get("scenario"),
        "notes": session.get("notes"),
        "session_id": session.get("session_id"),
        "row_boundaries": {
            "processed": row_boundary(start_snapshot, stop_snapshot, "processed"),
            "windows": row_boundary(start_snapshot, stop_snapshot, "windows"),
            "risk": row_boundary(start_snapshot, stop_snapshot, "risk"),
        },
    }


def row_boundary(start_snapshot: dict[str, Any], stop_snapshot: dict[str, Any], kind: str) -> dict[str, Any]:
    start = start_snapshot.get(kind, {}) if isinstance(start_snapshot, dict) else {}
    stop = stop_snapshot.get(kind, {}) if isinstance(stop_snapshot, dict) else {}
    start_rows = int(start.get("row_count") or 0)
    stop_rows = int(stop.get("row_count") or 0)
    return {
        "start_row": start_rows,
        "stop_row": stop_rows,
        "rows_added": max(stop_rows - start_rows, 0),
        "start_latest_timestamp": start.get("latest_timestamp"),
        "stop_latest_timestamp": stop.get("latest_timestamp"),
        "start_sha256": start.get("sha256"),
        "stop_sha256": stop.get("sha256"),
    }


def readiness_snapshot(base_dir: Path, date_text: str) -> dict[str, Any]:
    runtime = runtime_metadata(base_dir)
    files = paths_for_date(base_dir, date_text)
    return {
        "zeek": runtime["services"].get("zeek"),
        "collector": runtime["services"].get("collector"),
        "pipeline": runtime["services"].get("pipeline"),
        "gateway": runtime["services"].get("gateway"),
        "telegram": runtime["services"].get("telegram"),
        "lan_interface": (
            runtime["network_profile"].get("detected_lan_interface")
            or runtime["network_profile"].get("configured_lan_interface")
        ),
        "wan_interface": (
            runtime["network_profile"].get("detected_wan_interface")
            or runtime["network_profile"].get("configured_wan_interface")
        ),
        "live_files": {name: str(path) for name, path in files.items()},
    }


def print_readiness(readiness: dict[str, Any]) -> None:
    print(f"[READY] zeek={readiness.get('zeek')}")
    print(f"[READY] collector={readiness.get('collector')}")
    print(f"[READY] pipeline={readiness.get('pipeline')}")
    print(f"[READY] lan_interface={readiness.get('lan_interface')}")
    for path in readiness.get("live_files", {}).values():
        print(f"[READY] live_file={path}")
    inactive = [
        name for name in ("zeek", "collector", "pipeline")
        if readiness.get(name) not in {"active", "unknown"}
    ]
    for name in inactive:
        print(f"[WARN] {name} service is {readiness.get(name)}")


def command_start(args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    validate_start_args(args)
    if load_active_session(base_dir) is not None:
        raise SessionError("cannot start a new session while another session is active")
    utc_now, local_now = now_pair()
    local_date = local_now.strftime("%Y-%m-%d")
    readiness = readiness_snapshot(base_dir, local_date)
    snapshot = evidence_snapshot(base_dir, local_date)
    metadata = runtime_metadata(base_dir)
    session = {
        "session_id": session_id(local_now, args.label, args.scenario),
        "label": args.label,
        "scenario": args.scenario,
        "expected_classes": args.expected_class or [],
        "source_ips": [validate_ip(item) for item in args.source_ip],
        "local_date": local_date,
        "utc_start": iso(utc_now),
        "local_start": iso(local_now),
        "utc_end": None,
        "local_end": None,
        "duration_seconds": None,
        "notes": args.notes,
        "runtime_metadata": metadata,
        "readiness": readiness,
        "start_snapshot": snapshot,
        "stop_snapshot": None,
        "completed": False,
    }
    write_json(active_path(base_dir), session)

    print_readiness(readiness)
    print(f"[SESSION] id={session['session_id']}")
    print(f"[SESSION] label={session['label']}")
    print(f"[SESSION] scenario={session['scenario']}")
    print(f"[SESSION] expected_class={','.join(session['expected_classes']) or 'n/a'}")
    print(f"[SESSION] source_ip={','.join(session['source_ips']) or 'n/a'}")
    print(f"[SESSION] start={session['local_start']}")
    print(f"[SESSION] risk_start_row={snapshot['risk']['row_count']}")
    print("[RESULT] GROUND-TRUTH SESSION STARTED")
    return 0


def parse_iso_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def command_stop(_args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    session = load_active_session(base_dir)
    if session is None:
        raise SessionError("no active ground-truth session")
    utc_now, local_now = now_pair()
    start = parse_iso_datetime(str(session["utc_start"]))
    duration = max((utc_now - start).total_seconds(), 0.0)
    stop_snapshot = evidence_snapshot(base_dir, str(session["local_date"]))
    session.update(
        {
            "utc_end": iso(utc_now),
            "local_end": iso(local_now),
            "duration_seconds": round(duration, 3),
            "stop_snapshot": stop_snapshot,
            "completed": True,
        }
    )
    if parse_iso_datetime(session["utc_end"]) < parse_iso_datetime(session["utc_start"]):
        raise SessionError("session end time is earlier than start time")
    output = sessions_dir(base_dir) / f"{session['session_id']}.json"
    write_json(output, session)
    update_local_manifest(base_dir)
    remove_active(base_dir)
    risk_rows_added = row_boundary(session["start_snapshot"], stop_snapshot, "risk")["rows_added"]

    print(f"[SESSION] end={session['local_end']}")
    print(f"[SESSION] duration_seconds={session['duration_seconds']}")
    print(f"[SESSION] risk_rows_added={risk_rows_added}")
    print(f"[SESSION] output={output}")
    print("[RESULT] GROUND-TRUTH SESSION COMPLETED")
    return 0


def command_status(_args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    session = load_active_session(base_dir)
    if session is None:
        print("[SESSION] active=false")
        print("[RESULT] NO ACTIVE GROUND-TRUTH SESSION")
        return 0
    print("[SESSION] active=true")
    print(f"[SESSION] id={session['session_id']}")
    print(f"[SESSION] label={session['label']}")
    print(f"[SESSION] scenario={session['scenario']}")
    print(f"[SESSION] start={session['local_start']}")
    print("[RESULT] GROUND-TRUTH SESSION STATUS")
    return 0


def command_list(_args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    paths = sorted(sessions_dir(base_dir).glob("*.json"))
    if not paths:
        print("[SESSION] completed_count=0")
        print("[RESULT] GROUND-TRUTH SESSION LIST")
        return 0
    print(f"[SESSION] completed_count={len(paths)}")
    for path in paths:
        try:
            session = read_json(path)
        except (OSError, json.JSONDecodeError):
            print(f"[SESSION] malformed={path}")
            continue
        print(
            "[SESSION] "
            f"id={session.get('session_id')} "
            f"label={session.get('label')} "
            f"scenario={session.get('scenario')} "
            f"start={session.get('local_start')} "
            f"end={session.get('local_end')}"
        )
    print("[RESULT] GROUND-TRUTH SESSION LIST")
    return 0


def command_export(args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    sessions = []
    for path in sorted(sessions_dir(base_dir).glob("*.json")):
        try:
            session = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(session, dict) and session.get("completed"):
            sessions.append(manifest_session(session))
    manifest = {"sessions": sessions}
    output = args.output
    if not output.is_absolute():
        output = base_dir / output
    write_json(output, manifest)
    print(f"[SESSION] exported_sessions={len(sessions)}")
    print(f"[SESSION] output={output}")
    print("[RESULT] GROUND-TRUTH MANIFEST EXPORTED")
    return 0


def dispatch(args: argparse.Namespace, base_dir: Path = BASE_DIR) -> int:
    if args.command == "start":
        return command_start(args, base_dir)
    if args.command == "stop":
        return command_stop(args, base_dir)
    if args.command == "status":
        return command_status(args, base_dir)
    if args.command == "list":
        return command_list(args, base_dir)
    if args.command == "export":
        return command_export(args, base_dir)
    raise SessionError(f"unsupported command: {args.command}")


def main() -> int:
    try:
        return dispatch(parse_args())
    except SessionError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
