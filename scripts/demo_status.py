#!/usr/bin/env python3
"""
demo_status.py - Terminal-friendly NetGuard-AI Gateway demo status.

Read-only status view. This script does not modify system, pipeline, or ML
files.
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
REPORT_DIR = BASE_DIR / "data" / "reports"
ALERTS_LOG = BASE_DIR / "logs" / "alerts.log"

SERVICES = [
    "zeek",
    "netguard-collector",
    "netguard-pipeline",
    "netguard-auth-monitor",
]


def today() -> str:
    return datetime.now().date().isoformat()


def section(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def service_status(service_name: str) -> tuple[str, str]:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "WARN", "systemctl unavailable"

    try:
        result = subprocess.run(
            [systemctl, "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "WARN", f"status unavailable: {exc}"

    state = result.stdout.strip() or result.stderr.strip() or "unknown"
    if result.returncode == 0 and state == "active":
        return "OK", "active"
    return "WARN", state


def print_services() -> None:
    section("Services")
    for service_name in SERVICES:
        level, state = service_status(service_name)
        print(f"[{level}] {service_name:<24} {state}")


def print_network(profile: dict[str, Any]) -> None:
    gateway = profile.get("gateway") if isinstance(profile.get("gateway"), dict) else {}
    lan = profile.get("lan") if isinstance(profile.get("lan"), dict) else {}

    section("WAN/LAN Config")
    if not profile:
        print("[WARN] config/network_profile.json unavailable or invalid")
        return

    print(f"Profile:        {profile.get('profile_name', 'unknown')}")
    print(f"Mode:           {profile.get('mode', 'unknown')}")
    print(f"WAN interface:  {gateway.get('wan_interface', 'unknown')}")
    print(f"LAN interface:  {gateway.get('lan_interface', 'unknown')}")
    print(f"Gateway IP:     {gateway.get('gateway_ip') or lan.get('gateway_ip') or profile.get('gateway_ip', 'unknown')}")
    print(f"LAN CIDR:       {lan.get('cidr') or ', '.join(profile.get('monitored_networks', [])) or 'unknown'}")
    print(f"DHCP range:     {lan.get('dhcp_start', 'unknown')} - {lan.get('dhcp_end', 'unknown')}")
    print(f"AP mgmt IP:     {lan.get('ap_management_ip', 'unknown')}")


def alert_path_for(day: str) -> Path:
    report_path = REPORT_DIR / f"alerts_{day}.jsonl"
    if report_path.exists():
        return report_path
    return ALERTS_LOG


def parse_alert_line(line: str) -> dict[str, Any]:
    stripped = line.strip()
    if not stripped:
        return {}

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return {
            "time": "",
            "source": "legacy-log",
            "severity": "",
            "alert_type": "text",
            "message": stripped,
        }

    return data if isinstance(data, dict) else {"message": stripped}


def read_alerts(day: str) -> tuple[Path, list[dict[str, Any]]]:
    path = alert_path_for(day)
    if not path.exists():
        return path, []

    alerts: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                parsed = parse_alert_line(line)
                if parsed:
                    alerts.append(parsed)
    except OSError:
        return path, []

    return path, alerts


def alert_is_today(alert: dict[str, Any], day: str, source_path: Path) -> bool:
    if source_path.name == f"alerts_{day}.jsonl":
        return True

    value = str(alert.get("time", ""))
    return value.startswith(day)


def print_alerts(day: str) -> None:
    path, alerts = read_alerts(day)
    count_today = sum(1 for alert in alerts if alert_is_today(alert, day, path))

    section("Alerts")
    print(f"Source:             {path.relative_to(BASE_DIR) if path.is_absolute() else path}")
    print(f"Alerts count today: {count_today}")
    print()
    print("Last 20 alerts:")

    if not alerts:
        print("  (none)")
        return

    for alert in alerts[-20:]:
        timestamp = str(alert.get("time", ""))[:19] or "unknown-time"
        severity = str(alert.get("severity", "")).upper() or "INFO"
        source = str(alert.get("source", "unknown"))
        alert_type = str(alert.get("alert_type", "alert"))
        message = str(alert.get("message") or alert.get("explanation") or alert.get("summary") or "")
        if len(message) > 100:
            message = message[:97] + "..."
        print(f"  {timestamp:<19} {severity:<8} {source:<18} {alert_type:<18} {message}")


def max_risk_for(day: str) -> tuple[Path, float | None]:
    path = REPORT_DIR / f"risk_{day}.csv"
    if not path.exists():
        return path, None

    max_risk: float | None = None
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if "risk_score" not in (reader.fieldnames or []):
                return path, None
            for row in reader:
                try:
                    risk = float(row.get("risk_score", ""))
                except ValueError:
                    continue
                max_risk = risk if max_risk is None else max(max_risk, risk)
    except OSError:
        return path, None

    return path, max_risk


def print_risk(day: str) -> None:
    path, max_risk = max_risk_for(day)
    section("Risk")
    print(f"Source:        {path.relative_to(BASE_DIR) if path.is_absolute() else path}")
    if max_risk is None:
        print("Max risk today: unavailable")
    else:
        print(f"Max risk today: {max_risk:.2f}")


def main() -> int:
    day = today()
    print(f"NetGuard-AI Gateway Demo Status - {day}")
    print(f"Project: {BASE_DIR}")

    profile = load_json(NETWORK_PROFILE)
    print_services()
    print_network(profile)
    print_alerts(day)
    print_risk(day)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
