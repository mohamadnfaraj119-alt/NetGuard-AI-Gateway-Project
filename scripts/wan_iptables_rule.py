#!/usr/bin/env python3
"""
wan_iptables_rule.py - Safe helper for the NetGuard WAN iptables LOG rule.

Usage examples:
  python scripts/wan_iptables_rule.py --print
  python scripts/wan_iptables_rule.py --status
  sudo python scripts/wan_iptables_rule.py --install --apply
  sudo python scripts/wan_iptables_rule.py --remove --apply

Without --apply, --install and --remove are dry-run only. This script manages
only the NETGUARD_WAN LOG rule and never flushes iptables or edits unrelated
rules.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
LOG_PREFIX = "NETGUARD_WAN "


def line(level: str, message: str) -> None:
    print(f"[{level}] {message}", flush=True)


def ok(message: str) -> None:
    line("OK", message)


def warn(message: str) -> None:
    line("WARN", message)


def dry_run(message: str) -> None:
    line("DRY-RUN", message)


def error(message: str) -> None:
    line("ERROR", message)


def load_json(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def configured_wan_interface() -> str | None:
    profile = load_json(NETWORK_PROFILE)
    gateway = profile.get("gateway")
    candidates: list[object] = []

    if isinstance(gateway, dict):
        candidates.append(gateway.get("wan_interface"))
    candidates.append(profile.get("wan_interface"))

    for candidate in candidates:
        interface = str(candidate or "").strip()
        if interface and interface.lower() != "auto":
            return interface
    return None


def default_route_interface() -> str | None:
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    for route in result.stdout.splitlines():
        parts = route.split()
        if "dev" not in parts:
            continue
        dev_index = parts.index("dev")
        if dev_index + 1 < len(parts):
            return parts[dev_index + 1]
    return None


def resolve_wan_interface() -> tuple[str | None, str]:
    configured = configured_wan_interface()
    if configured:
        return configured, "config/network_profile.json"

    detected = default_route_interface()
    if detected:
        return detected, "default route"

    return None, "unresolved"


def rule_spec(interface: str) -> list[str]:
    return [
        "INPUT",
        "-i",
        interface,
        "-p",
        "tcp",
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-j",
        "LOG",
        "--log-prefix",
        LOG_PREFIX,
        "--log-level",
        "4",
    ]


def install_command(interface: str) -> list[str]:
    return ["iptables", "-I", *rule_spec(interface)]


def check_command(interface: str) -> list[str]:
    return ["iptables", "-C", *rule_spec(interface)]


def remove_command(interface: str) -> list[str]:
    return ["iptables", "-D", *rule_spec(interface)]


def command_text(command: list[str]) -> str:
    return shlex.join(command)


def run_iptables(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )


def iptables_available() -> bool:
    return shutil.which("iptables") is not None


def rule_present(interface: str) -> tuple[bool | None, str]:
    if not iptables_available():
        return None, "iptables not found"

    result = run_iptables(check_command(interface))
    detail = (result.stderr or result.stdout).strip()
    if result.returncode == 0:
        return True, "installed"
    if result.returncode == 1:
        return False, detail or "not installed"
    return None, detail or f"iptables check failed with exit {result.returncode}"


def print_rule(interface: str) -> int:
    print(command_text(install_command(interface)))
    return 0


def status(interface: str, source: str) -> int:
    ok(f"WAN interface: {interface} ({source})")
    ok(f"managed rule: {command_text(install_command(interface))}")

    present, detail = rule_present(interface)
    if present is True:
        ok("NETGUARD_WAN LOG rule is installed")
        return 0
    if present is False:
        warn("NETGUARD_WAN LOG rule is not installed")
        return 0

    warn(f"rule status unavailable: {detail}")
    return 0


def install(interface: str, apply: bool) -> int:
    present, detail = rule_present(interface)
    if present is True:
        ok("NETGUARD_WAN LOG rule already installed; no duplicate added")
        return 0

    command = install_command(interface)
    if not apply:
        if present is None:
            warn(f"could not confirm current rule state: {detail}")
        dry_run(f"would install: {command_text(command)}")
        return 0

    if present is None:
        error(f"cannot safely install because current rule state is unknown: {detail}")
        return 1

    result = run_iptables(command)
    if result.returncode == 0:
        ok("installed NETGUARD_WAN LOG rule")
        return 0

    detail = (result.stderr or result.stdout).strip()
    error(f"install failed: {detail or f'exit {result.returncode}'}")
    return 1


def remove(interface: str, apply: bool) -> int:
    present, detail = rule_present(interface)
    if present is False:
        ok("NETGUARD_WAN LOG rule is not installed; nothing to remove")
        return 0

    command = remove_command(interface)
    if not apply:
        if present is None:
            warn(f"could not confirm current rule state: {detail}")
        dry_run(f"would remove matching rule: {command_text(command)}")
        return 0

    if present is None:
        error(f"cannot safely remove because current rule state is unknown: {detail}")
        return 1

    removed = 0
    while True:
        result = run_iptables(command)
        if result.returncode == 0:
            removed += 1
            continue
        if result.returncode == 1:
            break

        detail = (result.stderr or result.stdout).strip()
        error(f"remove failed: {detail or f'exit {result.returncode}'}")
        return 1

    ok(f"removed {removed} matching NETGUARD_WAN LOG rule(s)")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the NetGuard WAN iptables LOG rule safely.")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--status", action="store_true", help="show rule status")
    actions.add_argument("--print", action="store_true", help="print the install command")
    actions.add_argument("--install", action="store_true", help="install the rule; dry-run unless --apply is set")
    actions.add_argument("--remove", action="store_true", help="remove the rule; dry-run unless --apply is set")
    parser.add_argument("--apply", action="store_true", help="apply --install or --remove")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    interface, source = resolve_wan_interface()
    if not interface:
        error(f"could not resolve WAN interface ({source})")
        return 1

    if args.apply and not (args.install or args.remove):
        error("--apply is only valid with --install or --remove")
        return 2

    if args.print:
        return print_rule(interface)
    if args.status:
        return status(interface, source)
    if args.install:
        return install(interface, args.apply)
    if args.remove:
        return remove(interface, args.apply)

    error("no action selected")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
