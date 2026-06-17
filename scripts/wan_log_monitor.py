#!/usr/bin/env python3
"""
wan_log_monitor.py - Initial NETGUARD_WAN kernel log parser.

This monitor only reads kernel log lines from journalctl and emits alerts
through alert_writer.py. It does not create firewall rules or modify system
configuration.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import alert_writer


BASE_DIR = Path(__file__).resolve().parent.parent
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
REPORT_DIR = BASE_DIR / "data" / "reports"
PREFIX = "NETGUARD_WAN"
JOURNALCTL_CMD = ["journalctl", "-k", "-f", "-o", "cat", "-n", "0"]
PORT_SCAN_THRESHOLD = 25
PORT_SCAN_WINDOW_SECONDS = 30
ALERT_COOLDOWN_SECONDS = 30


@dataclass(frozen=True)
class WanLogEvent:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    input_interface: str


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _line(status: str, message: str) -> None:
    print(f"[{status}] {message}", flush=True)


def ok(message: str) -> None:
    _line("OK", message)


def warn(message: str) -> None:
    _line("WARN", message)


def today() -> str:
    return datetime.now().date().isoformat()


def load_json(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def parse_kernel_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def parse_wan_line(line: str) -> WanLogEvent | None:
    if PREFIX not in line:
        return None

    values = parse_kernel_fields(line)
    src_ip = values.get("SRC", "")
    dst_ip = values.get("DST", "")
    protocol = values.get("PROTO", "")
    input_interface = values.get("IN", "")
    dst_port_raw = values.get("DPT", "")

    if not src_ip or not dst_ip or not dst_port_raw:
        return None

    try:
        dst_port = int(dst_port_raw)
    except ValueError:
        return None

    return WanLogEvent(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol or "unknown",
        input_interface=input_interface or "unknown",
    )


class WanPortScanDetector:
    def __init__(self) -> None:
        self._ports_by_source: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self._last_alert_by_source: dict[str, datetime] = {}

    def observe(self, event: WanLogEvent, now: datetime) -> dict[str, object] | None:
        source_window = self._ports_by_source[event.src_ip]
        source_window.append((now, event.dst_port))

        while source_window and (now - source_window[0][0]).total_seconds() > PORT_SCAN_WINDOW_SECONDS:
            source_window.popleft()

        unique_ports = {port for _, port in source_window}
        if len(unique_ports) < PORT_SCAN_THRESHOLD:
            return None

        last_alert = self._last_alert_by_source.get(event.src_ip)
        if last_alert and (now - last_alert).total_seconds() < ALERT_COOLDOWN_SECONDS:
            return None

        self._last_alert_by_source[event.src_ip] = now
        sorted_ports = sorted(unique_ports)
        reason = (
            f"WAN source touched {len(unique_ports)} unique destination ports "
            f"within {PORT_SCAN_WINDOW_SECONDS} seconds"
        )
        return {
            "time": now.isoformat(),
            "source": "wan_log_monitor",
            "direction": "wan_to_gateway",
            "alert_type": "wan_port_scan",
            "severity": "high",
            "risk_score": 90.0,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "input_interface": event.input_interface,
            "reason": reason,
            "message": reason,
            "unique_dst_ports": len(unique_ports),
            "dst_ports_sample": sorted_ports[:25],
            "window_seconds": PORT_SCAN_WINDOW_SECONDS,
        }


def is_wan_alert(alert: dict[str, object]) -> bool:
    source = str(alert.get("source", ""))
    direction = str(alert.get("direction", ""))
    alert_type = str(alert.get("alert_type", ""))
    return (
        source == "wan_log_monitor"
        or direction.startswith("wan_")
        or alert_type.startswith("wan_")
    )


def read_wan_alerts_today() -> tuple[Path, list[dict[str, object]]]:
    path = REPORT_DIR / f"alerts_{today()}.jsonl"
    if not path.exists():
        return path, []

    alerts: list[dict[str, object]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and is_wan_alert(record):
                    alerts.append(record)
    except OSError:
        return path, []

    return path, alerts


def print_last_wan_alerts(alerts: list[dict[str, object]]) -> None:
    print("Last 5 WAN alerts:")
    if not alerts:
        print("  (none)")
        return

    for alert in alerts[-5:]:
        timestamp = str(alert.get("time", ""))[:19] or "unknown-time"
        severity = str(alert.get("severity", "")).upper() or "INFO"
        alert_type = str(alert.get("alert_type", "alert"))
        src_ip = str(alert.get("src_ip", "unknown-src"))
        dst_ip = str(alert.get("dst_ip", "unknown-dst"))
        ports = str(alert.get("unique_dst_ports", alert.get("dst_port", "")))
        print(f"  {timestamp:<19} {severity:<8} {alert_type:<18} {src_ip} -> {dst_ip} ports={ports}")


def print_status() -> int:
    journalctl_path = shutil.which("journalctl")
    ok(f"parser prefix: {PREFIX}")
    ok(
        "threshold: "
        f"{PORT_SCAN_THRESHOLD} unique dst ports / {PORT_SCAN_WINDOW_SECONDS}s"
    )
    if journalctl_path:
        ok(f"journalctl exists: {journalctl_path}")
    else:
        warn("journalctl exists: no")

    report_path, wan_alerts = read_wan_alerts_today()
    ok(f"WAN alerts today: {len(wan_alerts)} from {report_path.relative_to(BASE_DIR)}")
    print_last_wan_alerts(wan_alerts)
    ok("no firewall or system changes will be made")
    return 0


def configured_wan_interface() -> str | None:
    profile = load_json(NETWORK_PROFILE)
    gateway = profile.get("gateway")
    if not isinstance(gateway, dict):
        return None

    interface = str(gateway.get("wan_interface", "")).strip()
    if interface and interface.lower() != "auto":
        return interface
    return None


def default_wan_interface() -> str | None:
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

    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" not in parts:
            continue
        dev_index = parts.index("dev")
        if dev_index + 1 < len(parts):
            return parts[dev_index + 1]
    return None


def wan_interface() -> str | None:
    return configured_wan_interface() or default_wan_interface()


def iptables_log_command(interface: str) -> list[str]:
    return [
        "sudo",
        "iptables",
        "-I",
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
        f"{PREFIX} ",
        "--log-level",
        "4",
    ]


def print_iptables_rule() -> int:
    interface = wan_interface()
    if not interface:
        print("[FAIL] unable to resolve WAN interface from config or default route", file=sys.stderr)
        return 1

    print(shlex.join(iptables_log_command(interface)))
    return 0


def sample_wan_lines() -> list[str]:
    src_ip = "192.168.68.2"
    dst_ip = "192.168.68.13"
    return [
        (
            "kernel: NETGUARD_WAN IN=enp0s31f6 OUT= "
            "MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 "
            f"SRC={src_ip} DST={dst_ip} LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
            f"ID={40000 + offset} PROTO=TCP SPT={58433 + offset} DPT={port} "
            "WINDOW=64240 RES=0x00 SYN URGP=0"
        )
        for offset, port in enumerate(range(10000, 10000 + PORT_SCAN_THRESHOLD))
    ]


def run_test_parse() -> int:
    detector = WanPortScanDetector()
    base_time = _utc_now()
    alerts: list[dict[str, object]] = []

    for offset, line in enumerate(sample_wan_lines()):
        event = parse_wan_line(line)
        if event is None:
            print("[FAIL] sample NETGUARD_WAN line did not parse", file=sys.stderr)
            return 1

        now = base_time + timedelta(seconds=offset)
        alert = detector.observe(event, now)
        if alert is not None:
            alerts.append(alert)

    if len(alerts) != 1:
        print(f"[FAIL] expected exactly one alert, got {len(alerts)}", file=sys.stderr)
        return 1

    written = alert_writer.write_alert(alerts[0])
    ok(f"parsed sample NETGUARD_WAN lines: {PORT_SCAN_THRESHOLD}")
    ok(
        "wrote WAN port scan alert: "
        f"src={written['src_ip']} ports={written['unique_dst_ports']}"
    )
    ok(f"log: {alert_writer.ALERTS_LOG.relative_to(BASE_DIR)}")
    ok("no firewall or system changes were made")
    return 0


def follow_kernel_logs(verbose: bool = False) -> int:
    detector = WanPortScanDetector()
    try:
        process = subprocess.Popen(
            JOURNALCTL_CMD,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        print(f"[FAIL] unable to start journalctl: {exc}", file=sys.stderr)
        return 1

    assert process.stdout is not None
    ok(f"following kernel logs for {PREFIX}")

    try:
        for line in process.stdout:
            if verbose and PREFIX in line:
                ok(f"received {PREFIX} line")

            event = parse_wan_line(line)
            if event is None:
                continue

            alert = detector.observe(event, _utc_now())
            if alert is None:
                continue

            written = alert_writer.write_alert(alert)
            ok(
                "alert written: "
                f"{written['alert_type']} src={written['src_ip']} "
                f"ports={written['unique_dst_ports']}"
            )
    except KeyboardInterrupt:
        ok("stopped")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor NETGUARD_WAN kernel log lines.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print parser readiness and exit without following logs",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="print monitor status and exit without following logs",
    )
    parser.add_argument(
        "--test-parse",
        action="store_true",
        help="parse synthetic NETGUARD_WAN lines and write one test alert",
    )
    parser.add_argument(
        "--print-iptables-rule",
        action="store_true",
        help="print the safe iptables LOG rule without applying it",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print when NETGUARD_WAN log lines are received",
    )
    return parser.parse_args()


def main() -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass

    args = parse_args()
    if args.print_iptables_rule:
        return print_iptables_rule()

    if args.test_parse:
        return run_test_parse()

    if args.dry_run or args.status:
        return print_status()

    return follow_kernel_logs(verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
