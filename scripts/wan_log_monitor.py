#!/usr/bin/env python3
"""
wan_log_monitor.py - Initial NETGUARD_WAN kernel log parser.

This monitor only reads kernel log lines from journalctl and emits alerts
through alert_writer.py. It does not create firewall rules or modify system
configuration.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import alert_writer


BASE_DIR = Path(__file__).resolve().parent.parent
PREFIX = "NETGUARD_WAN"
JOURNALCTL_CMD = ["journalctl", "-k", "-f", "-n", "0"]
PORT_SCAN_THRESHOLD = 25
PORT_SCAN_WINDOW_SECONDS = 30
ALERT_COOLDOWN_SECONDS = 30

KEY_VALUE_PATTERN = re.compile(r"\b([A-Z]+)=([^\s]+)")


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
    print(f"[{status}] {message}")


def ok(message: str) -> None:
    _line("OK", message)


def warn(message: str) -> None:
    _line("WARN", message)


def parse_wan_line(line: str) -> WanLogEvent | None:
    if PREFIX not in line:
        return None

    values = {key: value for key, value in KEY_VALUE_PATTERN.findall(line)}
    src_ip = values.get("SRC", "")
    dst_ip = values.get("DST", "")
    protocol = values.get("PROTO", "").lower()
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


def print_status() -> int:
    journalctl_path = shutil.which("journalctl")
    if journalctl_path:
        ok(f"journalctl found: {journalctl_path}")
    else:
        warn("journalctl not found in PATH")

    ok(f"parser prefix: {PREFIX}")
    ok(f"kernel log command: {' '.join(JOURNALCTL_CMD)}")
    ok(
        "WAN port scan threshold: "
        f"{PORT_SCAN_THRESHOLD} unique dst ports / {PORT_SCAN_WINDOW_SECONDS}s"
    )
    ok(f"alert writer log: {alert_writer.ALERTS_LOG.relative_to(BASE_DIR)}")
    ok("no firewall or system changes will be made")
    return 0


def follow_kernel_logs() -> int:
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.dry_run or args.status:
        return print_status()

    return follow_kernel_logs()


if __name__ == "__main__":
    raise SystemExit(main())
