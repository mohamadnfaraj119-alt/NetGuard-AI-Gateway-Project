#!/usr/bin/env python3
"""
demo_replay.py - Write one deterministic demo alert for a named scenario.

Replay alerts are written through alert_writer.py so they use the same JSONL
destinations as the rest of the demo tooling.
"""

from __future__ import annotations

import argparse
from typing import Any

import alert_writer


SCENARIOS: dict[str, dict[str, Any]] = {
    "lan_port_scan": {
        "source": "demo_replay",
        "direction": "lan_to_gateway",
        "alert_type": "lan_port_scan",
        "severity": "high",
        "risk_score": 82.5,
        "src_ip": "192.168.50.42",
        "dst_ip": "192.168.50.1",
        "reason": "LAN host probed multiple gateway TCP ports in a short window",
    },
    "wan_port_scan": {
        "source": "demo_replay",
        "direction": "wan_to_gateway",
        "alert_type": "wan_port_scan",
        "severity": "high",
        "risk_score": 88.0,
        "src_ip": "203.0.113.77",
        "dst_ip": "198.51.100.10",
        "reason": "External host scanned exposed gateway ports across common services",
    },
    "ssh_attempts": {
        "source": "demo_replay",
        "direction": "wan_to_gateway",
        "alert_type": "ssh_attempts",
        "severity": "medium",
        "risk_score": 71.0,
        "src_ip": "203.0.113.88",
        "dst_ip": "198.51.100.10",
        "reason": "Repeated SSH login attempts detected against the gateway",
    },
    "dns_burst": {
        "source": "demo_replay",
        "direction": "lan_to_wan",
        "alert_type": "dns_burst",
        "severity": "medium",
        "risk_score": 64.5,
        "src_ip": "192.168.50.25",
        "dst_ip": "8.8.8.8",
        "reason": "LAN host generated an unusual burst of DNS queries",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay one NetGuard-AI demo alert.")
    parser.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIOS),
        help="demo scenario to replay",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    alert = dict(SCENARIOS[args.scenario])
    alert["message"] = alert["reason"]

    written = alert_writer.write_alert(alert)

    print(f"[OK] replayed scenario: {args.scenario}")
    print(f"[OK] alert_type: {written['alert_type']}")
    print(f"[OK] severity: {written['severity']}")
    print(f"[OK] risk_score: {written['risk_score']}")
    print(f"[OK] log: {alert_writer.ALERTS_LOG.relative_to(alert_writer.BASE_DIR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
