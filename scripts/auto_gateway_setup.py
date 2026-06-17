#!/usr/bin/env python3
"""
auto_gateway_setup.py - NetGuard-AI Gateway v7.6 dry-run planner.

This script is intentionally dry-run only. It detects local network state and
prints the gateway changes that would be needed, but it never writes system
files or applies netplan, dnsmasq, iptables, or sysctl changes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
DEFAULT_LAN_SUBNET = ipaddress.ip_network("10.77.0.0/24")


def status(label: str, message: str) -> None:
    print(f"[{label}] {message}")


def load_network_profile() -> dict[str, Any]:
    if not NETWORK_PROFILE.exists():
        status("WARN", "config/network_profile.json missing; using defaults")
        return {}

    try:
        with NETWORK_PROFILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        status("WARN", f"could not read config/network_profile.json; using defaults ({exc})")
        return {}

    if not isinstance(data, dict):
        status("WARN", "config/network_profile.json is not an object; using defaults")
        return {}

    status("OK", "loaded config/network_profile.json")
    return data


def select_lan_subnet(profile: dict[str, Any]) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    lan = profile.get("lan")
    if isinstance(lan, dict) and isinstance(lan.get("cidr"), str):
        try:
            network = ipaddress.ip_network(lan["cidr"], strict=False)
        except ValueError:
            status("WARN", f"ignoring invalid lan.cidr: {lan['cidr']}")
        else:
            status("OK", f"selected LAN subnet from config lan.cidr: {network}")
            return network

    monitored = profile.get("monitored_networks")
    if isinstance(monitored, list):
        for item in monitored:
            if not isinstance(item, str):
                continue
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError:
                status("WARN", f"ignoring invalid monitored network: {item}")
                continue
            status("OK", f"selected LAN subnet from config monitored_networks: {network}")
            return network

    status("WARN", f"no valid LAN subnet found; using default {DEFAULT_LAN_SUBNET}")
    return DEFAULT_LAN_SUBNET


def select_dhcp_range(profile: dict[str, Any],
                      lan_subnet: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    lan = profile.get("lan")
    if not isinstance(lan, dict):
        status("WARN", "config lan section missing; using example DHCP range")
        return example_dhcp_range(lan_subnet)

    dhcp_start = lan.get("dhcp_start")
    dhcp_end = lan.get("dhcp_end")
    if not isinstance(dhcp_start, str) or not isinstance(dhcp_end, str):
        status("WARN", "lan.dhcp_start or lan.dhcp_end missing; using example DHCP range")
        return example_dhcp_range(lan_subnet)

    try:
        start_ip = ipaddress.ip_address(dhcp_start)
        end_ip = ipaddress.ip_address(dhcp_end)
    except ValueError:
        status("WARN", "configured DHCP range contains an invalid IP; using example DHCP range")
        return example_dhcp_range(lan_subnet)

    if start_ip not in lan_subnet or end_ip not in lan_subnet:
        status("WARN", "configured DHCP range is outside LAN subnet; using example DHCP range")
        return example_dhcp_range(lan_subnet)
    if int(start_ip) > int(end_ip):
        status("WARN", "configured DHCP range start is greater than end; using example DHCP range")
        return example_dhcp_range(lan_subnet)

    status("OK", f"selected DHCP range from config lan section: {start_ip} - {end_ip}")
    return f"{start_ip} - {end_ip}"


def run_ip_json(args: list[str]) -> list[dict[str, Any]]:
    ip_bin = shutil.which("ip")
    if not ip_bin:
        status("WARN", "ip command not found; network detection limited")
        return []

    try:
        result = subprocess.run(
            [ip_bin, "-json", *args],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        status("WARN", f"ip {' '.join(args)} failed: {exc}")
        return []

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        status("WARN", f"ip {' '.join(args)} failed: {detail}")
        return []

    try:
        data = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        status("WARN", f"ip {' '.join(args)} returned invalid JSON: {exc}")
        return []

    if not isinstance(data, list):
        status("WARN", f"ip {' '.join(args)} returned unexpected data")
        return []

    return data


def detect_wan(default_routes: list[dict[str, Any]], addresses: list[dict[str, Any]]) -> dict[str, Any]:
    route = next((item for item in default_routes if item.get("dst") == "default"), None)
    if not route:
        status("WARN", "default route not detected")
        return {}

    wan_iface = route.get("dev")
    wan_gateway = route.get("gateway")
    wan_ip = route.get("prefsrc")
    wan_network = None

    for iface in addresses:
        if iface.get("ifname") != wan_iface:
            continue
        for addr in iface.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            local = addr.get("local")
            prefixlen = addr.get("prefixlen")
            if not local or prefixlen is None:
                continue
            wan_ip = wan_ip or local
            wan_network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
            break

    if wan_iface:
        detail = f"WAN interface detected: {wan_iface}"
        if wan_ip:
            detail += f" ({wan_ip}"
            if wan_network:
                detail += f"/{wan_network.prefixlen}"
            detail += ")"
        if wan_gateway:
            detail += f", gateway {wan_gateway}"
        status("OK", detail)

    return {
        "interface": wan_iface,
        "gateway": wan_gateway,
        "ip": wan_ip,
        "network": wan_network,
    }


def _is_candidate_lan(iface: dict[str, Any], wan_iface: str | None) -> bool:
    ifname = iface.get("ifname")
    if not ifname or ifname == "lo" or ifname == wan_iface:
        return False
    if str(ifname).startswith(("tailscale", "tun", "tap", "docker", "br-", "veth")):
        return False
    flags = set(iface.get("flags", []))
    return "UP" in flags or "LOWER_UP" in flags


def detect_lan(addresses: list[dict[str, Any]], wan_iface: str | None,
               configured_name: str | None = None) -> dict[str, Any]:
    candidates = [iface for iface in addresses if _is_candidate_lan(iface, wan_iface)]

    chosen = None
    if configured_name:
        chosen = next((iface for iface in candidates if iface.get("ifname") == configured_name), None)
        if chosen:
            status("OK", f"configured LAN interface detected: {configured_name}")
        else:
            status("WARN", f"configured LAN interface not detected: {configured_name}")

    if chosen is None and candidates:
        chosen = candidates[0]
        status("OK", f"selected LAN interface candidate: {chosen.get('ifname')}")

    if chosen is None:
        status("WARN", "LAN interface could not be detected")
        return {}

    lan_ip = None
    lan_network = None
    for addr in chosen.get("addr_info", []):
        if addr.get("family") != "inet":
            continue
        local = addr.get("local")
        prefixlen = addr.get("prefixlen")
        if not local or prefixlen is None:
            continue
        lan_ip = local
        lan_network = ipaddress.ip_network(f"{local}/{prefixlen}", strict=False)
        break

    if lan_ip and lan_network:
        status("OK", f"LAN interface address detected: {chosen.get('ifname')} ({lan_ip}/{lan_network.prefixlen})")
    else:
        status("WARN", f"LAN interface has no IPv4 address: {chosen.get('ifname')}")

    return {
        "interface": chosen.get("ifname"),
        "ip": lan_ip,
        "network": lan_network,
    }


def gateway_ip_for(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    if network.version == 4 and network.num_addresses > 2:
        return str(network.network_address + 1)
    return str(network.network_address)


def example_dhcp_range(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    if network.version != 4 or network.num_addresses < 16:
        return "not suggested for this subnet"

    first = network.network_address + 10
    last_offset = min(200, network.num_addresses - 2)
    last = network.network_address + last_offset
    return f"{first} - {last}"


def print_plan(mode: str, wan: dict[str, Any], lan: dict[str, Any],
               lan_subnet: ipaddress.IPv4Network | ipaddress.IPv6Network,
               dhcp_range: str,
               conflict: bool) -> None:
    print()
    print("Dry-run gateway setup plan")
    print(f"Mode: {mode}")
    print(f"Project root: {BASE_DIR}")
    print()
    print("Detected network state:")
    print(f"  WAN interface: {wan.get('interface') or 'unknown'}")
    print(f"  WAN IP/subnet: {wan.get('network') or 'unknown'}")
    print(f"  WAN gateway: {wan.get('gateway') or 'unknown'}")
    print(f"  LAN interface: {lan.get('interface') or 'unknown'}")
    print(f"  Existing LAN IP/subnet: {lan.get('network') or 'unknown'}")
    print()
    print("Selected demo LAN plan:")
    print(f"  LAN subnet: {lan_subnet}")
    print(f"  Gateway LAN IP: {gateway_ip_for(lan_subnet)}")
    print(f"  DHCP range: {dhcp_range}")
    print()
    print("Would change in a future --apply implementation:")
    print("  - netplan: assign LAN interface static gateway IP")
    print("  - sysctl: enable IPv4 forwarding")
    print("  - iptables/nftables: enable NAT from LAN to WAN")
    print("  - dnsmasq: serve DHCP/DNS on the LAN interface")
    print("  - services: restart affected network services")
    print()
    print("Dry-run safety:")
    print("  - No system files were modified")
    print("  - No netplan changes were applied")
    print("  - No dnsmasq changes were applied")
    print("  - No iptables/nftables changes were applied")
    print("  - No sysctl changes were applied")

    if conflict:
        print()
        print("Conflict detected:")
        print("  - Selected LAN subnet overlaps with detected WAN subnet")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run planner for NetGuard-AI Gateway setup."
    )
    parser.add_argument(
        "--mode",
        choices=["demo"],
        required=True,
        help="setup profile to plan",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the setup plan without applying changes",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.dry_run:
        status("FAIL", "--apply is not implemented; rerun with --dry-run")
        return 1

    print("NetGuard-AI Gateway v7.6 auto setup")
    status("OK", "dry-run mode active; no changes will be applied")

    profile = load_network_profile()
    lan_subnet = select_lan_subnet(profile)
    dhcp_range = select_dhcp_range(profile, lan_subnet)
    configured_lan = None
    gateway = profile.get("gateway")
    if isinstance(gateway, dict) and isinstance(gateway.get("lan_interface"), str):
        configured_lan = gateway["lan_interface"]

    default_routes = run_ip_json(["route", "show", "default"])
    addresses = run_ip_json(["addr", "show"])
    wan = detect_wan(default_routes, addresses)
    lan = detect_lan(addresses, wan.get("interface"), configured_lan)

    wan_network = wan.get("network")
    conflict = bool(wan_network and lan_subnet.overlaps(wan_network))
    if conflict:
        status("FAIL", f"subnet conflict: LAN {lan_subnet} overlaps WAN {wan_network}")
    else:
        status("OK", "no WAN/LAN subnet conflict detected")

    print_plan(args.mode, wan, lan, lan_subnet, dhcp_range, conflict)
    status("OK", "dry-run completed safely")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
