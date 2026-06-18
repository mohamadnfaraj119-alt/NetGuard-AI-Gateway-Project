#!/usr/bin/env python3
"""
NetGuard-AI Gateway v7.8
Portable Gateway Doctor - read-only readiness checker.
"""

import argparse
import json
import shlex
import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"
IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")
ZEEK_NODE_CFGS = [
    Path("/opt/zeek/etc/node.cfg"),
    Path("/usr/local/zeek/etc/node.cfg"),
]
SERVICES = [
    "zeek",
    "netguard-collector",
    "netguard-pipeline",
    "netguard-wan-monitor",
]
REQUIRED_NETWORK_SECTIONS = [
    "gateway",
    "lan",
    "trusted_networks",
    "zeek",
    "runtime",
]
CHECK_COUNTS = {
    "FAIL": 0,
    "WARN": 0,
}
CHECKS = []
JSON_OUTPUT = False


def reset_report():
    CHECK_COUNTS["FAIL"] = 0
    CHECK_COUNTS["WARN"] = 0
    CHECKS.clear()


def line(status, message):
    if status in ("OK", "WARN", "FAIL"):
        CHECKS.append({
            "status": status,
            "message": message,
        })
    if status in CHECK_COUNTS:
        CHECK_COUNTS[status] += 1
    if not JSON_OUTPUT:
        print(f"[{status}] {message}")


def ok(message):
    line("OK", message)


def warn(message):
    line("WARN", message)


def fail(message):
    line("FAIL", message)


def final_result():
    if CHECK_COUNTS["FAIL"]:
        return "NOT READY as NetGuard-AI gateway"
    if CHECK_COUNTS["WARN"]:
        return "READY with warnings as NetGuard-AI gateway"
    return "READY as NetGuard-AI gateway"


def print_result():
    print(f"[RESULT] {final_result()}")


def print_json_result():
    print(json.dumps({
        "checks": CHECKS,
        "fail_count": CHECK_COUNTS["FAIL"],
        "warn_count": CHECK_COUNTS["WARN"],
        "final_result": final_result(),
    }, indent=2))


def load_profile():
    if not NETWORK_PROFILE.exists():
        fail("network_profile missing")
        return {}

    try:
        with NETWORK_PROFILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        fail("network_profile invalid JSON")
        return {}
    except OSError:
        fail("network_profile missing")
        return {}

    if not isinstance(data, dict):
        fail("network_profile is not an object")
        return {}

    ok("network_profile loaded")
    missing_sections = [
        section for section in REQUIRED_NETWORK_SECTIONS
        if section not in data
    ]
    if missing_sections:
        warn(f"network_profile missing sections: {', '.join(missing_sections)}")

    return data


def configured_wan(profile):
    gateway = profile.get("gateway", {})
    value = gateway.get("wan_interface") if isinstance(gateway, dict) else None

    if value and str(value).lower() != "auto":
        return str(value), "config/network_profile.json"

    return None, None


def default_route_wan():
    result = subprocess.run(
        ["ip", "-json", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0 or not result.stdout.strip():
        return None, "default route not found"

    try:
        routes = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None, "default route output invalid"

    if not isinstance(routes, list):
        return None, "default route output invalid"

    route = next((item for item in routes if isinstance(item, dict)), None)
    if not route:
        return None, "default route not found"

    dev = route.get("dev")
    if not dev:
        return None, "default route has no dev field"

    return str(dev), "default route"



def detect_lan(wan):
    result = subprocess.run(
        ["ip", "-json", "addr", "show"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return None, "ip addr failed"

    try:
        interfaces = json.loads(result.stdout)
    except Exception:
        return None, "could not parse ip addr output"

    ignored = ("lo", "docker", "br-", "veth", "tun", "tap", "tailscale")

    for item in interfaces:
        name = item.get("ifname", "")
        flags = item.get("flags", [])

        if not name or name == wan:
            continue
        if name.startswith(ignored):
            continue
        if "UP" in flags or "LOWER_UP" in flags:
            return name, "active non-WAN interface"

    return None, "not detected"



def default_route_detail():
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0 or not result.stdout.strip():
        return None, "default route not found"

    return result.stdout.strip().splitlines()[0], "ok"


def check_ip_forwarding():
    try:
        value = IP_FORWARD.read_text(encoding="utf-8").strip()
    except OSError:
        warn("IP forwarding status unknown")
        return

    if value == "1":
        ok("IP forwarding enabled")
    elif value == "0":
        fail("IP forwarding disabled")
    else:
        warn("IP forwarding status unknown")


def check_nat_readiness(wan):
    if not shutil.which("iptables"):
        warn("NAT readiness unknown: iptables not found")
        return

    try:
        result = subprocess.run(
            ["iptables", "-t", "nat", "-S", "POSTROUTING"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        warn(f"NAT readiness unknown: {exc}")
        return

    if result.returncode != 0:
        reason = (result.stderr or result.stdout).strip() or f"iptables exited {result.returncode}"
        warn(f"NAT readiness unknown: {reason}")
        return

    masquerade_found = False
    masquerade_for_wan = False

    for line in result.stdout.splitlines():
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()

        if "-j" in parts:
            jump_index = parts.index("-j")
            is_masquerade = jump_index + 1 < len(parts) and parts[jump_index + 1] == "MASQUERADE"
        else:
            is_masquerade = "MASQUERADE" in parts

        if not is_masquerade:
            continue

        masquerade_found = True
        if "-o" in parts:
            output_index = parts.index("-o")
            if output_index + 1 < len(parts) and parts[output_index + 1] == wan:
                masquerade_for_wan = True

    if masquerade_for_wan:
        ok(f"NAT readiness confirmed for WAN interface {wan}")
    elif masquerade_found:
        warn(f"NAT MASQUERADE exists, but not for WAN interface {wan}")
    else:
        fail("NAT readiness missing: no MASQUERADE rule found")


def read_zeek_interface():
    for path in ZEEK_NODE_CFGS:
        if not path.exists():
            continue

        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("interface="):
                interface = stripped.split("=", 1)[1].strip()
                if interface:
                    return interface

    return None


def check_zeek_interface(wan, lan):
    zeek_interface = read_zeek_interface()
    if not zeek_interface:
        warn("Zeek interface unknown: node.cfg not found or interface not configured")
        return

    if zeek_interface == wan:
        ok(f"Zeek monitors WAN interface {zeek_interface}")
    elif zeek_interface == lan:
        ok(f"Zeek monitors LAN interface {zeek_interface}")
    else:
        warn(f"Zeek interface {zeek_interface} does not match WAN {wan} or LAN {lan}")


def check_services():
    systemctl = shutil.which("systemctl")
    if not systemctl:
        warn("systemd check unavailable: systemctl not found")
        return

    for service in SERVICES:
        try:
            result = subprocess.run(
                [systemctl, "is-active", service],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            fail(f"service {service} {exc}")
            continue

        state = result.stdout.strip() or result.stderr.strip() or "unknown"
        if result.returncode == 0 and state == "active":
            ok(f"service {service} active")
        else:
            fail(f"service {service} {state}")


def main():
    global JSON_OUTPUT

    reset_report()
    parser = argparse.ArgumentParser(
        description="NetGuard-AI Gateway v7.8 portable doctor readiness checker"
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    JSON_OUTPUT = args.json

    if args.apply:
        print("[FAIL] --apply is not implemented yet. No changes applied.")
        return 1

    profile = load_profile()

    wan, source = configured_wan(profile)
    if not wan:
        wan, source = default_route_wan()

    ok("read-only mode confirmed")

    route_line, route_status = default_route_detail()
    if route_line:
        ok(f"default route: {route_line}")
    else:
        fail(f"default route: {route_status}")
        if JSON_OUTPUT:
            print_json_result()
        else:
            print_result()
        return 1

    if wan:
        ok(f"WAN interface detected: {wan} ({source})")
    else:
        fail(f"WAN interface not detected: {source}")
        if JSON_OUTPUT:
            print_json_result()
        else:
            print_result()
        return 1

    lan, lan_source = detect_lan(wan)

    if lan:
        ok(f"LAN interface detected: {lan} ({lan_source})")
    else:
        warn(f"LAN interface not detected: {lan_source}")

    check_ip_forwarding()
    check_nat_readiness(wan)
    check_zeek_interface(wan, lan)
    check_services()
    if JSON_OUTPUT:
        print_json_result()
    else:
        print_result()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
