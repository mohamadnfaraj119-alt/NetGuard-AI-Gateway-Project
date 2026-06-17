#!/usr/bin/env python3
"""
config_loader.py - NetGuard-AI Gateway v7.6 configuration validator.

This module is intentionally standalone. It validates the safe config layer
without changing existing pipeline behavior.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
NETWORK_PROFILE = CONFIG_DIR / "network_profile.json"
THRESHOLDS_PROFILE = CONFIG_DIR / "thresholds_profile.json"


class ConfigError(Exception):
    """Raised when a configuration file is missing or invalid."""


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"missing file: {path.relative_to(BASE_DIR)}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path.relative_to(BASE_DIR)}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path.relative_to(BASE_DIR)} must contain a JSON object")

    return data


def _require(data: dict[str, Any], key: str, expected_type: type | tuple[type, ...]) -> Any:
    if key not in data:
        raise ConfigError(f"missing required field: {key}")

    value = data[key]
    if not isinstance(value, expected_type):
        expected = (
            " or ".join(t.__name__ for t in expected_type)
            if isinstance(expected_type, tuple)
            else expected_type.__name__
        )
        raise ConfigError(f"field {key} must be {expected}")

    return value


def _require_string(data: dict[str, Any], key: str) -> str:
    value = _require(data, key, str)
    if not value.strip():
        raise ConfigError(f"field {key} must not be empty")
    return value


def _require_bool(data: dict[str, Any], key: str) -> bool:
    return _require(data, key, bool)


def _require_object(data: dict[str, Any], key: str) -> dict[str, Any]:
    return _require(data, key, dict)


def _require_list(data: dict[str, Any], key: str) -> list[Any]:
    value = _require(data, key, list)
    if not value:
        raise ConfigError(f"field {key} must not be empty")
    return value


def _require_number(data: dict[str, Any], key: str, minimum: float | None = None,
                    maximum: float | None = None) -> float:
    value = _require(data, key, (int, float))
    numeric_value = float(value)

    if minimum is not None and numeric_value < minimum:
        raise ConfigError(f"field {key} must be >= {minimum}")
    if maximum is not None and numeric_value > maximum:
        raise ConfigError(f"field {key} must be <= {maximum}")

    return numeric_value


def _validate_ip(value: str, field: str) -> None:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"field {field} must be a valid IP address") from exc


def _validate_network_list(values: list[Any], field: str) -> None:
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"field {field}[{index}] must be a non-empty string")
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(f"field {field}[{index}] must be a valid CIDR network") from exc


def validate_network_profile(path: Path = NETWORK_PROFILE) -> dict[str, Any]:
    data = _load_json(path)

    _require_string(data, "profile_name")
    _require_string(data, "profile_version")
    _require_bool(data, "gateway_mode")

    gateway = _require_object(data, "gateway")
    _require_string(gateway, "hostname")
    gateway_ip = _require_string(gateway, "gateway_ip")
    _validate_ip(gateway_ip, "gateway.gateway_ip")
    _require_string(gateway, "wan_interface")
    _require_string(gateway, "lan_interface")

    monitored_networks = _require_list(data, "monitored_networks")
    trusted_networks = _require_list(data, "trusted_networks")
    _validate_network_list(monitored_networks, "monitored_networks")
    _validate_network_list(trusted_networks, "trusted_networks")

    zeek = _require_object(data, "zeek")
    _require_string(zeek, "log_dir")
    required_logs = _require_list(zeek, "required_logs")
    for index, value in enumerate(required_logs):
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"field zeek.required_logs[{index}] must be a non-empty string")

    runtime = _require_object(data, "runtime")
    _require_string(runtime, "data_dir")
    _require_string(runtime, "logs_dir")
    _require_string(runtime, "models_dir")

    return data


def validate_thresholds_profile(path: Path = THRESHOLDS_PROFILE) -> dict[str, Any]:
    data = _load_json(path)

    _require_string(data, "profile_name")
    _require_string(data, "profile_version")

    risk_score_bands = _require_object(data, "risk_score_bands")
    low = _require_number(risk_score_bands, "low", 0, 100)
    medium = _require_number(risk_score_bands, "medium", 0, 100)
    high = _require_number(risk_score_bands, "high", 0, 100)
    critical = _require_number(risk_score_bands, "critical", 0, 100)
    if not low < medium < high < critical:
        raise ConfigError("risk_score_bands must be strictly increasing: low < medium < high < critical")

    traffic_limits = _require_object(data, "traffic_limits")
    _require_number(traffic_limits, "max_connections_30s", 0)
    _require_number(traffic_limits, "max_unique_dst_ports_30s", 0)
    _require_number(traffic_limits, "max_dns_rate_1m", 0)

    anomaly = _require_object(data, "anomaly")
    _require_number(anomaly, "p99_baseline", 0, 1)
    _require_number(anomaly, "max_score", 0, 1)

    return data


def check_config() -> int:
    print("NetGuard-AI Gateway v7.6 config check")
    print(f"Config directory: {CONFIG_DIR.relative_to(BASE_DIR)}")

    checks = [
        ("network profile", validate_network_profile),
        ("thresholds profile", validate_thresholds_profile),
    ]
    valid = True

    for label, validator in checks:
        try:
            validator()
            print(f"[OK] {label}")
        except ConfigError as exc:
            valid = False
            print(f"[FAIL] {label}: {exc}")

    if valid:
        print("Status: valid")
        return 0

    print("Status: invalid")
    return 1


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate NetGuard-AI Gateway v7.6 configuration files."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate required configuration files and exit",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.check:
        return check_config()

    print("No action selected. Use --check to validate configuration.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
