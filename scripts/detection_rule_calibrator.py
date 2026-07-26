#!/usr/bin/env python3
"""
Offline rule-calibration replay evaluator for NetGuard-AI.

This script evaluates candidate classification policies against existing risk
reports. It does not change production detection rules, thresholds, model
artifacts, services, network configuration, or evidence files.
"""

import argparse
import csv
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "data" / "reports"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
AUDIT_DIR = BASE_DIR / "data" / "audit"
DEFAULT_COOLDOWN_SECONDS = 10 * 60
EXPECTED_2026_07_26_COUNTS = {
    "FAILED_CONNECTION_PATTERN": 159,
    "PORT_SCAN": 3,
    "DNS_ANOMALY": 3,
    "LOW_SIGNAL_REVIEW": 2,
}
CLASSIFICATIONS = (
    "PORT_SCAN",
    "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
    "FAILED_CONNECTION_PATTERN",
    "DNS_ANOMALY",
    "DOS_LIKE_BURST",
    "BOT_LIKE_BEHAVIOR",
    "UNKNOWN_SUSPICIOUS",
    "LOW_SIGNAL_REVIEW",
)

if str(BASE_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "scripts"))

import attack_classifier  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline detection rule calibration and replay evaluator."
    )
    parser.add_argument(
        "--normal-date",
        required=True,
        type=parse_date,
        help="Known-normal date to use for false-positive replay, formatted YYYY-MM-DD.",
    )
    parser.add_argument(
        "--attack-date",
        type=parse_date,
        help="Optional attack evidence date. Prefer --attack-manifest for scoped labels.",
    )
    parser.add_argument(
        "--attack-manifest",
        type=Path,
        help="Optional JSON ground-truth manifest for controlled attack sessions.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory. Default: data/audit/detection_calibration_<normal-date>/.",
    )
    parser.add_argument(
        "--top",
        type=positive_int,
        default=10,
        help="Number of top rows/reasons/examples to include. Default: 10.",
    )
    return parser.parse_args()


def parse_date(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must be formatted as YYYY-MM-DD") from exc
    return value


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return number


def read_csv_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return [dict(row) for row in reader], list(reader.fieldnames or [])


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def row_value(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def row_float(row: dict[str, Any], *names: str) -> float:
    value = row_value(row, *names)
    if not value:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def bool_flag(row: dict[str, Any], name: str) -> bool:
    return row_value(row, name).lower() in {"1", "true", "yes", "y"}


def confidence(base: float, reasons: list[str], cap: float = 0.95) -> float:
    return round(min(cap, base + min(len(reasons), 5) * 0.04), 2)


def parse_time(row: dict[str, Any]) -> datetime | None:
    value = row_value(row, "datetime", "time", "timestamp")
    if value:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                pass
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    ts = row_float(row, "ts")
    if ts:
        try:
            return datetime.fromtimestamp(ts)
        except (OSError, OverflowError, ValueError):
            return None
    return None


def time_text(row: dict[str, Any]) -> str:
    dt = parse_time(row)
    if dt:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    return row_value(row, "datetime", "time", "timestamp", "ts") or "n/a"


def is_current_suspicious(row: dict[str, Any]) -> bool:
    risk = row_float(row, "risk_score")
    anomaly = row_float(row, "anomaly_score")
    failed = row_float(row, "failed_conn_rate_30s")
    connections = row_float(row, "connections_30s")
    dns = row_float(row, "dns_rate_30s")
    return (
        risk >= 20.0
        or anomaly >= 0.35
        or failed >= 0.8
        or connections >= 80.0
        or dns >= 1.0
    )


def classify_current_policy(
    row: dict[str, Any],
    suspicious_rows_by_src: Counter[str],
    trusted_ips: set[str] | None = None,
) -> dict[str, Any]:
    trusted_ips = trusted_ips or set()
    risk = row_float(row, "risk_score")
    anomaly = row_float(row, "anomaly_score")
    connections = row_float(row, "connections_30s")
    failed = row_float(row, "failed_conn_rate_30s")
    dns = row_float(row, "dns_rate_30s")
    unique_ports = row_float(row, "unique_dst_ports_30s")
    unique_ips = row_float(row, "unique_dst_ips_30s")
    bytes_rate = row_float(row, "bytes_per_sec_30s", "bytes_per_sec")
    burst = row_float(row, "burst_score_30s", "burst_score")
    dst_port = row_value(row, "dst_port", "id.resp_p")
    service = row_value(row, "service").lower()
    proto = row_value(row, "proto", "protocol")
    src_ip = row_value(row, "src_ip")
    repeated = suspicious_rows_by_src[src_ip] if src_ip else 0
    is_trusted_admin = src_ip in trusted_ips
    candidates: list[tuple[str, float, list[str]]] = []

    reasons = []
    if bool_flag(row, "flag_burst"):
        reasons.append("flag_burst is set")
    if connections >= 120 and risk >= 20:
        reasons.append(f"connections_30s={connections:.0f} >= 120 with elevated risk")
    if burst >= 0.8 and (risk >= 20 or anomaly >= 0.35):
        reasons.append(f"burst_score={burst:.2f} >= 0.8 with risk/anomaly support")
    if bytes_rate >= 100000 and (risk >= 20 or anomaly >= 0.35):
        reasons.append(f"bytes_per_sec={bytes_rate:.0f} is high with risk/anomaly support")
    if reasons:
        candidates.append(("DOS_LIKE_BURST", confidence(0.58, reasons, 0.86), reasons))

    reasons = []
    if bool_flag(row, "flag_port_scan"):
        reasons.append("flag_port_scan is set")
    if unique_ports >= 10:
        reasons.append(f"unique_dst_ports_30s={unique_ports:.0f} >= 10")
    if unique_ips >= 10:
        reasons.append(f"unique_dst_ips_30s={unique_ips:.0f} >= 10")
    if connections >= 80 and failed >= 0.3:
        reasons.append(f"connections_30s={connections:.0f} with failed_conn_rate_30s={failed:.2f}")
    if risk >= 30 and connections >= 50:
        reasons.append(f"risk_score={risk:.2f} with elevated connections")
    scan_evidence = (
        (unique_ports >= 10 or unique_ips >= 10)
        and (connections >= 50 or failed >= 0.3 or risk >= 20)
    )
    if bool_flag(row, "flag_port_scan") or scan_evidence:
        candidates.append(("PORT_SCAN", confidence(0.58, reasons, 0.9), reasons))

    service_context = " ".join([service, proto, row_value(row, "protocol")]).lower()
    has_ssh_context = dst_port == "22" or "ssh" in service_context
    strong_login_pattern = (
        has_ssh_context
        and failed >= 0.8
        and connections >= 20
        and (risk >= 20 or anomaly >= 0.35)
    )
    reasons = []
    if has_ssh_context:
        reasons.append("explicit SSH evidence is present")
    if bool_flag(row, "flag_brute_force"):
        reasons.append("flag_brute_force is set")
    if failed >= 0.8:
        reasons.append(f"failed_conn_rate_30s={failed:.2f} >= 0.8")
    if connections >= 20:
        reasons.append(f"connections_30s={connections:.0f} >= 20")
    if risk >= 20:
        reasons.append(f"risk_score={risk:.2f} >= 20")
    if anomaly >= 0.35:
        reasons.append(f"anomaly_score={anomaly:.4f} >= 0.35")
    if repeated >= 5:
        reasons.append(f"source has {repeated} suspicious rows")
    if strong_login_pattern:
        ssh_score = confidence(0.62, reasons, 0.88)
        if is_trusted_admin and not (failed >= 0.95 and connections >= 50 and risk >= 30):
            ssh_score = max(0.35, round(ssh_score - 0.12, 2))
            reasons.append("src_ip is marked as trusted/admin management source")
        candidates.append(("SSH_BRUTE_FORCE_OR_LOGIN_PATTERN", ssh_score, reasons))

    reasons = []
    failed_pattern = failed >= 0.8 and (
        connections >= 10 or repeated >= 5 or bool_flag(row, "flag_brute_force")
    )
    if failed >= 0.8:
        reasons.append(f"failed_conn_rate_30s={failed:.2f} >= 0.8")
    if connections >= 10:
        reasons.append(f"connections_30s={connections:.0f} >= 10")
    if repeated >= 5:
        reasons.append(f"source has {repeated} suspicious rows")
    if bool_flag(row, "flag_brute_force"):
        reasons.append("flag_brute_force is set without explicit SSH evidence")
    if failed_pattern and not has_ssh_context:
        failed_score = confidence(0.44, reasons, 0.72)
        if is_trusted_admin:
            failed_score = max(0.25, round(failed_score - 0.1, 2))
            reasons.append("src_ip is marked as trusted/admin management source")
        candidates.append(("FAILED_CONNECTION_PATTERN", failed_score, reasons))

    reasons = []
    if bool_flag(row, "flag_dns_flood"):
        reasons.append("flag_dns_flood is set")
    if dns >= 1.0:
        reasons.append(f"dns_rate_30s={dns:.2f} >= 1.0")
    if anomaly >= 0.35:
        reasons.append(f"anomaly_score={anomaly:.4f} >= 0.35")
    if risk >= 20:
        reasons.append(f"risk_score={risk:.2f} >= 20")
    if dns >= 1.0:
        candidates.append(("DNS_ANOMALY", confidence(0.55, reasons, 0.86), reasons))

    reasons = []
    medium_signals = 0
    if anomaly >= 0.35:
        medium_signals += 1
        reasons.append(f"anomaly_score={anomaly:.4f} >= 0.35")
    if repeated >= 3:
        medium_signals += 1
        reasons.append(f"source has {repeated} suspicious rows")
    if risk >= 20:
        medium_signals += 1
        reasons.append(f"risk_score={risk:.2f} >= 20")
    if failed >= 0.5:
        medium_signals += 1
        reasons.append(f"failed_conn_rate_30s={failed:.2f} >= 0.5")
    if connections >= 30:
        medium_signals += 1
        reasons.append(f"connections_30s={connections:.0f} >= 30")
    clearer_labels = {candidate[0] for candidate in candidates}
    if medium_signals >= 3 and not clearer_labels.intersection({
        "PORT_SCAN",
        "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
        "FAILED_CONNECTION_PATTERN",
        "DNS_ANOMALY",
        "DOS_LIKE_BURST",
    }):
        candidates.append(("BOT_LIKE_BEHAVIOR", confidence(0.44, reasons, 0.74), reasons))

    if candidates:
        classification, score, reasons = sorted(
            candidates, key=lambda item: (item[1], len(item[2])), reverse=True
        )[0]
    elif risk >= 30 or anomaly >= 0.35:
        classification = "UNKNOWN_SUSPICIOUS"
        reasons = []
        if risk >= 30:
            reasons.append(f"risk_score={risk:.2f} >= 30")
        if anomaly >= 0.35:
            reasons.append(f"anomaly_score={anomaly:.4f} >= 0.35")
        score = confidence(0.42, reasons, 0.62)
    else:
        classification = "LOW_SIGNAL_REVIEW"
        reasons = ["suspicious threshold met, but supporting indicators are weak"]
        if 20 <= risk < 30:
            reasons.append(f"risk_score={risk:.2f} is in review range")
        score = confidence(0.25, reasons, 0.49)

    if is_trusted_admin and "src_ip is marked as trusted/admin management source" not in reasons:
        reasons = list(reasons) + ["src_ip is marked as trusted/admin management source"]
        if classification in {"UNKNOWN_SUSPICIOUS", "LOW_SIGNAL_REVIEW"}:
            score = max(0.25, round(score - 0.05, 2))

    return {
        "classification": classification,
        "confidence": score,
        "reasons": reasons,
        "src_ip": src_ip or "n/a",
        "time": time_text(row),
    }


def current_policy_rows(risk_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    suspicious = [row for row in risk_rows if is_current_suspicious(row)]
    repeated = Counter(row_value(row, "src_ip") for row in suspicious)
    repeated.pop("", None)
    results = []
    for index, row in enumerate(risk_rows):
        if not is_current_suspicious(row):
            continue
        classified = classify_current_policy(row, repeated)
        item = dict(row)
        item.update(classified)
        item["row_index"] = index
        item["estimated_failed_connections_30s"] = estimated_failed_count(item)
        item["reason_text"] = "; ".join(str(reason) for reason in item["reasons"])
        results.append(item)
    return results


def production_policy_rows(risk_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    suspicious = [row for row in risk_rows if attack_classifier.is_suspicious_row(row)]
    repeated = Counter(attack_classifier.row_value(row, "src_ip") for row in suspicious)
    repeated.pop("", None)
    results = []
    for index, row in enumerate(risk_rows):
        if not attack_classifier.is_suspicious_row(row):
            continue
        classified = attack_classifier.classify_row(row, repeated, set())
        item = dict(row)
        item.update(
            {
                "classification": classified["attack_type"],
                "confidence": float(classified["confidence"]),
                "reasons": list(classified["reasons"]),
                "src_ip": classified["src_ip"],
                "time": classified["time"],
                "row_index": index,
            }
        )
        item["estimated_failed_connections_30s"] = estimated_failed_count(item)
        item["reason_text"] = "; ".join(str(reason) for reason in item["reasons"])
        results.append(item)
    return results


def estimated_failed_count(row: dict[str, Any]) -> float:
    return row_float(row, "connections_30s") * row_float(row, "failed_conn_rate_30s")


def source_class_key(row: dict[str, Any]) -> tuple[str, str]:
    return str(row.get("src_ip") or "n/a"), str(row.get("classification") or "")


def group_sequences(rows: list[dict[str, Any]], max_gap_seconds: int = 90) -> list[list[dict[str, Any]]]:
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_key[source_class_key(row)].append(row)
    sequences = []
    for items in by_key.values():
        ordered = sorted(items, key=lambda row: (parse_time(row) or datetime.min, int(row.get("row_index", 0))))
        current: list[dict[str, Any]] = []
        previous_dt: datetime | None = None
        for row in ordered:
            current_dt = parse_time(row)
            if (
                current
                and previous_dt is not None
                and current_dt is not None
                and (current_dt - previous_dt).total_seconds() <= max_gap_seconds
            ):
                current.append(row)
            else:
                if current:
                    sequences.append(current)
                current = [row]
            previous_dt = current_dt
        if current:
            sequences.append(current)
    return sequences


def persistence_counts(rows: list[dict[str, Any]]) -> dict[int, int]:
    counts: dict[int, int] = {}
    for sequence in group_sequences(rows):
        length = len(sequence)
        for row in sequence:
            counts[int(row["row_index"])] = length
    return counts


def source_class_occurrence_counts(rows: list[dict[str, Any]]) -> Counter[tuple[str, str]]:
    return Counter(source_class_key(row) for row in rows)


def has_protocol_specific_evidence(row: dict[str, Any]) -> bool:
    keys = ("nxdomain_rate_30s", "unique_query_count_30s", "unique_dns_queries_30s", "dst_port", "service")
    if row_value(row, "dst_port", "service"):
        service = row_value(row, "service").lower()
        return row_value(row, "dst_port") == "22" or "ssh" in service
    return any(row_value(row, key) for key in keys[:3])


def independent_signal_groups(
    row: dict[str, Any],
    persistence_count: int = 1,
    current_repeated_count: int = 0,
) -> set[str]:
    signals: set[str] = set()
    anomaly = row_float(row, "anomaly_score")
    risk = row_float(row, "risk_score")
    classification = str(row.get("classification") or "")
    connections = row_float(row, "connections_30s")
    failed_rate = row_float(row, "failed_conn_rate_30s")
    failed_abs = estimated_failed_count(row)
    unique_ports = row_float(row, "unique_dst_ports_30s")
    unique_ips = row_float(row, "unique_dst_ips_30s")
    dns = row_float(row, "dns_rate_30s")
    burst = row_float(row, "burst_score_30s")

    if anomaly >= 0.35:
        signals.add("model_evidence")
    elif anomaly > 0:
        signals.add("nonzero_model_context")
    if risk >= 20:
        signals.add("risk_evidence")
    if classification == "FAILED_CONNECTION_PATTERN":
        if failed_rate >= 0.8 and (connections >= 10 or current_repeated_count >= 5):
            signals.add("direct_failed_connection_behavior")
    elif classification == "PORT_SCAN":
        if unique_ports >= 10 or (unique_ips >= 10 and connections >= 50):
            signals.add("direct_port_scan_behavior")
    elif classification == "DNS_ANOMALY":
        if dns >= 1.0:
            signals.add("direct_dns_behavior")
    elif classification == "DOS_LIKE_BURST":
        if connections >= 120 or burst >= 0.8:
            signals.add("direct_burst_behavior")
    elif classification == "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN":
        if failed_abs >= 5 and failed_rate >= 0.8 and connections >= 10:
            signals.add("direct_failed_connection_behavior")
    elif classification in {"BOT_LIKE_BEHAVIOR", "UNKNOWN_SUSPICIOUS", "LOW_SIGNAL_REVIEW"}:
        if failed_rate >= 0.8 or connections >= 30 or dns >= 1.0 or unique_ips >= 10 or unique_ports >= 10:
            signals.add("direct_behavior")
    if persistence_count >= 3:
        signals.add("persistence_evidence")
    if has_protocol_specific_evidence(row):
        signals.add("protocol_specific_evidence")
    return signals


@dataclass(frozen=True)
class CandidatePolicy:
    name: str
    description: str
    failed_min_connections: int = 0
    failed_min_absolute: float = 0.0
    failed_min_rate: float = 0.8
    failed_min_risk: float = 0.0
    failed_min_anomaly: float = 0.0
    failed_min_persistence: int = 1
    failed_require_additional_signal: bool = False
    port_min_unique_ports: int = 10
    port_min_unique_ips: int = 10
    port_min_connections: int = 0
    port_require_failed_or_risk: bool = False
    port_require_unique_ports_when_low_connections: bool = False
    dns_min_rate: float = 1.0
    dns_min_risk: float = 0.0
    dns_min_anomaly: float = 0.0
    dns_min_persistence: int = 1
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS


def candidate_policies() -> list[CandidatePolicy]:
    return [
        CandidatePolicy("current_policy", "Current production-equivalent offline policy."),
        CandidatePolicy(
            "failed_abs_ge_5_connections_ge_10",
            "Require FAILED_CONNECTION_PATTERN to have at least 10 connections and about 5 failed attempts.",
            failed_min_connections=10,
            failed_min_absolute=5,
        ),
        CandidatePolicy(
            "failed_abs_ge_10_risk_ge_20",
            "Require FAILED_CONNECTION_PATTERN to have about 10 failed attempts and risk_score >= 20.",
            failed_min_connections=10,
            failed_min_absolute=10,
            failed_min_risk=20,
        ),
        CandidatePolicy(
            "failed_abs_ge_5_plus_independent_signal",
            "Require FAILED_CONNECTION_PATTERN failed evidence plus another independent signal group.",
            failed_min_connections=10,
            failed_min_absolute=5,
            failed_require_additional_signal=True,
        ),
        CandidatePolicy(
            "failed_persistent_3_abs_ge_5",
            "Require FAILED_CONNECTION_PATTERN evidence across at least 3 consecutive windows.",
            failed_min_connections=10,
            failed_min_absolute=5,
            failed_min_persistence=3,
        ),
        CandidatePolicy(
            "portscan_no_cdn_fanout",
            "Require port-scan evidence beyond many destination IPs alone.",
            port_min_connections=50,
            port_require_failed_or_risk=True,
            port_require_unique_ports_when_low_connections=True,
        ),
        CandidatePolicy(
            "dns_persistent_or_model_risk",
            "Require DNS anomaly to be persistent or backed by elevated model/risk evidence.",
            dns_min_risk=30,
            dns_min_anomaly=0.35,
            dns_min_persistence=2,
        ),
        CandidatePolicy(
            "combined_conservative",
            "Combine denominator-aware failed-connection, stricter port-scan, and DNS corroboration checks.",
            failed_min_connections=10,
            failed_min_absolute=5,
            failed_min_risk=20,
            failed_require_additional_signal=True,
            port_min_connections=50,
            port_require_failed_or_risk=True,
            port_require_unique_ports_when_low_connections=True,
            dns_min_risk=30,
            dns_min_anomaly=0.35,
            dns_min_persistence=2,
        ),
    ]


def passes_failed_candidate(
    row: dict[str, Any],
    policy: CandidatePolicy,
    persistence_count: int,
    repeated_count: int,
) -> bool:
    if policy.name == "current_policy":
        return True
    if row_float(row, "connections_30s") < policy.failed_min_connections:
        return False
    if estimated_failed_count(row) < policy.failed_min_absolute:
        return False
    if row_float(row, "failed_conn_rate_30s") < policy.failed_min_rate:
        return False
    if row_float(row, "risk_score") < policy.failed_min_risk:
        return False
    if row_float(row, "anomaly_score") < policy.failed_min_anomaly:
        return False
    if persistence_count < policy.failed_min_persistence:
        return False
    if policy.failed_require_additional_signal:
        signals = independent_signal_groups(row, persistence_count, repeated_count)
        signals.discard("direct_failed_connection_behavior")
        if not signals:
            return False
    return True


def passes_port_candidate(row: dict[str, Any], policy: CandidatePolicy) -> bool:
    if policy.name == "current_policy":
        return True
    unique_ports = row_float(row, "unique_dst_ports_30s")
    unique_ips = row_float(row, "unique_dst_ips_30s")
    connections = row_float(row, "connections_30s")
    failed = row_float(row, "failed_conn_rate_30s")
    risk = row_float(row, "risk_score")
    has_port_spread = unique_ports >= policy.port_min_unique_ports
    has_ip_fanout = unique_ips >= policy.port_min_unique_ips
    if policy.port_require_unique_ports_when_low_connections and connections < policy.port_min_connections:
        return has_port_spread and (failed >= 0.3 or risk >= 20)
    if not (has_port_spread or has_ip_fanout):
        return False
    if connections < policy.port_min_connections:
        return False
    if policy.port_require_failed_or_risk and not (failed >= 0.3 or risk >= 30):
        return False
    return True


def passes_dns_candidate(row: dict[str, Any], policy: CandidatePolicy, persistence_count: int) -> bool:
    if policy.name == "current_policy":
        return True
    if row_float(row, "dns_rate_30s") < policy.dns_min_rate:
        return False
    if persistence_count >= policy.dns_min_persistence:
        return True
    return row_float(row, "risk_score") >= policy.dns_min_risk and row_float(row, "anomaly_score") >= policy.dns_min_anomaly


def apply_candidate(
    current_rows: list[dict[str, Any]],
    policy: CandidatePolicy,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    persistence = persistence_counts(current_rows)
    repeated = source_class_occurrence_counts(current_rows)
    retained = []
    removed = []
    for row in current_rows:
        classification = str(row.get("classification"))
        persistence_count = persistence.get(int(row["row_index"]), 1)
        repeated_count = repeated[source_class_key(row)]
        keep = True
        if classification == "FAILED_CONNECTION_PATTERN":
            keep = passes_failed_candidate(row, policy, persistence_count, repeated_count)
        elif classification == "PORT_SCAN":
            keep = passes_port_candidate(row, policy)
        elif classification == "DNS_ANOMALY":
            keep = passes_dns_candidate(row, policy, persistence_count)
        item = dict(row)
        item["candidate_policy"] = policy.name
        item["candidate_action"] = "retained" if keep else "removed"
        item["persistence_sequence_length"] = persistence_count
        item["independent_signal_groups"] = ",".join(
            sorted(independent_signal_groups(row, persistence_count, repeated_count))
        )
        if keep:
            retained.append(item)
        else:
            removed.append(item)
    return retained, removed


def cooldown_alert_count(rows: list[dict[str, Any]], cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS) -> int:
    last_by_key: dict[tuple[str, str], datetime] = {}
    alerts = 0
    for row in sorted(rows, key=lambda item: parse_time(item) or datetime.min):
        key = source_class_key(row)
        current = parse_time(row)
        if current is None:
            alerts += 1
            continue
        previous = last_by_key.get(key)
        if previous is None or (current - previous).total_seconds() >= cooldown_seconds:
            alerts += 1
            last_by_key[key] = current
    return alerts


def percent(part: int | float, whole: int | float) -> float:
    if not whole:
        return 0.0
    return round(float(part) / float(whole) * 100.0, 4)


def candidate_metrics(
    normal_risk_count: int,
    current_count: int,
    policy: CandidatePolicy,
    retained: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = Counter(str(row.get("classification")) for row in retained)
    false_positive_rows = len(retained)
    fp_rate = percent(false_positive_rows, normal_risk_count)
    repeated_sequences = [seq for seq in group_sequences(retained) if len(seq) >= 2]
    alerts_after_cooldown = cooldown_alert_count(retained, policy.cooldown_seconds)
    normal_target_met = fp_rate <= 1.0 and alerts_after_cooldown <= 5
    return {
        "candidate_policy": policy.name,
        "description": policy.description,
        "total_alerts": false_positive_rows,
        "false_positive_rows": false_positive_rows,
        "false_positive_rate": fp_rate,
        "unique_alerted_sources": len({str(row.get("src_ip") or "n/a") for row in retained}),
        "repeated_alert_sequences": len(repeated_sequences),
        "alerts_after_cooldown": alerts_after_cooldown,
        "classification_counts": json.dumps(dict(counts), sort_keys=True),
        "percentage_reduction_vs_current": percent(current_count - false_positive_rows, current_count),
        "normal_target_met": normal_target_met,
        "production_ready": False,
        "production_ready_reason": "Not production-ready without labeled attack-retention evidence.",
    }


def quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 6)
    pos = (len(ordered) - 1) * q
    lower = math.floor(pos)
    upper = min(lower + 1, len(ordered) - 1)
    weight = pos - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 6)


def distribution(values: list[float]) -> dict[str, float | None]:
    return {
        "min": round(min(values), 6) if values else None,
        "p50": quantile(values, 0.50),
        "p75": quantile(values, 0.75),
        "p90": quantile(values, 0.90),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
        "max": round(max(values), 6) if values else None,
    }


def failed_connection_analysis(
    current_rows: list[dict[str, Any]],
    policy_results: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]],
    top: int,
) -> dict[str, Any]:
    failed_rows = [row for row in current_rows if row.get("classification") == "FAILED_CONNECTION_PATTERN"]
    by_source = Counter(str(row.get("src_ip") or "n/a") for row in failed_rows)
    sequences = group_sequences(failed_rows)
    durations = []
    for sequence in sequences:
        start = parse_time(sequence[0])
        end = parse_time(sequence[-1])
        if start and end:
            durations.append((end - start).total_seconds())
    removed_by_candidate = {}
    for name, (_retained, removed) in policy_results.items():
        removed_by_candidate[name] = sum(
            1 for row in removed if row.get("classification") == "FAILED_CONNECTION_PATTERN"
        )
    return {
        "count": len(failed_rows),
        "source_ip_distribution": dict(by_source.most_common(top)),
        "connections_30s": distribution([row_float(row, "connections_30s") for row in failed_rows]),
        "failed_conn_rate_30s": distribution([row_float(row, "failed_conn_rate_30s") for row in failed_rows]),
        "estimated_absolute_failed_connections_30s": distribution([estimated_failed_count(row) for row in failed_rows]),
        "risk_score": distribution([row_float(row, "risk_score") for row in failed_rows]),
        "anomaly_score": distribution([row_float(row, "anomaly_score") for row in failed_rows]),
        "sequence_count": len(sequences),
        "sequence_duration_seconds": distribution(durations),
        "removed_by_candidate": removed_by_candidate,
        "measurable_cause": infer_failed_connection_cause(failed_rows, sequences, by_source),
    }


def infer_failed_connection_cause(
    failed_rows: list[dict[str, Any]],
    sequences: list[list[dict[str, Any]]],
    by_source: Counter[str],
) -> list[str]:
    causes = []
    if failed_rows:
        small_denominator = sum(1 for row in failed_rows if row_float(row, "connections_30s") < 10)
        if percent(small_denominator, len(failed_rows)) >= 50:
            causes.append("small denominators dominate failed-rate evidence")
        retry_like = sum(
            1 for row in failed_rows
            if row_float(row, "connections_30s") < 10 and row_float(row, "failed_conn_rate_30s") >= 0.8
        )
        if percent(retry_like, len(failed_rows)) >= 50:
            causes.append("ordinary retry-shaped rows are measurable: high failed rate with few connections")
        if by_source:
            source, count = by_source.most_common(1)[0]
            if percent(count, len(failed_rows)) >= 70:
                causes.append(f"specific source/device dominates: {source}")
    if any(len(sequence) >= 3 for sequence in sequences):
        causes.append("repeated overlapping windows are present")
    if not causes:
        causes.append("no single dominant cause identified from available fields")
    return causes


def load_manifest(path: Path | None, attack_date: str | None = None) -> tuple[list[dict[str, Any]], list[str]]:
    gaps = []
    if path is None:
        if attack_date:
            gaps.append(
                f"--attack-date {attack_date} was supplied without a manifest; date-wide attack labeling was not assumed."
            )
        else:
            gaps.append("No attack ground-truth manifest supplied; attack recall is unavailable.")
        return [], gaps
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [f"Could not read attack manifest: {exc}"]
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        return [], ["Attack manifest has no sessions list; attack recall is unavailable."]
    valid = []
    for index, session in enumerate(sessions):
        if not isinstance(session, dict):
            gaps.append(f"Session {index} is not an object and was skipped.")
            continue
        if session.get("label") != "attack":
            gaps.append(f"Session {index} label is not attack and was skipped.")
            continue
        if not session.get("date") or not session.get("expected_classes"):
            gaps.append(f"Session {index} lacks date or expected_classes and was skipped.")
            continue
        valid.append(session)
    if not valid:
        gaps.append("No valid attack sessions supplied; attack recall is unavailable.")
    return valid, gaps


def row_in_session(row: dict[str, Any], session: dict[str, Any]) -> bool:
    source_ips = session.get("source_ips") or []
    if source_ips and str(row.get("src_ip") or "") not in set(map(str, source_ips)):
        return False
    current = parse_time(row)
    start_text = session.get("time_start")
    end_text = session.get("time_end")
    if current and start_text:
        try:
            if current < datetime.fromisoformat(str(start_text)):
                return False
        except ValueError:
            pass
    if current and end_text:
        try:
            if current > datetime.fromisoformat(str(end_text)):
                return False
        except ValueError:
            pass
    return True


def attack_validation_rows(
    sessions: list[dict[str, Any]],
    policies: list[CandidatePolicy],
    base_dir: Path,
) -> list[dict[str, Any]]:
    rows = []
    if not sessions:
        return [
            {
                "candidate_policy": policy.name,
                "session_date": "",
                "expected_classes": "",
                "true_positives": "",
                "missed_expected_attacks": "",
                "detection_rate_recall": "unavailable",
                "detection_delay_seconds": "unavailable",
                "detected_classifications": "",
                "notes": "No valid attack ground-truth manifest supplied.",
            }
            for policy in policies
        ]
    by_date: dict[str, list[dict[str, Any]]] = {}
    for session in sessions:
        date = str(session["date"])
        if date not in by_date:
            risk_rows, _headers = read_csv_rows(base_dir / "data" / "reports" / f"risk_{date}.csv")
            by_date[date] = current_policy_rows(risk_rows)
    for policy in policies:
        for session in sessions:
            date = str(session["date"])
            expected = [str(item) for item in session.get("expected_classes", [])]
            session_current = [row for row in by_date.get(date, []) if row_in_session(row, session)]
            retained, _removed = apply_candidate(session_current, policy)
            detected_classes = sorted({str(row.get("classification")) for row in retained})
            detected_expected = sorted(set(expected).intersection(detected_classes))
            missed = sorted(set(expected).difference(detected_classes))
            delay = "unavailable"
            if retained and session.get("time_start"):
                try:
                    start = datetime.fromisoformat(str(session["time_start"]))
                    first = min((parse_time(row) for row in retained if parse_time(row)), default=None)
                    if first:
                        delay = int((first - start).total_seconds())
                except ValueError:
                    pass
            rows.append(
                {
                    "candidate_policy": policy.name,
                    "session_date": date,
                    "expected_classes": ",".join(expected),
                    "true_positives": len(detected_expected),
                    "missed_expected_attacks": ",".join(missed),
                    "detection_rate_recall": percent(len(detected_expected), len(expected)),
                    "detection_delay_seconds": delay,
                    "detected_classifications": ",".join(detected_classes),
                    "notes": str(session.get("notes") or ""),
                }
            )
    return rows


def build_reproduction_rows(current_rows: list[dict[str, Any]], production_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    production_by_index = {int(row["row_index"]): row for row in production_rows}
    rows = []
    for row in current_rows:
        index = int(row["row_index"])
        prod = production_by_index.get(index, {})
        rows.append(
            {
                "row_index": index,
                "time": row.get("time"),
                "src_ip": row.get("src_ip"),
                "offline_classification": row.get("classification"),
                "production_classification": prod.get("classification", ""),
                "offline_confidence": row.get("confidence"),
                "production_confidence": prod.get("confidence", ""),
                "match": row.get("classification") == prod.get("classification"),
                "risk_score": row_float(row, "risk_score"),
                "anomaly_score": row_float(row, "anomaly_score"),
                "connections_30s": row_float(row, "connections_30s"),
                "failed_conn_rate_30s": row_float(row, "failed_conn_rate_30s"),
                "estimated_failed_connections_30s": estimated_failed_count(row),
                "reasons": row.get("reason_text", ""),
            }
        )
    return rows


def best_normal_candidate(candidate_rows: list[dict[str, Any]]) -> str:
    candidates = [row for row in candidate_rows if row["candidate_policy"] != "current_policy"]
    if not candidates:
        return "n/a"
    ordered = sorted(
        candidates,
        key=lambda row: (
            not bool(row["normal_target_met"]),
            float(row["false_positive_rate"]),
            int(row["alerts_after_cooldown"]),
            -float(row["percentage_reduction_vs_current"]),
        ),
    )
    return str(ordered[0]["candidate_policy"])


def summarize_calibration(
    normal_date: str,
    normal_risk_rows: list[dict[str, str]],
    normal_windows_headers: list[str],
    current_rows: list[dict[str, Any]],
    production_rows: list[dict[str, Any]],
    policies: list[CandidatePolicy],
    sessions: list[dict[str, Any]],
    manifest_gaps: list[str],
    top: int,
    base_dir: Path,
) -> dict[str, Any]:
    production_counts = Counter(str(row.get("classification")) for row in production_rows)
    current_counts = Counter(str(row.get("classification")) for row in current_rows)
    reproduction_rows = build_reproduction_rows(current_rows, production_rows)
    reproduction_matches = (
        len(current_rows) == len(production_rows)
        and all(row["match"] for row in reproduction_rows)
        and dict(current_counts) == dict(production_counts)
    )
    expected_snapshot_matches = True
    expected_mismatch = {}
    if normal_date == "2026-07-26":
        expected_total = sum(EXPECTED_2026_07_26_COUNTS.values())
        expected_snapshot_matches = len(current_rows) == expected_total and all(
            current_counts.get(key, 0) == value
            for key, value in EXPECTED_2026_07_26_COUNTS.items()
        )
        if not expected_snapshot_matches:
            expected_mismatch = {
                "expected_total": expected_total,
                "observed_total": len(current_rows),
                "expected_counts": EXPECTED_2026_07_26_COUNTS,
                "observed_counts": dict(current_counts),
            }

    policy_results = {}
    candidate_comparison = []
    retained_removed_rows = []
    breakdown_rows = []
    for policy in policies:
        retained, removed = apply_candidate(current_rows, policy)
        policy_results[policy.name] = (retained, removed)
        metrics = candidate_metrics(len(normal_risk_rows), len(current_rows), policy, retained)
        candidate_comparison.append(metrics)
        for row in retained + removed:
            retained_removed_rows.append(
                {
                    "candidate_policy": policy.name,
                    "candidate_action": row["candidate_action"],
                    "row_index": row["row_index"],
                    "time": row.get("time"),
                    "src_ip": row.get("src_ip"),
                    "classification": row.get("classification"),
                    "confidence": row.get("confidence"),
                    "risk_score": row_float(row, "risk_score"),
                    "anomaly_score": row_float(row, "anomaly_score"),
                    "connections_30s": row_float(row, "connections_30s"),
                    "failed_conn_rate_30s": row_float(row, "failed_conn_rate_30s"),
                    "estimated_failed_connections_30s": estimated_failed_count(row),
                    "unique_dst_ips_30s": row_float(row, "unique_dst_ips_30s"),
                    "unique_dst_ports_30s": row_float(row, "unique_dst_ports_30s"),
                    "dns_rate_30s": row_float(row, "dns_rate_30s"),
                    "persistence_sequence_length": row.get("persistence_sequence_length"),
                    "independent_signal_groups": row.get("independent_signal_groups"),
                    "reasons": row.get("reason_text", ""),
                }
            )
        retained_counts = Counter(str(row.get("classification")) for row in retained)
        for classification in CLASSIFICATIONS:
            breakdown_rows.append(
                {
                    "candidate_policy": policy.name,
                    "classification": classification,
                    "retained_count": retained_counts.get(classification, 0),
                    "removed_count": sum(
                        1 for row in removed if row.get("classification") == classification
                    ),
                }
            )

    failed_analysis = failed_connection_analysis(current_rows, policy_results, top)
    attack_rows = attack_validation_rows(sessions, policies, base_dir)
    unavailable_features = [
        field for field in (
            "failed_conn_count_30s",
            "nxdomain_rate_30s",
            "unique_query_count_30s",
            "unique_dns_queries_30s",
            "unique_dst_domains_30s",
            "dst_ip_concentration_30s",
        )
        if field not in set().union(*(row.keys() for row in normal_risk_rows)) if normal_risk_rows
    ]

    summary = {
        "normal_date": normal_date,
        "normal_risk_rows": len(normal_risk_rows),
        "normal_window_headers": normal_windows_headers,
        "current_suspicious_rows": len(current_rows),
        "production_suspicious_rows": len(production_rows),
        "offline_reproduction_matches_production": reproduction_matches,
        "expected_2026_07_26_snapshot_matches": expected_snapshot_matches,
        "expected_2026_07_26_snapshot_mismatch": expected_mismatch,
        "current_classification_counts": dict(current_counts),
        "production_classification_counts": dict(production_counts),
        "candidate_comparison": candidate_comparison,
        "best_normal_traffic_candidate_provisional": best_normal_candidate(candidate_comparison),
        "candidate_classification_breakdown": breakdown_rows,
        "failed_connection_analysis": failed_analysis,
        "attack_validation_available": bool(sessions),
        "attack_validation": attack_rows,
        "ground_truth_gaps": manifest_gaps,
        "unavailable_features": unavailable_features,
        "independence_definition": {
            "model_evidence": "anomaly_score >= 0.35; non-zero below that is context only",
            "risk_evidence": "risk_score >= 20, tracked separately because it may aggregate heuristic features",
            "direct_behavioral_rule_evidence": "one heuristic family such as failed-connection rate/count, DNS rate, port spread, or burst behavior; multiple comparisons inside one family count once",
            "persistence_evidence": "same source IP and classification in at least three nearby windows",
            "protocol_specific_evidence": "explicit protocol context such as SSH service/port or DNS-specific fields when available",
        },
    }
    return {
        "summary": summary,
        "reproduction_rows": reproduction_rows,
        "candidate_comparison": candidate_comparison,
        "candidate_breakdown": breakdown_rows,
        "retained_removed_rows": retained_removed_rows,
        "attack_rows": attack_rows,
    }


def output_paths(output_dir: Path) -> dict[str, Path]:
    return {
        "calibration_summary": output_dir / "calibration_summary.json",
        "calibration_report": output_dir / "calibration_report.md",
        "current_policy_reproduction": output_dir / "current_policy_reproduction.csv",
        "candidate_comparison": output_dir / "candidate_comparison.csv",
        "candidate_classification_breakdown": output_dir / "candidate_classification_breakdown.csv",
        "false_positive_examples": output_dir / "false_positive_examples.csv",
        "retained_and_removed_rows": output_dir / "retained_and_removed_rows.csv",
        "attack_validation": output_dir / "attack_validation.csv",
        "ground_truth_gaps": output_dir / "ground_truth_gaps.md",
    }


def markdown_report(summary: dict[str, Any]) -> str:
    failed = summary["failed_connection_analysis"]
    lines = [
        f"# Detection Rule Calibration Replay: {summary['normal_date']}",
        "",
        "## Observed Facts",
        "",
        f"- Normal risk rows: {summary['normal_risk_rows']}",
        f"- Current suspicious rows: {summary['current_suspicious_rows']}",
        f"- Offline reproduction matched current production classifier: {summary['offline_reproduction_matches_production']}",
        f"- Historical 2026-07-26 expected 167-row snapshot matched: {summary['expected_2026_07_26_snapshot_matches']}",
        f"- Current classification counts: `{json.dumps(summary['current_classification_counts'], sort_keys=True)}`",
        f"- Attack validation available: {summary['attack_validation_available']}",
        "",
        "## Candidate Simulations",
        "",
        "| Candidate | FP rows | FP rate | Alerts after cooldown | Reduction vs current | Normal target met |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in summary["candidate_comparison"]:
        lines.append(
            f"| `{row['candidate_policy']}` | {row['false_positive_rows']} | "
            f"{row['false_positive_rate']:.2f}% | {row['alerts_after_cooldown']} | "
            f"{row['percentage_reduction_vs_current']:.2f}% | {row['normal_target_met']} |"
        )
    lines.extend(
        [
            "",
            "## FAILED_CONNECTION_PATTERN Analysis",
            "",
            f"- Count: {failed['count']}",
            f"- Source IP distribution: `{json.dumps(failed['source_ip_distribution'], sort_keys=True)}`",
            f"- connections_30s distribution: `{json.dumps(failed['connections_30s'], sort_keys=True)}`",
            f"- failed_conn_rate_30s distribution: `{json.dumps(failed['failed_conn_rate_30s'], sort_keys=True)}`",
            f"- estimated absolute failed connections: `{json.dumps(failed['estimated_absolute_failed_connections_30s'], sort_keys=True)}`",
            f"- risk_score distribution: `{json.dumps(failed['risk_score'], sort_keys=True)}`",
            f"- anomaly_score distribution: `{json.dumps(failed['anomaly_score'], sort_keys=True)}`",
            f"- sequence duration seconds: `{json.dumps(failed['sequence_duration_seconds'], sort_keys=True)}`",
            f"- measurable causes: `{json.dumps(failed['measurable_cause'])}`",
            f"- removed by candidate: `{json.dumps(failed['removed_by_candidate'], sort_keys=True)}`",
            "",
            "## Trade-Offs",
            "",
            "- Candidates with strict absolute failed-count and risk requirements reduce normal false positives, but attack recall remains unavailable unless a scoped attack manifest is supplied.",
            "- Cooldown/collapse metrics reduce actionable alert volume without proving that row-level classifications should change.",
            "- Normal-only evidence can identify false-positive mechanisms; it cannot prove a production-safe threshold.",
            "",
            "## Unavailable Evidence",
            "",
        ]
    )
    if summary["unavailable_features"]:
        for field in summary["unavailable_features"]:
            lines.append(f"- `{field}`")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Recommended Next Experiment",
            "",
            "- Build a scoped attack ground-truth manifest from verified controlled test sessions before choosing a production candidate.",
            "- Replay this calibrator with `--attack-manifest` and compare normal false-positive reduction against attack-retention results.",
            "- Do not modify production rules from this normal-only replay alone.",
            "",
            "This report is an offline simulation only. It does not modify or claim to modify production rules.",
            "",
        ]
    )
    return "\n".join(lines)


def ground_truth_gaps_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Ground Truth Gaps",
        "",
        "## Observed Facts",
        "",
    ]
    for gap in summary["ground_truth_gaps"]:
        lines.append(f"- {gap}")
    lines.extend(
        [
            "",
            "## Inference",
            "",
            "- Historical project evidence may contain attacks, but date-wide attack labeling is not safe without a scoped manifest.",
            "",
            "## Recommended Investigation",
            "",
            "- Create a manifest with verified source IPs, time bounds, and expected classes for controlled attack sessions.",
            "- Re-run the calibrator with `--attack-manifest` before considering production rule changes.",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(output_dir: Path, data: dict[str, Any], current_rows: list[dict[str, Any]], top: int) -> dict[str, Path]:
    paths = output_paths(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = data["summary"]
    paths["calibration_summary"].write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["calibration_report"].write_text(markdown_report(summary), encoding="utf-8")
    paths["ground_truth_gaps"].write_text(ground_truth_gaps_markdown(summary), encoding="utf-8")
    write_csv(
        paths["current_policy_reproduction"],
        data["reproduction_rows"],
        [
            "row_index",
            "time",
            "src_ip",
            "offline_classification",
            "production_classification",
            "offline_confidence",
            "production_confidence",
            "match",
            "risk_score",
            "anomaly_score",
            "connections_30s",
            "failed_conn_rate_30s",
            "estimated_failed_connections_30s",
            "reasons",
        ],
    )
    write_csv(
        paths["candidate_comparison"],
        data["candidate_comparison"],
        [
            "candidate_policy",
            "description",
            "total_alerts",
            "false_positive_rows",
            "false_positive_rate",
            "unique_alerted_sources",
            "repeated_alert_sequences",
            "alerts_after_cooldown",
            "classification_counts",
            "percentage_reduction_vs_current",
            "normal_target_met",
            "production_ready",
            "production_ready_reason",
        ],
    )
    write_csv(
        paths["candidate_classification_breakdown"],
        data["candidate_breakdown"],
        ["candidate_policy", "classification", "retained_count", "removed_count"],
    )
    examples = sorted(
        current_rows,
        key=lambda row: (
            row.get("classification") != "FAILED_CONNECTION_PATTERN",
            -estimated_failed_count(row),
            -row_float(row, "risk_score"),
        ),
    )[:top]
    write_csv(
        paths["false_positive_examples"],
        [
            {
                "row_index": row["row_index"],
                "time": row.get("time"),
                "src_ip": row.get("src_ip"),
                "classification": row.get("classification"),
                "confidence": row.get("confidence"),
                "connections_30s": row_float(row, "connections_30s"),
                "failed_conn_rate_30s": row_float(row, "failed_conn_rate_30s"),
                "estimated_failed_connections_30s": estimated_failed_count(row),
                "risk_score": row_float(row, "risk_score"),
                "anomaly_score": row_float(row, "anomaly_score"),
                "unique_dst_ips_30s": row_float(row, "unique_dst_ips_30s"),
                "unique_dst_ports_30s": row_float(row, "unique_dst_ports_30s"),
                "dns_rate_30s": row_float(row, "dns_rate_30s"),
                "reasons": row.get("reason_text", ""),
            }
            for row in examples
        ],
        [
            "row_index",
            "time",
            "src_ip",
            "classification",
            "confidence",
            "connections_30s",
            "failed_conn_rate_30s",
            "estimated_failed_connections_30s",
            "risk_score",
            "anomaly_score",
            "unique_dst_ips_30s",
            "unique_dst_ports_30s",
            "dns_rate_30s",
            "reasons",
        ],
    )
    write_csv(
        paths["retained_and_removed_rows"],
        data["retained_removed_rows"],
        [
            "candidate_policy",
            "candidate_action",
            "row_index",
            "time",
            "src_ip",
            "classification",
            "confidence",
            "risk_score",
            "anomaly_score",
            "connections_30s",
            "failed_conn_rate_30s",
            "estimated_failed_connections_30s",
            "unique_dst_ips_30s",
            "unique_dst_ports_30s",
            "dns_rate_30s",
            "persistence_sequence_length",
            "independent_signal_groups",
            "reasons",
        ],
    )
    write_csv(
        paths["attack_validation"],
        data["attack_rows"],
        [
            "candidate_policy",
            "session_date",
            "expected_classes",
            "true_positives",
            "missed_expected_attacks",
            "detection_rate_recall",
            "detection_delay_seconds",
            "detected_classifications",
            "notes",
        ],
    )
    return paths


def run_calibration(
    normal_date: str,
    attack_date: str | None = None,
    attack_manifest: Path | None = None,
    output_dir: Path | None = None,
    top: int = 10,
    base_dir: Path = BASE_DIR,
) -> tuple[dict[str, Any], dict[str, Path]]:
    normal_risk_rows, _risk_headers = read_csv_rows(base_dir / "data" / "reports" / f"risk_{normal_date}.csv")
    _window_rows, window_headers = read_csv_rows(base_dir / "data" / "windows" / f"windows_{normal_date}.csv")
    current_rows = current_policy_rows(normal_risk_rows)
    production_rows = production_policy_rows(normal_risk_rows)
    sessions, manifest_gaps = load_manifest(attack_manifest, attack_date)
    policies = candidate_policies()
    data = summarize_calibration(
        normal_date,
        normal_risk_rows,
        window_headers,
        current_rows,
        production_rows,
        policies,
        sessions,
        manifest_gaps,
        top,
        base_dir,
    )
    target_dir = output_dir or base_dir / "data" / "audit" / f"detection_calibration_{normal_date}"
    paths = write_outputs(target_dir, data, current_rows, top)
    return data["summary"], paths


def print_console(summary: dict[str, Any], output_dir: Path) -> None:
    print(f"[CALIBRATION] normal_date={summary['normal_date']}")
    print(f"[CALIBRATION] normal_risk_rows={summary['normal_risk_rows']}")
    print(f"[CALIBRATION] current_suspicious_rows={summary['current_suspicious_rows']}")
    print(f"[CALIBRATION] reproduction_matches_production={summary['offline_reproduction_matches_production']}")
    print(f"[CALIBRATION] expected_167_snapshot_matches={summary['expected_2026_07_26_snapshot_matches']}")
    print(f"[CALIBRATION] best_normal_candidate_provisional={summary['best_normal_traffic_candidate_provisional']}")
    print(f"[CALIBRATION] attack_recall={ 'available' if summary['attack_validation_available'] else 'unavailable' }")
    print(f"[CALIBRATION] output_dir={output_dir}")
    if not summary["offline_reproduction_matches_production"]:
        print("[WARN] OFFLINE REPRODUCTION DOES NOT MATCH PRODUCTION CLASSIFIER")
    if not summary["expected_2026_07_26_snapshot_matches"]:
        print("[WARN] CURRENT 2026-07-26 FILE DOES NOT MATCH THE EARLIER 167-ROW SNAPSHOT")
    print("[RESULT] DETECTION RULE CALIBRATION COMPLETE")


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir or BASE_DIR / "data" / "audit" / f"detection_calibration_{args.normal_date}"
    summary, _paths = run_calibration(
        normal_date=args.normal_date,
        attack_date=args.attack_date,
        attack_manifest=args.attack_manifest,
        output_dir=output_dir,
        top=args.top,
    )
    print_console(summary, output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
