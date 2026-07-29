#!/usr/bin/env python3
"""
Read-only attack classification layer for NetGuard-AI risk reports.

This script classifies suspicious risk-report windows into preliminary,
explainable attack/suspicious behavior types. It does not modify data, models,
services, firewall rules, or system state. Evidence export is optional and only
occurs when --export-md or --export-json is explicitly provided.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "data" / "reports"
BASELINE_STATS = BASE_DIR / "models" / "anomaly" / "baseline_stats.json"
REPORT_EXPORTS_DIR = BASE_DIR / "reports" / "audit_exports"

RISK_FILE_RE = re.compile(r"^risk_(\d{4}-\d{2}-\d{2})\.csv$")
DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
)
ATTACK_TYPES = (
    "PORT_SCAN",
    "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
    "FAILED_CONNECTION_PATTERN",
    "DNS_ANOMALY",
    "DOS_LIKE_BURST",
    "BOT_LIKE_BEHAVIOR",
    "UNKNOWN_SUSPICIOUS",
    "LOW_SIGNAL_REVIEW",
)
CLASSIFICATION_NOTE = (
    "These labels are preliminary, explainable classifications for analyst "
    "review and do not represent guaranteed ground truth."
)
RETRAINING_NOTE = (
    "Classification output must not be used to approve baseline retraining "
    "automatically."
)
CALIBRATION_NOTE = (
    "SSH brute force classification requires explicit SSH evidence such as "
    "port 22 or service=ssh."
)
SAFETY_NOTE = (
    "Read-only by default. Evidence export only occurs when explicitly "
    "requested and only to approved export paths."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only attack classification over NetGuard-AI risk reports."
    )
    parser.add_argument(
        "--date",
        dest="audit_date",
        type=parse_date_arg,
        help="Classify one specific date, formatted as YYYY-MM-DD.",
    )
    parser.add_argument(
        "--from",
        dest="from_date",
        type=parse_date_arg,
        help="Start date for an inclusive classification range.",
    )
    parser.add_argument(
        "--to",
        dest="to_date",
        type=parse_date_arg,
        help="End date for an inclusive classification range.",
    )
    parser.add_argument(
        "--top",
        type=top_count_arg,
        default=10,
        help="Top classified events to show, from 1 to 50. Default: 10.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress detailed classified events.",
    )
    parser.add_argument(
        "--export-md",
        help="Export classification evidence to Markdown under /tmp/ or reports/audit_exports/.",
    )
    parser.add_argument(
        "--export-json",
        help="Export classification evidence to JSON under /tmp/ or reports/audit_exports/.",
    )
    parser.add_argument(
        "--trusted-admin-ip",
        action="append",
        default=[],
        help="Trusted/admin management source IPv4 address. Can be repeated.",
    )
    args = parser.parse_args()

    if args.audit_date and (args.from_date or args.to_date):
        parser.error("--date cannot be combined with --from or --to")
    if bool(args.from_date) != bool(args.to_date):
        parser.error("--from and --to must be used together")

    return args


def parse_date_arg(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid date '{value}', expected YYYY-MM-DD"
        ) from exc
    return value


def top_count_arg(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--top must be an integer from 1 to 50") from exc

    if count < 1 or count > 50:
        raise argparse.ArgumentTypeError("--top must be an integer from 1 to 50")
    return count


def parse_datetime(value: object) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("empty datetime")

    for fmt in DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass

    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid datetime: {value}") from exc


def load_training_datetime() -> datetime:
    with BASELINE_STATS.open("r", encoding="utf-8") as fh:
        stats = json.load(fh)

    trained_at = stats.get("trained_at")
    if not trained_at:
        raise ValueError(f"Missing trained_at in {BASELINE_STATS}")
    return parse_datetime(trained_at)


def date_range(start: str, end: str) -> list[str]:
    start_date = datetime.strptime(start, "%Y-%m-%d").date()
    end_date = datetime.strptime(end, "%Y-%m-%d").date()
    if start_date > end_date:
        raise ValueError("--from date must be on or before --to date")

    days = []
    current = start_date
    while current <= end_date:
        days.append(current.isoformat())
        current = current.fromordinal(current.toordinal() + 1)
    return days


def existing_report_dates() -> set[str]:
    dates = set()
    for path in REPORTS_DIR.glob("risk_*.csv"):
        match = RISK_FILE_RE.match(path.name)
        if match:
            dates.add(match.group(1))
    return dates


def default_dates(training_dt: datetime) -> list[str]:
    dates = []
    for path in REPORTS_DIR.glob("risk_*.csv"):
        match = RISK_FILE_RE.match(path.name)
        if not match:
            continue

        day = datetime.strptime(match.group(1), "%Y-%m-%d").date()
        if day > training_dt.date():
            dates.append(match.group(1))
    return sorted(set(dates))


def selected_dates(args: argparse.Namespace, training_dt: datetime) -> list[str]:
    if args.audit_date:
        dates = [args.audit_date]
    elif args.from_date and args.to_date:
        dates = date_range(args.from_date, args.to_date)
    else:
        return default_dates(training_dt)

    available_dates = existing_report_dates()
    return [day for day in dates if day in available_dates]


def validate_export_path(value: str) -> Path:
    path = Path(value).expanduser()
    resolved = path.resolve()
    tmp_root = Path("/tmp").resolve()
    reports_root = REPORT_EXPORTS_DIR.resolve()

    try:
        resolved.relative_to(tmp_root)
        return resolved
    except ValueError:
        pass

    try:
        resolved.relative_to(reports_root)
        return resolved
    except ValueError as exc:
        raise ValueError(
            "export paths must be under /tmp/ or reports/audit_exports/"
        ) from exc


def validate_export_paths(args: argparse.Namespace) -> dict[str, Path]:
    paths = {}
    if args.export_md:
        paths["md"] = validate_export_path(args.export_md)
    if args.export_json:
        paths["json"] = validate_export_path(args.export_json)
    return paths


def validate_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"invalid trusted admin IP '{value}', expected IPv4 address") from exc


def trusted_admin_ips(args: argparse.Namespace) -> set[str]:
    values = []
    env_value = os.environ.get("NETGUARD_TRUSTED_ADMIN_IPS", "")
    if env_value.strip():
        values.extend(part.strip() for part in env_value.split(",") if part.strip())
    values.extend(args.trusted_admin_ip or [])
    return {validate_ipv4(value) for value in values}


def row_value(row: dict[str, str], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def row_float(row: dict[str, str], *names: str) -> float | None:
    value = row_value(row, *names)
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def row_time(row: dict[str, str]) -> tuple[str, datetime | None]:
    value = row_value(row, "timestamp", "window_start", "datetime")
    if value:
        try:
            dt = parse_datetime(value)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt
        except ValueError:
            return value, None

    ts_value = row_float(row, "ts")
    if ts_value is not None:
        try:
            dt = datetime.fromtimestamp(ts_value)
            return dt.strftime("%Y-%m-%d %H:%M:%S"), dt
        except (OverflowError, OSError, ValueError):
            pass

    ts = row_value(row, "ts")
    return ts or "n/a", None


def bool_flag(row: dict[str, str], name: str) -> bool:
    value = row_value(row, name).lower()
    return value in {"1", "true", "yes", "y"}


def is_suspicious_row(row: dict[str, str]) -> bool:
    risk = row_float(row, "risk_score") or 0.0
    anomaly = row_float(row, "anomaly_score") or 0.0
    failed = row_float(row, "failed_conn_rate_30s") or 0.0
    connections = row_float(row, "connections_30s") or 0.0
    dns = row_float(row, "dns_rate_30s") or 0.0
    return (
        risk >= 20.0
        or anomaly >= 0.35
        or failed >= 0.8
        or connections >= 80.0
        or dns >= 1.0
    )


def confidence(base: float, reasons: list[str], cap: float = 0.95) -> float:
    return round(min(cap, base + min(len(reasons), 5) * 0.04), 2)


def classify_row(
    row: dict[str, str],
    suspicious_rows_by_src: Counter[str],
    trusted_ips: set[str],
) -> dict[str, object]:
    risk = row_float(row, "risk_score") or 0.0
    anomaly = row_float(row, "anomaly_score") or 0.0
    connections = row_float(row, "connections_30s") or 0.0
    failed = row_float(row, "failed_conn_rate_30s") or 0.0
    dns = row_float(row, "dns_rate_30s") or 0.0
    unique_ports = row_float(row, "unique_dst_ports_30s") or 0.0
    unique_ports_1m = row_float(row, "unique_dst_ports_1m") or 0.0
    unique_ips = row_float(row, "unique_dst_ips_30s") or 0.0
    bytes_rate = row_float(row, "bytes_per_sec_30s", "bytes_per_sec") or 0.0
    burst = row_float(row, "burst_score_30s", "burst_score") or 0.0
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
    if unique_ports >= 20:
        reasons.append(f"unique_dst_ports_30s={unique_ports:.0f} >= 20")
    if unique_ports_1m >= 20:
        reasons.append(f"unique_dst_ports_1m={unique_ports_1m:.0f} >= 20")
    if connections >= 80 and failed >= 0.3:
        reasons.append(
            f"connections_30s={connections:.0f} with failed_conn_rate_30s={failed:.2f}"
        )
    if risk >= 30 and connections >= 50:
        reasons.append(f"risk_score={risk:.2f} with elevated connections")
    scan_evidence = bool_flag(row, "flag_port_scan") and (unique_ports >= 20 or unique_ports_1m >= 20)
    if scan_evidence:
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
    failed_pattern = failed >= 0.8 and (connections >= 10 or repeated >= 5 or bool_flag(row, "flag_brute_force"))
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
        attack_type, score, reasons = sorted(
            candidates, key=lambda item: (item[1], len(item[2])), reverse=True
        )[0]
    elif risk >= 30 or anomaly >= 0.35:
        attack_type = "UNKNOWN_SUSPICIOUS"
        reasons = []
        if risk >= 30:
            reasons.append(f"risk_score={risk:.2f} >= 30")
        if anomaly >= 0.35:
            reasons.append(f"anomaly_score={anomaly:.4f} >= 0.35")
        score = confidence(0.42, reasons, 0.62)
    else:
        attack_type = "LOW_SIGNAL_REVIEW"
        reasons = ["suspicious threshold met, but supporting indicators are weak"]
        if 20 <= risk < 30:
            reasons.append(f"risk_score={risk:.2f} is in review range")
        score = confidence(0.25, reasons, 0.49)

    if is_trusted_admin and "src_ip is marked as trusted/admin management source" not in reasons:
        reasons = list(reasons) + ["src_ip is marked as trusted/admin management source"]
        if attack_type in {"UNKNOWN_SUSPICIOUS", "LOW_SIGNAL_REVIEW"}:
            score = max(0.25, round(score - 0.05, 2))

    time_value, _ = row_time(row)
    return {
        "time": time_value,
        "src_ip": src_ip or "n/a",
        "attack_type": attack_type,
        "confidence": score,
        "risk_score": round(risk, 4),
        "anomaly_score": round(anomaly, 4),
        "connections_30s": round(connections, 4),
        "failed_conn_rate_30s": round(failed, 4),
        "dns_rate_30s": round(dns, 4),
        "reasons": reasons,
        "proto": proto,
        "service": service,
        "dst_port": dst_port,
    }


def event_sort_key(event: dict[str, object]) -> tuple[float, float, float, float]:
    return (
        float(event["confidence"]),
        float(event["risk_score"]),
        float(event["anomaly_score"]),
        float(event["connections_30s"]),
    )


def event_brief(event: dict[str, object]) -> str:
    return (
        f"{event['attack_type']} confidence={float(event['confidence']):.2f} "
        f"src_ip={event['src_ip']} time={event['time']} "
        f"risk_score={float(event['risk_score']):.2f}"
    )


def audit_day(day: str, trusted_ips: set[str]) -> dict[str, object]:
    risk_file = REPORTS_DIR / f"risk_{day}.csv"
    rows = []
    suspicious_rows = []

    with risk_file.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(row)
            if is_suspicious_row(row):
                suspicious_rows.append(row)

    suspicious_rows_by_src = Counter(row_value(row, "src_ip") for row in suspicious_rows)
    suspicious_rows_by_src.pop("", None)
    events = [
        classify_row(row, suspicious_rows_by_src, trusted_ips)
        for row in suspicious_rows
    ]
    events.sort(key=event_sort_key, reverse=True)

    attack_counts = Counter(str(event["attack_type"]) for event in events)
    src_counts = Counter(str(event["src_ip"]) for event in events if event["src_ip"] != "n/a")

    highest_confidence = events[0] if events else None
    highest_risk = max(events, key=lambda event: float(event["risk_score"])) if events else None

    return {
        "date": day,
        "risk_rows": len(rows),
        "suspicious_rows": len(suspicious_rows),
        "classified_rows": len(events),
        "attack_type_counts": {attack_type: attack_counts.get(attack_type, 0) for attack_type in ATTACK_TYPES},
        "top_src_ip_counts": dict(src_counts.most_common(5)),
        "highest_confidence_event": highest_confidence,
        "highest_risk_event": highest_risk,
        "classified_events": events,
    }


def overall_counts(summaries: list[dict[str, object]]) -> dict[str, int]:
    counts = {attack_type: 0 for attack_type in ATTACK_TYPES}
    for summary in summaries:
        for attack_type, count in summary["attack_type_counts"].items():
            counts[attack_type] += int(count)
    return counts


def all_events(summaries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = []
    for summary in summaries:
        for event in summary["classified_events"]:
            item = dict(event)
            item["date"] = summary["date"]
            events.append(item)
    return sorted(events, key=event_sort_key, reverse=True)


def top_display_events(events: list[dict[str, object]], top_count: int) -> list[dict[str, object]]:
    non_low = [event for event in events if event["attack_type"] != "LOW_SIGNAL_REVIEW"]
    if len(non_low) >= top_count:
        return non_low[:top_count]
    if non_low:
        low = [event for event in events if event["attack_type"] == "LOW_SIGNAL_REVIEW"]
        return (non_low + low)[:top_count]
    return events[:top_count]


def high_confidence_counts(events: list[dict[str, object]]) -> dict[str, int]:
    counts = {attack_type: 0 for attack_type in ATTACK_TYPES}
    non_low_present = any(event["attack_type"] != "LOW_SIGNAL_REVIEW" for event in events)
    for event in events:
        if float(event["confidence"]) < 0.65:
            continue
        attack_type = str(event["attack_type"])
        if attack_type == "LOW_SIGNAL_REVIEW" and non_low_present:
            continue
        counts[attack_type] += 1
    return counts


def likely_actionable_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        event
        for event in events
        if float(event["confidence"]) >= 0.65 and event["attack_type"] != "LOW_SIGNAL_REVIEW"
    ]


def print_day_summary(summary: dict[str, object]) -> None:
    print(f"Date: {summary['date']}")
    print(f"  risk_rows: {summary['risk_rows']}")
    print(f"  suspicious_rows: {summary['suspicious_rows']}")
    print(f"  classified_rows: {summary['classified_rows']}")
    print("  top_attack_types:")
    top_attacks = [
        (attack_type, count)
        for attack_type, count in Counter(summary["attack_type_counts"]).most_common()
        if count > 0
    ][:5]
    if top_attacks:
        for attack_type, count in top_attacks:
            print(f"    - {attack_type}: {count}")
    else:
        print("    - none")

    print("  top_source_ips:")
    if summary["top_src_ip_counts"]:
        for src_ip, count in summary["top_src_ip_counts"].items():
            print(f"    - {src_ip}: {count}")
    else:
        print("    - none")

    if summary["highest_confidence_event"]:
        print(f"  highest_confidence_event: {event_brief(summary['highest_confidence_event'])}")
    else:
        print("  highest_confidence_event: none")

    if summary["highest_risk_event"]:
        print(f"  highest_risk_event: {event_brief(summary['highest_risk_event'])}")
    else:
        print("  highest_risk_event: none")
    print()


def print_event(event: dict[str, object]) -> None:
    reasons = "; ".join(str(reason) for reason in event["reasons"]) or "n/a"
    print(
        "  - "
        f"time={event['time']} src_ip={event['src_ip']} "
        f"attack_type={event['attack_type']} confidence={float(event['confidence']):.2f} "
        f"risk_score={float(event['risk_score']):.2f} "
        f"anomaly_score={float(event['anomaly_score']):.4f} "
        f"connections_30s={float(event['connections_30s']):.0f} "
        f"failed_conn_rate_30s={float(event['failed_conn_rate_30s']):.4f} "
        f"dns_rate_30s={float(event['dns_rate_30s']):.4f} "
        f"reasons={reasons}"
    )


def print_overall_summary(
    counts: dict[str, int], high_counts: dict[str, int], actionable_count: int
) -> None:
    print("Attack Classification Summary:")
    for attack_type in ATTACK_TYPES:
        print(f"  {attack_type}: {counts[attack_type]}")
    print("High Confidence Summary:")
    for attack_type in ATTACK_TYPES:
        print(f"  {attack_type}: {high_counts[attack_type]}")
    print("Likely Actionable Events:")
    print(f"  {actionable_count}")
    print("Classification Calibration:")
    print(f"  {CALIBRATION_NOTE}")
    print("Classification Note:")
    print(f"  {CLASSIFICATION_NOTE}")
    print("Retraining Note:")
    print(f"  {RETRAINING_NOTE}")


def export_day(summary: dict[str, object], summary_only: bool) -> dict[str, object]:
    day = {
        "date": summary["date"],
        "metrics": {
            "risk_rows": summary["risk_rows"],
            "suspicious_rows": summary["suspicious_rows"],
            "classified_rows": summary["classified_rows"],
            "highest_confidence_event": summary["highest_confidence_event"],
            "highest_risk_event": summary["highest_risk_event"],
        },
        "attack_type_counts": summary["attack_type_counts"],
        "top_src_ip_counts": summary["top_src_ip_counts"],
    }
    if not summary_only:
        day["classified_events"] = summary["classified_events"]
    return day


def export_payload(
    training_dt: datetime,
    dates: list[str],
    summaries: list[dict[str, object]],
    summary_only: bool,
    trusted_ips: set[str],
) -> dict[str, object]:
    events = all_events(summaries)
    return {
        "trained_at": training_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "selected_dates": dates,
        "classification_note": CLASSIFICATION_NOTE,
        "calibration_note": CALIBRATION_NOTE,
        "trusted_admin_ips": sorted(trusted_ips),
        "days": [export_day(summary, summary_only) for summary in summaries],
        "overall_attack_type_counts": overall_counts(summaries),
        "high_confidence_attack_type_counts": high_confidence_counts(events),
        "likely_actionable_events": likely_actionable_events(events),
        "retraining_note": RETRAINING_NOTE,
        "safety_note": SAFETY_NOTE,
    }


def markdown_event(event: dict[str, object]) -> str:
    reasons = "; ".join(str(reason) for reason in event["reasons"]) or "n/a"
    return (
        f"- time={event['time']} src_ip={event['src_ip']} "
        f"attack_type={event['attack_type']} confidence={float(event['confidence']):.2f} "
        f"risk_score={float(event['risk_score']):.2f} reasons={reasons}"
    )


def markdown_export(payload: dict[str, object], summary_only: bool) -> str:
    lines = [
        "# Attack Classification",
        "",
        f"trained_at: {payload['trained_at']}",
        f"selected_dates: {', '.join(payload['selected_dates'])}",
        "",
        f"Classification Note: {payload['classification_note']}",
        f"Classification Calibration: {payload['calibration_note']}",
        f"trusted_admin_ips: {', '.join(payload['trusted_admin_ips']) if payload['trusted_admin_ips'] else 'none'}",
        "",
    ]

    for day in payload["days"]:
        metrics = day["metrics"]
        lines.extend(
            [
                f"## Date: {day['date']}",
                "",
                f"- risk_rows: {metrics['risk_rows']}",
                f"- suspicious_rows: {metrics['suspicious_rows']}",
                f"- classified_rows: {metrics['classified_rows']}",
                "",
                "### Attack Type Counts",
            ]
        )
        for attack_type in ATTACK_TYPES:
            lines.append(f"- {attack_type}: {day['attack_type_counts'][attack_type]}")
        lines.append("")
        lines.append("### Top Source IPs")
        if day["top_src_ip_counts"]:
            for src_ip, count in day["top_src_ip_counts"].items():
                lines.append(f"- {src_ip}: {count}")
        else:
            lines.append("- none")

        if not summary_only:
            lines.extend(["", "### Classified Events"])
            events = day.get("classified_events", [])
            if events:
                lines.extend(markdown_event(event) for event in events)
            else:
                lines.append("- none")
        lines.append("")

    lines.append("## Classification Summary")
    for attack_type in ATTACK_TYPES:
        lines.append(f"- {attack_type}: {payload['overall_attack_type_counts'][attack_type]}")

    lines.extend(["", "## High Confidence Summary"])
    for attack_type in ATTACK_TYPES:
        lines.append(f"- {attack_type}: {payload['high_confidence_attack_type_counts'][attack_type]}")

    lines.extend(["", "## Likely Actionable Events", "", str(len(payload['likely_actionable_events']))])

    lines.extend(
        [
            "",
            "## Retraining Note",
            "",
            str(payload["retraining_note"]),
            "",
            "## Safety Note",
            "",
            str(payload["safety_note"]),
            "",
        ]
    )
    return "\n".join(lines)


def write_exports(
    paths: dict[str, Path], payload: dict[str, object], summary_only: bool
) -> None:
    if not paths:
        return

    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)

    if "md" in paths:
        paths["md"].write_text(markdown_export(payload, summary_only), encoding="utf-8")
        print(f"Exported Markdown: {paths['md']}")
    if "json" in paths:
        paths["json"].write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Exported JSON: {paths['json']}")


def main() -> int:
    args = parse_args()
    training_dt = load_training_datetime()

    try:
        export_paths = validate_export_paths(args)
        trusted_ips = trusted_admin_ips(args)
        dates = selected_dates(args, training_dt)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if not dates:
        print("[ERROR] No risk reports found for selected dates.", file=sys.stderr)
        return 1

    summaries = [audit_day(day, trusted_ips) for day in dates]
    events = all_events(summaries)
    top_events = top_display_events(events, args.top)
    counts = overall_counts(summaries)
    high_counts = high_confidence_counts(events)
    actionable_events = likely_actionable_events(events)

    print("Attack Classification")
    print(f"trained_at: {training_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"dates: {', '.join(dates)}")
    print(f"trusted_admin_ips: {', '.join(sorted(trusted_ips)) if trusted_ips else 'none'}")
    print(f"Classification Note: {CLASSIFICATION_NOTE}")
    print(f"Classification Calibration: {CALIBRATION_NOTE}")
    print()

    for summary in summaries:
        print_day_summary(summary)

    if not args.summary_only:
        print("Top events prioritize higher-confidence non-low-signal classifications.")
        print(f"Top Classified Events: {len(top_events)}")
        if top_events:
            for event in top_events:
                print_event(event)
        else:
            print("  - none")
        print()

    print_overall_summary(counts, high_counts, len(actionable_events))

    payload = export_payload(training_dt, dates, summaries, args.summary_only, trusted_ips)
    write_exports(export_paths, payload, args.summary_only)
    print()
    print("[RESULT] ATTACK CLASSIFICATION COMPLETE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] attack classification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
