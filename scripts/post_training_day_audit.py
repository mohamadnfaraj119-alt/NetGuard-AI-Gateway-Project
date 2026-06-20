#!/usr/bin/env python3
"""
Read-only post-training day audit.

Audits risk reports collected after the model training timestamp and suggests a
preliminary data hygiene label. This script does not modify data, models, or
system state.
"""

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "data" / "reports"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
BASELINE_STATS = BASE_DIR / "models" / "anomaly" / "baseline_stats.json"

RISK_FILE_RE = re.compile(r"^risk_(\d{4}-\d{2}-\d{2})\.csv$")
DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
)
TOP_WINDOW_VALUE_FIELDS = (
    "src_ip",
    "risk_score",
    "anomaly_score",
    "connections_30s",
    "failed_conn_rate_30s",
    "dns_rate_30s",
)
TOP_WINDOW_SORT_FIELDS = ("risk_score", "anomaly_score", "connections_30s")
SUSPICIOUS_IP_THRESHOLDS = (
    ("risk_score", 20.0),
    ("anomaly_score", 0.35),
    ("failed_conn_rate_30s", 0.8),
    ("connections_30s", 80.0),
    ("dns_rate_30s", 1.0),
)
SUSPICIOUS_IP_MAX_FIELDS = (
    ("risk_score", "max_risk_score"),
    ("anomaly_score", "max_anomaly_score"),
    ("connections_30s", "max_connections_30s"),
    ("failed_conn_rate_30s", "max_failed_conn_rate_30s"),
    ("dns_rate_30s", "max_dns_rate_30s"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only audit of post-training day risk reports."
    )
    parser.add_argument(
        "dates",
        nargs="*",
        help="Optional dates to audit, formatted as YYYY-MM-DD.",
    )
    return parser.parse_args()


def load_training_datetime() -> datetime:
    with BASELINE_STATS.open("r", encoding="utf-8") as fh:
        stats = json.load(fh)

    trained_at = stats.get("trained_at")
    if not trained_at:
        raise ValueError(f"Missing trained_at in {BASELINE_STATS}")

    return parse_datetime(trained_at)


def parse_datetime(value: str) -> datetime:
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


def parse_date_arg(value: str) -> str:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid date '{value}', expected YYYY-MM-DD"
        ) from exc
    return value


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


def count_csv_rows(path: Path) -> int:
    if not path.exists():
        return 0

    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        next(reader, None)
        return sum(1 for _ in reader)


def parse_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def row_datetime(row: dict[str, str]) -> datetime | None:
    value = row.get("datetime")
    if value:
        try:
            return parse_datetime(value)
        except ValueError:
            pass

    ts_value = parse_float(row.get("ts", ""))
    if ts_value is None:
        return None

    try:
        return datetime.fromtimestamp(ts_value)
    except (OverflowError, OSError, ValueError):
        return None


def ge_count(row: dict[str, str], column: str, threshold: float) -> int:
    value = parse_float(row.get(column, ""))
    return int(value is not None and value >= threshold)


def top_window_sort_key(row: dict[str, str]) -> tuple[float, float, float] | None:
    values = []
    has_sort_value = False

    for field in TOP_WINDOW_SORT_FIELDS:
        value = parse_float(row.get(field, ""))
        if value is None:
            values.append(float("-inf"))
            continue

        values.append(value)
        has_sort_value = True

    if not has_sort_value:
        return None

    return tuple(values)


def top_window_time(row: dict[str, str]) -> str | None:
    for field in ("timestamp", "window_start"):
        value = row.get(field, "").strip()
        if value:
            return value

    ts = row.get("ts", "").strip()
    ts_value = parse_float(ts)
    if ts_value is not None:
        try:
            return datetime.fromtimestamp(ts_value).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            pass

    return ts or None


def compact_top_window(row: dict[str, str]) -> dict[str, str]:
    compact = {}

    time_value = top_window_time(row)
    if time_value:
        compact["time"] = time_value

    for field in TOP_WINDOW_VALUE_FIELDS:
        value = row.get(field, "").strip()
        if value:
            compact[field] = value

    return compact


def is_suspicious_ip_row(row: dict[str, str]) -> bool:
    for field, threshold in SUSPICIOUS_IP_THRESHOLDS:
        value = parse_float(row.get(field, ""))
        if value is not None and value >= threshold:
            return True
    return False


def update_suspicious_ip_group(
    groups: dict[str, dict[str, object]], row: dict[str, str], dt: datetime | None
) -> None:
    src_ip = row.get("src_ip", "").strip()
    if not src_ip or not is_suspicious_ip_row(row):
        return

    group = groups.setdefault(
        src_ip,
        {
            "src_ip": src_ip,
            "suspicious_rows": 0,
            "max_risk_score": None,
            "max_anomaly_score": None,
            "max_connections_30s": None,
            "max_failed_conn_rate_30s": None,
            "max_dns_rate_30s": None,
            "first_time": None,
            "last_time": None,
        },
    )
    group["suspicious_rows"] = int(group["suspicious_rows"]) + 1

    for source_field, output_field in SUSPICIOUS_IP_MAX_FIELDS:
        value = parse_float(row.get(source_field, ""))
        current = group[output_field]
        if value is not None and (current is None or value > float(current)):
            group[output_field] = value

    if dt is not None:
        first_time = group["first_time"]
        last_time = group["last_time"]
        if first_time is None or dt < first_time:
            group["first_time"] = dt
        if last_time is None or dt > last_time:
            group["last_time"] = dt


def format_compact_number(value: object) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.4f}".rstrip("0").rstrip(".")


def compact_suspicious_ip_group(group: dict[str, object]) -> dict[str, object]:
    return {
        "src_ip": group["src_ip"],
        "suspicious_rows": group["suspicious_rows"],
        "max_risk_score": format_compact_number(group["max_risk_score"]),
        "max_anomaly_score": format_compact_number(group["max_anomaly_score"]),
        "max_connections_30s": format_compact_number(group["max_connections_30s"]),
        "max_failed_conn_rate_30s": format_compact_number(
            group["max_failed_conn_rate_30s"]
        ),
        "max_dns_rate_30s": format_compact_number(group["max_dns_rate_30s"]),
        "first_time": format_datetime(group["first_time"]),
        "last_time": format_datetime(group["last_time"]),
    }


def suspicious_ip_sort_key(group: dict[str, object]) -> tuple[float, int, float]:
    max_risk = group["max_risk_score"]
    max_anomaly = group["max_anomaly_score"]
    return (
        float(max_risk) if max_risk is not None else float("-inf"),
        int(group["suspicious_rows"]),
        float(max_anomaly) if max_anomaly is not None else float("-inf"),
    )


def build_suspicious_ip_summary(
    groups: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    sorted_groups = sorted(
        groups.values(), key=suspicious_ip_sort_key, reverse=True
    )[:5]
    return [compact_suspicious_ip_group(group) for group in sorted_groups]


def audit_day(day: str) -> dict[str, object]:
    risk_file = REPORTS_DIR / f"risk_{day}.csv"
    windows_file = WINDOWS_DIR / f"windows_{day}.csv"

    summary = {
        "date": day,
        "risk_rows": 0,
        "windows_rows": count_csv_rows(windows_file),
        "time_start": None,
        "time_end": None,
        "coverage_hours": 0.0,
        "unique_src_ip": 0,
        "max_risk_score": 0.0,
        "risk_ge_20": 0,
        "risk_ge_30": 0,
        "risk_ge_60": 0,
        "anomaly_ge_035": 0,
        "failed_conn_rate_ge_08": 0,
        "connections_ge_80": 0,
        "dns_rate_ge_10": 0,
        "suggested_label": "INCOMPLETE",
        "review_notes": [],
        "top_suspicious_windows": [],
        "suspicious_ip_summary": [],
    }

    if not risk_file.exists():
        summary["review_notes"].append("Required risk report is missing.")
        return summary

    src_ips = set()
    datetimes = []
    top_window_candidates = []
    suspicious_ip_groups = {}

    with risk_file.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            summary["risk_rows"] += 1

            src_ip = row.get("src_ip", "").strip()
            if src_ip:
                src_ips.add(src_ip)

            dt = row_datetime(row)
            if dt is not None:
                datetimes.append(dt)

            risk_score = parse_float(row.get("risk_score", ""))
            if risk_score is not None:
                summary["max_risk_score"] = max(
                    summary["max_risk_score"], risk_score
                )
                summary["risk_ge_20"] += int(risk_score >= 20)
                summary["risk_ge_30"] += int(risk_score >= 30)
                summary["risk_ge_60"] += int(risk_score >= 60)

            summary["anomaly_ge_035"] += ge_count(row, "anomaly_score", 0.35)
            summary["failed_conn_rate_ge_08"] += ge_count(
                row, "failed_conn_rate_30s", 0.8
            )
            summary["connections_ge_80"] += ge_count(row, "connections_30s", 80)
            summary["dns_rate_ge_10"] += ge_count(row, "dns_rate_30s", 1.0)

            sort_key = top_window_sort_key(row)
            compact = compact_top_window(row)
            if sort_key is not None and compact:
                top_window_candidates.append((sort_key, compact))

            update_suspicious_ip_group(suspicious_ip_groups, row, dt)

    summary["unique_src_ip"] = len(src_ips)
    summary["top_suspicious_windows"] = [
        row
        for _, row in sorted(
            top_window_candidates, key=lambda candidate: candidate[0], reverse=True
        )[:5]
    ]
    summary["suspicious_ip_summary"] = build_suspicious_ip_summary(
        suspicious_ip_groups
    )

    if datetimes:
        start = min(datetimes)
        end = max(datetimes)
        summary["time_start"] = start
        summary["time_end"] = end
        summary["coverage_hours"] = max(
            0.0, (end - start).total_seconds() / 3600.0
        )

    classify(summary)
    return summary


def classify(summary: dict[str, object]) -> None:
    notes = summary["review_notes"]
    coverage_hours = float(summary["coverage_hours"])
    max_risk = float(summary["max_risk_score"])
    risk_ge_20 = int(summary["risk_ge_20"])
    risk_ge_30 = int(summary["risk_ge_30"])
    anomaly_ge_035 = int(summary["anomaly_ge_035"])
    failed_conn_rate_ge_08 = int(summary["failed_conn_rate_ge_08"])
    connections_ge_80 = int(summary["connections_ge_80"])
    dns_rate_ge_10 = int(summary["dns_rate_ge_10"])

    if int(summary["risk_rows"]) == 0:
        summary["suggested_label"] = "INCOMPLETE"
        notes.append("Risk report has no rows.")
        return

    if summary["time_start"] is None or summary["time_end"] is None:
        summary["suggested_label"] = "INCOMPLETE"
        notes.append("No valid datetime values were found.")
        return

    if risk_ge_20 > 0:
        notes.append(f"Review point: risk_score >= 20 count is {risk_ge_20}.")
    if anomaly_ge_035 > 0:
        notes.append(
            f"Review point: anomaly_score >= 0.35 count is {anomaly_ge_035}."
        )
    if failed_conn_rate_ge_08 > 0:
        notes.append(
            "Review point: failed_conn_rate_30s >= 0.8 count is "
            f"{failed_conn_rate_ge_08}."
        )
    if connections_ge_80 > 0:
        notes.append(
            f"Review point: connections_30s >= 80 count is {connections_ge_80}."
        )
    if dns_rate_ge_10 > 0:
        notes.append(f"Review point: dns_rate_30s >= 1.0 count is {dns_rate_ge_10}.")

    suspicious = (
        risk_ge_30 > 0
        or anomaly_ge_035 >= 3
        or failed_conn_rate_ge_08 >= 50
        or connections_ge_80 >= 10
        or dns_rate_ge_10 >= 5
    )

    if suspicious:
        summary["suggested_label"] = "SUSPICIOUS_VALIDATION"
        if risk_ge_30 > 0:
            notes.append("Suspicious threshold met: risk_score >= 30 count > 0.")
        if anomaly_ge_035 >= 3:
            notes.append("Suspicious threshold met: anomaly_score >= 0.35 count >= 3.")
        if failed_conn_rate_ge_08 >= 50:
            notes.append(
                "Suspicious threshold met: failed_conn_rate_30s >= 0.8 count >= 50."
            )
        if connections_ge_80 >= 10:
            notes.append("Suspicious threshold met: connections_30s >= 80 count >= 10.")
        if dns_rate_ge_10 >= 5:
            notes.append("Suspicious threshold met: dns_rate_30s >= 1.0 count >= 5.")
        return

    if coverage_hours >= 20:
        summary["suggested_label"] = "CANDIDATE_CLEAN"
        notes.append("Coverage is at least 20 hours with low suspicious indicators.")
        return

    if coverage_hours < 20 and max_risk < 20 and risk_ge_30 == 0:
        summary["suggested_label"] = "PARTIAL_CANDIDATE_CLEAN"
        notes.append("Coverage is under 20 hours, but risk remains below 20.")
        return

    summary["suggested_label"] = "INCOMPLETE"
    notes.append("Coverage is too short or unresolved risk requires review.")


def format_datetime(value: object) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return "n/a"


def print_summary(summary: dict[str, object]) -> None:
    print(f"Date: {summary['date']}")
    print(f"  risk_rows: {summary['risk_rows']}")
    print(f"  windows_rows: {summary['windows_rows']}")
    print(f"  time_start: {format_datetime(summary['time_start'])}")
    print(f"  time_end: {format_datetime(summary['time_end'])}")
    print(f"  coverage_hours: {float(summary['coverage_hours']):.2f}")
    print(f"  unique_src_ip: {summary['unique_src_ip']}")
    print(f"  max_risk_score: {float(summary['max_risk_score']):.2f}")
    print(f"  risk_score >= 20: {summary['risk_ge_20']}")
    print(f"  risk_score >= 30: {summary['risk_ge_30']}")
    print(f"  risk_score >= 60: {summary['risk_ge_60']}")
    print(f"  anomaly_score >= 0.35: {summary['anomaly_ge_035']}")
    print(f"  failed_conn_rate_30s >= 0.8: {summary['failed_conn_rate_ge_08']}")
    print(f"  connections_30s >= 80: {summary['connections_ge_80']}")
    print(f"  dns_rate_30s >= 1.0: {summary['dns_rate_ge_10']}")
    print(f"  suggested_label: {summary['suggested_label']}")
    print("  review_notes:")
    for note in summary["review_notes"]:
        print(f"    - {note}")
    print("  top_suspicious_windows:")
    top_windows = summary.get("top_suspicious_windows", [])
    if top_windows:
        for row in top_windows:
            fields = " ".join(f"{key}={value}" for key, value in row.items())
            print(f"    - {fields}")
    else:
        print("    - none")
    print("  suspicious_ip_summary:")
    suspicious_ips = summary.get("suspicious_ip_summary", [])
    if suspicious_ips:
        for row in suspicious_ips:
            fields = " ".join(f"{key}={value}" for key, value in row.items())
            print(f"    - {fields}")
    else:
        print("    - none")
    print()


def main() -> int:
    args = parse_args()
    requested_dates = [parse_date_arg(value) for value in args.dates]
    training_dt = load_training_datetime()

    dates = requested_dates or default_dates(training_dt)

    print("Post-Training Day Audit")
    print(f"trained_at: {training_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"dates: {', '.join(dates) if dates else 'none'}")
    print(
        "Note: Suggested labels are preliminary and do not automatically "
        "approve retraining."
    )
    print()

    for day in dates:
        print_summary(audit_day(day))

    print("[RESULT] POST-TRAINING DAY AUDIT COMPLETE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] post-training day audit failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
