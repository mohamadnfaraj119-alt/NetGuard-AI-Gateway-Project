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
    }

    if not risk_file.exists():
        summary["review_notes"].append("Required risk report is missing.")
        return summary

    src_ips = set()
    datetimes = []

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

    summary["unique_src_ip"] = len(src_ips)

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
