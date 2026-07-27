#!/usr/bin/env python3
"""
Read-only false-positive audit for NetGuard-AI detection/classification output.

The audit measures how existing processed, window, and risk report files behave
under the current classifier. It does not modify thresholds, models, source
evidence, network services, or detection logic.
"""

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
REPORTS_DIR = BASE_DIR / "data" / "reports"
AUDIT_DIR = BASE_DIR / "data" / "audit"
CLASSIFICATIONS = (
    "DNS_ANOMALY",
    "PORT_SCAN",
    "FAILED_CONNECTION_PATTERN",
    "DOS_LIKE_BURST",
    "BOT_LIKE_BEHAVIOR",
    "SSH_BRUTE_FORCE_OR_LOGIN_PATTERN",
    "UNKNOWN_SUSPICIOUS",
    "LOW_SIGNAL_REVIEW",
)
NUMERIC_FEATURES = (
    "dns_rate_30s",
    "unique_dst_ips_30s",
    "unique_dst_ports_30s",
    "failed_conn_rate_30s",
    "connections_30s",
    "risk_score",
    "anomaly_score",
    "confidence",
)
CONFIDENCE_RANGES = (
    ("0.00-0.49", 0.0, 0.5),
    ("0.50-0.64", 0.5, 0.65),
    ("0.65-0.79", 0.65, 0.8),
    ("0.80-1.00", 0.8, None),
)
RISK_RANGES = (
    ("0-19.99", 0.0, 20.0),
    ("20-29.99", 20.0, 30.0),
    ("30-59.99", 30.0, 60.0),
    ("60-100", 60.0, None),
)
ANOMALY_RANGES = (
    ("0", 0.0, 0.0),
    ("0.0001-0.3499", 0.0001, 0.35),
    ("0.35-0.6999", 0.35, 0.7),
    ("0.70+", 0.7, None),
)

if str(BASE_DIR / "scripts") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "scripts"))

import attack_classifier  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only false-positive audit for NetGuard-AI detection accuracy."
    )
    parser.add_argument(
        "--date",
        default=datetime.now().strftime("%Y-%m-%d"),
        type=parse_date,
        help="Audit date formatted as YYYY-MM-DD. Default: today.",
    )
    parser.add_argument(
        "--label",
        choices=("normal", "attack", "unknown"),
        default="unknown",
        help="Ground-truth label for analyzed rows. Default: unknown.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for audit outputs. Default: data/audit/detection_accuracy_<date>/.",
    )
    parser.add_argument(
        "--top",
        type=positive_int,
        default=10,
        help="Number of top sources/reasons to show in summaries. Default: 10.",
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


def default_output_dir(date: str) -> Path:
    return AUDIT_DIR / f"detection_accuracy_{date}"


def input_paths(date: str, base_dir: Path = BASE_DIR) -> dict[str, Path]:
    return {
        "processed": base_dir / "data" / "processed" / f"baseline_{date}.csv",
        "windows": base_dir / "data" / "windows" / f"windows_{date}.csv",
        "risk": base_dir / "data" / "reports" / f"risk_{date}.csv",
    }


def read_csv_rows(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    if not path.exists():
        return [], []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows = [dict(row) for row in reader]
        return rows, list(reader.fieldnames or [])


def row_float(row: dict[str, Any], key: str) -> float | None:
    value = row.get(key)
    if value is None or str(value).strip() == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def row_time(row: dict[str, Any]) -> str:
    return str(row.get("time") or row.get("datetime") or row.get("timestamp") or row.get("ts") or "").strip()


def classify_risk_rows(risk_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    suspicious_rows = [row for row in risk_rows if attack_classifier.is_suspicious_row(row)]
    suspicious_rows_by_src = Counter(
        attack_classifier.row_value(row, "src_ip") for row in suspicious_rows
    )
    suspicious_rows_by_src.pop("", None)

    events = []
    for row_index, row in enumerate(risk_rows):
        if not attack_classifier.is_suspicious_row(row):
            continue
        event = attack_classifier.classify_row(row, suspicious_rows_by_src, set())
        enriched = dict(row)
        enriched.update(
            {
                "row_index": row_index,
                "classification": str(event["attack_type"]),
                "confidence": float(event["confidence"]),
                "classified_time": str(event["time"]),
                "reasons": list(event.get("reasons", [])),
            }
        )
        events.append(enriched)
    return events


def percentage(part: int | float, whole: int | float) -> float:
    if not whole:
        return 0.0
    return round((float(part) / float(whole)) * 100.0, 4)


def numeric_values(rows: list[dict[str, Any]], field: str) -> list[float]:
    values = []
    for row in rows:
        value = row_float(row, field)
        if value is not None:
            values.append(value)
    return values


def quantile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 6)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 6)


def quantile_summary(values: list[float]) -> dict[str, float | None]:
    return {
        "p50": quantile(values, 0.50),
        "p75": quantile(values, 0.75),
        "p90": quantile(values, 0.90),
        "p95": quantile(values, 0.95),
        "p99": quantile(values, 0.99),
        "max": round(max(values), 6) if values else None,
    }


def range_label(value: float, ranges: tuple[tuple[str, float, float | None], ...]) -> str:
    for label, start, end in ranges:
        if end is None and value >= start:
            return label
        if end is not None and start <= value < end:
            return label
        if start == end and value == start:
            return label
    return "unavailable"


def anomaly_range(value: float | None) -> str:
    if value is None:
        return "unavailable"
    if value == 0:
        return "0"
    return range_label(value, ANOMALY_RANGES)


def flatten_reasons(rows: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        reasons = row.get("reasons", [])
        if isinstance(reasons, list):
            for reason in reasons:
                text = str(reason).strip()
                if text:
                    counts[text] += 1
    return counts


def reason_signal(reason: str) -> str:
    text = reason.lower()
    if "anomaly_score" in text:
        return "anomaly"
    if "risk_score" in text:
        return "risk"
    if "connections_30s" in text:
        return "connections"
    if "failed_conn_rate" in text:
        return "failed_connections"
    if "dns_rate" in text or "dns" in text:
        return "dns"
    if "unique_dst_ports" in text or "unique_dst_ips" in text:
        return "scan_spread"
    if "flag_" in text:
        return "flag"
    if "burst_score" in text:
        return "burst"
    if "bytes_per_sec" in text:
        return "bytes_rate"
    if "ssh" in text or "port 22" in text:
        return "ssh_context"
    if "source has" in text:
        return "repeated_source"
    return "other"


def signal_set(row: dict[str, Any]) -> set[str]:
    reasons = row.get("reasons", [])
    if not isinstance(reasons, list):
        return set()
    return {reason_signal(str(reason)) for reason in reasons if str(reason).strip()}


def is_anomaly_zero(row: dict[str, Any]) -> bool:
    return (row_float(row, "anomaly_score") or 0.0) == 0.0


def is_heuristic_only(row: dict[str, Any]) -> bool:
    signals = signal_set(row)
    return is_anomaly_zero(row) and bool(signals) and "anomaly" not in signals


def has_multiple_independent_signals(row: dict[str, Any]) -> bool:
    signals = signal_set(row)
    if "risk" in signals and len(signals) > 1:
        signals = set(signals)
        signals.remove("risk")
    return len(signals) >= 2


def min_median_max(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"min": None, "median": None, "max": None}
    ordered = sorted(values)
    return {
        "min": round(ordered[0], 6),
        "median": round(statistics.median(ordered), 6),
        "max": round(ordered[-1], 6),
    }


def classification_breakdown(
    suspicious_rows: list[dict[str, Any]], top: int
) -> list[dict[str, Any]]:
    total = len(suspicious_rows)
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in suspicious_rows:
        by_class[str(row.get("classification", "UNKNOWN_SUSPICIOUS"))].append(row)

    rows = []
    for classification in CLASSIFICATIONS:
        items = by_class.get(classification, [])
        source_counts = Counter(str(row.get("src_ip") or "n/a") for row in items)
        reasons = flatten_reasons(items)
        feature_summary = {
            field: min_median_max(numeric_values(items, field))
            for field in NUMERIC_FEATURES
            if field != "confidence" and any(field in row for row in items)
        }
        rows.append(
            {
                "classification": classification,
                "count": len(items),
                "percentage_of_suspicious_rows": percentage(len(items), total),
                "confidence_min": min_median_max(numeric_values(items, "confidence"))["min"],
                "confidence_median": min_median_max(numeric_values(items, "confidence"))["median"],
                "confidence_max": min_median_max(numeric_values(items, "confidence"))["max"],
                "risk_score_min": min_median_max(numeric_values(items, "risk_score"))["min"],
                "risk_score_median": min_median_max(numeric_values(items, "risk_score"))["median"],
                "risk_score_max": min_median_max(numeric_values(items, "risk_score"))["max"],
                "anomaly_score_min": min_median_max(numeric_values(items, "anomaly_score"))["min"],
                "anomaly_score_median": min_median_max(numeric_values(items, "anomaly_score"))["median"],
                "anomaly_score_max": min_median_max(numeric_values(items, "anomaly_score"))["max"],
                "top_source_ips": json.dumps(source_counts.most_common(top)),
                "top_reasons": json.dumps(reasons.most_common(top)),
                "feature_value_summary": json.dumps(feature_summary, sort_keys=True),
                "anomaly_score_zero_rows": sum(1 for row in items if is_anomaly_zero(row)),
                "heuristic_only_rows": sum(1 for row in items if is_heuristic_only(row)),
            }
        )
    return rows


def distribution_counts(
    suspicious_rows: list[dict[str, Any]], field: str, ranges: tuple[tuple[str, float, float | None], ...]
) -> dict[str, int]:
    counts = {label: 0 for label, _start, _end in ranges}
    counts["unavailable"] = 0
    for row in suspicious_rows:
        value = row_float(row, field)
        if value is None:
            counts["unavailable"] += 1
        else:
            counts[range_label(value, ranges)] += 1
    return counts


def anomaly_distribution_counts(suspicious_rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {label: 0 for label, _start, _end in ANOMALY_RANGES}
    counts["unavailable"] = 0
    for row in suspicious_rows:
        counts[anomaly_range(row_float(row, "anomaly_score"))] += 1
    return counts


def repeated_sequences(suspicious_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in suspicious_rows:
        key = (str(row.get("src_ip") or "n/a"), str(row.get("classification") or "UNKNOWN_SUSPICIOUS"))
        grouped[key].append(row)

    sequences = []
    for (src_ip, classification), rows in grouped.items():
        if len(rows) < 2:
            continue
        ordered = sorted(rows, key=lambda row: int(row.get("row_index", 0)))
        longest_run = 1
        current_run = 1
        previous_index = int(ordered[0].get("row_index", 0))
        for row in ordered[1:]:
            current_index = int(row.get("row_index", 0))
            if current_index == previous_index + 1:
                current_run += 1
            else:
                longest_run = max(longest_run, current_run)
                current_run = 1
            previous_index = current_index
        longest_run = max(longest_run, current_run)
        sequences.append(
            {
                "src_ip": src_ip,
                "classification": classification,
                "count": len(ordered),
                "first_timestamp": row_time(ordered[0]) or str(ordered[0].get("classified_time", "")),
                "last_timestamp": row_time(ordered[-1]) or str(ordered[-1].get("classified_time", "")),
                "longest_consecutive_sequence": longest_run,
                "max_risk_score": max(row_float(row, "risk_score") or 0.0 for row in ordered),
                "max_confidence": max(row_float(row, "confidence") or 0.0 for row in ordered),
            }
        )
    return sorted(sequences, key=lambda item: (item["count"], item["max_risk_score"]), reverse=True)


def feature_quantile_rows(risk_rows: list[dict[str, Any]], suspicious_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    available = set()
    for row in risk_rows:
        available.update(row.keys())
    available.update({"confidence"} if suspicious_rows else set())
    unavailable = [field for field in NUMERIC_FEATURES if field not in available]

    rows = []
    for field in NUMERIC_FEATURES:
        if field not in available:
            continue
        source_rows = suspicious_rows if field == "confidence" else risk_rows
        values = numeric_values(source_rows, field)
        summary = quantile_summary(values)
        rows.append(
            {
                "feature": field,
                "scope": "suspicious_rows" if field == "confidence" else "risk_rows",
                "count": len(values),
                **summary,
            }
        )
    return rows, unavailable


def build_summary(
    date: str,
    label: str,
    paths: dict[str, Path],
    rows_by_kind: dict[str, list[dict[str, str]]],
    headers_by_kind: dict[str, list[str]],
    suspicious_rows: list[dict[str, Any]],
    top: int,
) -> dict[str, Any]:
    risk_rows = rows_by_kind["risk"]
    risk_row_count = len(risk_rows)
    suspicious_count = len(suspicious_rows)
    anomaly_zero_count = sum(1 for row in risk_rows if is_anomaly_zero(row))
    suspicious_anomaly_zero = sum(1 for row in suspicious_rows if is_anomaly_zero(row))
    heuristic_only_count = sum(1 for row in suspicious_rows if is_heuristic_only(row))
    multiple_signals_count = sum(1 for row in suspicious_rows if has_multiple_independent_signals(row))
    classification_counts = Counter(str(row.get("classification")) for row in suspicious_rows)
    src_counts = Counter(str(row.get("src_ip") or "n/a") for row in suspicious_rows)
    reason_counts = flatten_reasons(suspicious_rows)
    repeated = repeated_sequences(suspicious_rows)
    quantiles, unavailable_quantile_fields = feature_quantile_rows(risk_rows, suspicious_rows)
    false_positive_rate = percentage(suspicious_count, risk_row_count) if label == "normal" else None

    return {
        "date": date,
        "ground_truth": label,
        "input_files": {name: str(path) for name, path in paths.items()},
        "missing_files": [name for name, path in paths.items() if not path.exists()],
        "headers": headers_by_kind,
        "processed_row_count": len(rows_by_kind["processed"]),
        "window_row_count": len(rows_by_kind["windows"]),
        "risk_row_count": risk_row_count,
        "suspicious_row_count": suspicious_count,
        "suspicious_window_percentage": percentage(suspicious_count, risk_row_count),
        "normal_window_percentage": percentage(max(risk_row_count - suspicious_count, 0), risk_row_count),
        "suspicious_rows_by_classification": dict(classification_counts.most_common()),
        "suspicious_rows_by_source_ip": dict(src_counts.most_common(top)),
        "suspicious_rows_by_confidence_range": distribution_counts(
            suspicious_rows, "confidence", CONFIDENCE_RANGES
        ),
        "suspicious_rows_by_risk_score_range": distribution_counts(
            suspicious_rows, "risk_score", RISK_RANGES
        ),
        "suspicious_rows_by_anomaly_score_range": anomaly_distribution_counts(suspicious_rows),
        "top_triggering_reasons": dict(reason_counts.most_common(top)),
        "anomaly_score_zero_rows": anomaly_zero_count,
        "anomaly_score_zero_percentage": percentage(anomaly_zero_count, risk_row_count),
        "suspicious_rows_anomaly_score_zero": suspicious_anomaly_zero,
        "suspicious_rows_heuristic_only": heuristic_only_count,
        "suspicious_rows_multiple_independent_signals": multiple_signals_count,
        "repeated_sequence_count": len(repeated),
        "longest_consecutive_suspicious_sequence": max(
            (int(item["longest_consecutive_sequence"]) for item in repeated),
            default=1 if suspicious_rows else 0,
        ),
        "estimated_false_positive_rate": false_positive_rate,
        "top_false_positive_class": (
            classification_counts.most_common(1)[0][0]
            if label == "normal" and classification_counts
            else None
        ),
        "feature_quantiles": quantiles,
        "unavailable_quantile_fields": unavailable_quantile_fields,
        "classification_breakdown": classification_breakdown(suspicious_rows, top),
        "repeated_sequences": repeated,
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def suspicious_csv_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    base_fields = []
    for row in rows:
        for key in row.keys():
            if key not in {"reasons"} and key not in base_fields:
                base_fields.append(key)
    if "reasons" not in base_fields:
        base_fields.append("reasons")

    output = []
    for row in rows:
        item = dict(row)
        item["reasons"] = "; ".join(str(reason) for reason in row.get("reasons", []))
        output.append(item)
    return output, base_fields


def reason_breakdown_rows(suspicious_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    total = len(suspicious_rows)
    counts = flatten_reasons(suspicious_rows)
    return [
        {"reason": reason, "count": count, "percentage_of_suspicious_rows": percentage(count, total)}
        for reason, count in counts.most_common()
    ]


def write_outputs(
    output_dir: Path,
    summary: dict[str, Any],
    suspicious_rows: list[dict[str, Any]],
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "audit_summary": output_dir / "audit_summary.json",
        "audit_report": output_dir / "audit_report.md",
        "suspicious_rows": output_dir / "suspicious_rows.csv",
        "classification_breakdown": output_dir / "classification_breakdown.csv",
        "trigger_reason_breakdown": output_dir / "trigger_reason_breakdown.csv",
        "repeated_sequences": output_dir / "repeated_sequences.csv",
        "feature_quantiles": output_dir / "feature_quantiles.csv",
    }

    paths["audit_summary"].write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    paths["audit_report"].write_text(markdown_report(summary), encoding="utf-8")

    suspicious_rows_for_csv, suspicious_fields = suspicious_csv_rows(suspicious_rows)
    write_csv(paths["suspicious_rows"], suspicious_rows_for_csv, suspicious_fields or ["row_index"])
    write_csv(
        paths["classification_breakdown"],
        summary["classification_breakdown"],
        [
            "classification",
            "count",
            "percentage_of_suspicious_rows",
            "confidence_min",
            "confidence_median",
            "confidence_max",
            "risk_score_min",
            "risk_score_median",
            "risk_score_max",
            "anomaly_score_min",
            "anomaly_score_median",
            "anomaly_score_max",
            "top_source_ips",
            "top_reasons",
            "feature_value_summary",
            "anomaly_score_zero_rows",
            "heuristic_only_rows",
        ],
    )
    write_csv(
        paths["trigger_reason_breakdown"],
        reason_breakdown_rows(suspicious_rows),
        ["reason", "count", "percentage_of_suspicious_rows"],
    )
    write_csv(
        paths["repeated_sequences"],
        summary["repeated_sequences"],
        [
            "src_ip",
            "classification",
            "count",
            "first_timestamp",
            "last_timestamp",
            "longest_consecutive_sequence",
            "max_risk_score",
            "max_confidence",
        ],
    )
    write_csv(
        paths["feature_quantiles"],
        summary["feature_quantiles"],
        ["feature", "scope", "count", "p50", "p75", "p90", "p95", "p99", "max"],
    )
    return paths


def markdown_report(summary: dict[str, Any]) -> str:
    false_positive_rate = summary["estimated_false_positive_rate"]
    false_positive_text = "n/a" if false_positive_rate is None else f"{false_positive_rate:.2f}%"
    missing = summary["missing_files"] or ["none"]
    lines = [
        f"# Detection Accuracy Audit: {summary['date']}",
        "",
        "## Observed Fact",
        "",
        f"- Ground truth label: `{summary['ground_truth']}`",
        f"- Processed rows: {summary['processed_row_count']}",
        f"- Window rows: {summary['window_row_count']}",
        f"- Risk rows: {summary['risk_row_count']}",
        f"- Suspicious rows: {summary['suspicious_row_count']}",
        f"- Suspicious-window percentage: {summary['suspicious_window_percentage']:.2f}%",
        f"- Normal-window percentage: {summary['normal_window_percentage']:.2f}%",
        f"- Estimated false-positive rate: {false_positive_text}",
        f"- Missing input files: {', '.join(missing)}",
        "",
        "### Suspicious Rows By Classification",
        "",
    ]
    classification_counts = summary["suspicious_rows_by_classification"]
    if classification_counts:
        for classification, count in classification_counts.items():
            lines.append(f"- `{classification}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "### Top Triggering Reasons", ""])
    top_reasons = summary["top_triggering_reasons"]
    if top_reasons:
        for reason, count in top_reasons.items():
            lines.append(f"- {reason}: {count}")
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "### Signal Audit",
            "",
            f"- Rows where `anomaly_score` is zero: {summary['anomaly_score_zero_rows']} ({summary['anomaly_score_zero_percentage']:.2f}%)",
            f"- Suspicious rows where `anomaly_score` is zero: {summary['suspicious_rows_anomaly_score_zero']}",
            f"- Suspicious rows triggered only by heuristic evidence: {summary['suspicious_rows_heuristic_only']}",
            f"- Suspicious rows involving multiple independent signals: {summary['suspicious_rows_multiple_independent_signals']}",
            f"- Repeated source/classification sequences: {summary['repeated_sequence_count']}",
            f"- Longest consecutive suspicious sequence: {summary['longest_consecutive_suspicious_sequence']}",
            "",
            "## Inference",
            "",
        ]
    )

    if summary["ground_truth"] == "normal":
        lines.append(
            "Because the supplied ground truth is `normal`, every suspicious "
            "classification in this audit is counted as a false positive for "
            "measurement purposes."
        )
    else:
        lines.append(
            "False-positive rate is not estimated because the supplied ground "
            "truth is not `normal`."
        )
    if summary["suspicious_rows_heuristic_only"]:
        lines.append(
            "Some suspicious rows have `anomaly_score = 0`; this suggests the "
            "current suspicious classifications can be driven by heuristic "
            "signals even when the anomaly model contributes no score."
        )

    lines.extend(
        [
            "",
            "## Recommended Investigation",
            "",
            "- Review the highest-count classifications and reasons in `classification_breakdown.csv` and `trigger_reason_breakdown.csv` before any threshold or model changes.",
            "- Compare repeated `src_ip + classification` sequences against packet/window evidence to determine whether repeated known-normal behavior is being overcounted.",
            "- Treat all classifications here as preliminary labels for analysis, not confirmed attacks.",
            "",
            "## Feature Quantiles",
            "",
        ]
    )
    for item in summary["feature_quantiles"]:
        lines.append(
            f"- `{item['feature']}` ({item['scope']}): "
            f"p50={item['p50']} p75={item['p75']} p90={item['p90']} "
            f"p95={item['p95']} p99={item['p99']} max={item['max']}"
        )
    if summary["unavailable_quantile_fields"]:
        lines.append(
            f"- Unavailable fields: {', '.join(summary['unavailable_quantile_fields'])}"
        )
    return "\n".join(lines) + "\n"


def run_audit(
    date: str,
    label: str,
    output_dir: Path | None = None,
    top: int = 10,
    base_dir: Path = BASE_DIR,
) -> tuple[dict[str, Any], dict[str, Path]]:
    paths = input_paths(date, base_dir)
    rows_by_kind: dict[str, list[dict[str, str]]] = {}
    headers_by_kind: dict[str, list[str]] = {}
    for kind, path in paths.items():
        rows, headers = read_csv_rows(path)
        rows_by_kind[kind] = rows
        headers_by_kind[kind] = headers

    suspicious_rows = classify_risk_rows(rows_by_kind["risk"]) if rows_by_kind["risk"] else []
    target_dir = output_dir if output_dir is not None else base_dir / "data" / "audit" / f"detection_accuracy_{date}"
    summary = build_summary(
        date,
        label,
        paths,
        rows_by_kind,
        headers_by_kind,
        suspicious_rows,
        top,
    )
    output_paths = write_outputs(target_dir, summary, suspicious_rows)
    return summary, output_paths


def print_console_summary(summary: dict[str, Any], output_dir: Path) -> None:
    false_positive_rate = summary["estimated_false_positive_rate"]
    false_positive_text = "n/a" if false_positive_rate is None else f"{false_positive_rate:.2f}%"
    print(f"[AUDIT] date={summary['date']}")
    print(f"[AUDIT] ground_truth={summary['ground_truth']}")
    print(f"[AUDIT] risk_rows={summary['risk_row_count']}")
    print(f"[AUDIT] suspicious_rows={summary['suspicious_row_count']}")
    print(f"[AUDIT] false_positive_rate={false_positive_text}")
    print(f"[AUDIT] top_false_positive_class={summary['top_false_positive_class'] or 'n/a'}")
    print(f"[AUDIT] output_dir={output_dir}")
    if summary["ground_truth"] == "normal" and (false_positive_rate or 0.0) > 5.0:
        print("[WARN] FALSE-POSITIVE RATE EXCEEDS ACCEPTABLE TARGET")
    if summary["missing_files"]:
        print(f"[WARN] missing_files={','.join(summary['missing_files'])}")
    print("[RESULT] DETECTION ACCURACY AUDIT COMPLETE")


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir or default_output_dir(args.date)
    summary, _paths = run_audit(args.date, args.label, output_dir, args.top)
    print_console_summary(summary, output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
