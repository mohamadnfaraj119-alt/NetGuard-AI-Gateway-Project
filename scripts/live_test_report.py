#!/usr/bin/env python3
"""
Build a compact evidence report for a controlled live test.

Examples:
  python scripts/live_test_report.py --date 2026-06-12 --start 10:10 --end 10:25
  python scripts/live_test_report.py --date 2026-06-12 --start 10:10 --end 10:25 --src-ip 192.168.1.156
"""

import argparse
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
LOCAL_TZ = "Asia/Riyadh"


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise SystemExit(f"Missing file: {path}")
    return pd.read_csv(path, low_memory=False)


def local_window(date: str, start: str, end: str):
    start_ts = pd.Timestamp(f"{date} {start}", tz=LOCAL_TZ).tz_convert("UTC").tz_localize(None)
    end_ts = pd.Timestamp(f"{date} {end}", tz=LOCAL_TZ).tz_convert("UTC").tz_localize(None)
    return start_ts, end_ts


def filter_by_time(df: pd.DataFrame, start_utc, end_utc) -> pd.DataFrame:
    if "ts" not in df.columns:
        return df.iloc[0:0].copy()
    out = df.copy()
    out["dt_utc"] = pd.to_datetime(out["ts"], unit="s", errors="coerce")
    return out[(out["dt_utc"] >= start_utc) & (out["dt_utc"] <= end_utc)].copy()


def add_filters(df: pd.DataFrame, src_ip: str | None, target_ip: str | None) -> pd.DataFrame:
    out = df
    if src_ip and "src_ip" in out.columns:
        out = out[out["src_ip"].astype(str) == src_ip]
    if target_ip and "dst_ip" in out.columns:
        out = out[out["dst_ip"].astype(str) == target_ip]
    return out


def value_counts_block(title: str, series: pd.Series, limit: int = 15) -> list[str]:
    lines = [f"\n## {title}"]
    if series.empty:
        lines.append("(none)")
        return lines
    for key, count in series.astype(str).value_counts().head(limit).items():
        lines.append(f"- {key}: {count}")
    return lines


def main():
    parser = argparse.ArgumentParser(description="NetGuard-AI live test evidence report")
    parser.add_argument("--date", required=True, help="YYYY-MM-DD")
    parser.add_argument("--start", required=True, help="local HH:MM or HH:MM:SS")
    parser.add_argument("--end", required=True, help="local HH:MM or HH:MM:SS")
    parser.add_argument("--src-ip", default=None)
    parser.add_argument("--target-ip", default=None)
    parser.add_argument("--name", default="live-test")
    args = parser.parse_args()

    start_utc, end_utc = local_window(args.date, args.start, args.end)

    baseline = read_csv(BASE_DIR / "data" / "processed" / f"baseline_{args.date}.csv")
    risk_path = BASE_DIR / "data" / "reports" / f"risk_{args.date}.csv"
    risk = read_csv(risk_path) if risk_path.exists() else pd.DataFrame()

    base_win = add_filters(filter_by_time(baseline, start_utc, end_utc), args.src_ip, args.target_ip)
    risk_win = add_filters(filter_by_time(risk, start_utc, end_utc), args.src_ip, None) if not risk.empty else risk

    lines = [
        f"# Live Test Report: {args.name}",
        "",
        f"- date: {args.date}",
        f"- local window: {args.start} -> {args.end} ({LOCAL_TZ})",
        f"- utc window: {start_utc} -> {end_utc}",
        f"- src_ip filter: {args.src_ip or '(none)'}",
        f"- target_ip filter: {args.target_ip or '(none)'}",
        f"- baseline rows: {len(base_win)}",
        f"- risk rows: {len(risk_win)}",
    ]

    if not base_win.empty:
        lines += value_counts_block("Top src_ip", base_win.get("src_ip", pd.Series(dtype=str)))
        lines += value_counts_block("Top dst_ip", base_win.get("dst_ip", pd.Series(dtype=str)))
        lines += value_counts_block("Top dst_port", base_win.get("dst_port", pd.Series(dtype=str)), 25)
        state_cols = [c for c in base_win.columns if c.startswith("conn_state_")]
        if state_cols:
            lines.append("\n## Conn State Sums")
            for key, count in base_win[state_cols].sum().sort_values(ascending=False).items():
                lines.append(f"- {key}: {int(count)}")

    if not risk_win.empty:
        high = risk_win.sort_values("risk_score", ascending=False).head(10)
        show_cols = [
            c for c in [
                "datetime", "src_ip", "risk_score", "risk_level",
                "score_anomaly", "score_scan", "score_burst", "score_dns",
                "flag_port_scan", "flag_brute_force", "flag_burst", "flag_dns_flood",
                "explanation",
            ]
            if c in high.columns
        ]
        lines.append("\n## Top Risk Rows")
        lines.append(high[show_cols].to_string(index=False))

    out_dir = BASE_DIR / "data" / "reports" / "live_tests"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = args.name.replace(" ", "_").replace("/", "_")
    out_path = out_dir / f"{args.date}_{safe_name}.md"
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(out_path)


if __name__ == "__main__":
    main()
