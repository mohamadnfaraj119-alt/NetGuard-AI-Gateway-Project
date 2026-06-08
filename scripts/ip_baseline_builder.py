#!/usr/bin/env python3
"""
ip_baseline_builder.py
======================
Builds per-IP behavioral baselines from baseline_*.csv (flow level).

Per-IP stats computed:
  - connections/day, unique dst_ports, outbound_ratio, dns_rate, bytes

Usage:
  python scripts/ip_baseline_builder.py
  python scripts/ip_baseline_builder.py --days 6 --dry-run
  python scripts/ip_baseline_builder.py --min-windows 100
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime

import numpy as np
import pandas as pd

# ─── Config ───────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.expanduser("~/zeek-ids")
INPUT_DIR   = os.path.join(BASE_DIR, "data", "processed")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "baselines", "ip_baselines.json")

# Min flows per IP to trust a per-IP baseline (~1 day of a normal device)
MIN_FLOWS_DEFAULT = 500

# Noise filter (قاعدة ثابتة)
NOISE_DST_IPS = {
    "224.0.0.251", "224.0.0.1",
    "192.168.68.255", "192.168.1.255", "255.255.255.255",
    "ff02::fb", "ff02::1:3", "ff02::1", "ff02::2", "ff02::16",
}
NOISE_PORTS = {137, 138, 139, 5353, 1900, 5355}

GLOBAL_BASELINE = {
    "connections_30s_max":      35.0,
    "unique_dst_ports_30s_max":  5.0,
    "port_entropy_30s_max":      0.115,
    "burst_score_30s_max":       0.287,
    "dns_rate_1m_max":           2.117,
    "outbound_ratio_30s_mean":   0.5,
    "P99_BASELINE":              0.782,
}


# ─── Load ─────────────────────────────────────────────────────────────────────

def load_baselines(days=None) -> pd.DataFrame:
    pattern = os.path.join(INPUT_DIR, "baseline_*.csv")
    files   = sorted(glob.glob(pattern))

    if not files:
        sys.exit(f"❌ No baseline files found in: {INPUT_DIR}")

    if days:
        files = files[-days:]

    print(f"   Found {len(files)} file(s):")
    frames = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            frames.append(df)
            print(f"   ✅ {os.path.basename(f)}: {len(df):,} rows")
        except Exception as e:
            print(f"   ⚠  Skip {os.path.basename(f)}: {e}")

    if not frames:
        sys.exit("❌ No valid baseline files loaded.")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n   Total flows : {len(combined):,}")
    return combined


def apply_noise_filter(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    if "dst_ip" in df.columns:
        df = df[~df["dst_ip"].isin(NOISE_DST_IPS)]
    if "dst_port" in df.columns:
        df = df[~df["dst_port"].isin(NOISE_PORTS)]
    dropped = before - len(df)
    if dropped:
        print(f"   🔕 Noise filter removed {dropped:,} rows")
    return df


# ─── Per-IP Stats ─────────────────────────────────────────────────────────────

def pct(series, p):
    """Safe percentile."""
    v = series.dropna()
    return round(float(np.percentile(v, p)), 6) if len(v) else 0.0


def compute_ip_stats(ip_df: pd.DataFrame) -> dict:
    """
    Compute behavioral stats per IP from flow-level baseline CSV.
    Groups flows into 30s buckets to mirror window_engine outputs.
    """
    stats = {"flow_count": len(ip_df)}

    # ── 1. Group into 30s buckets ──
    if "ts" in ip_df.columns:
        ip_df = ip_df.copy()
        ip_df["bucket"] = (ip_df["ts"] // 30).astype(int)
        grp = ip_df.groupby("bucket")

        # connections_30s
        conn_per_bucket = grp.size()
        stats["connections_30s_p50"] = pct(conn_per_bucket, 50)
        stats["connections_30s_p90"] = pct(conn_per_bucket, 90)
        stats["connections_30s_p95"] = pct(conn_per_bucket, 95)
        stats["connections_30s_p99"] = pct(conn_per_bucket, 99)
        stats["connections_30s_max"] = round(float(conn_per_bucket.max()), 6)

        # unique_dst_ports_30s
        if "dst_port" in ip_df.columns:
            ports_per_bucket = grp["dst_port"].nunique()
            stats["unique_dst_ports_30s_p99"] = pct(ports_per_bucket, 99)
            stats["unique_dst_ports_30s_max"] = round(float(ports_per_bucket.max()), 6)

        # outbound_ratio_30s
        if "is_external" in ip_df.columns:
            out_per_bucket = grp["is_external"].mean()
            stats["outbound_ratio_30s_p99"]  = pct(out_per_bucket, 99)
            stats["outbound_ratio_30s_mean"] = round(float(out_per_bucket.mean()), 6)

        # dns_rate_30s → scale to per-minute (×2)
        if "is_dns" in ip_df.columns:
            dns_per_bucket = grp["is_dns"].sum() * 2  # per-minute equivalent
            stats["dns_rate_1m_p99"] = pct(dns_per_bucket, 99)
            stats["dns_rate_1m_max"] = round(float(dns_per_bucket.max()), 6)

    # ── 2. Flow-level features (no bucketing needed) ──
    if "orig_bytes" in ip_df.columns:
        v = ip_df["orig_bytes"].dropna()
        stats["orig_bytes_p99"] = pct(v, 99)
        stats["orig_bytes_max"] = round(float(v.max()), 6)

    if "duration" in ip_df.columns:
        v = ip_df["duration"].dropna()
        stats["duration_p99"] = pct(v, 99)

    return stats


# ─── Build ────────────────────────────────────────────────────────────────────

def build_ip_baselines(df: pd.DataFrame, min_flows: int) -> dict:
    if "src_ip" not in df.columns:
        sys.exit("❌ 'src_ip' column not found.")

    counts      = df.groupby("src_ip").size()
    qualified   = counts[counts >= min_flows].index.tolist()
    unqualified = counts[counts <  min_flows].index.tolist()

    print(f"\n{'─'*58}")
    print(f"  IPs with per-IP baseline  (≥{min_flows} flows): {len(qualified)}")
    print(f"  IPs using global fallback (<{min_flows} flows): {len(unqualified)}")
    print(f"{'─'*58}")

    ip_baselines = {}

    for ip in sorted(qualified):
        ip_df = df[df["src_ip"] == ip]
        stats = compute_ip_stats(ip_df)

        ip_baselines[ip] = {
            "use_per_ip":   True,
            "last_updated": datetime.now().isoformat(),
            **stats,
        }
        c99 = stats.get("connections_30s_p99", "—")
        d99 = stats.get("dns_rate_1m_p99",     "—")
        print(f"  ✅ {ip:<18}  flows={stats['flow_count']:>6}  "
              f"conn_p99={c99}  dns_p99={d99}")

    for ip in sorted(unqualified):
        n = int(counts[ip])
        ip_baselines[ip] = {
            "use_per_ip":    False,
            "flow_count":    n,
            "last_updated":  datetime.now().isoformat(),
            "reason":        f"insufficient data ({n} < {min_flows})",
        }
        print(f"  ⚠  {ip:<18}  flows={n:>6}  → global fallback")

    return ip_baselines


# ─── Save ─────────────────────────────────────────────────────────────────────

def save(ip_baselines: dict, path: str, dry_run: bool) -> None:
    output = {
        "generated_at":       datetime.now().isoformat(),
        "min_flows_threshold": 0,  # filled in main
        "global_baseline":    GLOBAL_BASELINE,
        "ip_baselines":       ip_baselines,
    }

    if dry_run:
        print(f"\n🔵 DRY RUN — would write to: {path}")
        sample = {k: v for k, v in list(ip_baselines.items())[:2]}
        print(json.dumps(sample, indent=2))
        return

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    size = os.path.getsize(path) / 1024
    print(f"\n✅ Saved → {path}  ({size:.1f} KB)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    _MIN_DEFAULT = MIN_FLOWS_DEFAULT

    parser = argparse.ArgumentParser(
        description="Build per-IP baselines from baseline_*.csv (flow level)."
    )
    parser.add_argument("--days", type=int, default=None,
                        help="Use last N days (default: all)")
    parser.add_argument("--min-flows", type=int, default=_MIN_DEFAULT,
                        help=f"Min flows for per-IP baseline (default: {_MIN_DEFAULT})")
    parser.add_argument("--output", default=OUTPUT_PATH,
                        help=f"Output JSON (default: {OUTPUT_PATH})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print without saving")
    args = parser.parse_args()

    min_flows = args.min_flows

    print("=" * 58)
    print("  ip_baseline_builder.py  (source: baseline_*.csv)")
    print(f"  min_flows   = {min_flows}")
    print(f"  days        = {args.days or 'all'}")
    print("=" * 58)

    print("\n📂 Loading baseline data...")
    df = load_baselines(days=args.days)
    df = apply_noise_filter(df)
    print(f"   Unique src_ips: {df['src_ip'].nunique()}")

    print("\n🧮 Building per-IP baselines...")
    ip_baselines = build_ip_baselines(df, min_flows=min_flows)

    # Store threshold used
    for v in ip_baselines.values():
        pass  # already stored in each entry

    save(ip_baselines, args.output, dry_run=args.dry_run)

    # Summary
    per_ip  = sum(1 for v in ip_baselines.values() if v.get("use_per_ip"))
    global_ = sum(1 for v in ip_baselines.values() if not v.get("use_per_ip"))
    print(f"\n{'═'*58}")
    print(f"  📋 per-IP baseline : {per_ip} IPs")
    print(f"  🌐 global fallback : {global_} IPs")
    print(f"{'═'*58}")
    print("\n  Next:")
    print("  python scripts/ip_baseline_builder.py  (بدون --dry-run)")
    print("  python -c \"import baseline_loader; print(baseline_loader.summary())\"")


if __name__ == "__main__":
    main()
