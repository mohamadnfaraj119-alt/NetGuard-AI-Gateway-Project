#!/usr/bin/env python3
"""
window_engine.py — NetGuard-AI v2.0
Sliding Window Analysis — Per-IP Mode

التغييرات v2.0:
  - per-IP windowing: نافذة لكل src_ip منفصلاً (بدل الشبكة كلها)
  - إضافة عمود src_ip في الـ output
  - get_local_ips(): تلقائي من بيانات الشبكة — لا hardcode
  - --network-wide: للتوافق مع الإصدار القديم فقط
  - IF يحتاج إعادة تدريب بعد هذا التغيير

الاستخدام:
  python scripts/window_engine.py
  python scripts/window_engine.py --input data/processed/baseline_2026-06-08.csv
  python scripts/window_engine.py --live
  python scripts/window_engine.py --network-wide   # وضع قديم للتوافق فقط

v1.1 (محتفظ):
  - filter_noise() — استثناء broadcast/multicast
  - إصلاح Port Entropy السالب
  - شرط unique_dst_ports > 1 على flag_brute_force
  - brute_force threshold: 10 → 15
"""

import argparse
import logging
import math
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "processed"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
LOGS_DIR    = BASE_DIR / "logs"

WINDOWS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "window_engine.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ─── أحجام النوافذ (ثواني) ───────────────────────────────────────────────────
WINDOWS = {
    "30s": 30,
    "1m":  60,
    "5m":  300,
}

# ─── Thresholds (معيَّرة — قاعدة ثابتة) ──────────────────────────────────────
THRESHOLDS = {
    "port_scan_ports_30s":     15,
    "brute_force_failures_1m": 15,
    "burst_connections_30s":   90,
    "dns_burst_1m":            120,
}

# ─── Noise Filter (قاعدة ثابتة — في كل script) ───────────────────────────────
NOISE_DST_IPS = {
    "224.0.0.251", "224.0.0.1",
    "192.168.68.255", "192.168.1.255", "255.255.255.255",
    "ff02::fb", "ff02::1:3", "ff02::1", "ff02::2", "ff02::16",
}
NOISE_PORTS = {137, 138, 139, 5353, 1900, 5355}

# ─── LAN prefix — أجهزة المنزل فقط ─────────────────────────────────────────
LAN_PREFIX = "192.168.1."


# ══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════════════════

def filter_noise(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    if "dst_ip" in df.columns:
        df = df[~df["dst_ip"].isin(NOISE_DST_IPS)]
    if "dst_port" in df.columns:
        df = df[~df["dst_port"].isin(NOISE_PORTS)]
    return df


def get_local_ips(df: pd.DataFrame) -> list[str]:
    """
    يستخرج IPs الأجهزة المحلية (192.168.1.x) من البيانات تلقائياً.
    لا hardcode — القاعدة 19 في الوثيقة.
    """
    if "src_ip" not in df.columns:
        return []
    all_ips = df["src_ip"].dropna().unique()
    local   = [ip for ip in all_ips if str(ip).startswith(LAN_PREFIX)]
    return sorted(local)


def compute_port_entropy(ports: pd.Series) -> float:
    if ports.empty:
        return 0.0
    counts  = ports.value_counts(normalize=True)
    entropy = abs(-sum(p * math.log2(p) for p in counts if p > 0))
    return round(entropy / math.log2(65535), 4)


def compute_burst_score(conn_times: pd.Series, window_sec: int) -> float:
    if len(conn_times) < 2:
        return 0.0
    times = conn_times.sort_values().values.astype(float)
    diffs = np.diff(times)
    if diffs.mean() == 0:
        return 0.0
    cv = diffs.std() / (diffs.mean() + 1e-9)
    return round(min(cv / 10, 1.0), 4)


# ══════════════════════════════════════════════════════════════════════════════
# Features لنافذة واحدة (بدون تغيير من v1.1)
# ══════════════════════════════════════════════════════════════════════════════

def features_for_window(df_win: pd.DataFrame, window_name: str, window_sec: int) -> dict:
    FEATURE_KEYS = [
        "connections", "unique_dst_ports", "unique_dst_ips",
        "failed_conn_rate", "dns_rate", "avg_conn_duration",
        "outbound_ratio", "bytes_per_sec", "port_entropy",
        "burst_score", "conn_rate_per_ip", "unique_ports_per_ip"
    ]
    suffix = f"_{window_name}"

    if df_win.empty:
        return {f"{k}{suffix}": 0 for k in FEATURE_KEYS}

    n     = len(df_win)
    feats = {}

    feats[f"connections{suffix}"] = n

    feats[f"unique_dst_ports{suffix}"] = int(
        df_win["dst_port"].nunique() if "dst_port" in df_win.columns else 0
    )

    feats[f"unique_dst_ips{suffix}"] = int(
        df_win["dst_ip"].nunique() if "dst_ip" in df_win.columns else 0
    )

    failed_cols = [c for c in ["conn_state_REJ", "conn_state_S0"] if c in df_win.columns]
    if failed_cols:
        failed = df_win[failed_cols].sum(axis=1).gt(0).sum()
        feats[f"failed_conn_rate{suffix}"] = round(float(failed) / n, 4)
    else:
        feats[f"failed_conn_rate{suffix}"] = 0.0

    if "is_dns" in df_win.columns:
        feats[f"dns_rate{suffix}"] = round(float(df_win["is_dns"].sum()) / window_sec, 4)
    else:
        feats[f"dns_rate{suffix}"] = 0.0

    if "duration" in df_win.columns:
        feats[f"avg_conn_duration{suffix}"] = round(
            float(df_win["duration"].clip(lower=0).mean()), 4
        )
    else:
        feats[f"avg_conn_duration{suffix}"] = 0.0

    if "is_external" in df_win.columns:
        feats[f"outbound_ratio{suffix}"] = round(float(df_win["is_external"].mean()), 4)
    else:
        feats[f"outbound_ratio{suffix}"] = 0.0

    byte_cols = [c for c in ["orig_bytes", "resp_bytes"] if c in df_win.columns]
    if byte_cols:
        total_bytes = float(df_win[byte_cols].fillna(0).sum(axis=1).sum())
        feats[f"bytes_per_sec{suffix}"] = round(total_bytes / window_sec, 2)
    else:
        feats[f"bytes_per_sec{suffix}"] = 0.0

    if "dst_port" in df_win.columns:
        feats[f"port_entropy{suffix}"] = compute_port_entropy(
            df_win["dst_port"].dropna()
        )
    else:
        feats[f"port_entropy{suffix}"] = 0.0

    if "ts" in df_win.columns:
        feats[f"burst_score{suffix}"] = compute_burst_score(df_win["ts"], window_sec)
    else:
        feats[f"burst_score{suffix}"] = 0.0

    if "src_ip" in df_win.columns:
        ip_counts = df_win["src_ip"].value_counts()
        feats[f"conn_rate_per_ip{suffix}"] = round(float(ip_counts.max()) / window_sec, 4)
    else:
        feats[f"conn_rate_per_ip{suffix}"] = 0.0

    if "src_ip" in df_win.columns and "dst_port" in df_win.columns:
        ports_per_ip = df_win.groupby("src_ip")["dst_port"].nunique()
        feats[f"unique_ports_per_ip{suffix}"] = int(ports_per_ip.max())
    else:
        feats[f"unique_ports_per_ip{suffix}"] = 0

    return feats


def compute_flags(row: dict) -> dict:
    """Flags الكشف — مشتركة بين per-IP و network-wide."""
    flags = {}
    flags["flag_port_scan"] = int(
        row.get("unique_dst_ports_30s", 0) > THRESHOLDS["port_scan_ports_30s"]
    )
    total_failures   = row.get("failed_conn_rate_1m", 0) * row.get("connections_1m", 0)
    unique_dst       = max(row.get("unique_dst_ips_1m", 1), 1)
    failures_per_dst = total_failures / unique_dst
    flags["flag_brute_force"] = int(
        failures_per_dst > 15          # رُفع من 8 → 15
        and unique_dst <= 3            # هجوم مركّز على هدف محدد جداً
        and row.get("unique_dst_ports_1m", 0) > 1
    )
    flags["flag_burst"] = int(
        row.get("connections_30s", 0) > THRESHOLDS["burst_connections_30s"]
    )
    flags["flag_dns_flood"] = int(
        row.get("dns_rate_1m", 0) * 60 > THRESHOLDS["dns_burst_1m"]
    )
    flags["flag_any"] = int(
        flags["flag_port_scan"] or flags["flag_brute_force"]
        or flags["flag_burst"]  or flags["flag_dns_flood"]
    )
    return flags


# ══════════════════════════════════════════════════════════════════════════════
# Per-IP Processing (v2.0 — الجديد)
# ══════════════════════════════════════════════════════════════════════════════

def process_single_ip(df_ip: pd.DataFrame, ip: str, step_sec: int = 30) -> pd.DataFrame:
    """
    يبني نوافذ زمنية لـ IP واحد فقط.
    نفس منطق v1.1 لكن على بيانات IP منفرد.
    """
    t_start   = df_ip["ts"].min()
    t_end     = df_ip["ts"].max()
    window_max = max(WINDOWS.values())
    t_current  = t_start + window_max

    results = []
    while t_current <= t_end + step_sec:
        row = {
            "ts":       t_current,
            "datetime": datetime.fromtimestamp(t_current).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":   ip,
        }

        for win_name, win_sec in WINDOWS.items():
            t_win_start = t_current - win_sec
            df_win      = df_ip[
                (df_ip["ts"] >= t_win_start) & (df_ip["ts"] < t_current)
            ].copy()
            df_win = filter_noise(df_win)
            row.update(features_for_window(df_win, win_name, win_sec))

        row.update(compute_flags(row))
        results.append(row)
        t_current += step_sec

    return pd.DataFrame(results)


def process_per_ip(df: pd.DataFrame, step_sec: int = 30) -> pd.DataFrame:
    """
    يبني نوافذ لكل IP محلي منفصلاً ثم يجمعها.
    الـ output يحتوي عمود src_ip — مطلوب لـ risk_engine و IF.
    """
    local_ips = get_local_ips(df)

    if not local_ips:
        log.error("❌ لم يُعثر على IPs محلية (192.168.1.x) في البيانات")
        return pd.DataFrame()

    log.info(f"🖥  أجهزة محلية مكتشفة: {len(local_ips)}")
    for ip in local_ips:
        n = len(df[df["src_ip"] == ip])
        log.info(f"   {ip}: {n:,} flow")

    all_frames = []
    for ip in local_ips:
        df_ip = df[df["src_ip"] == ip].copy()
        df_ip = df_ip.sort_values("ts").reset_index(drop=True)

        if len(df_ip) < 10:
            log.warning(f"   ⚠  {ip}: flows قليلة ({len(df_ip)}) — تجاهل")
            continue

        df_windows = process_single_ip(df_ip, ip, step_sec)
        all_frames.append(df_windows)
        log.info(f"   ✅ {ip}: {len(df_windows)} نافذة")

    if not all_frames:
        return pd.DataFrame()

    combined = pd.concat(all_frames, ignore_index=True)
    combined = combined.sort_values(["ts", "src_ip"]).reset_index(drop=True)
    return combined


# ══════════════════════════════════════════════════════════════════════════════
# Network-Wide Processing (v1.1 — للتوافق فقط)
# ══════════════════════════════════════════════════════════════════════════════

def process_network_wide(df: pd.DataFrame, step_sec: int = 30) -> pd.DataFrame:
    """وضع الشبكة الكاملة — v1.1 — لا يُستخدم إلا للمقارنة."""
    log.warning("⚠️  وضع network-wide — للتوافق فقط. استخدم per-IP للإنتاج.")

    t_start    = df["ts"].min()
    t_end      = df["ts"].max()
    window_max = max(WINDOWS.values())
    t_current  = t_start + window_max
    results    = []

    while t_current <= t_end + step_sec:
        row = {
            "ts":       t_current,
            "datetime": datetime.fromtimestamp(t_current).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for win_name, win_sec in WINDOWS.items():
            t_win_start = t_current - win_sec
            df_win      = df[(df["ts"] >= t_win_start) & (df["ts"] < t_current)].copy()
            df_win      = filter_noise(df_win)
            row.update(features_for_window(df_win, win_name, win_sec))
        row.update(compute_flags(row))
        results.append(row)
        t_current += step_sec

    return pd.DataFrame(results)


# ══════════════════════════════════════════════════════════════════════════════
# process_dataframe — نقطة الدخول الموحدة
# ══════════════════════════════════════════════════════════════════════════════

def process_dataframe(df: pd.DataFrame, step_sec: int = 30,
                      per_ip: bool = True) -> pd.DataFrame:
    if df.empty:
        log.warning("⚠️  DataFrame فارغ")
        return pd.DataFrame()
    if "ts" not in df.columns:
        log.error("❌ العمود 'ts' غير موجود")
        return pd.DataFrame()

    df = df.copy()
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)

    t_start      = df["ts"].min()
    t_end        = df["ts"].max()
    duration_min = (t_end - t_start) / 60

    log.info(f"📊 البيانات: {len(df):,} سجل")
    log.info(f"⏱️  الفترة: {duration_min:.1f} دقيقة "
             f"({datetime.fromtimestamp(t_start).strftime('%Y-%m-%d %H:%M:%S')} → "
             f"{datetime.fromtimestamp(t_end).strftime('%Y-%m-%d %H:%M:%S')})")

    noise_before = len(df)
    df_check     = filter_noise(df.copy())
    noise_count  = noise_before - len(df_check)
    if noise_count:
        log.info(f"🔇 {noise_count:,} سجل noise (broadcast/multicast)")

    if per_ip:
        df_out = process_per_ip(df, step_sec)
    else:
        df_out = process_network_wide(df, step_sec)

    if df_out.empty:
        return df_out

    log.info(f"✅ تم إنشاء {len(df_out):,} نافذة زمنية")

    flagged = int(df_out["flag_any"].sum()) if "flag_any" in df_out.columns else 0
    if flagged:
        log.warning(f"⚠️  نوافذ مشبوهة: {flagged} / {len(df_out)}")
        for flag in ["flag_port_scan", "flag_brute_force", "flag_burst", "flag_dns_flood"]:
            count = int(df_out[flag].sum())
            if count:
                log.warning(f"   {flag}: {count}")
    else:
        log.info("🟢 لا أنماط مشبوهة")

    return df_out


# ══════════════════════════════════════════════════════════════════════════════
# Live Mode
# ══════════════════════════════════════════════════════════════════════════════

def live_mode(per_ip: bool = True):
    log.info("🔴 وضع المراقبة المستمرة — Ctrl+C للإيقاف")

    while True:
        today      = datetime.now().strftime("%Y-%m-%d")
        input_file = DATA_DIR / f"baseline_{today}.csv"

        if not input_file.exists():
            log.warning(f"⏳ في انتظار: {input_file.name}")
            time.sleep(30)
            continue

        try:
            df         = pd.read_csv(input_file)
            df_windows = process_dataframe(df, step_sec=30, per_ip=per_ip)

            if df_windows.empty:
                time.sleep(30)
                continue

            # آخر نافذة لكل IP
            last_rows = df_windows.sort_values("ts").groupby("src_ip").last()
            print(f"\n{'='*60}")
            print(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            for ip, last in last_rows.iterrows():
                flags = [k for k in ["flag_port_scan", "flag_brute_force",
                                     "flag_burst", "flag_dns_flood"]
                         if last.get(k, 0)]
                status = "⚠️  " + ", ".join(flags) if flags else "✅"
                print(f"  {ip:<18} conn={last.get('connections_30s',0):>4.0f} "
                      f"dns={last.get('dns_rate_1m',0):>5.1f}/m  {status}")

        except Exception as e:
            log.error(f"❌ {e}")

        time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetGuard-AI — Window Engine v2.0")
    parser.add_argument("--input",  "-i", default=None)
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument("--live",   "-l", action="store_true")
    parser.add_argument("--step",   type=int, default=30)
    parser.add_argument("--network-wide", action="store_true",
                        help="وضع الشبكة الكاملة (v1.1) — للتوافق فقط")
    args = parser.parse_args()

    per_ip = not args.network_wide

    if args.live:
        live_mode(per_ip=per_ip)
        return

    input_file = Path(args.input) if args.input else \
                 DATA_DIR / f"baseline_{datetime.now().strftime('%Y-%m-%d')}.csv"

    if not input_file.exists():
        log.error(f"❌ الملف غير موجود: {input_file}")
        sys.exit(1)

    log.info(f"📂 قراءة: {input_file.name}")
    log.info(f"🔧 الوضع: {'per-IP ✅' if per_ip else 'network-wide (legacy)'}")

    try:
        df = pd.read_csv(input_file)
        log.info(f"✅ تم تحميل {len(df):,} سجل | {df.shape[1]} عمود")
    except Exception as e:
        log.error(f"❌ خطأ في القراءة: {e}")
        sys.exit(1)

    df_windows = process_dataframe(df, step_sec=args.step, per_ip=per_ip)

    if df_windows.empty:
        log.error("❌ لم تُنتج أي نوافذ")
        sys.exit(1)

    output_file = Path(args.output) if args.output else \
                  WINDOWS_DIR / f"windows_{datetime.now().strftime('%Y-%m-%d')}.csv"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df_windows.to_csv(output_file, index=False)

    log.info(f"💾 تم الحفظ: {output_file}")
    log.info(f"   الأعمدة: {df_windows.shape[1]} | الصفوف: {len(df_windows):,}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"📊 ملخص النوافذ — {'per-IP' if per_ip else 'network-wide'}")
    print(f"{'='*60}")

    if per_ip and "src_ip" in df_windows.columns:
        for ip, grp in df_windows.groupby("src_ip"):
            flags = int(grp["flag_any"].sum()) if "flag_any" in grp.columns else 0
            c_max = grp["connections_30s"].max() if "connections_30s" in grp.columns else 0
            c_avg = grp["connections_30s"].mean() if "connections_30s" in grp.columns else 0
            print(f"  {ip:<18}  نوافذ={len(grp):>5}  "
                  f"conn avg={c_avg:>5.1f} max={c_max:>5.0f}  "
                  f"{'⚠️  flags='+str(flags) if flags else '✅ نظيف'}")
    else:
        for win in WINDOWS:
            col = f"connections_{win}"
            if col in df_windows.columns:
                print(f"  {win}: avg={df_windows[col].mean():.1f} "
                      f"max={df_windows[col].max():.0f}")

    print(f"{'='*60}")
    total_flags = int(df_windows["flag_any"].sum()) if "flag_any" in df_windows.columns else 0
    print(f"  إجمالي النوافذ المشبوهة: {total_flags} / {len(df_windows)}")
    print(f"{'='*60}")

    if per_ip:
        print("\n  ⚠️  تذكير: IF يحتاج إعادة تدريب على البيانات الجديدة")
        print("  python scripts/assess_data.py")
        print("  python scripts/anomaly_model.py --train --windows ...")


if __name__ == "__main__":
    main()
