#!/usr/bin/env python3
"""
window_engine.py — NetGuard-AI v1.1
Sliding Window Analysis على بيانات الشبكة
يحلل النمط الزمني بدل flow منفرد

الاستخدام:
  python scripts/window_engine.py
  python scripts/window_engine.py --input data/processed/baseline_2026-05-12.csv
  python scripts/window_engine.py --input data/processed/baseline_2026-05-12.csv \
                                   --output data/windows/windows_2026-05-12.csv
  python scripts/window_engine.py --live   # وضع المراقبة المستمرة

التغييرات v1.1:
  - إضافة filter_noise() — استثناء broadcast/multicast (NetBIOS, mDNS, SSDP)
  - إصلاح Port Entropy السالب (abs)
  - إضافة شرط unique_dst_ports > 1 على flag_brute_force
  - رفع threshold brute_force من 10 → 15
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

# ─── المسارات الافتراضية ──────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "processed"
WINDOWS_DIR = BASE_DIR / "data" / "windows"
LOGS_DIR    = BASE_DIR / "logs"

WINDOWS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ─── إعداد الـ Logging ───────────────────────────────────────────────────────
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

# ─── أحجام النوافذ الزمنية (بالثواني) ───────────────────────────────────────
WINDOWS = {
    "30s": 30,
    "1m":  60,
    "5m":  300,
}

# ─── حدود الكشف (معيَّرة لشبكة بيت — تُضبط بعد Live Testing) ────────────────
THRESHOLDS = {
    "port_scan_ports_30s":     15,   # >15 منفذ في 30s  → port scan
    "brute_force_failures_1m": 15,   # >15 فشل في 1m   → brute force
    "burst_connections_30s":   50,   # >50 اتصال في 30s → burst
    "dns_burst_1m":            30,   # >30 DNS في 1m    → dns flood
}

# ─── Noise Filter — Broadcast / Multicast طبيعي في أي شبكة ──────────────────
NOISE_DST_IPS = {
    "224.0.0.251",      # mDNS multicast IPv4
    "224.0.0.1",        # All hosts multicast
    "192.168.68.255", "192.168.1.255",   # Broadcast الشبكتين
    "255.255.255.255",  # Limited broadcast
    "ff02::fb",         # mDNS multicast IPv6
    "ff02::1:3",        # LLMNR IPv6
    "ff02::1",          # All nodes IPv6
    "ff02::2",          # All routers IPv6
}

NOISE_PORTS = {
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    139,   # NetBIOS Session
    5353,  # mDNS
    1900,  # SSDP (UPnP discovery)
    5355,  # LLMNR
}


def filter_noise(df: pd.DataFrame) -> pd.DataFrame:
    """
    إزالة broadcast/multicast من الحسابات.
    هذه ليست اتصالات حقيقية — بروتوكولات اكتشاف الشبكة الطبيعية.
    Zeek يسجلها كـ S0 لأنه لا يرى رداً (طبيعي في multicast).
    """
    if df.empty:
        return df
    if "dst_ip" in df.columns:
        df = df[~df["dst_ip"].isin(NOISE_DST_IPS)]
    if "dst_port" in df.columns:
        df = df[~df["dst_port"].isin(NOISE_PORTS)]
    return df


# ══════════════════════════════════════════════════════════════════════════════
# حساب الـ Features لنافذة زمنية واحدة
# ══════════════════════════════════════════════════════════════════════════════

def compute_port_entropy(ports: pd.Series) -> float:
    """
    حساب Shannon Entropy لتوزيع المنافذ.
    عشوائية عالية = Port Scan محتمل.
    النتيجة على [0, 1].
    """
    if ports.empty:
        return 0.0
    counts = ports.value_counts(normalize=True)
    entropy = abs(-sum(p * math.log2(p) for p in counts if p > 0))
    return round(entropy / math.log2(65535), 4)


def compute_burst_score(conn_times: pd.Series, window_sec: int) -> float:
    """
    قياس مدى الاندفاع في الاتصالات.
    0 = موزع بالتساوي (طبيعي) | 1 = كل شيء في لحظة واحدة (burst).
    """
    if len(conn_times) < 2:
        return 0.0
    times = conn_times.sort_values().values.astype(float)
    diffs = np.diff(times)
    if diffs.mean() == 0:
        return 0.0
    cv = diffs.std() / (diffs.mean() + 1e-9)
    return round(min(cv / 10, 1.0), 4)


def features_for_window(df_win: pd.DataFrame, window_name: str, window_sec: int) -> dict:
    """
    استخراج جميع الـ features لنافذة زمنية واحدة.
    المدخل  : df_win — الصفوف داخل النافذة (بعد filter_noise)
    المخرج  : dict بجميع الـ features
    """
    FEATURE_KEYS = [
        "connections", "unique_dst_ports", "unique_dst_ips",
        "failed_conn_rate", "dns_rate", "avg_conn_duration",
        "outbound_ratio", "bytes_per_sec", "port_entropy",
        "burst_score", "conn_rate_per_ip", "unique_ports_per_ip"
    ]
    suffix = f"_{window_name}"

    if df_win.empty:
        return {f"{k}{suffix}": 0 for k in FEATURE_KEYS}

    n = len(df_win)
    feats = {}

    # ── 1. عدد الاتصالات ─────────────────────────────────────────────────────
    feats[f"connections{suffix}"] = n

    # ── 2. تنوع المنافذ المستهدفة ─────────────────────────────────────────────
    feats[f"unique_dst_ports{suffix}"] = int(
        df_win["dst_port"].nunique() if "dst_port" in df_win.columns else 0
    )

    # ── 3. تنوع الـ IPs المستهدفة ────────────────────────────────────────────
    feats[f"unique_dst_ips{suffix}"] = int(
        df_win["dst_ip"].nunique() if "dst_ip" in df_win.columns else 0
    )

    # ── 4. نسبة الاتصالات الفاشلة ────────────────────────────────────────────
    failed_cols = [c for c in ["conn_state_REJ", "conn_state_S0"] if c in df_win.columns]
    if failed_cols:
        failed = df_win[failed_cols].sum(axis=1).gt(0).sum()
        feats[f"failed_conn_rate{suffix}"] = round(float(failed) / n, 4)
    else:
        feats[f"failed_conn_rate{suffix}"] = 0.0

    # ── 5. معدل طلبات DNS (بالثانية) ─────────────────────────────────────────
    if "is_dns" in df_win.columns:
        feats[f"dns_rate{suffix}"] = round(float(df_win["is_dns"].sum()) / window_sec, 4)
    else:
        feats[f"dns_rate{suffix}"] = 0.0

    # ── 6. متوسط مدة الاتصال ─────────────────────────────────────────────────
    if "duration" in df_win.columns:
        feats[f"avg_conn_duration{suffix}"] = round(
            float(df_win["duration"].clip(lower=0).mean()), 4
        )
    else:
        feats[f"avg_conn_duration{suffix}"] = 0.0

    # ── 7. نسبة الحركة الخارجية ──────────────────────────────────────────────
    if "is_external" in df_win.columns:
        feats[f"outbound_ratio{suffix}"] = round(float(df_win["is_external"].mean()), 4)
    else:
        feats[f"outbound_ratio{suffix}"] = 0.0

    # ── 8. معدل البيانات (bytes/sec) ─────────────────────────────────────────
    byte_cols = [c for c in ["orig_bytes", "resp_bytes"] if c in df_win.columns]
    if byte_cols:
        total_bytes = float(df_win[byte_cols].fillna(0).sum(axis=1).sum())
        feats[f"bytes_per_sec{suffix}"] = round(total_bytes / window_sec, 2)
    else:
        feats[f"bytes_per_sec{suffix}"] = 0.0

    # ── 9. Port Entropy ───────────────────────────────────────────────────────
    if "dst_port" in df_win.columns:
        feats[f"port_entropy{suffix}"] = compute_port_entropy(
            df_win["dst_port"].dropna()
        )
    else:
        feats[f"port_entropy{suffix}"] = 0.0

    # ── 10. Burst Score ───────────────────────────────────────────────────────
    if "ts" in df_win.columns:
        feats[f"burst_score{suffix}"] = compute_burst_score(df_win["ts"], window_sec)
    else:
        feats[f"burst_score{suffix}"] = 0.0

    # ── 11. معدل اتصالات أعلى src_ip في النافذة ──────────────────────────────
    if "src_ip" in df_win.columns:
        ip_counts = df_win["src_ip"].value_counts()
        feats[f"conn_rate_per_ip{suffix}"] = round(float(ip_counts.max()) / window_sec, 4)
    else:
        feats[f"conn_rate_per_ip{suffix}"] = 0.0

    # ── 12. أكبر عدد منافذ فريدة لـ src_ip واحد ─────────────────────────────
    if "src_ip" in df_win.columns and "dst_port" in df_win.columns:
        ports_per_ip = df_win.groupby("src_ip")["dst_port"].nunique()
        feats[f"unique_ports_per_ip{suffix}"] = int(ports_per_ip.max())
    else:
        feats[f"unique_ports_per_ip{suffix}"] = 0

    return feats


# ══════════════════════════════════════════════════════════════════════════════
# المعالج الرئيسي
# ══════════════════════════════════════════════════════════════════════════════

def process_dataframe(df: pd.DataFrame, step_sec: int = 30) -> pd.DataFrame:
    """
    يأخذ DataFrame من بيانات الـ baseline ويُخرج DataFrame
    بـ features النوافذ الزمنية.
    step_sec : خطوة الإزاحة بين النوافذ (افتراضي 30s)
    """
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

    log.info(f"📊 البيانات: {len(df)} سجل")
    log.info(f"⏱️  الفترة: {duration_min:.1f} دقيقة "
             f"({datetime.fromtimestamp(t_start).strftime('%Y-%m-%d %H:%M:%S')} → "
             f"{datetime.fromtimestamp(t_end).strftime('%Y-%m-%d %H:%M:%S')})")

    # إحصاء الـ noise
    df_clean    = filter_noise(df.copy())
    noise_count = len(df) - len(df_clean)
    if noise_count > 0:
        log.info(f"🔇 استثناء {noise_count} سجل noise (broadcast/multicast) من الحسابات")

    results    = []
    window_max = max(WINDOWS.values())
    t_current  = t_start + window_max

    while t_current <= t_end + step_sec:
        row = {
            "ts":       t_current,
            "datetime": datetime.fromtimestamp(t_current).strftime("%Y-%m-%d %H:%M:%S"),
        }

        for win_name, win_sec in WINDOWS.items():
            t_win_start = t_current - win_sec
            df_win      = df[(df["ts"] >= t_win_start) & (df["ts"] < t_current)].copy()
            df_win      = filter_noise(df_win)
            feats       = features_for_window(df_win, win_name, win_sec)
            row.update(feats)

        # ── Flags الكشف ───────────────────────────────────────────────────────
        row["flag_port_scan"] = int(
            row.get("unique_dst_ports_30s", 0) > THRESHOLDS["port_scan_ports_30s"]
        )
        row["flag_brute_force"] = int(
            row.get("failed_conn_rate_1m", 0) * row.get("connections_1m", 0)
            > THRESHOLDS["brute_force_failures_1m"]
            and row.get("unique_dst_ports_1m", 0) > 1
        )
        row["flag_burst"] = int(
            row.get("connections_30s", 0) > THRESHOLDS["burst_connections_30s"]
        )
        row["flag_dns_flood"] = int(
            row.get("dns_rate_1m", 0) * 60 > THRESHOLDS["dns_burst_1m"]
        )
        row["flag_any"] = int(
            row["flag_port_scan"] or row["flag_brute_force"]
            or row["flag_burst"]  or row["flag_dns_flood"]
        )

        results.append(row)
        t_current += step_sec

    df_out = pd.DataFrame(results)
    log.info(f"✅ تم إنشاء {len(df_out)} نافذة زمنية")

    flagged = int(df_out["flag_any"].sum()) if "flag_any" in df_out.columns else 0
    if flagged > 0:
        log.warning(f"⚠️  نوافذ مشبوهة: {flagged} / {len(df_out)}")
        for flag in ["flag_port_scan", "flag_brute_force", "flag_burst", "flag_dns_flood"]:
            count = int(df_out[flag].sum())
            if count:
                log.warning(f"   {flag}: {count}")
    else:
        log.info("🟢 لا أنماط مشبوهة — Baseline نظيف")

    return df_out


# ══════════════════════════════════════════════════════════════════════════════
# وضع المراقبة المستمرة
# ══════════════════════════════════════════════════════════════════════════════

def live_mode():
    """مراقبة مستمرة — يقرأ baseline اليوم كل 30 ثانية"""
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
            df_windows = process_dataframe(df, step_sec=30)

            if not df_windows.empty:
                last = df_windows.iloc[-1]
                print(f"\n{'='*55}")
                print(f"🕐 {last['datetime']}")
                print(f"   الاتصالات  30s: {last.get('connections_30s', 0):.0f} | "
                      f"1m: {last.get('connections_1m', 0):.0f} | "
                      f"5m: {last.get('connections_5m', 0):.0f}")
                print(f"   منافذ مختلفة : {last.get('unique_dst_ports_30s', 0):.0f} (30s)")
                print(f"   Port Entropy  : {last.get('port_entropy_30s', 0):.3f}")
                print(f"   Burst Score   : {last.get('burst_score_30s', 0):.3f}")
                print(f"   bytes/sec     : {last.get('bytes_per_sec_30s', 0):.1f}")
                print(f"   conn/IP/sec   : {last.get('conn_rate_per_ip_30s', 0):.3f}")
                flags = [k for k in ["flag_port_scan", "flag_brute_force",
                                     "flag_burst", "flag_dns_flood"]
                         if last.get(k, 0)]
                print(f"   {'⚠️  FLAGS: ' + ', '.join(flags) if flags else '✅ طبيعي'}")

        except Exception as e:
            log.error(f"❌ خطأ: {e}")

        time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetGuard-AI — Window Engine v1.1")
    parser.add_argument("--input",  "-i", default=None,
                        help="ملف CSV للمعالجة (افتراضي: baseline اليوم)")
    parser.add_argument("--output", "-o", default=None,
                        help="ملف CSV للحفظ (افتراضي: data/windows/windows_YYYY-MM-DD.csv)")
    parser.add_argument("--live",   "-l", action="store_true",
                        help="وضع المراقبة المستمرة")
    parser.add_argument("--step",   type=int, default=30,
                        help="خطوة الإزاحة بين النوافذ بالثواني (افتراضي: 30)")
    args = parser.parse_args()

    if args.live:
        live_mode()
        return

    input_file = Path(args.input) if args.input else \
                 DATA_DIR / f"baseline_{datetime.now().strftime('%Y-%m-%d')}.csv"

    if not input_file.exists():
        log.error(f"❌ الملف غير موجود: {input_file}")
        sys.exit(1)

    log.info(f"📂 قراءة: {input_file.name}")

    try:
        df = pd.read_csv(input_file)
        log.info(f"✅ تم تحميل {len(df)} سجل | {df.shape[1]} عمود")
    except Exception as e:
        log.error(f"❌ خطأ في القراءة: {e}")
        sys.exit(1)

    df_windows = process_dataframe(df, step_sec=args.step)

    if df_windows.empty:
        log.error("❌ لم تُنتج أي نوافذ")
        sys.exit(1)

    if args.output:
        output_file = Path(args.output)
        output_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_file = WINDOWS_DIR / f"windows_{datetime.now().strftime('%Y-%m-%d')}.csv"

    df_windows.to_csv(output_file, index=False)
    log.info(f"💾 تم الحفظ: {output_file}")
    log.info(f"   الأعمدة: {df_windows.shape[1]} | الصفوف: {len(df_windows)}")

    print("\n" + "="*55)
    print("📊 ملخص النوافذ الزمنية")
    print("="*55)
    for win in WINDOWS:
        col = f"connections_{win}"
        if col in df_windows.columns:
            print(f"  {win:4s} → متوسط: {df_windows[col].mean():.1f} | "
                  f"أقصى: {df_windows[col].max():.0f}")
    print("="*55)
    for feat in ["unique_dst_ports_30s", "port_entropy_30s", "burst_score_30s",
                 "bytes_per_sec_30s", "conn_rate_per_ip_30s", "unique_ports_per_ip_30s"]:
        if feat in df_windows.columns:
            print(f"  {feat:38s}: "
                  f"mean={df_windows[feat].mean():.3f} | "
                  f"max={df_windows[feat].max():.3f}")
    print("="*55)


if __name__ == "__main__":
    main()
