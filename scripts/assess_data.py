#!/usr/bin/env python3
"""
NetGuard-AI Gateway — Data Assessment Script
يقيّم البيانات المجموعة ويعطي قرار: هل أنت جاهز للتدريب؟
الإصدار: 1.0
"""

import os
import sys
import glob
import json
import re
import argparse
import warnings
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

warnings.filterwarnings("ignore")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import pandas as pd
    import numpy as np
except ImportError:
    print("❌ تحتاج: pip install pandas numpy")
    sys.exit(1)

# ─────────────────────────────────────────────
# إعدادات
# ─────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
WINDOWS_DIR   = BASE_DIR / "data" / "windows"
MODELS_DIR    = BASE_DIR / "models" / "anomaly"
NETWORK_PROFILE = BASE_DIR / "config" / "network_profile.json"

# معايير القبول
MIN_DAYS          = 3
MIN_RECORDS       = 10_000
MIN_WINDOWS       = 5_000
MAX_GAP_HOURS     = 6       # فجوة مقبولة
MAX_NOISE_RATIO   = 0.05    # أقصى 5% ضوضاء بعد الفلتر
MAX_ANOMALY_RATE  = 0.15    # من معيار الاستثناء
MIN_INTEGRITY     = 7       # من معيار الاستثناء

NOISE_DST_IPS = {
    "224.0.0.251", "224.0.0.1",
    "192.168.68.255", "192.168.1.255", "255.255.255.255",
    "ff02::fb", "ff02::1:3", "ff02::1", "ff02::2", "ff02::16",
}
NOISE_PORTS = {137, 138, 139, 5353, 1900, 5355}

BANNED_FEATURES = {"Flow Bytes/s", "Flow Packets/s",
                   "flow_bytes_per_sec", "flow_packets_per_sec"}
REVIEW_FEATURE_PATTERNS = ("bytes_per_sec", "packets_per_sec")

SEPARATOR = "─" * 60

# ─────────────────────────────────────────────
# مساعدات
# ─────────────────────────────────────────────
def header(title):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)

def ok(msg):   print(f"  ✅  {msg}")
def warn(msg): print(f"  ⚠️   {msg}")
def err(msg):  print(f"  ❌  {msg}")
def info(msg): print(f"  ℹ️   {msg}")

FALLBACK_LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def load_monitored_networks() -> tuple:
    try:
        with NETWORK_PROFILE.open(encoding="utf-8") as f:
            profile = json.load(f)
    except Exception:
        return FALLBACK_LOCAL_NETWORKS

    candidates = []
    for key in ("monitored_networks", "trusted_networks"):
        value = profile.get(key)
        if isinstance(value, list):
            candidates.extend(str(item) for item in value)

    lan = profile.get("lan")
    if isinstance(lan, dict) and lan.get("cidr"):
        candidates.append(str(lan["cidr"]))

    networks = []
    for raw_network in candidates:
        try:
            network = ipaddress.ip_network(raw_network, strict=False)
        except ValueError:
            continue
        if network.is_private and network not in networks:
            networks.append(network)

    return tuple(networks) if networks else FALLBACK_LOCAL_NETWORKS


def monitored_networks_label() -> str:
    return ", ".join(str(network) for network in MONITORED_NETWORKS)


def is_monitored_ip(value) -> bool:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return any(address in network for network in MONITORED_NETWORKS)


MONITORED_NETWORKS = load_monitored_networks()

def load_baselines():
    files = sorted(glob.glob(str(PROCESSED_DIR / "baseline_*.csv")))
    if not files:
        return None, []
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            date_str = Path(f).stem.replace("baseline_", "")
            df["_source_file"] = date_str
            dfs.append(df)
        except Exception as e:
            warn(f"تعذّر قراءة {Path(f).name}: {e}")
    if not dfs:
        return None, []
    return pd.concat(dfs, ignore_index=True), files

def load_windows():
    daily_re = re.compile(r"windows_\d{4}-\d{2}-\d{2}\.csv$")
    files = [
        f for f in sorted(glob.glob(str(WINDOWS_DIR / "windows_*.csv")))
        if daily_re.search(Path(f).name)
    ]
    if not files:
        return None, []
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            date_str = Path(f).stem.replace("windows_", "")
            df["_source_file"] = date_str
            dfs.append(df)
        except Exception as e:
            warn(f"تعذّر قراءة {Path(f).name}: {e}")
    if not dfs:
        return None, []
    return pd.concat(dfs, ignore_index=True), files

# ─────────────────────────────────────────────
# 1. فحص الكمية
# ─────────────────────────────────────────────
def check_quantity(df_base, base_files, df_win, win_files):
    header("1 / الكمية والتغطية الزمنية")
    scores = []

    # أيام الـ baseline
    n_days = len(base_files)
    info(f"ملفات Baseline: {n_days} يوم")
    for f in base_files:
        info(f"  • {Path(f).name}")

    if n_days >= MIN_DAYS:
        ok(f"عدد الأيام: {n_days} ≥ {MIN_DAYS} المطلوب")
        scores.append(1)
    else:
        warn(f"عدد الأيام: {n_days} < {MIN_DAYS} المطلوب")
        scores.append(0)

    # عدد السجلات
    n_rec = len(df_base)
    info(f"إجمالي سجلات Baseline: {n_rec:,}")
    if n_rec >= MIN_RECORDS:
        ok(f"السجلات: {n_rec:,} ≥ {MIN_RECORDS:,} المطلوب")
        scores.append(1)
    else:
        warn(f"السجلات: {n_rec:,} < {MIN_RECORDS:,} المطلوب")
        scores.append(0)

    # عدد النوافذ
    if df_win is not None:
        n_win = len(df_win)
        info(f"إجمالي نوافذ Windows: {n_win:,}")
        if n_win >= MIN_WINDOWS:
            ok(f"النوافذ: {n_win:,} ≥ {MIN_WINDOWS:,} المطلوب")
            scores.append(1)
        else:
            warn(f"النوافذ: {n_win:,} < {MIN_WINDOWS:,} المطلوب")
            scores.append(0)
    else:
        warn("لا توجد ملفات Windows بعد — شغّل window_engine.py أولاً")
        scores.append(0)

    # توزيع يومي
    if "_source_file" in df_base.columns:
        per_day = df_base.groupby("_source_file").size()
        print()
        info("توزيع السجلات اليومي:")
        for day, cnt in per_day.items():
            flag = "✅" if cnt >= 1000 else "⚠️"
            print(f"    {flag} {day}: {cnt:,} سجل")

    return scores

# ─────────────────────────────────────────────
# 2. فحص الاستمرارية الزمنية
# ─────────────────────────────────────────────
def check_continuity(df_base):
    header("2 / الاستمرارية الزمننية (فجوات)")
    scores = []

    ts_col = None
    for c in ["ts", "timestamp", "start_time", "time"]:
        if c in df_base.columns:
            ts_col = c
            break

    if ts_col is None:
        warn("لا يوجد عمود timestamp — تخطّي فحص الفجوات")
        return [0]

    try:
        df_base[ts_col] = pd.to_numeric(df_base[ts_col], errors="coerce")
        ts = df_base[ts_col].dropna().sort_values()
        ts_dt = pd.to_datetime(ts, unit="s")

        gaps = ts_dt.diff().dropna()
        big_gaps = gaps[gaps > pd.Timedelta(hours=MAX_GAP_HOURS)]

        info(f"أول سجل: {ts_dt.iloc[0]}")
        info(f"آخر سجل: {ts_dt.iloc[-1]}")
        duration = ts_dt.iloc[-1] - ts_dt.iloc[0]
        info(f"المدة الكلية: {duration}")

        if len(big_gaps) == 0:
            ok(f"لا توجد فجوات > {MAX_GAP_HOURS} ساعة")
            scores.append(1)
        else:
            warn(f"فجوات كبيرة (>{MAX_GAP_HOURS}h): {len(big_gaps)}")
            for idx in big_gaps.nlargest(3).index:
                gap_val = big_gaps[idx]
                gap_time = ts_dt[idx]
                print(f"    ⚠️  {gap_time.date()} — فجوة {gap_val}")
            scores.append(0 if len(big_gaps) > 3 else 0.5)

    except Exception as e:
        warn(f"خطأ في تحليل الوقت: {e}")
        scores.append(0)

    return scores

# ─────────────────────────────────────────────
# 3. فحص الجودة (Integrity)
# ─────────────────────────────────────────────
def check_quality(df_base):
    header("3 / جودة البيانات")
    scores = []

    # نسبة القيم الفارغة
    null_ratio = df_base.isnull().mean()
    high_null = null_ratio[null_ratio > 0.1]
    if len(high_null) == 0:
        ok("لا توجد أعمدة بنسبة null > 10%")
        scores.append(1)
    else:
        warn(f"أعمدة بـ null عالي:")
        for col, ratio in high_null.items():
            print(f"    ⚠️  {col}: {ratio:.1%}")
        scores.append(0.5)

    # فحص Feature Leakage
    leaked = [c for c in df_base.columns if c in BANNED_FEATURES]
    if not leaked:
        ok("لا يوجد Feature Leakage")
        scores.append(1)
    else:
        err(f"Feature Leakage موجود: {leaked}")
        scores.append(0)

    # عدد الأعمدة
    info(f"عدد الأعمدة: {len(df_base.columns)}")

    # فحص الـ duplicates
    dup_ratio = df_base.duplicated().sum() / len(df_base)
    if dup_ratio < 0.01:
        ok(f"Duplicates: {dup_ratio:.2%} — مقبول")
        scores.append(1)
    else:
        warn(f"Duplicates: {dup_ratio:.2%} — مرتفع")
        scores.append(0.5)

    # فحص الأعمدة الرقمية للقيم اللانهائية
    numeric_cols = df_base.select_dtypes(include=[np.number]).columns
    inf_cols = []
    for c in numeric_cols:
        if np.isinf(df_base[c].replace([np.inf, -np.inf], np.nan).fillna(0)).any():
            inf_cols.append(c)
    # بديل أبسط:
    inf_mask = df_base[numeric_cols].isin([np.inf, -np.inf])
    inf_cols = inf_mask.columns[inf_mask.any()].tolist()

    if not inf_cols:
        ok("لا توجد قيم Inf في الأعمدة الرقمية")
        scores.append(1)
    else:
        warn(f"قيم Inf في: {inf_cols[:5]}")
        scores.append(0.5)

    return scores

# ─────────────────────────────────────────────
# 4. فحص الضوضاء
# ─────────────────────────────────────────────
def check_noise(df_base):
    header("4 / فحص الضوضاء (Noise Filter)")
    scores = []

    dst_col = None
    for c in ["id.resp_h", "dst_ip", "dst", "resp_h"]:
        if c in df_base.columns:
            dst_col = c
            break

    port_col = None
    for c in ["id.resp_p", "dst_port", "port", "resp_p"]:
        if c in df_base.columns:
            port_col = c
            break

    if dst_col:
        noise_ip = df_base[dst_col].isin(NOISE_DST_IPS).sum()
        noise_ratio = noise_ip / len(df_base)
        info(f"سجلات Noise IPs المتبقية: {noise_ip:,} ({noise_ratio:.2%})")
        if noise_ratio < MAX_NOISE_RATIO:
            ok("Noise Filter يعمل بشكل صحيح")
            scores.append(1)
        else:
            warn(f"نسبة ضوضاء مرتفعة: {noise_ratio:.2%} > {MAX_NOISE_RATIO:.0%}")
            scores.append(0)
    else:
        warn("لا يوجد عمود dst_ip — تخطّي فحص Noise")
        scores.append(0.5)

    if port_col:
        try:
            noise_port = df_base[port_col].astype(str).apply(
                lambda x: int(float(x)) if x.replace('.','').isdigit() else 0
            ).isin(NOISE_PORTS).sum()
            noise_port_ratio = noise_port / len(df_base)
            info(f"سجلات Noise Ports المتبقية: {noise_port:,} ({noise_port_ratio:.2%})")
            if noise_port_ratio < MAX_NOISE_RATIO:
                ok("Noise Ports محذوفة بشكل صحيح")
                scores.append(1)
            else:
                warn(f"منافذ ضوضاء متبقية: {noise_port_ratio:.2%}")
                scores.append(0)
        except Exception:
            scores.append(0.5)
    else:
        scores.append(0.5)

    return scores

# ─────────────────────────────────────────────
# 5. فحص توزيع الـ Features (Windows)
# ─────────────────────────────────────────────
def check_features(df_win):
    header("5 / توزيع الـ Features (Windows)")

    if df_win is None:
        warn("لا توجد ملفات Windows — شغّل window_engine.py أولاً")
        return [0]

    scores = []
    numeric_cols = df_win.select_dtypes(include=[np.number]).columns.tolist()
    
    # حذف أعمدة الوقت والـ flags
    exclude = {"ts", "timestamp", "window_start", "window_end"}
    feature_cols = [c for c in numeric_cols if c not in exclude]

    info(f"عدد الـ Feature Columns: {len(feature_cols)}")

    # فحص القيم الصفرية (أعمدة ميتة)
    zero_cols = []
    for c in feature_cols:
        if df_win[c].std() == 0:
            zero_cols.append(c)

    if not zero_cols:
        ok("لا توجد أعمدة بتباين صفري")
        scores.append(1)
    else:
        warn(f"أعمدة بتباين صفري ({len(zero_cols)}): {zero_cols[:5]}")
        scores.append(0.5)

    # إحصائيات أهم الـ features
    key_features = [c for c in feature_cols if any(
        k in c for k in ["connections", "bytes", "ports", "duration"]
    )][:6]

    if key_features:
        print()
        info("إحصائيات Features الرئيسية:")
        print(f"    {'Feature':<35} {'mean':>10} {'std':>10} {'p99':>10}")
        print(f"    {'─'*35} {'─'*10} {'─'*10} {'─'*10}")
        for c in key_features:
            col = df_win[c].replace([np.inf, -np.inf], np.nan).dropna()
            if len(col) > 0:
                print(f"    {c:<35} {col.mean():>10.2f} {col.std():>10.2f} {col.quantile(0.99):>10.2f}")

    # فحص الـ Flags
    flag_cols = [c for c in df_win.columns if c.startswith("flag_")]
    if flag_cols:
        print()
        info("معدل الـ Flags (يجب أن يكون قريباً من 0 في Baseline):")
        flag_ok = True
        for c in flag_cols:
            rate = df_win[c].mean() if df_win[c].dtype in [float, int] else (df_win[c] > 0).mean()
            flag = "✅" if rate < 0.05 else "⚠️"
            if rate >= 0.05:
                flag_ok = False
            print(f"    {flag} {c}: {rate:.2%}")
        scores.append(1 if flag_ok else 0.5)
    else:
        scores.append(0.5)

    return scores

# ─────────────────────────────────────────────
# 6. فحص per-IP windows
# ─────────────────────────────────────────────
def check_per_ip_windows(df_win):
    header("6 / per-IP Windows Readiness")

    if df_win is None:
        warn("لا توجد ملفات Windows — لا يمكن فحص per-IP")
        return [0]

    scores = []

    if "src_ip" not in df_win.columns:
        err("windows لا تحتوي src_ip — هذا يعني أن window_engine ليس v2.0/per-IP")
        return [0, 0]

    counts = df_win["src_ip"].dropna().astype(str).value_counts()
    monitored_mask = [is_monitored_ip(ip) for ip in counts.index]
    local_counts = counts[monitored_mask]

    info(f"عدد src_ip في windows: {counts.size}")
    info(f"عدد أجهزة LAN في windows ({monitored_networks_label()}): {local_counts.size}")

    if local_counts.size >= 2:
        ok("windows مبنية per-IP وليست network-wide")
        scores.append(1)
    else:
        warn("تنوع per-IP ضعيف — تحقق أن الأجهزة تمر عبر Gateway")
        scores.append(0.5 if local_counts.size == 1 else 0)

    print()
    info("أكثر الأجهزة ظهوراً في windows:")
    for ip, cnt in local_counts.head(10).items():
        marker = "✅" if cnt >= 100 else "⚠️"
        print(f"    {marker} {ip:<15} {cnt:>7,} نافذة")

    low_data = local_counts[local_counts < 100]
    if len(low_data) == 0:
        ok("كل أجهزة LAN لديها 100+ نافذة")
        scores.append(1)
    else:
        warn(f"أجهزة ببيانات قليلة (<100 نافذة): {len(low_data)}")
        scores.append(0.5)

    if "_source_file" in df_win.columns:
        per_day_ip = df_win.groupby("_source_file")["src_ip"].nunique()
        print()
        info("تنوع الأجهزة اليومي في windows:")
        for day, cnt in per_day_ip.items():
            marker = "✅" if cnt >= 2 else "⚠️"
            print(f"    {marker} {day}: {cnt} src_ip")

    return scores

# ─────────────────────────────────────────────
# 7. فحص عقد النموذج الحالي
# ─────────────────────────────────────────────
def check_model_contract():
    header("7 / Model Feature Contract")
    scores = []

    features_file = MODELS_DIR / "feature_names.json"
    if not features_file.exists():
        warn(f"لا يوجد feature_names.json: {features_file}")
        return [0.5]

    try:
        with open(features_file, encoding="utf-8") as f:
            feature_names = json.load(f)
    except Exception as e:
        warn(f"تعذر قراءة feature_names.json: {e}")
        return [0]

    info(f"IF feature count: {len(feature_names)}")

    review_features = [
        feat for feat in feature_names
        if any(pattern in feat for pattern in REVIEW_FEATURE_PATTERNS)
    ]

    if review_features:
        warn("Features تحتاج مراجعة قبل التدريب القادم:")
        for feat in review_features:
            print(f"    ⚠️  {feat}")
        info("لا نحذفها الآن بدون retraining، لكن يجب اختبار أثرها على FP/Recall.")
        scores.append(0.5)
    else:
        ok("لا توجد rate/throughput features مثيرة للالتباس في IF")
        scores.append(1)

    if "src_ip" in feature_names:
        err("src_ip موجود داخل model features — هذا Feature Leakage")
        scores.append(0)
    else:
        ok("src_ip غير داخل model features")
        scores.append(1)

    return scores

# ─────────────────────────────────────────────
# 8. فحص تنوع الشبكة (Gateway)
# ─────────────────────────────────────────────
def check_network_diversity(df_base):
    header("8 / تنوع الشبكة (Gateway Coverage)")
    scores = []

    src_col = None
    for c in ["id.orig_h", "src_ip", "src", "orig_h"]:
        if c in df_base.columns:
            src_col = c
            break

    if src_col:
        local_ips = df_base[src_col].dropna()
        lan_ips = local_ips[local_ips.astype(str).map(is_monitored_ip)]
        unique_lan = lan_ips.nunique()
        info(f"أجهزة LAN مرصودة ({monitored_networks_label()}): {unique_lan}")
        
        if unique_lan >= 2:
            ok(f"Gateway يرى {unique_lan} أجهزة — تنوع جيد")
            scores.append(1)
        elif unique_lan == 1:
            warn("جهاز واحد فقط — تأكد من اتصال الأجهزة عبر TP-Link")
            scores.append(0.5)
        else:
            err("لا يوجد أجهزة LAN مرصودة — تحقق من Zeek interface")
            scores.append(0)

        # أكثر الـ IPs نشاطاً
        top_ips = local_ips.value_counts().head(5)
        print()
        info("أكثر الـ IPs نشاطاً:")
        for ip, cnt in top_ips.items():
            print(f"    • {ip}: {cnt:,} اتصال")
    else:
        warn("لا يوجد عمود src_ip")
        scores.append(0.5)

    return scores

# ─────────────────────────────────────────────
# 9. القرار النهائي
# ─────────────────────────────────────────────
def final_decision(all_scores, df_base, df_win, base_files):
    header("9 / القرار النهائي")

    total = sum(all_scores)
    max_score = len(all_scores)
    pct = total / max_score if max_score > 0 else 0

    n_days = len(base_files)
    n_rec = len(df_base) if df_base is not None else 0
    n_win = len(df_win) if df_win is not None else 0

    print(f"\n  النتيجة الإجمالية: {total:.1f} / {max_score} ({pct:.0%})\n")

    # شروط حاسمة
    hard_fail = []
    if n_days < MIN_DAYS:
        hard_fail.append(f"الأيام {n_days} < {MIN_DAYS} المطلوبة")
    if n_rec < MIN_RECORDS:
        hard_fail.append(f"السجلات {n_rec:,} < {MIN_RECORDS:,} المطلوبة")
    if n_win < MIN_WINDOWS:
        hard_fail.append(f"النوافذ {n_win:,} < {MIN_WINDOWS:,} المطلوبة")

    if hard_fail:
        print("  ❌  غير جاهز للتدريب")
        print()
        for f in hard_fail:
            print(f"       • {f}")
        print()
        # تقدير الوقت المتبقي
        if n_days > 0 and n_rec > 0:
            rec_per_day = n_rec / n_days
            days_needed = max(0, MIN_DAYS - n_days)
            rec_needed  = max(0, MIN_RECORDS - n_rec)
            days_for_rec = int(np.ceil(rec_needed / rec_per_day)) if rec_per_day > 0 else "؟"
            wait_days = max(days_needed, days_for_rec if isinstance(days_for_rec, int) else 0)
            if wait_days > 0:
                ready_date = (datetime.now() + timedelta(days=wait_days)).strftime("%Y-%m-%d")
                info(f"التقدير: {wait_days} يوم إضافي — جاهز تقريباً في {ready_date}")

    elif pct >= 0.75:
        print("  ✅  جاهز للتدريب!")
        print()
        print("       الخطوة التالية:")
        print("       python scripts/anomaly_model.py --train --windows data/windows/...")
    else:
        print("  ⚠️   يمكن التدريب لكن البيانات تحتاج تحسين")
        print()
        print("       التوصية: أكمل جمع البيانات يوم إضافي ثم أعد التقييم")

    # ملخص سريع
    print()
    print("  ─── ملخص ───")
    print(f"  الأيام    : {n_days}")
    print(f"  السجلات   : {n_rec:,}")
    print(f"  النوافذ   : {n_win:,}")
    print(f"  الجاهزية  : {pct:.0%}")
    print()

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    global BASE_DIR, PROCESSED_DIR, WINDOWS_DIR, MODELS_DIR

    parser = argparse.ArgumentParser(description="NetGuard-AI Gateway — Data Assessment")
    parser.add_argument("--base-dir", default=str(BASE_DIR),
                        help="مسار المشروع. الافتراضي: root المستنتج من مكان السكربت")
    args = parser.parse_args()

    BASE_DIR = Path(args.base_dir).expanduser().resolve()
    PROCESSED_DIR = BASE_DIR / "data" / "processed"
    WINDOWS_DIR = BASE_DIR / "data" / "windows"
    MODELS_DIR = BASE_DIR / "models" / "anomaly"

    print()
    print("══════════════════════════════════════════════════════")
    print("   NetGuard-AI Gateway — Data Assessment v1.1")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Project: {BASE_DIR}")
    print("══════════════════════════════════════════════════════")

    # تحقق من المسارات
    if not PROCESSED_DIR.exists():
        print(f"\n❌ المسار غير موجود: {PROCESSED_DIR}")
        print("   تأكد من تشغيل collector.py أولاً")
        sys.exit(1)

    # تحميل البيانات
    print(f"\n  جاري تحميل البيانات من: {PROCESSED_DIR}")
    df_base, base_files = load_baselines()

    if df_base is None or len(base_files) == 0:
        print("\n❌ لا توجد ملفات Baseline!")
        print("   تأكد من: sudo systemctl status netguard-collector")
        sys.exit(1)

    print(f"  جاري تحميل النوافذ من: {WINDOWS_DIR}")
    df_win, win_files = load_windows()

    # تشغيل الفحوصات
    all_scores = []
    all_scores += check_quantity(df_base, base_files, df_win, win_files)
    all_scores += check_continuity(df_base)
    all_scores += check_quality(df_base)
    all_scores += check_noise(df_base)
    all_scores += check_features(df_win)
    all_scores += check_per_ip_windows(df_win)
    all_scores += check_model_contract()
    all_scores += check_network_diversity(df_base)

    # القرار
    final_decision(all_scores, df_base, df_win, base_files)


if __name__ == "__main__":
    main()
