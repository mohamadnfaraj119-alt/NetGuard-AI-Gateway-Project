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
import warnings
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

warnings.filterwarnings("ignore")

try:
    import pandas as pd
    import numpy as np
except ImportError:
    print("❌ تحتاج: pip install pandas numpy")
    sys.exit(1)

# ─────────────────────────────────────────────
# إعدادات
# ─────────────────────────────────────────────
BASE_DIR = Path.home() / "zeek-ids"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
WINDOWS_DIR   = BASE_DIR / "data" / "windows"

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
    files = sorted(glob.glob(str(WINDOWS_DIR / "windows_*.csv")))
    if not files:
        return None, []
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
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
    exclude = {"ts", "timestamp", "window_start", "window_end",
               "port_scan", "brute_force", "dns_exfil", "data_exfil", "syn_flood"}
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
    flag_cols = [c for c in df_win.columns if c in
                 {"port_scan", "brute_force", "dns_exfil", "data_exfil", "syn_flood"}]
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
# 6. فحص تنوع الشبكة (Gateway)
# ─────────────────────────────────────────────
def check_network_diversity(df_base):
    header("6 / تنوع الشبكة (Gateway Coverage)")
    scores = []

    src_col = None
    for c in ["id.orig_h", "src_ip", "src", "orig_h"]:
        if c in df_base.columns:
            src_col = c
            break

    if src_col:
        local_ips = df_base[src_col].dropna()
        lan_ips = local_ips[local_ips.astype(str).str.startswith("192.168.1.")]
        unique_lan = lan_ips.nunique()
        info(f"أجهزة LAN مرصودة (192.168.1.x): {unique_lan}")
        
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
# 7. القرار النهائي
# ─────────────────────────────────────────────
def final_decision(all_scores, df_base, df_win, base_files):
    header("7 / القرار النهائي")

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
    print()
    print("══════════════════════════════════════════════════════")
    print("   NetGuard-AI Gateway — Data Assessment v1.0")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
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
    all_scores += check_network_diversity(df_base)

    # القرار
    final_decision(all_scores, df_base, df_win, base_files)


if __name__ == "__main__":
    main()
