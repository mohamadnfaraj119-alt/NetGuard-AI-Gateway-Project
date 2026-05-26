#!/usr/bin/env python3
"""
integrity.py — NetGuard-AI
Log Integrity Layer — فحص سلامة البيانات قبل أي نمذجة

الاستخدام:
  python scripts/integrity.py
  python scripts/integrity.py --input data/processed/baseline_2026-05-12.csv
  python scripts/integrity.py --days 7
  python scripts/integrity.py --fix   # يحاول إصلاح المشاكل تلقائياً
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "processed"
REPORTS_DIR = BASE_DIR / "data" / "reports"
LOGS_DIR    = BASE_DIR / "logs"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ─── إعداد الـ Logging ───────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "integrity.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ─── حدود قبول البيانات ──────────────────────────────────────────────────────
LIMITS = {
    "min_records":          50,     # أقل عدد سجلات مقبول لليوم
    "max_missing_pct":       5.0,   # أقصى نسبة قيم مفقودة %
    "max_duplicate_pct":     1.0,   # أقصى نسبة تكرار %
    "max_gap_minutes":      60,     # أكبر فجوة زمنية مقبولة (دقيقة)
    "max_gap_critical":    120,     # فجوة حرجة تستوجب تحذيراً قوياً
    "min_protocol_variety":  2,     # على الأقل بروتوكولان مختلفان
    "min_unique_ips":        3,     # على الأقل 3 IPs مختلفة
    "max_zero_bytes_pct":   80.0,   # أقصى نسبة سجلات بدون bytes %
}

# ─── الأعمدة الأساسية المطلوبة ───────────────────────────────────────────────
REQUIRED_COLUMNS = [
    "ts", "src_ip", "dst_ip", "dst_port", "duration",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_state_S0", "conn_state_SF", "conn_state_REJ",
    "is_external",
]


# ══════════════════════════════════════════════════════════════════════════════
# فحوصات الـ Integrity
# ══════════════════════════════════════════════════════════════════════════════

def check_file_exists(filepath: Path) -> dict:
    """فحص وجود الملف وأنه غير فارغ"""
    result = {"check": "file_exists", "status": "pass", "detail": ""}

    if not filepath.exists():
        result["status"] = "fail"
        result["detail"] = f"الملف غير موجود: {filepath.name}"
        return result

    size_kb = filepath.stat().st_size / 1024
    if size_kb < 1:
        result["status"] = "fail"
        result["detail"] = f"الملف فارغ أو صغير جداً: {size_kb:.1f} KB"
        return result

    result["detail"] = f"{size_kb:.1f} KB"
    return result


def check_required_columns(df: pd.DataFrame) -> dict:
    """فحص وجود الأعمدة الأساسية"""
    result = {"check": "required_columns", "status": "pass", "detail": ""}

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        result["status"] = "fail"
        result["detail"] = f"أعمدة مفقودة: {missing}"
    else:
        result["detail"] = f"جميع الأعمدة الـ {len(REQUIRED_COLUMNS)} موجودة"

    return result


def check_minimum_records(df: pd.DataFrame) -> dict:
    """فحص الحد الأدنى من السجلات"""
    result = {"check": "minimum_records", "status": "pass", "detail": ""}

    n = len(df)
    if n < LIMITS["min_records"]:
        result["status"] = "warn"
        result["detail"] = f"{n} سجل — أقل من الحد الأدنى {LIMITS['min_records']}"
    else:
        result["detail"] = f"{n} سجل ✅"

    result["value"] = n
    return result


def check_missing_values(df: pd.DataFrame) -> dict:
    """فحص القيم المفقودة في الأعمدة الأساسية"""
    result = {"check": "missing_values", "status": "pass", "detail": "", "breakdown": {}}

    existing_req = [c for c in REQUIRED_COLUMNS if c in df.columns]
    missing_stats = {}

    for col in existing_req:
        pct = df[col].isna().mean() * 100
        if pct > 0:
            missing_stats[col] = round(pct, 2)

    total_missing_pct = df[existing_req].isna().mean().mean() * 100

    if total_missing_pct > LIMITS["max_missing_pct"]:
        result["status"] = "warn"
        result["detail"] = f"نسبة القيم المفقودة: {total_missing_pct:.2f}%"
    else:
        result["detail"] = f"نسبة القيم المفقودة: {total_missing_pct:.2f}% ✅"

    result["value"]     = round(total_missing_pct, 2)
    result["breakdown"] = missing_stats
    return result


def check_duplicates(df: pd.DataFrame) -> dict:
    """فحص السجلات المكررة"""
    result = {"check": "duplicates", "status": "pass", "detail": ""}

    dup_cols = [c for c in ["ts", "src_ip", "dst_ip", "dst_port"] if c in df.columns]
    if not dup_cols:
        result["status"] = "warn"
        result["detail"] = "لا يمكن فحص التكرار — أعمدة المفتاح غير موجودة"
        return result

    dup_count = df.duplicated(subset=dup_cols).sum()
    dup_pct   = dup_count / len(df) * 100

    if dup_pct > LIMITS["max_duplicate_pct"]:
        result["status"] = "warn"
        result["detail"] = f"{dup_count} سجل مكرر ({dup_pct:.2f}%)"
    else:
        result["detail"] = f"{dup_count} سجل مكرر ({dup_pct:.2f}%) ✅"

    result["value"] = dup_count
    return result


def check_time_gaps(df: pd.DataFrame) -> dict:
    """فحص الفجوات الزمنية في البيانات"""
    result = {"check": "time_gaps", "status": "pass", "detail": "", "gaps": []}

    if "ts" not in df.columns:
        result["status"] = "warn"
        result["detail"] = "عمود ts غير موجود"
        return result

    ts = pd.to_numeric(df["ts"], errors="coerce").dropna().sort_values()
    if len(ts) < 2:
        result["detail"] = "بيانات غير كافية للفحص"
        return result

    diffs_min = np.diff(ts.values) / 60
    gaps      = diffs_min[diffs_min > LIMITS["max_gap_minutes"]]

    if len(gaps) == 0:
        result["detail"] = f"لا فجوات > {LIMITS['max_gap_minutes']} دقيقة ✅"
        return result

    max_gap = float(gaps.max())
    result["gaps"] = [round(float(g), 1) for g in sorted(gaps, reverse=True)[:5]]

    if max_gap > LIMITS["max_gap_critical"]:
        result["status"] = "warn"
        result["detail"] = (f"أكبر فجوة: {max_gap:.0f} دقيقة ⚠️ "
                            f"| إجمالي فجوات: {len(gaps)}")
    else:
        result["status"] = "info"
        result["detail"] = (f"أكبر فجوة: {max_gap:.0f} دقيقة "
                            f"| إجمالي فجوات: {len(gaps)}")

    result["value"] = round(max_gap, 1)
    return result


def check_timestamp_order(df: pd.DataFrame) -> dict:
    """فحص ترتيب الـ timestamps — يجب أن تكون تصاعدية"""
    result = {"check": "timestamp_order", "status": "pass", "detail": ""}

    if "ts" not in df.columns:
        result["detail"] = "عمود ts غير موجود"
        return result

    ts = pd.to_numeric(df["ts"], errors="coerce").dropna()
    out_of_order = (ts.diff() < 0).sum()

    if out_of_order > 0:
        result["status"] = "warn"
        result["detail"] = f"{out_of_order} timestamp غير مرتب — قد يؤثر على Window Engine"
    else:
        result["detail"] = "Timestamps مرتبة تصاعدياً ✅"

    result["value"] = int(out_of_order)
    return result


def check_protocol_variety(df: pd.DataFrame) -> dict:
    """فحص تنوع البروتوكولات"""
    result = {"check": "protocol_variety", "status": "pass", "detail": "", "counts": {}}

    proto_cols = {"TCP": "proto_tcp", "UDP": "proto_udp", "ICMP": "proto_icmp"}
    counts     = {}
    active     = 0

    for name, col in proto_cols.items():
        if col in df.columns:
            c = int(df[col].sum())
            counts[name] = c
            if c > 0:
                active += 1

    if active < LIMITS["min_protocol_variety"]:
        result["status"] = "warn"
        result["detail"] = f"بروتوكولات نشطة: {active} فقط"
    else:
        result["detail"] = (f"TCP:{counts.get('TCP',0)} | "
                            f"UDP:{counts.get('UDP',0)} | "
                            f"ICMP:{counts.get('ICMP',0)} ✅")

    result["counts"] = counts
    return result


def check_ip_variety(df: pd.DataFrame) -> dict:
    """فحص تنوع الـ IPs"""
    result = {"check": "ip_variety", "status": "pass", "detail": ""}

    if "dst_ip" not in df.columns:
        result["detail"] = "عمود dst_ip غير موجود"
        return result

    unique_ips = int(df["dst_ip"].nunique())

    if unique_ips < LIMITS["min_unique_ips"]:
        result["status"] = "warn"
        result["detail"] = f"{unique_ips} IP مختلف فقط — تنوع منخفض"
    else:
        result["detail"] = f"{unique_ips} IP مختلف ✅"

    result["value"] = unique_ips
    return result


def check_zero_bytes(df: pd.DataFrame) -> dict:
    """فحص نسبة السجلات بدون بيانات bytes"""
    result = {"check": "zero_bytes", "status": "pass", "detail": ""}

    byte_cols = [c for c in ["orig_bytes", "resp_bytes"] if c in df.columns]
    if not byte_cols:
        result["detail"] = "أعمدة bytes غير موجودة"
        return result

    zero_mask = df[byte_cols].fillna(0).sum(axis=1) == 0
    zero_pct  = zero_mask.mean() * 100

    if zero_pct > LIMITS["max_zero_bytes_pct"]:
        result["status"] = "warn"
        result["detail"] = f"{zero_pct:.1f}% من السجلات بدون bytes — تحقق من الـ collector"
    else:
        result["detail"] = f"{zero_pct:.1f}% سجلات بدون bytes ✅"

    result["value"] = round(zero_pct, 1)
    return result


def check_sudden_drop(df: pd.DataFrame) -> dict:
    """
    كشف انخفاض مفاجئ في حركة الشبكة
    يقارن كثافة السجلات في كل 10 دقائق
    """
    result = {"check": "sudden_drop", "status": "pass", "detail": ""}

    if "ts" not in df.columns or len(df) < 10:
        result["detail"] = "بيانات غير كافية"
        return result

    ts     = pd.to_numeric(df["ts"], errors="coerce").dropna()
    t_min  = ts.min()
    t_max  = ts.max()
    window = 600  # 10 دقائق

    buckets = []
    t = t_min
    while t < t_max:
        count = ((ts >= t) & (ts < t + window)).sum()
        buckets.append(count)
        t += window

    if len(buckets) < 3:
        result["detail"] = "فترة قصيرة جداً للتحليل"
        return result

    buckets  = pd.Series(buckets)
    mean_cnt = buckets.mean()
    drops    = (buckets < mean_cnt * 0.1).sum()  # أقل من 10% من المتوسط

    if drops > 0:
        result["status"] = "warn"
        result["detail"] = (f"{drops} فترة انخفاض مفاجئ "
                            f"(< 10% من المتوسط {mean_cnt:.0f} سجل/10دقائق)")
    else:
        result["detail"] = f"لا انخفاض مفاجئ — متوسط {mean_cnt:.0f} سجل/10دقائق ✅"

    result["value"] = int(drops)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# الإصلاح التلقائي
# ══════════════════════════════════════════════════════════════════════════════

def auto_fix(df: pd.DataFrame, filepath: Path) -> pd.DataFrame:
    """
    إصلاح تلقائي للمشاكل البسيطة:
    - حذف السجلات المكررة
    - ترتيب الـ timestamps
    - حفظ النسخة المصلحة
    """
    original_len = len(df)
    fixed        = False

    # إصلاح 1: حذف التكرار
    dup_cols = [c for c in ["ts", "src_ip", "dst_ip", "dst_port"] if c in df.columns]
    if dup_cols:
        before = len(df)
        df = df.drop_duplicates(subset=dup_cols)
        removed = before - len(df)
        if removed > 0:
            log.info(f"🔧 حذف {removed} سجل مكرر")
            fixed = True

    # إصلاح 2: ترتيب timestamps
    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        before_drop = len(df)
        df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
        dropped = before_drop - len(df)
        if dropped > 0:
            log.info(f"🔧 حذف {dropped} سجل بـ timestamp غير صالح")
            fixed = True
        else:
            log.info("🔧 ترتيب Timestamps")
            fixed = True

    if fixed:
        # حفظ النسخة الأصلية كـ backup
        backup = filepath.with_suffix(".csv.bak")
        import shutil
        shutil.copy2(filepath, backup)
        log.info(f"💾 نسخة احتياطية: {backup.name}")

        # حفظ النسخة المصلحة
        df.to_csv(filepath, index=False)
        log.info(f"✅ تم حفظ النسخة المصلحة: {original_len} → {len(df)} سجل")

    return df


# ══════════════════════════════════════════════════════════════════════════════
# التقرير الرئيسي
# ══════════════════════════════════════════════════════════════════════════════

def run_checks(filepath: Path, fix: bool = False) -> dict:
    """
    تشغيل جميع الفحوصات على ملف واحد
    يُرجع dict بالنتائج الكاملة
    """
    report = {
        "file":     filepath.name,
        "date":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checks":   [],
        "score":    0,
        "status":   "unknown",
        "records":  0,
    }

    # ── فحص الملف أولاً ──────────────────────────────────────────────────────
    file_check = check_file_exists(filepath)
    report["checks"].append(file_check)

    if file_check["status"] == "fail":
        report["status"] = "fail"
        return report

    # ── قراءة البيانات ────────────────────────────────────────────────────────
    try:
        df = pd.read_csv(filepath)
        report["records"] = len(df)
    except Exception as e:
        report["checks"].append({
            "check": "read_file", "status": "fail",
            "detail": f"خطأ في القراءة: {e}"
        })
        report["status"] = "fail"
        return report

    # ── الإصلاح التلقائي قبل الفحص ───────────────────────────────────────────
    if fix:
        df = auto_fix(df, filepath)
        report["records"] = len(df)

    # ── تشغيل جميع الفحوصات ──────────────────────────────────────────────────
    checks = [
        check_required_columns(df),
        check_minimum_records(df),
        check_missing_values(df),
        check_duplicates(df),
        check_time_gaps(df),
        check_timestamp_order(df),
        check_protocol_variety(df),
        check_ip_variety(df),
        check_zero_bytes(df),
        check_sudden_drop(df),
    ]

    report["checks"].extend(checks)

    # ── حساب الـ Score ────────────────────────────────────────────────────────
    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == "pass")
    warned = sum(1 for c in checks if c["status"] == "warn")
    failed = sum(1 for c in checks if c["status"] == "fail")

    score = round((passed * 10 + warned * 5) / total)
    report["score"]  = score
    report["passed"] = passed
    report["warned"] = warned
    report["failed"] = failed

    if failed > 0:
        report["status"] = "fail"
    elif warned > 2:
        report["status"] = "warn"
    else:
        report["status"] = "pass"

    return report


def print_report(report: dict):
    """طباعة التقرير بشكل مقروء"""
    icons = {"pass": "✅", "warn": "⚠️ ", "fail": "❌", "info": "ℹ️ "}

    print(f"\n{'='*60}")
    print(f"🔍 Integrity Report — {report['file']}")
    print(f"   الوقت: {report['date']}")
    print(f"   السجلات: {report['records']:,}")
    print(f"{'='*60}")

    for check in report["checks"]:
        icon   = icons.get(check["status"], "•")
        detail = check.get("detail", "")
        print(f"  {icon} {check['check']:25s} {detail}")

        # تفاصيل إضافية
        if check.get("gaps"):
            print(f"      الفجوات (دقيقة): {check['gaps']}")
        if check.get("breakdown"):
            for col, pct in check["breakdown"].items():
                print(f"      {col}: {pct}%")

    print(f"{'='*60}")
    score  = report.get("score", 0)
    status = report.get("status", "unknown")
    passed = report.get("passed", 0)
    warned = report.get("warned", 0)
    failed = report.get("failed", 0)

    emoji = "🟢" if status == "pass" else "🟡" if status == "warn" else "🔴"
    print(f"  {emoji} النتيجة: {score}/10 | "
          f"نجح:{passed} تحذير:{warned} فشل:{failed}")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetGuard-AI — Integrity Check")
    parser.add_argument("--input", "-i", default=None,
                        help="ملف CSV للفحص (افتراضي: baseline اليوم)")
    parser.add_argument("--days",  "-d", type=int, default=1,
                        help="فحص آخر N أيام (افتراضي: 1)")
    parser.add_argument("--fix",   "-f", action="store_true",
                        help="إصلاح تلقائي للمشاكل البسيطة")
    args = parser.parse_args()

    all_reports = []

    # ── تحديد الملفات للفحص ──────────────────────────────────────────────────
    if args.input:
        files = [Path(args.input)]
    else:
        today = datetime.now().date()
        files = []
        for i in range(args.days):
            date      = today - timedelta(days=i)
            filepath  = DATA_DIR / f"baseline_{date}.csv"
            files.append(filepath)

    # ── فحص كل ملف ───────────────────────────────────────────────────────────
    for filepath in files:
        log.info(f"🔍 فحص: {filepath.name}")
        report = run_checks(filepath, fix=args.fix)
        print_report(report)
        all_reports.append(report)

        # حفظ التقرير JSON
        report_file = REPORTS_DIR / f"integrity_{filepath.stem}.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2, default=int)
        log.info(f"💾 تقرير محفوظ: {report_file.name}")

    # ── ملخص إذا كان أكثر من ملف ─────────────────────────────────────────────
    if len(all_reports) > 1:
        print(f"\n{'='*60}")
        print(f"📊 ملخص {len(all_reports)} يوم")
        print(f"{'='*60}")
        for r in all_reports:
            emoji = "🟢" if r["status"] == "pass" else \
                    "🟡" if r["status"] == "warn" else "🔴"
            print(f"  {emoji} {r['file']:40s} {r['records']:5,} سجل | "
                  f"Score: {r['score']}/10")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
