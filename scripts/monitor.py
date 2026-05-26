import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
import json
import os

# ========================================
# الإعدادات
# ========================================

DATA_DIR    = Path("/home/mtech/zeek-ids/data/processed")
REPORT_DIR  = Path("/home/mtech/zeek-ids/data/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# الحد الأدنى للبيانات الجيدة
THRESHOLDS = {
    "min_records_per_day"     : 500,    # أقل حد مقبول يومياً
    "good_records_per_day"    : 2000,   # حد جيد يومياً
    "max_missing_ratio"       : 0.10,   # أقصى نسبة قيم مفقودة (10%)
    "max_duplicate_ratio"     : 0.05,   # أقصى نسبة تكرار (5%)
    "min_protocol_diversity"  : 2,      # أقل عدد بروتوكولات مختلفة
    "min_unique_ips"          : 3,      # أقل عدد IPs مختلفة
    "max_gap_minutes"         : 60,     # أقصى فجوة زمنية مقبولة (دقيقة)
}

# ========================================
# تحميل البيانات
# ========================================

def load_data(days=1):
    """تحميل بيانات آخر N أيام"""
    all_dfs = []
    for i in range(days):
        date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
        filepath = DATA_DIR / f"baseline_{date}.csv"
        if filepath.exists():
            try:
                df = pd.read_csv(filepath)
                df["_date"] = date
                all_dfs.append(df)
            except Exception as e:
                print(f"⚠️  خطأ في قراءة {filepath}: {e}")

    if not all_dfs:
        return pd.DataFrame()

    return pd.concat(all_dfs, ignore_index=True)

# ========================================
# فحوصات الجودة
# ========================================

def check_quantity(df, date):
    """فحص الكمية"""
    count = len(df[df["_date"] == date]) if "_date" in df.columns else len(df)

    if count >= THRESHOLDS["good_records_per_day"]:
        status = "✅ ممتاز"
        score  = 100
    elif count >= THRESHOLDS["min_records_per_day"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ قليل جداً"
        score  = 20

    return {
        "metric"  : "الكمية اليومية",
        "value"   : count,
        "unit"    : "سجل",
        "status"  : status,
        "score"   : score,
        "target"  : THRESHOLDS["good_records_per_day"]
    }

def check_missing_values(df):
    """فحص القيم المفقودة"""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    missing = df[numeric_cols].isnull().sum().sum()
    total   = df[numeric_cols].size
    ratio   = missing / total if total > 0 else 0

    if ratio <= 0.02:
        status = "✅ ممتاز"
        score  = 100
    elif ratio <= THRESHOLDS["max_missing_ratio"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ كثير جداً"
        score  = 20

    return {
        "metric"  : "القيم المفقودة",
        "value"   : round(ratio * 100, 2),
        "unit"    : "%",
        "status"  : status,
        "score"   : score,
        "target"  : THRESHOLDS["max_missing_ratio"] * 100
    }

def check_duplicates(df):
    """فحص التكرار"""
    feature_cols = [c for c in df.columns if c not in ["src_ip", "dst_ip", "ts", "_date"]]
    duplicates   = df[feature_cols].duplicated().sum()
    ratio        = duplicates / len(df) if len(df) > 0 else 0

    if ratio <= 0.02:
        status = "✅ ممتاز"
        score  = 100
    elif ratio <= THRESHOLDS["max_duplicate_ratio"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ تكرار عالٍ"
        score  = 20

    return {
        "metric"  : "التكرار",
        "value"   : round(ratio * 100, 2),
        "unit"    : "%",
        "status"  : status,
        "score"   : score,
        "target"  : THRESHOLDS["max_duplicate_ratio"] * 100
    }

def check_protocol_diversity(df):
    """فحص تنوع البروتوكولات"""
    protocols = []
    if "proto_tcp"  in df.columns and df["proto_tcp"].sum()  > 0: protocols.append("TCP")
    if "proto_udp"  in df.columns and df["proto_udp"].sum()  > 0: protocols.append("UDP")
    if "proto_icmp" in df.columns and df["proto_icmp"].sum() > 0: protocols.append("ICMP")

    count = len(protocols)

    if count >= 3:
        status = "✅ ممتاز"
        score  = 100
    elif count >= THRESHOLDS["min_protocol_diversity"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ تنوع ضعيف"
        score  = 20

    return {
        "metric"    : "تنوع البروتوكولات",
        "value"     : count,
        "unit"      : f"بروتوكولات ({', '.join(protocols)})",
        "status"    : status,
        "score"     : score,
        "target"    : THRESHOLDS["min_protocol_diversity"]
    }

def check_ip_diversity(df):
    """فحص تنوع الـ IPs"""
    if "dst_ip" not in df.columns:
        return {"metric": "تنوع IPs", "value": 0, "unit": "IP", "status": "❌", "score": 0, "target": 3}

    unique_ips = df["dst_ip"].nunique()

    if unique_ips >= 20:
        status = "✅ ممتاز"
        score  = 100
    elif unique_ips >= THRESHOLDS["min_unique_ips"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ تنوع ضعيف"
        score  = 20

    return {
        "metric"  : "تنوع الـ IPs",
        "value"   : unique_ips,
        "unit"    : "IP مختلف",
        "status"  : status,
        "score"   : score,
        "target"  : 20
    }

def check_time_gaps(df):
    """فحص الفجوات الزمنية"""
    if "ts" not in df.columns or len(df) < 2:
        return {"metric": "الفجوات الزمنية", "value": 0, "unit": "دقيقة", "status": "⚠️", "score": 50, "target": 60}

    ts_sorted  = df["ts"].dropna().sort_values()
    gaps       = ts_sorted.diff().dropna()
    max_gap    = gaps.max() / 60  # تحويل لدقائق

    if max_gap <= 10:
        status = "✅ ممتاز"
        score  = 100
    elif max_gap <= THRESHOLDS["max_gap_minutes"]:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ فجوات كبيرة"
        score  = 20

    return {
        "metric"  : "أكبر فجوة زمنية",
        "value"   : round(max_gap, 1),
        "unit"    : "دقيقة",
        "status"  : status,
        "score"   : score,
        "target"  : THRESHOLDS["max_gap_minutes"]
    }

def check_time_diversity(df):
    """فحص تنوع أوقات الجمع"""
    if "hour_of_day" not in df.columns:
        return {"metric": "تنوع الأوقات", "value": 0, "unit": "ساعة", "status": "⚠️", "score": 50, "target": 8}

    unique_hours = df["hour_of_day"].nunique()

    if unique_hours >= 12:
        status = "✅ ممتاز"
        score  = 100
    elif unique_hours >= 8:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ تنوع ضعيف"
        score  = 20

    return {
        "metric"  : "تنوع الأوقات",
        "value"   : unique_hours,
        "unit"    : "ساعة مختلفة",
        "status"  : status,
        "score"   : score,
        "target"  : 12
    }

def check_external_traffic(df):
    """فحص وجود حركة خارجية"""
    if "is_external" not in df.columns:
        return {"metric": "حركة خارجية", "value": 0, "unit": "%", "status": "⚠️", "score": 50, "target": 30}

    ratio = df["is_external"].mean() * 100

    if 20 <= ratio <= 80:
        status = "✅ ممتاز"
        score  = 100
    elif ratio > 5:
        status = "⚠️  مقبول"
        score  = 60
    else:
        status = "❌ لا توجد حركة خارجية"
        score  = 20

    return {
        "metric"  : "الحركة الخارجية",
        "value"   : round(ratio, 1),
        "unit"    : "%",
        "status"  : status,
        "score"   : score,
        "target"  : "20-80"
    }

# ========================================
# التقرير الكامل
# ========================================

def generate_report(days=7):
    print("\n" + "=" * 60)
    print("📊 NetGuard-AI — تقرير جودة البيانات")
    print(f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    df = load_data(days=days)

    if df.empty:
        print("❌ لا توجد بيانات!")
        return

    today = datetime.now().strftime("%Y-%m-%d")

    # ========== إحصائيات عامة ==========
    print("\n📁 الإحصائيات العامة:")
    print(f"   إجمالي السجلات    : {len(df):,}")

    # ملفات موجودة
    files = list(DATA_DIR.glob("baseline_*.csv"))
    print(f"   أيام البيانات     : {len(files)} يوم")

    if "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        oldest = pd.to_datetime(df["ts"].min(), unit="s").strftime("%Y-%m-%d %H:%M")
        newest = pd.to_datetime(df["ts"].max(), unit="s").strftime("%Y-%m-%d %H:%M")
        print(f"   أقدم سجل         : {oldest}")
        print(f"   أحدث سجل         : {newest}")

    # ========== فحوصات الجودة ==========
    print("\n🔍 فحوصات الجودة:")

    checks = [
        check_quantity(df, today),
        check_missing_values(df),
        check_duplicates(df),
        check_protocol_diversity(df),
        check_ip_diversity(df),
        check_time_gaps(df),
        check_time_diversity(df),
        check_external_traffic(df),
    ]

    total_score = 0
    for check in checks:
        print(f"\n   {check['status']} {check['metric']}")
        print(f"      القيمة  : {check['value']} {check['unit']}")
        print(f"      الهدف   : {check['target']}")
        total_score += check["score"]

    # ========== التقييم الكلي ==========
    avg_score = total_score / len(checks)
    print("\n" + "=" * 60)
    print(f"🏆 التقييم الكلي: {avg_score:.0f}/100", end="  ")

    if avg_score >= 80:
        print("← بيانات ممتازة ✅")
    elif avg_score >= 60:
        print("← بيانات مقبولة ⚠️")
    else:
        print("← بيانات ضعيفة ❌")

    # ========== توزيع البروتوكولات ==========
    print("\n📡 توزيع البروتوكولات:")
    if "proto_tcp" in df.columns:
        tcp  = df["proto_tcp"].sum()
        udp  = df["proto_udp"].sum()
        icmp = df["proto_icmp"].sum()
        total = tcp + udp + icmp
        if total > 0:
            print(f"   TCP  : {tcp:,} ({tcp/total*100:.1f}%)")
            print(f"   UDP  : {udp:,} ({udp/total*100:.1f}%)")
            print(f"   ICMP : {icmp:,} ({icmp/total*100:.1f}%)")

    # ========== أكثر الـ IPs نشاطاً ==========
    print("\n🌐 أكثر الـ IPs الخارجية نشاطاً:")
    if "dst_ip" in df.columns and "is_external" in df.columns:
        external = df[df["is_external"] == 1]["dst_ip"].value_counts().head(5)
        for ip, count in external.items():
            print(f"   {ip:<20} : {count:,} اتصال")

    # ========== توزيع الأوقات ==========
    print("\n⏰ توزيع الجمع حسب الوقت:")
    if "hour_of_day" in df.columns:
        hourly = df["hour_of_day"].value_counts().sort_index()
        for hour, count in hourly.items():
            bar = "█" * min(int(count / max(hourly) * 20), 20)
            print(f"   {hour:02d}:00  {bar} {count}")

    # ========== التوصيات ==========
    print("\n💡 التوصيات:")
    recommendations = []

    qty_check = check_quantity(df, today)
    if qty_check["score"] < 100:
        recommendations.append("← استخدم الإنترنت أكثر لجمع بيانات أكثر")

    gap_check = check_time_gaps(df)
    if gap_check["score"] < 100:
        recommendations.append("← تأكد أن Zeek يعمل باستمرار بدون crashes")

    time_check = check_time_diversity(df)
    if time_check["score"] < 100:
        recommendations.append("← شغّل اللابتوب في أوقات مختلفة (صباح/مساء/ليل)")

    ext_check = check_external_traffic(df)
    if ext_check["score"] < 100:
        recommendations.append("← تصفح مواقع خارجية لتنويع البيانات")

    if not recommendations:
        print("   ✅ البيانات في حالة ممتازة — استمر!")
    else:
        for rec in recommendations:
            print(f"   {rec}")

    # ========== حفظ التقرير ==========
    report_file = REPORT_DIR / f"report_{today}.json"
    report_data = {
        "date"        : today,
        "total_records": len(df),
        "avg_score"   : avg_score,
        "checks"      : checks
    }
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)

    print(f"\n📄 تم حفظ التقرير في: {report_file}")
    print("=" * 60 + "\n")

    return avg_score

# ========================================
# تشغيل
# ========================================

if __name__ == "__main__":
    import sys
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    generate_report(days=days)
