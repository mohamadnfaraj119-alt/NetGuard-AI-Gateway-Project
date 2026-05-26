#!/usr/bin/env python3
"""
anomaly_model.py — NetGuard-AI
Behavioral Anomaly Detection بـ Isolation Forest
يتدرب على Window Features من Baseline نظيف

الاستخدام:
  python scripts/anomaly_model.py --train
  python scripts/anomaly_model.py --train --windows data/windows/windows_2026-05-12.csv,data/windows/windows_2026-05-13.csv
  python scripts/anomaly_model.py --predict --input data/windows/windows_2026-05-13.csv
  python scripts/anomaly_model.py --evaluate
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import pickle

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
WINDOWS_DIR = BASE_DIR / "data" / "windows"
MODELS_DIR  = BASE_DIR / "models" / "anomaly"
LOGS_DIR    = BASE_DIR / "logs"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE    = MODELS_DIR / "isolation_forest.pkl"
SCALER_FILE   = MODELS_DIR / "scaler.pkl"
FEATURES_FILE = MODELS_DIR / "feature_names.json"
STATS_FILE    = MODELS_DIR / "baseline_stats.json"

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "anomaly_model.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ─── الـ Features المستخدمة للتدريب ──────────────────────────────────────────
# نستثني: ts, datetime, flag_* (هذه labels وليست features)
# نستثني: الـ features التي mean=0 دائماً (لا قيمة إحصائية)
FEATURE_GROUPS = {
    "30s": [
        "connections_30s",
        "unique_dst_ports_30s",
        "unique_dst_ips_30s",
        "failed_conn_rate_30s",
        "dns_rate_30s",
        "avg_conn_duration_30s",
        "outbound_ratio_30s",
        "bytes_per_sec_30s",
        "port_entropy_30s",
        "burst_score_30s",
        "conn_rate_per_ip_30s",
        "unique_ports_per_ip_30s",
    ],
    "1m": [
        "connections_1m",
        "unique_dst_ports_1m",
        "unique_dst_ips_1m",
        "failed_conn_rate_1m",
        "dns_rate_1m",
        "avg_conn_duration_1m",
        "outbound_ratio_1m",
        "bytes_per_sec_1m",
        "port_entropy_1m",
        "burst_score_1m",
        "conn_rate_per_ip_1m",
        "unique_ports_per_ip_1m",
    ],
    "5m": [
        "connections_5m",
        "unique_dst_ports_5m",
        "unique_dst_ips_5m",
        "failed_conn_rate_5m",
        "dns_rate_5m",
        "avg_conn_duration_5m",
        "outbound_ratio_5m",
        "bytes_per_sec_5m",
        "port_entropy_5m",
        "burst_score_5m",
        "conn_rate_per_ip_5m",
        "unique_ports_per_ip_5m",
    ],
}

# الـ Features النهائية للتدريب (36 feature)
ALL_FEATURES = (
    FEATURE_GROUPS["30s"] +
    FEATURE_GROUPS["1m"]  +
    FEATURE_GROUPS["5m"]
)


# ══════════════════════════════════════════════════════════════════════════════
# تحميل البيانات
# ══════════════════════════════════════════════════════════════════════════════

def load_windows(files: list) -> pd.DataFrame:
    """تحميل ودمج ملفات الـ windows"""
    dfs = []
    for f in files:
        path = Path(f)
        if not path.exists():
            log.warning(f"⚠️  الملف غير موجود: {path.name} — تخطي")
            continue
        df = pd.read_csv(path)
        log.info(f"✅ {path.name}: {len(df)} نافذة")
        dfs.append(df)

    if not dfs:
        log.error("❌ لا توجد بيانات للتحميل")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True)
    log.info(f"📊 إجمالي النوافذ: {len(combined)}")
    return combined


def prepare_features(df: pd.DataFrame, fit_features: list = None) -> tuple:
    """
    تجهيز الـ features للتدريب أو التنبؤ
    يُرجع: (X, feature_names_used)
    """
    # الـ features الموجودة فعلاً في الـ DataFrame
    available = [f for f in ALL_FEATURES if f in df.columns]
    missing   = [f for f in ALL_FEATURES if f not in df.columns]

    if missing:
        log.warning(f"⚠️  features غير موجودة: {missing}")

    if fit_features:
        # وضع التنبؤ — نستخدم نفس features التدريب
        available = [f for f in fit_features if f in df.columns]

    X = df[available].fillna(0).values
    return X, available


# ══════════════════════════════════════════════════════════════════════════════
# التدريب
# ══════════════════════════════════════════════════════════════════════════════

def train(files: list):
    """
    تدريب Isolation Forest على بيانات الـ Baseline
    """
    log.info("=" * 55)
    log.info("🚀 بدء التدريب — Isolation Forest")
    log.info("=" * 55)

    # ── تحميل البيانات ────────────────────────────────────────────────────────
    df = load_windows(files)

    # ── استثناء النوافذ الفارغة (خمول كامل) ──────────────────────────────────
    before = len(df)
    df = df[df["connections_5m"] > 0].reset_index(drop=True)
    removed = before - len(df)
    if removed > 0:
        log.info(f"🔇 استثناء {removed} نافذة فارغة (خمول كامل)")

    log.info(f"📊 نوافذ التدريب: {len(df)}")

    # ── تجهيز الـ Features ────────────────────────────────────────────────────
    X, feature_names = prepare_features(df)
    log.info(f"✅ Features: {len(feature_names)}")

    # ── Scaling — RobustScaler أفضل من StandardScaler للـ outliers ───────────
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # ── إحصاء الـ Baseline (للمقارنة لاحقاً) ─────────────────────────────────
    df_features = pd.DataFrame(X, columns=feature_names)
    baseline_stats = {}
    for feat in feature_names:
        baseline_stats[feat] = {
            "mean":   round(float(df_features[feat].mean()), 4),
            "std":    round(float(df_features[feat].std()), 4),
            "median": round(float(df_features[feat].median()), 4),
            "p95":    round(float(df_features[feat].quantile(0.95)), 4),
            "p99":    round(float(df_features[feat].quantile(0.99)), 4),
            "max":    round(float(df_features[feat].max()), 4),
        }

    # ── التدريب ───────────────────────────────────────────────────────────────
    # contamination=0.01: نفترض 1% anomaly في الـ baseline
    # n_estimators=200: أكثر من الافتراضي (100) لدقة أفضل
    # max_samples='auto': يأخذ min(256, n_samples)
    # random_state=42: للتكرارية
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,         # استخدم كل الـ CPU cores
    )

    log.info("⏳ تدريب النموذج...")
    model.fit(X_scaled)
    log.info("✅ اكتمل التدريب")

    # ── تقييم على الـ Baseline نفسه ───────────────────────────────────────────
    predictions = model.predict(X_scaled)        # 1=normal, -1=anomaly
    scores      = model.score_samples(X_scaled)  # سالب = أكثر شذوذاً

    normal_count  = (predictions == 1).sum()
    anomaly_count = (predictions == -1).sum()
    normal_pct    = normal_count / len(predictions) * 100

    log.info(f"\n📊 نتائج التقييم على الـ Baseline:")
    log.info(f"   طبيعي  : {normal_count:,} ({normal_pct:.1f}%)")
    log.info(f"   شاذ    : {anomaly_count:,} ({100-normal_pct:.1f}%)")

    # تحقق: يجب أن يكون 98%+ طبيعي
    if normal_pct < 95:
        log.warning("⚠️  نسبة الطبيعي منخفضة — قد تحتاج مزيداً من الـ Baseline")
    else:
        log.info("✅ النسبة ممتازة — النموذج يفهم الـ Baseline جيداً")

    # ── توزيع الـ Anomaly Scores ──────────────────────────────────────────────
    scores_normalized = normalize_scores(scores)
    log.info(f"\n📈 توزيع Anomaly Score (0=طبيعي, 1=شاذ):")
    log.info(f"   mean : {scores_normalized.mean():.3f}")
    log.info(f"   p95  : {np.percentile(scores_normalized, 95):.3f}")
    log.info(f"   p99  : {np.percentile(scores_normalized, 99):.3f}")
    log.info(f"   max  : {scores_normalized.max():.3f}")

    # ── حفظ النموذج ───────────────────────────────────────────────────────────
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    with open(SCALER_FILE, "wb") as f:
        pickle.dump(scaler, f)

    with open(FEATURES_FILE, "w") as f:
        json.dump(feature_names, f, indent=2)

    with open(STATS_FILE, "w") as f:
        meta = {
            "trained_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "training_files": [str(f) for f in files],
            "n_windows":     len(df),
            "n_features":    len(feature_names),
            "normal_pct":    round(normal_pct, 2),
            "score_mean":    round(float(scores_normalized.mean()), 4),
            "score_p95":     round(float(np.percentile(scores_normalized, 95)), 4),
            "score_p99":     round(float(np.percentile(scores_normalized, 99)), 4),
            "score_max":     round(float(scores_normalized.max()), 4),
            "baseline_stats": baseline_stats,
        }
        json.dump(meta, f, ensure_ascii=False, indent=2)

    log.info(f"\n💾 النموذج محفوظ في: {MODELS_DIR}")
    log.info(f"   isolation_forest.pkl")
    log.info(f"   scaler.pkl")
    log.info(f"   feature_names.json")
    log.info(f"   baseline_stats.json")

    print_training_summary(meta)


def normalize_scores(raw_scores: np.ndarray) -> np.ndarray:
    """
    تحويل Isolation Forest scores إلى [0, 1]
    score_samples يُرجع قيم سالبة — أقل = أكثر شذوذاً
    نعكسها ونطبّع على [0, 1]
    """
    scores = -raw_scores  # اجعل الأكثر شذوذاً أعلى
    min_s  = scores.min()
    max_s  = scores.max()
    if max_s == min_s:
        return np.zeros_like(scores)
    return (scores - min_s) / (max_s - min_s)


def print_training_summary(meta: dict):
    print(f"\n{'='*55}")
    print(f"✅ تم التدريب بنجاح")
    print(f"{'='*55}")
    print(f"  النوافذ      : {meta['n_windows']:,}")
    print(f"  الـ Features : {meta['n_features']}")
    print(f"  طبيعي        : {meta['normal_pct']}%")
    print(f"  Score p95    : {meta['score_p95']}")
    print(f"  Score p99    : {meta['score_p99']}")
    print(f"{'='*55}")
    print(f"  الاستخدام التالي:")
    print(f"  python scripts/anomaly_model.py --predict \\")
    print(f"    --input data/windows/windows_$(date +%Y-%m-%d).csv")
    print(f"{'='*55}\n")


# ══════════════════════════════════════════════════════════════════════════════
# التنبؤ
# ══════════════════════════════════════════════════════════════════════════════

def predict(input_file: str, output_file: str = None):
    """
    تطبيق النموذج على بيانات جديدة
    يُضيف عمودي anomaly_score و is_anomaly
    """
    # ── تحميل النموذج ────────────────────────────────────────────────────────
    if not MODEL_FILE.exists():
        log.error("❌ النموذج غير موجود — شغّل --train أولاً")
        sys.exit(1)

    with open(MODEL_FILE,  "rb") as f: model  = pickle.load(f)
    with open(SCALER_FILE, "rb") as f: scaler = pickle.load(f)
    with open(FEATURES_FILE)     as f: feature_names = json.load(f)
    with open(STATS_FILE)        as f: stats = json.load(f)

    log.info(f"✅ النموذج محمّل (تدرّب: {stats['trained_at']})")

    # ── تحميل البيانات ────────────────────────────────────────────────────────
    path = Path(input_file)
    if not path.exists():
        log.error(f"❌ الملف غير موجود: {path}")
        sys.exit(1)

    df = pd.read_csv(path)
    log.info(f"📂 {path.name}: {len(df)} نافذة")

    # ── تجهيز الـ Features ────────────────────────────────────────────────────
    X, _ = prepare_features(df, fit_features=feature_names)
    X_scaled = scaler.transform(X)

    # ── التنبؤ ────────────────────────────────────────────────────────────────
    predictions = model.predict(X_scaled)
    raw_scores  = model.score_samples(X_scaled)
    norm_scores = normalize_scores(raw_scores)

    df["anomaly_score"] = np.round(norm_scores, 4)
    df["is_anomaly"]    = (predictions == -1).astype(int)

    # ── الملخص ───────────────────────────────────────────────────────────────
    anomalies = df["is_anomaly"].sum()
    total     = len(df)
    pct       = anomalies / total * 100

    print(f"\n{'='*55}")
    print(f"🔍 نتائج التنبؤ — {path.name}")
    print(f"{'='*55}")
    print(f"  النوافذ الكلية  : {total:,}")
    print(f"  طبيعي           : {total-anomalies:,} ({100-pct:.1f}%)")
    print(f"  شاذ (anomaly)   : {anomalies:,} ({pct:.1f}%)")
    print(f"  Score mean      : {norm_scores.mean():.3f}")
    print(f"  Score max       : {norm_scores.max():.3f}")
    print(f"{'='*55}")

    # إظهار أعلى 10 نوافذ شذوذاً
    if anomalies > 0:
        print(f"\n⚠️  أعلى النوافذ شذوذاً:")
        top = df.nlargest(min(10, anomalies), "anomaly_score")[
            ["datetime", "anomaly_score", "connections_30s",
             "unique_dst_ports_30s", "bytes_per_sec_30s",
             "burst_score_30s"] +
            [c for c in ["flag_port_scan", "flag_burst",
                          "flag_brute_force", "flag_dns_flood"]
             if c in df.columns]
        ]
        print(top.to_string(index=False))
    else:
        print("✅ لا anomalies — الـ Baseline نظيف تماماً")

    # ── حفظ النتائج ──────────────────────────────────────────────────────────
    if output_file:
        out_path = Path(output_file)
    else:
        out_path = path.parent / f"predicted_{path.name}"

    df.to_csv(out_path, index=False)
    log.info(f"💾 النتائج محفوظة: {out_path.name}")

    return df


# ══════════════════════════════════════════════════════════════════════════════
# التقييم
# ══════════════════════════════════════════════════════════════════════════════

def evaluate():
    """
    تقييم شامل للنموذج على كل ملفات الـ windows الموجودة
    """
    if not MODEL_FILE.exists():
        log.error("❌ النموذج غير موجود — شغّل --train أولاً")
        sys.exit(1)

    window_files = sorted(WINDOWS_DIR.glob("windows_*.csv"))
    if not window_files:
        log.error("❌ لا توجد ملفات windows")
        sys.exit(1)

    with open(MODEL_FILE,  "rb") as f: model  = pickle.load(f)
    with open(SCALER_FILE, "rb") as f: scaler = pickle.load(f)
    with open(FEATURES_FILE)     as f: feature_names = json.load(f)
    with open(STATS_FILE)        as f: stats = json.load(f)

    print(f"\n{'='*60}")
    print(f"📊 تقييم النموذج — Isolation Forest")
    print(f"   تاريخ التدريب: {stats['trained_at']}")
    print(f"   نوافذ التدريب: {stats['n_windows']:,}")
    print(f"{'='*60}")

    for wf in window_files:
        df = pd.read_csv(wf)
        if df.empty:
            continue

        X, _ = prepare_features(df, fit_features=feature_names)
        X_scaled    = scaler.transform(X)
        predictions = model.predict(X_scaled)
        scores      = normalize_scores(model.score_samples(X_scaled))

        anomalies = (predictions == -1).sum()
        pct       = anomalies / len(df) * 100
        emoji     = "🟢" if pct < 2 else "🟡" if pct < 5 else "🔴"

        print(f"  {emoji} {wf.name:40s} "
              f"anomalies: {anomalies:3d}/{len(df):4d} ({pct:.1f}%) | "
              f"score_max: {scores.max():.3f}")

    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NetGuard-AI — Anomaly Model")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--train",    action="store_true", help="تدريب النموذج")
    group.add_argument("--predict",  action="store_true", help="تنبؤ على بيانات جديدة")
    group.add_argument("--evaluate", action="store_true", help="تقييم شامل")

    parser.add_argument("--windows", default=None,
                        help="ملفات windows للتدريب مفصولة بفاصلة "
                             "(افتراضي: windows_2026-05-12 و 2026-05-13)")
    parser.add_argument("--input",  "-i", default=None,
                        help="ملف windows للتنبؤ")
    parser.add_argument("--output", "-o", default=None,
                        help="ملف CSV لحفظ النتائج")
    args = parser.parse_args()

    if args.train:
        if args.windows:
            files = [f.strip() for f in args.windows.split(",")]
        else:
            # الافتراضي: 12 و13 مايو فقط (11 مايو مستثنى لاحتوائه burst غير طبيعي)
            files = [
                str(WINDOWS_DIR / "windows_2026-05-12.csv"),
                str(WINDOWS_DIR / "windows_2026-05-13.csv"),
            ]
        train(files)

    elif args.predict:
        if not args.input:
            # افتراضي: windows اليوم
            today = datetime.now().strftime("%Y-%m-%d")
            args.input = str(WINDOWS_DIR / f"windows_{today}.csv")
        predict(args.input, args.output)

    elif args.evaluate:
        evaluate()


if __name__ == "__main__":
    main()
