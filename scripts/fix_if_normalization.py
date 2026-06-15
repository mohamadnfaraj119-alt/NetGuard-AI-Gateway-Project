#!/usr/bin/env python3
"""
fix_if_normalization.py — NetGuard-AI Gateway
===============================================
يُصلح مشكلة data leakage في normalization الـ IF scores.

المشكلة:
  norm = (scores - scores.min()) / (scores.max() - scores.min())
  ← يستخدم min/max من بيانات الاختبار الجديدة في كل مرة
  ← الـ threshold 0.725 يتغير مع كل batch → غير موثوق

الإصلاح:
  1. أثناء التدريب: احفظ score_min و score_max في if_scaler.json
  2. أثناء الـ inference: استخدمهما ثابتَيْن دائماً

الاستخدام:
  # خطوة 1 — يُشغَّل مرة واحدة بعد كل إعادة تدريب IF
  python scripts/fix_if_normalization.py --fit \
      --windows data/windows/windows_full_training.csv

  # خطوة 2 — يُشغَّل لتحديث ip_baselines.json بالـ scores الصحيحة
  python scripts/fix_if_normalization.py --update-baselines

  # التحقق — يقارن الـ scores القديمة والجديدة
  python scripts/fix_if_normalization.py --verify \
      --windows data/windows/windows_2026-06-14.csv

Version: 1.0.0 — NetGuard-AI Gateway v7.4
"""

import json
import pickle
import argparse
import glob
import sys
import numpy as np
import pandas as pd
from pathlib import Path

# ─── مسارات المشروع ──────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
MODEL_DIR   = BASE_DIR / "models" / "anomaly"
BASELINE_DIR= BASE_DIR / "data"   / "baselines"
WINDOWS_DIR = BASE_DIR / "data"   / "windows"

IF_MODEL_PATH    = MODEL_DIR    / "isolation_forest.pkl"
SCALER_PATH      = MODEL_DIR    / "scaler.pkl"
FEATURE_PATH     = MODEL_DIR    / "feature_names.json"
IF_SCALER_PATH   = MODEL_DIR    / "if_scaler.json"      # ← الملف الجديد
IP_BASELINES_PATH= BASELINE_DIR / "ip_baselines.json"


# ─── تحميل النموذج ───────────────────────────────────────────────────────────
def _load_model():
    with open(IF_MODEL_PATH,  "rb") as f: model         = pickle.load(f)
    with open(SCALER_PATH,    "rb") as f: scaler        = pickle.load(f)
    with open(FEATURE_PATH)        as f: feature_names  = json.load(f)
    return model, scaler, feature_names


# ─── حساب الـ raw scores ─────────────────────────────────────────────────────
def _compute_raw_scores(df: pd.DataFrame, model, scaler, feature_names) -> np.ndarray:
    X    = df[feature_names].fillna(0).values
    X_sc = scaler.transform(X)
    raw  = model.score_samples(X_sc)
    return -raw   # score_samples يرجع قيماً سالبة — نعكسها


# ─── normalize باستخدام ثوابت محفوظة ────────────────────────────────────────
def normalize_scores(raw_scores: np.ndarray, score_min: float, score_max: float) -> np.ndarray:
    """
    normalize باستخدام score_min و score_max من بيانات التدريب فقط.
    أي قيمة خارج النطاق تُقيَّد بـ [0, 1].
    """
    denom = score_max - score_min
    if denom < 1e-9:
        return np.zeros_like(raw_scores)
    return np.clip((raw_scores - score_min) / denom, 0.0, 1.0)


# ─── --fit : يُشغَّل بعد كل إعادة تدريب ────────────────────────────────────
def cmd_fit(windows_path: str) -> None:
    """
    يحسب score_min و score_max من بيانات التدريب ويحفظهما في if_scaler.json.
    يجب تشغيله مباشرة بعد anomaly_model.py --train.
    """
    print(f"📂 تحميل بيانات التدريب: {windows_path}")
    df = pd.read_csv(windows_path)
    print(f"   {len(df):,} نافذة تدريب")

    model, scaler, feature_names = _load_model()
    raw_scores = _compute_raw_scores(df, model, scaler, feature_names)

    score_min = float(raw_scores.min())
    score_max = float(raw_scores.max())
    p99       = float(np.percentile(raw_scores, 99))
    p999      = float(np.percentile(raw_scores, 99.9))

    if_scaler = {
        "score_min":       score_min,
        "score_max":       score_max,
        "score_p99_raw":   p99,
        "score_p999_raw":  p999,
        "training_windows": len(df),
        "note": (
            "استخدم score_min و score_max هذين في كل normalization لاحقة "
            "— لا تحسبهما من بيانات الاختبار"
        ),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    with open(IF_SCALER_PATH, "w") as f:
        json.dump(if_scaler, f, indent=2, ensure_ascii=False)

    # normalize للتحقق
    norm = normalize_scores(raw_scores, score_min, score_max)
    p99_norm  = float(np.percentile(norm, 99))
    p999_norm = float(np.percentile(norm, 99.9))

    print(f"\n✅ تم حفظ if_scaler.json:")
    print(f"   score_min  = {score_min:.6f}")
    print(f"   score_max  = {score_max:.6f}")
    print(f"   p99  (raw) = {p99:.6f}  →  normalized: {p99_norm:.4f}")
    print(f"   p999 (raw) = {p999:.6f}  →  normalized: {p999_norm:.4f}")
    print(f"\n⚠️  P99_BASELINE الجديد = {p99_norm:.4f}")
    print(f"   عدّل risk_engine.py:")
    print(f"   P99_BASELINE = {p99_norm:.3f}")


# ─── --update-baselines : تحديث ip_baselines.json بالـ scores الصحيحة ────────
def cmd_update_baselines() -> None:
    """
    يعيد حساب if_p99 و if_p999 لكل IP باستخدام الـ scaler الثابت
    ويحدّث ip_baselines.json.
    """
    # تحميل الـ scaler الثابت
    if not IF_SCALER_PATH.exists():
        print("❌ if_scaler.json غير موجود — شغّل --fit أولاً")
        sys.exit(1)

    with open(IF_SCALER_PATH) as f:
        if_scaler = json.load(f)

    score_min = if_scaler["score_min"]
    score_max = if_scaler["score_max"]
    print(f"📐 score_min={score_min:.6f} | score_max={score_max:.6f} (من if_scaler.json)")

    # تحميل كل ملفات الـ windows
    files = sorted(glob.glob(str(WINDOWS_DIR / "windows_2026-*.csv")))
    if not files:
        print("❌ لا توجد ملفات windows_2026-*.csv")
        sys.exit(1)

    print(f"📂 تحميل {len(files)} ملف windows...")
    dfs = [pd.read_csv(f) for f in files]
    df  = pd.concat(dfs, ignore_index=True)
    print(f"   {len(df):,} نافذة إجمالية")

    model, scaler, feature_names = _load_model()
    raw_scores = _compute_raw_scores(df, model, scaler, feature_names)

    # normalize بالثوابت المحفوظة — لا بيانات الاختبار
    df["if_score"] = normalize_scores(raw_scores, score_min, score_max)

    # تحميل ip_baselines.json
    with open(IP_BASELINES_PATH) as f:
        data = json.load(f)

    updated = 0
    for ip, grp in df.groupby("src_ip"):
        if len(grp) < 100:
            continue
        if ip not in data["ip_baselines"]:
            data["ip_baselines"][ip] = {"use_per_ip": False}

        old_p999 = data["ip_baselines"][ip].get("if_p999", None)
        new_p99  = round(float(grp["if_score"].quantile(0.99)),  4)
        new_p999 = round(float(grp["if_score"].quantile(0.999)), 4)

        data["ip_baselines"][ip]["if_p99"]  = new_p99
        data["ip_baselines"][ip]["if_p999"] = new_p999

        change = ""
        if old_p999 is not None:
            delta = new_p999 - old_p999
            change = f"  (Δ {delta:+.3f})"

        print(f"  ✅ {ip:<20} if_p999={new_p999:.3f}{change}  [{len(grp):,} نافذة]")
        updated += 1

    with open(IP_BASELINES_PATH, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ تم تحديث ip_baselines.json — {updated} IP")
    print("⚠️  لا تنسَ تحديث P99_BASELINE في risk_engine.py (انظر --fit output)")


# ─── --verify : مقارنة الـ scores القديمة والجديدة ──────────────────────────
def cmd_verify(windows_path: str) -> None:
    """
    يقارن الـ normalization القديم (من بيانات الاختبار) والجديد (ثوابت محفوظة).
    يُظهر الفرق لتوضيح أهمية الإصلاح.
    """
    if not IF_SCALER_PATH.exists():
        print("❌ if_scaler.json غير موجود — شغّل --fit أولاً")
        sys.exit(1)

    with open(IF_SCALER_PATH) as f:
        if_scaler = json.load(f)

    score_min = if_scaler["score_min"]
    score_max = if_scaler["score_max"]

    print(f"📂 تحميل: {windows_path}")
    df = pd.read_csv(windows_path)
    print(f"   {len(df):,} نافذة اختبار")

    model, scaler, feature_names = _load_model()
    raw_scores = _compute_raw_scores(df, model, scaler, feature_names)

    # الطريقة القديمة — data leakage
    old_norm = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)

    # الطريقة الجديدة — ثوابت محفوظة
    new_norm = normalize_scores(raw_scores, score_min, score_max)

    print(f"\n{'المقياس':<30} {'قديم (leaky)':<18} {'جديد (ثابت)':<18} {'الفرق'}")
    print("-" * 75)
    metrics = [
        ("p50 (median)", 50),
        ("p90", 90),
        ("p99", 99),
        ("p99.9", 99.9),
        ("max", 100),
    ]
    for label, pct in metrics:
        old_v = float(np.percentile(old_norm, pct))
        new_v = float(np.percentile(new_norm, pct))
        diff  = new_v - old_v
        flag  = "⚠️" if abs(diff) > 0.05 else "✅"
        print(f"{label:<30} {old_v:<18.4f} {new_v:<18.4f} {diff:+.4f} {flag}")

    print(f"\n{'IP':<20} {'p999 قديم':<15} {'p999 جديد':<15} {'الفرق'}")
    print("-" * 55)
    df["if_score_old"] = old_norm
    df["if_score_new"] = new_norm
    for ip, grp in df.groupby("src_ip"):
        if len(grp) < 50:
            continue
        old_p = grp["if_score_old"].quantile(0.999)
        new_p = grp["if_score_new"].quantile(0.999)
        diff  = new_p - old_p
        flag  = "⚠️" if abs(diff) > 0.05 else "✅"
        print(f"{ip:<20} {old_p:<15.4f} {new_p:<15.4f} {diff:+.4f} {flag}")


# ─── Entry Point ─────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="إصلاح IF Normalization — NetGuard-AI Gateway v7.4"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--fit",
        action="store_true",
        help="احسب score_min/max من بيانات التدريب واحفظهما"
    )
    group.add_argument(
        "--update-baselines",
        action="store_true",
        help="أعد حساب ip_baselines.json بالـ scaler الثابت"
    )
    group.add_argument(
        "--verify",
        action="store_true",
        help="قارن الـ scores القديمة والجديدة على بيانات معينة"
    )
    parser.add_argument(
        "--windows",
        type=str,
        default=str(WINDOWS_DIR / "windows_full_training.csv"),
        help="مسار ملف الـ windows (لـ --fit و --verify)"
    )
    args = parser.parse_args()

    if args.fit:
        cmd_fit(args.windows)
    elif args.update_baselines:
        cmd_update_baselines()
    elif args.verify:
        cmd_verify(args.windows)


if __name__ == "__main__":
    main()
