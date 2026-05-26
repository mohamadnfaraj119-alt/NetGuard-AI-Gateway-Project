#!/usr/bin/env python3
"""
signature_model.py — NetGuard-AI
Signature-based Attack Detection بـ XGBoost
يتدرب على CICIDS2017 لتصنيف نوع الهجوم

الاستخدام:
  python scripts/signature_model.py --train
  python scripts/signature_model.py --evaluate
  python scripts/signature_model.py --predict --input data/windows/windows_2026-05-13.csv
  python scripts/signature_model.py --info
"""

import argparse
import json
import logging
import pickle
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE

try:
    import xgboost as xgb
except ImportError:
    print("❌ xgboost غير مثبت — شغّل: pip install xgboost imbalanced-learn --break-system-packages")
    sys.exit(1)

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent
CICIDS_DIR   = BASE_DIR / "data" / "cicids2017"
MODELS_DIR   = BASE_DIR / "models" / "signature"
LOGS_DIR     = BASE_DIR / "logs"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE    = MODELS_DIR / "xgboost.pkl"
SCALER_FILE   = MODELS_DIR / "scaler.pkl"
ENCODER_FILE  = MODELS_DIR / "label_encoder.pkl"
FEATURES_FILE = MODELS_DIR / "feature_names_signature.json"
META_FILE     = MODELS_DIR / "model_meta.json"

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "signature_model.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── ملفات CICIDS2017 ────────────────────────────────────────────────────────
CICIDS_FILES = [
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
]

# ─── Labels المقبولة (نتجاهل BENIGN + Heartbleed + Sql Injection) ────────────
ACCEPTED_ATTACKS = {
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
    "Bot",
}

# تبسيط الأسماء للعرض
LABEL_MAP = {
    "DoS Hulk":               "DoS",
    "DoS GoldenEye":          "DoS",
    "DoS slowloris":          "DoS_Slow",
    "DoS Slowhttptest":       "DoS_Slow",
    "Web Attack - Brute Force": "BruteForce",
    "Web Attack - XSS":       "WebAttack",
    "Bot":                    "Bot",
}

# ─── الـ 10 Features المشتركة مع Zeek (جدول المواءمة §18) ───────────────────
# الأسماء كما هي في CICIDS2017
CICIDS_FEATURES = [
    "Destination Port",           # → id.resp_p
    "Flow Duration",              # → duration
    "Total Fwd Packets",          # → orig_pkts
    "Total Backward Packets",     # → resp_pkts
    "Total Length of Fwd Packets", # → orig_bytes
    "Total Length of Bwd Packets", # → resp_bytes
    "SYN Flag Count",             # → تقريبي
    "RST Flag Count",             # → conn_state REJ/RSTO
    "FIN Flag Count",             # → conn_state SF
    "Down/Up Ratio",              # → resp_bytes/orig_bytes
]

# أسماء الـ features كما ستكون في Zeek (للتوافق عند التنبؤ)
ZEEK_FEATURE_NAMES = [
    "dst_port",
    "duration",
    "orig_pkts",
    "resp_pkts",
    "orig_bytes",
    "resp_bytes",
    "syn_flag",
    "rst_flag",
    "fin_flag",
    "down_up_ratio",
]

# الـ features الممنوعة (Feature Leakage) — نتحقق منها صراحةً
FORBIDDEN_FEATURES = {
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
}


# ══════════════════════════════════════════════════════════════════════════════
# تحميل وتنظيف CICIDS2017
# ══════════════════════════════════════════════════════════════════════════════

def load_cicids() -> pd.DataFrame:
    """
    تحميل ملفات CICIDS2017 وتنظيفها:
      - إزالة BENIGN + Heartbleed + Sql Injection
      - حذف Infinity و NaN
      - حذف Feature Leakage
      - اختيار 10 features المشتركة مع Zeek
      - تبسيط Labels
    """
    log.info("=" * 60)
    log.info("📂 تحميل CICIDS2017")
    log.info("=" * 60)

    dfs = []
    for fname in CICIDS_FILES:
        fpath = CICIDS_DIR / fname
        if not fpath.exists():
            log.warning(f"⚠️  غير موجود: {fname} — تخطي")
            continue

        log.info(f"📄 {fname}")
        df = pd.read_csv(fpath, low_memory=False)
        df.columns = df.columns.str.strip()

        # تحقق من غياب الـ features الممنوعة
        found_forbidden = FORBIDDEN_FEATURES & set(df.columns)
        if found_forbidden:
            log.info(f"   🚫 حذف feature leakage: {found_forbidden}")
            df = df.drop(columns=list(found_forbidden), errors="ignore")

        # تنظيف Label
        df["Label"] = df["Label"].str.strip()
        df["Label"] = df["Label"].str.replace("�", "-", regex=False)

        # إحصاء قبل التصفية
        label_counts = df["Label"].value_counts()
        log.info(f"   Labels: {dict(label_counts)}")

        # نأخذ الهجمات المقبولة فقط
        df = df[df["Label"].isin(ACCEPTED_ATTACKS)].copy()
        log.info(f"   ✅ بعد التصفية: {len(df):,} سجل")

        dfs.append(df)

    if not dfs:
        log.error("❌ لا توجد ملفات CICIDS2017")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True)
    log.info(f"\n📊 إجمالي سجلات الهجوم: {len(combined):,}")

    # تبسيط Labels
    combined["Label"] = combined["Label"].map(LABEL_MAP)
    log.info(f"\n📊 توزيع الفئات بعد التبسيط:")
    for label, count in combined["Label"].value_counts().items():
        log.info(f"   {label:15s}: {count:,}")

    return combined


def prepare_features(df: pd.DataFrame) -> tuple:
    """
    اختيار الـ 10 features وتنظيفها
    يُرجع: (X, y, feature_names)
    """
    # التحقق من توفر الـ features
    available = [f for f in CICIDS_FEATURES if f in df.columns]
    missing   = [f for f in CICIDS_FEATURES if f not in df.columns]

    if missing:
        log.warning(f"⚠️  features غير موجودة: {missing}")

    log.info(f"✅ Features المستخدمة ({len(available)}): {available}")

    X = df[available].copy()
    y = df["Label"].copy()

    # حذف Infinity
    X = X.replace([np.inf, -np.inf], np.nan)

    # حذف الصفوف التي فيها NaN
    mask  = X.notna().all(axis=1)
    X     = X[mask].reset_index(drop=True)
    y     = y[mask].reset_index(drop=True)

    removed = (~mask).sum()
    if removed > 0:
        log.info(f"🔇 حذف {removed:,} سجل يحتوي Infinity/NaN")

    # تحويل لـ float
    X = X.astype(float)

    log.info(f"📊 البيانات الجاهزة: {len(X):,} سجل | {len(available)} feature")

    return X, y, available


# ══════════════════════════════════════════════════════════════════════════════
# التدريب
# ══════════════════════════════════════════════════════════════════════════════

def train():
    """تدريب XGBoost على CICIDS2017"""
    log.info("=" * 60)
    log.info("🚀 بدء التدريب — XGBoost Signature Model")
    log.info("=" * 60)

    # ── تحميل البيانات ────────────────────────────────────────────────────────
    df = load_cicids()
    X, y, feature_names = prepare_features(df)

    # ── Encoding ──────────────────────────────────────────────────────────────
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    classes   = list(encoder.classes_)
    log.info(f"\n📋 الفئات: {classes}")

    # ── تقسيم 80/20 مع Stratify ──────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )
    log.info(f"\n📊 التقسيم:")
    log.info(f"   Train: {len(X_train):,}")
    log.info(f"   Test : {len(X_test):,}")

    # ── Scaling ───────────────────────────────────────────────────────────────
    scaler  = RobustScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── SMOTE للفئات القليلة ──────────────────────────────────────────────────
    log.info("\n⏳ تطبيق SMOTE على الفئات القليلة...")
    train_counts = pd.Series(y_train).value_counts()
    log.info(f"   قبل SMOTE: {dict(train_counts)}")

    # SMOTE يحتاج k_neighbors < أقل فئة
    min_samples = train_counts.min()
    k_neighbors = min(5, min_samples - 1)

    if k_neighbors >= 1:
        smote    = SMOTE(random_state=42, k_neighbors=k_neighbors)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        log.info(f"   بعد SMOTE : {dict(pd.Series(y_train).value_counts())}")
    else:
        log.warning("⚠️  SMOTE تخطي — فئة أقل من 2 سجل")

    # ── XGBoost ───────────────────────────────────────────────────────────────
    log.info("\n⏳ تدريب XGBoost...")

    n_classes = len(classes)
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="mlogloss",
        objective="multi:softprob" if n_classes > 2 else "binary:logistic",
        num_class=n_classes if n_classes > 2 else None,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )
    log.info("✅ اكتمل التدريب")

    # ── التقييم ───────────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    y_pred_labels = encoder.inverse_transform(y_pred)
    y_test_labels = encoder.inverse_transform(y_test)

    print(f"\n{'='*60}")
    print(f"📊 نتائج التقييم على Test Set")
    print(f"{'='*60}")
    print(classification_report(y_test_labels, y_pred_labels))

    # Accuracy
    accuracy = (y_pred == y_test).mean() * 100
    log.info(f"✅ Accuracy: {accuracy:.2f}%")

    # ── Feature Importance ────────────────────────────────────────────────────
    importance = model.feature_importances_
    print(f"\n📈 Feature Importance:")
    for feat, imp in sorted(zip(feature_names, importance),
                            key=lambda x: x[1], reverse=True):
        bar = "█" * int(imp * 50)
        print(f"   {feat:35s}: {imp:.4f} {bar}")

    # ── حفظ النموذج ───────────────────────────────────────────────────────────
    with open(MODEL_FILE,   "wb") as f: pickle.dump(model,   f)
    with open(SCALER_FILE,  "wb") as f: pickle.dump(scaler,  f)
    with open(ENCODER_FILE, "wb") as f: pickle.dump(encoder, f)

    with open(FEATURES_FILE, "w") as f:
        json.dump({
            "cicids_names": feature_names,
            "zeek_names":   ZEEK_FEATURE_NAMES[:len(feature_names)],
        }, f, indent=2)

    meta = {
        "trained_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "n_train":      int(len(X_train)),
        "n_test":       int(len(X_test)),
        "n_features":   len(feature_names),
        "classes":      classes,
        "accuracy":     round(float(accuracy), 2),
        "feature_names": feature_names,
    }
    with open(META_FILE, "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    log.info(f"\n💾 النموذج محفوظ في: {MODELS_DIR}")
    _print_summary(meta)


def _print_summary(meta: dict):
    print(f"\n{'='*60}")
    print(f"✅ تم التدريب بنجاح — XGBoost Signature Model")
    print(f"{'='*60}")
    print(f"  Train        : {meta['n_train']:,}")
    print(f"  Test         : {meta['n_test']:,}")
    print(f"  Features     : {meta['n_features']}")
    print(f"  Accuracy     : {meta['accuracy']}%")
    print(f"  الفئات       : {meta['classes']}")
    print(f"{'='*60}")
    print(f"  الاستخدام التالي:")
    print(f"  python scripts/signature_model.py --evaluate")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# التنبؤ على بيانات Zeek
# ══════════════════════════════════════════════════════════════════════════════

def predict(input_file: str, output_file: str = None):
    """
    تطبيق النموذج على windows من Zeek
    يُضيف: attack_type + attack_confidence
    """
    _check_model_exists()

    model, scaler, encoder, feature_meta = _load_model()
    zeek_names  = feature_meta.get("zeek_names", ZEEK_FEATURE_NAMES)

    path = Path(input_file)
    if not path.exists():
        log.error(f"❌ الملف غير موجود: {path}")
        sys.exit(1)

    df = pd.read_csv(path)
    log.info(f"📂 {path.name}: {len(df)} نافذة")

    # بناء الـ features من بيانات Zeek
    X = _build_zeek_features(df, zeek_names)

    if X is None:
        log.warning("⚠️  features Zeek غير كافية للتنبؤ")
        return df

    X_scaled = scaler.transform(X)

    # التنبؤ
    proba      = model.predict_proba(X_scaled)
    pred_class = np.argmax(proba, axis=1)
    confidence = np.max(proba, axis=1)

    df["attack_type"]       = encoder.inverse_transform(pred_class)
    df["attack_confidence"] = np.round(confidence, 4)

    # نُظهر فقط النوافذ عالية الثقة
    high_conf = df[df["attack_confidence"] > 0.7]
    if not high_conf.empty:
        print(f"\n⚠️  تصنيفات عالية الثقة (> 70%):")
        print(high_conf[["datetime", "attack_type",
                          "attack_confidence"]].to_string(index=False))

    out_path = Path(output_file) if output_file else \
               path.parent / f"signature_{path.name}"
    df.to_csv(out_path, index=False)
    log.info(f"💾 النتائج: {out_path.name}")

    return df


def _build_zeek_features(df: pd.DataFrame, zeek_names: list) -> np.ndarray:
    """
    بناء feature matrix من بيانات Zeek
    بعض الـ features تحتاج حساب (مثل down_up_ratio)
    """
    X = pd.DataFrame(index=df.index)

    mapping = {
        "dst_port":      "connections_30s",   # تقريب — نستخدم ما متاح
        "duration":      "avg_conn_duration_30s",
        "orig_pkts":     "connections_30s",
        "resp_pkts":     "connections_30s",
        "orig_bytes":    "bytes_per_sec_30s",
        "resp_bytes":    "bytes_per_sec_30s",
        "syn_flag":      "burst_score_30s",
        "rst_flag":      "failed_conn_rate_30s",
        "fin_flag":      "outbound_ratio_30s",
        "down_up_ratio": "outbound_ratio_30s",
    }

    for zeek_name in zeek_names:
        source_col = mapping.get(zeek_name)
        if source_col and source_col in df.columns:
            X[zeek_name] = df[source_col].fillna(0)
        else:
            X[zeek_name] = 0.0

    return X.values.astype(float)


# ══════════════════════════════════════════════════════════════════════════════
# التقييم
# ══════════════════════════════════════════════════════════════════════════════

def evaluate():
    """تقييم تفصيلي للنموذج"""
    _check_model_exists()

    with open(META_FILE) as f:
        meta = json.load(f)

    print(f"\n{'='*60}")
    print(f"📊 معلومات النموذج — XGBoost Signature")
    print(f"{'='*60}")
    print(f"  تاريخ التدريب : {meta['trained_at']}")
    print(f"  Train         : {meta['n_train']:,}")
    print(f"  Test          : {meta['n_test']:,}")
    print(f"  Features      : {meta['n_features']}")
    print(f"  Accuracy      : {meta['accuracy']}%")
    print(f"  الفئات        : {meta['classes']}")
    print(f"\n  Features المستخدمة:")
    for i, feat in enumerate(meta["feature_names"]):
        print(f"    {i+1:2d}. {feat}")
    print(f"{'='*60}\n")


def info():
    """معلومات عن الـ features والمواءمة"""
    print(f"\n{'='*65}")
    print(f"📋 جدول المواءمة CICIDS2017 ↔ Zeek")
    print(f"{'='*65}")
    print(f"  {'CICIDS2017 Feature':<35} {'Zeek Equivalent':<20}")
    print(f"  {'-'*35} {'-'*20}")
    pairs = list(zip(CICIDS_FEATURES, ZEEK_FEATURE_NAMES))
    for cicids, zeek in pairs:
        print(f"  {cicids:<35} {zeek:<20}")
    print(f"{'='*65}")
    print(f"\n  ❌ محذوف (Feature Leakage):")
    for f in FORBIDDEN_FEATURES:
        print(f"     {f}")
    print(f"{'='*65}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _check_model_exists():
    for f in [MODEL_FILE, SCALER_FILE, ENCODER_FILE]:
        if not f.exists():
            log.error(f"❌ {f.name} غير موجود — شغّل --train أولاً")
            sys.exit(1)


def _load_model():
    with open(MODEL_FILE,   "rb") as f: model   = pickle.load(f)
    with open(SCALER_FILE,  "rb") as f: scaler  = pickle.load(f)
    with open(ENCODER_FILE, "rb") as f: encoder = pickle.load(f)
    with open(FEATURES_FILE)      as f: feature_meta = json.load(f)

    with open(META_FILE) as f:
        meta = json.load(f)
    log.info(f"✅ النموذج محمّل — تدرّب: {meta['trained_at']} | "
             f"Accuracy: {meta['accuracy']}%")

    return model, scaler, encoder, feature_meta


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard-AI — Signature Model (XGBoost)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  python scripts/signature_model.py --train
  python scripts/signature_model.py --evaluate
  python scripts/signature_model.py --predict --input data/windows/windows_2026-05-13.csv
  python scripts/signature_model.py --info
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--train",   action="store_true", help="تدريب النموذج")
    group.add_argument("--evaluate",action="store_true", help="تقييم النموذج")
    group.add_argument("--predict", action="store_true", help="تنبؤ على بيانات Zeek")
    group.add_argument("--info",    action="store_true", help="معلومات الـ features")

    parser.add_argument("--input",  "-i", default=None, help="ملف windows للتنبؤ")
    parser.add_argument("--output", "-o", default=None, help="ملف CSV للحفظ")

    args = parser.parse_args()

    if args.train:
        train()
    elif args.evaluate:
        evaluate()
    elif args.predict:
        if not args.input:
            today = datetime.now().strftime("%Y-%m-%d")
            args.input = str(BASE_DIR / "data" / "windows" / f"windows_{today}.csv")
        predict(args.input, args.output)
    elif args.info:
        info()


if __name__ == "__main__":
    main()