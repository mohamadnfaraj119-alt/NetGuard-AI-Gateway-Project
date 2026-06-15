#!/usr/bin/env python3
"""
risk_engine.py — NetGuard-AI
نقطة الدخول النهائية للنظام

يجمع:
  1. Anomaly Score  ← Isolation Forest (Behavioral Layer)
  2. Scan Score     ← port_entropy + unique_dst_ports
  3. Burst Score    ← burst_score_30s + connections_30s
  4. DNS Score      ← dns_rate + flag_dns_flood
  5. External Score ← outbound_ratio

ويُخرج Risk Score 0-100 مع تنبيهات قابلة للتفسير.

الاستخدام:
  python scripts/risk_engine.py
  python scripts/risk_engine.py --date 2026-05-13
  python scripts/risk_engine.py --input data/windows/windows_2026-05-13.csv
  python scripts/risk_engine.py --input X --output Y
  python scripts/risk_engine.py --live
  python scripts/risk_engine.py --summary
"""

import argparse
import json
import logging
import pickle
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from baseline_loader import get_threshold
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from baseline_loader import get_threshold

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
WINDOWS_DIR = BASE_DIR / "data" / "windows"
MODELS_DIR  = BASE_DIR / "models" / "anomaly"
REPORTS_DIR = BASE_DIR / "data" / "reports"
LOGS_DIR    = BASE_DIR / "logs"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
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
        logging.FileHandler(LOGS_DIR / "risk_engine.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── أوزان Risk Engine (من القسم 17 — تُعيَّر بعد Live Testing) ──────────────
WEIGHTS = {
    "anomaly": 35,   # Isolation Forest output
    "scan":    30,   # port scan indicators
    "burst":   20,   # burst / flood indicators
    "dns":     15,   # DNS anomaly
    "external": 10,  # new/unusual external IPs
}
# المجموع 110 مقصود — cap عند 100 (انظر وثيقة السياق §17)

# ─── عتبات Risk Score ────────────────────────────────────────────────────────
THRESHOLDS = {
    "investigate": 30,   # 🟡 مشبوه
    "alert":       60,   # 🟠 خطر
    "critical":    80,   # 🔴 هجوم
}

# ─── Baseline للـ features (من وثيقة السياق §13) ────────────────────────────
# تُستخدم لحساب component scores بشكل نسبي
BASELINE = {
    "connections_30s_max":      35,
    "unique_dst_ports_30s_max":  5,
    "port_entropy_30s_max":      0.115,
    "burst_score_30s_max":       0.287,
    "dns_rate_1m_max":           2.117,    # طلبات/ثانية × 60
    "outbound_ratio_30s_mean":   0.5,
}


# ══════════════════════════════════════════════════════════════════════════════
# تحميل النموذج
# ══════════════════════════════════════════════════════════════════════════════

def load_model() -> tuple:
    """تحميل Isolation Forest + Scaler + Feature Names"""
    for f in [MODEL_FILE, SCALER_FILE, FEATURES_FILE]:
        if not f.exists():
            log.error(f"❌ ملف مفقود: {f.name} — شغّل anomaly_model.py --train أولاً")
            sys.exit(1)

    with open(MODEL_FILE,  "rb") as f: model  = pickle.load(f)
    with open(SCALER_FILE, "rb") as f: scaler = pickle.load(f)
    with open(FEATURES_FILE)     as f: feature_names = json.load(f)

    with open(STATS_FILE) as f:
        stats = json.load(f)

    log.info(f"✅ النموذج محمّل — تدرّب: {stats['trained_at']} | "
             f"نوافذ: {stats['n_windows']:,} | features: {stats['n_features']}")
    return model, scaler, feature_names


# ══════════════════════════════════════════════════════════════════════════════
# حساب Anomaly Score من IF
# ══════════════════════════════════════════════════════════════════════════════

def compute_anomaly_scores(df: pd.DataFrame, model, scaler, feature_names: list) -> np.ndarray:
    """
    يُشغّل Isolation Forest على الـ windows ويُعيد anomaly_score [0,1]
    0 = طبيعي تماماً | 1 = شاذ جداً
    """
    available = [f for f in feature_names if f in df.columns]
    missing   = [f for f in feature_names if f not in df.columns]

    if missing:
        log.warning(f"⚠️  features غير موجودة: {missing} — ستُعامل كـ 0")

    X = df[available].fillna(0).values

    # إضافة أعمدة ناقصة كـ 0
    if len(available) < len(feature_names):
        full_X = np.zeros((len(df), len(feature_names)))
        idx    = [feature_names.index(f) for f in available]
        full_X[:, idx] = X
        X = full_X

    X_scaled    = scaler.transform(X)
    raw_scores  = model.score_samples(X_scaled)  # سالب = أكثر شذوذاً
    norm_scores = _normalize(raw_scores)
    # per-IP threshold
    import json as _json
    try:
        with open(str(BASE_DIR / "data" / "baselines" / "ip_baselines.json")) as _f:
            _bl = _json.load(_f)
        _ip_baselines = _bl.get("ip_baselines", {})
    except Exception:
        _ip_baselines = {}

    adjusted = np.zeros(len(norm_scores))
    src_ips = df["src_ip"].values if "src_ip" in df.columns else [""] * len(df)
    for i, (score, ip) in enumerate(zip(norm_scores, src_ips)):
        ip_data  = _ip_baselines.get(str(ip), {})
        p99_thr  = ip_data.get("if_p99", 0.782)  # p99.9 per-IP أو global
        adjusted[i] = np.clip((score - p99_thr) / max(1.0 - p99_thr, 0.01), 0, 1)
    return adjusted
    


def _normalize(raw_scores: np.ndarray) -> np.ndarray:
    """تحويل IF scores إلى [0,1] باستخدام if_scaler.json"""

    scores = -raw_scores

    try:
        with open(MODELS_DIR / "if_scaler.json") as f:
            scaler_cfg = json.load(f)

        score_min = float(scaler_cfg["score_min"])
        score_max = float(scaler_cfg["score_max"])

        denom = score_max - score_min

        if denom <= 1e-9:
            return np.zeros_like(scores)

        return np.clip(
            (scores - score_min) / denom,
            0.0,
            1.0
        )

    except Exception as e:
        log.warning(
            f"⚠️ if_scaler.json غير متاح ({e}) — استخدام الطريقة القديمة"
        )

        s_min, s_max = scores.min(), scores.max()

        if s_max == s_min:
            return np.zeros_like(scores)

        return (scores - s_min) / (s_max - s_min)


# ══════════════════════════════════════════════════════════════════════════════
# حساب Component Scores
# ══════════════════════════════════════════════════════════════════════════════

def compute_scan_score(row: pd.Series, src_ip: str = "") -> float:
    """
    Port Scan Score [0, 1]
    مصادر: unique_dst_ports_30s + port_entropy_30s + flag_port_scan
    """
    ports   = row.get("unique_dst_ports_30s", 0)
    entropy = row.get("port_entropy_30s", 0)
    flag    = row.get("flag_port_scan", 0)

    # تطبيع نسبي على الـ baseline
    _port_max    = get_threshold(src_ip, "unique_dst_ports_30s") if src_ip else BASELINE["unique_dst_ports_30s_max"]
    _entr_max    = get_threshold(src_ip, "port_entropy_30s")     if src_ip else BASELINE["port_entropy_30s_max"]
    ports_norm   = min(ports   / max(_port_max * 3, 1), 1.0)
    entropy_norm = min(entropy / max(_entr_max * 3, 0.001), 1.0)

    score = (ports_norm * 0.5) + (entropy_norm * 0.3) + (float(flag) * 0.2)
    return round(min(score, 1.0), 4)


def compute_burst_score_component(row: pd.Series, src_ip: str = '') -> float:
    """
    Burst Score [0, 1]
    مصادر: burst_score_30s + connections_30s + flag_burst
    """
    burst   = row.get("burst_score_30s", 0)
    conns   = row.get("connections_30s", 0)
    flag    = row.get("flag_burst", 0)

    _burst_max = get_threshold(src_ip, "burst_score_30s") if src_ip else BASELINE["burst_score_30s_max"]
    _conn_max  = get_threshold(src_ip, "connections_30s")  if src_ip else BASELINE["connections_30s_max"]
    burst_norm = min(burst / max(_burst_max * 3, 0.001), 1.0)
    conns_norm = min(conns / max(_conn_max  * 3, 1), 1.0)

    score = (burst_norm * 0.5) + (conns_norm * 0.3) + (float(flag) * 0.2)
    return round(min(score, 1.0), 4)


def compute_dns_score(row: pd.Series, src_ip: str = '') -> float:
    """
    DNS Anomaly Score [0, 1]
    مصادر: dns_rate_1m + flag_dns_flood
    """
    dns_rate = row.get("dns_rate_1m", 0) * 60  # تحويل إلى طلبات/دقيقة
    flag     = row.get("flag_dns_flood", 0)

    _dns_max = get_threshold(src_ip, "dns_rate_1m") if src_ip else BASELINE["dns_rate_1m_max"]
    dns_norm = min(dns_rate / max(_dns_max * 6, 1), 1.0)

    score = (dns_norm * 0.7) + (float(flag) * 0.3)
    return round(min(score, 1.0), 4)


def compute_external_score(row: pd.Series) -> float:
    """
    External Traffic Score [0, 1]
    مصادر: outbound_ratio_30s
    يعطي score عالي فقط عند outbound عالي جداً (> 90%)
    لأن بعض الـ outbound طبيعي
    """
    ratio = row.get("outbound_ratio_30s", 0)

    # طبيعي حتى 70% — يبدأ الخطر فوق 90%
    if ratio < 0.95:
        return 0.0
    score = (ratio - 0.95) / 0.05  # [0,1] بين 70% و100%
    return round(min(score, 1.0), 4)


# ══════════════════════════════════════════════════════════════════════════════
# Risk Score النهائي
# ══════════════════════════════════════════════════════════════════════════════

def compute_risk_score(row: pd.Series, anomaly_score: float, src_ip: str = '') -> dict:
    """
    يحسب Risk Score الكلي لنافذة واحدة.
    يُعيد dict بكل المكونات + Score النهائي + التفسير.
    """
    scan_s     = compute_scan_score(row, src_ip)
    burst_s    = compute_burst_score_component(row, src_ip)
    dns_s      = compute_dns_score(row, src_ip)
    external_s = 0.0  # disabled — outbound=1.0 طبيعي في شبكة NAT منزلية

    raw = (
        anomaly_score * WEIGHTS["anomaly"]  +
        scan_s        * WEIGHTS["scan"]     +
        burst_s       * WEIGHTS["burst"]    +
        dns_s         * WEIGHTS["dns"]      +
        external_s    * WEIGHTS["external"]
    )

    final = round(min(raw, 100), 2)

    # التصنيف
    if final >= THRESHOLDS["critical"]:
        level, emoji = "CRITICAL", "🔴"
    elif final >= THRESHOLDS["alert"]:
        level, emoji = "ALERT",    "🟠"
    elif final >= THRESHOLDS["investigate"]:
        level, emoji = "INVESTIGATE", "🟡"
    else:
        level, emoji = "NORMAL",   "🟢"

    # التفسير — ما هي أعلى مساهم؟
    contributors = {
        "anomaly":  anomaly_score * WEIGHTS["anomaly"],
        "scan":     scan_s        * WEIGHTS["scan"],
        "burst":    burst_s       * WEIGHTS["burst"],
        "dns":      dns_s         * WEIGHTS["dns"],
        "external": external_s    * WEIGHTS["external"],
    }
    top = sorted(contributors.items(), key=lambda x: x[1], reverse=True)
    explanation = _build_explanation(row, top, level)

    return {
        "risk_score":        final,
        "risk_level":        level,
        "risk_emoji":        emoji,
        "score_anomaly":     round(anomaly_score * WEIGHTS["anomaly"], 2),
        "score_scan":        round(scan_s        * WEIGHTS["scan"],    2),
        "score_burst":       round(burst_s       * WEIGHTS["burst"],   2),
        "score_dns":         round(dns_s         * WEIGHTS["dns"],     2),
        "score_external":    round(external_s    * WEIGHTS["external"], 2),
        "component_anomaly": round(anomaly_score, 4),
        "component_scan":    round(scan_s,        4),
        "component_burst":   round(burst_s,       4),
        "component_dns":     round(dns_s,         4),
        "component_external":round(external_s,    4),
        "explanation":       explanation,
    }


def _build_explanation(row: pd.Series, top_contributors: list, level: str) -> str:
    """
    بناء تفسير نصي قابل للقراءة للتنبيه.
    """
    if level == "NORMAL":
        return "حركة طبيعية — لا مؤشرات مشبوهة"

    parts = []
    for name, score in top_contributors:
        if score < 1.0:
            continue
        if name == "anomaly":
            parts.append(f"نمط سلوكي شاذ (IF score: {row.get('anomaly_score', 0):.3f})")
        elif name == "scan":
            ports   = row.get("unique_dst_ports_30s", 0)
            entropy = row.get("port_entropy_30s", 0)
            parts.append(f"مسح منافذ محتمل ({ports:.0f} منفذ، entropy={entropy:.3f})")
        elif name == "burst":
            conns = row.get("connections_30s", 0)
            burst = row.get("burst_score_30s", 0)
            parts.append(f"اندفاع اتصالات ({conns:.0f} conn/30s، burst={burst:.3f})")
        elif name == "dns":
            dns = row.get("dns_rate_1m", 0) * 60
            parts.append(f"نشاط DNS مرتفع ({dns:.0f} طلب/دقيقة)")
        elif name == "external":
            ratio = row.get("outbound_ratio_30s", 0)
            parts.append(f"حركة خارجية عالية ({ratio*100:.0f}%)")

    return " | ".join(parts) if parts else "نمط غير طبيعي"


# ══════════════════════════════════════════════════════════════════════════════
# المعالج الرئيسي
# ══════════════════════════════════════════════════════════════════════════════

def run(input_file: Path, output_file: Path = None, verbose: bool = True) -> pd.DataFrame:
    """
    يشغّل pipeline كامل:
      1. تحميل النموذج
      2. تحميل windows
      3. حساب anomaly scores (IF)
      4. حساب risk scores (Risk Engine)
      5. طباعة التنبيهات
      6. حفظ النتائج
    """
    log.info("=" * 60)
    log.info("🚀 NetGuard-AI — Risk Engine")
    log.info("=" * 60)

    # ── تحميل النموذج ────────────────────────────────────────────────────────
    model, scaler, feature_names = load_model()

    # ── تحميل البيانات ───────────────────────────────────────────────────────
    if not input_file.exists():
        log.error(f"❌ الملف غير موجود: {input_file}")
        sys.exit(1)

    df = pd.read_csv(input_file)
    log.info(f"📂 {input_file.name}: {len(df)} نافذة")

    if df.empty:
        log.warning("⚠️  الملف فارغ")
        return df

    # ── حساب Anomaly Scores ──────────────────────────────────────────────────
    log.info("⏳ تشغيل Isolation Forest...")
    anomaly_scores = compute_anomaly_scores(df, model, scaler, feature_names)
    df["anomaly_score"] = np.round(anomaly_scores, 4)
    df["is_anomaly"]    = (anomaly_scores > 0.5).astype(int)

    # ── حساب Risk Scores ─────────────────────────────────────────────────────
    log.info("⏳ حساب Risk Scores...")
    risk_rows = []
    for i, row in df.iterrows():
        _ip  = str(row.get('src_ip', ''))
        risk = compute_risk_score(row, float(anomaly_scores[i]), _ip)
        risk_rows.append(risk)

    df_risk = pd.DataFrame(risk_rows)
    df      = pd.concat([df, df_risk], axis=1)

    # ── طباعة التنبيهات ──────────────────────────────────────────────────────
    if verbose:
        _print_alerts(df)

    # ── ملخص ─────────────────────────────────────────────────────────────────
    _print_summary(df, input_file.name)

    # ── حفظ ──────────────────────────────────────────────────────────────────
    if output_file is None:
        stem        = input_file.stem.replace("windows_", "")
        output_file = REPORTS_DIR / f"risk_{stem}.csv"

    df.to_csv(output_file, index=False)
    log.info(f"💾 النتائج: {output_file}")

    return df


def _print_alerts(df: pd.DataFrame):
    """طباعة التنبيهات فوق عتبة INVESTIGATE"""
    alerts = df[df["risk_score"] >= THRESHOLDS["investigate"]].copy()

    if alerts.empty:
        print(f"\n✅ لا تنبيهات — كل النوافذ طبيعية")
        return

    print(f"\n{'='*65}")
    print(f"⚠️  التنبيهات ({len(alerts)} نافذة)")
    print(f"{'='*65}")

    for _, row in alerts.sort_values("risk_score", ascending=False).iterrows():
        emoji = row.get("risk_emoji", "⚠️")
        _ip_str = f" | IP: {row['src_ip']}" if 'src_ip' in row else ""
        print(f"\n{emoji} [{row.get('datetime', 'N/A')}]{_ip_str} "
              f"Risk Score: {row['risk_score']:.1f}/100 — {row.get('risk_level','')}")
        print(f"   📋 {row.get('explanation', '')}")
        print(f"   المكونات: "
              f"IF={row.get('score_anomaly',0):.1f} | "
              f"Scan={row.get('score_scan',0):.1f} | "
              f"Burst={row.get('score_burst',0):.1f} | "
              f"DNS={row.get('score_dns',0):.1f} | "
              f"Ext={row.get('score_external',0):.1f}")

    print(f"\n{'='*65}")


def _print_summary(df: pd.DataFrame, filename: str):
    """ملخص إحصائي كامل"""
    total      = len(df)
    normal     = (df["risk_level"] == "NORMAL").sum()
    invest     = (df["risk_level"] == "INVESTIGATE").sum()
    alert      = (df["risk_level"] == "ALERT").sum()
    critical   = (df["risk_level"] == "CRITICAL").sum()

    # FP Budget check (§15)
    fp_count   = invest + alert + critical
    fp_status  = "✅" if fp_count <= 5 else "⚠️ " if fp_count <= 15 else "❌"

    print(f"\n{'='*60}")
    print(f"📊 ملخص — {filename}")
    print(f"{'='*60}")
    print(f"  النوافذ الكلية  : {total:,}")
    print(f"  🟢 طبيعي        : {normal:,}  ({normal/total*100:.1f}%)")
    print(f"  🟡 مشبوه        : {invest:,}  ({invest/total*100:.1f}%)")
    print(f"  🟠 خطر          : {alert:,}   ({alert/total*100:.1f}%)")
    print(f"  🔴 هجوم         : {critical:,} ({critical/total*100:.1f}%)")
    print(f"{'─'*60}")
    print(f"  Risk Score mean : {df['risk_score'].mean():.2f}")
    print(f"  Risk Score max  : {df['risk_score'].max():.2f}")
    print(f"  Anomaly mean    : {df['anomaly_score'].mean():.4f}")
    print(f"{'─'*60}")
    print(f"  {fp_status} FP Budget (تنبيهات/يوم): {fp_count} "
          f"{'≤ 5 ✅' if fp_count <= 5 else '> 5 — راجع الأوزان'}")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# وضع المراقبة المستمرة
# ══════════════════════════════════════════════════════════════════════════════

def live_mode():
    """مراقبة مستمرة — يشغّل كل 30 ثانية على windows اليوم"""
    log.info("🔴 وضع المراقبة المستمرة — Ctrl+C للإيقاف")
    model, scaler, feature_names = load_model()

    last_processed = 0

    while True:
        today      = datetime.now().strftime("%Y-%m-%d")
        input_file = WINDOWS_DIR / f"windows_{today}.csv"

        if not input_file.exists():
            log.warning(f"⏳ في انتظار: {input_file.name}")
            time.sleep(30)
            continue

        try:
            df = pd.read_csv(input_file)

            if len(df) <= last_processed:
                time.sleep(30)
                continue

            # معالجة فقط النوافذ الجديدة
            df_new         = df.iloc[last_processed:].copy()
            last_processed = len(df)

            anomaly_scores = compute_anomaly_scores(df_new, model, scaler, feature_names)
            df_new["anomaly_score"] = np.round(anomaly_scores, 4)

            for i, (idx, row) in enumerate(df_new.iterrows()):
                _ip  = str(row.get('src_ip', ''))
                risk = compute_risk_score(row, float(anomaly_scores[i]), _ip)

                score = risk["risk_score"]
                emoji = risk["risk_emoji"]
                level = risk["risk_level"]
                expl  = risk["explanation"]
                ts    = row.get("datetime", "N/A")

                if score >= THRESHOLDS["investigate"]:
                    print(f"\n{'='*60}")
                    print(f"{emoji} [{ts}] Risk Score: {score:.1f}/100 — {level}")
                    print(f"   {expl}")
                    print(f"   IF={risk['score_anomaly']:.1f} | "
                          f"Scan={risk['score_scan']:.1f} | "
                          f"Burst={risk['score_burst']:.1f} | "
                          f"DNS={risk['score_dns']:.1f} | "
                          f"Ext={risk['score_external']:.1f}")
                else:
                    print(f"🟢 [{ts}] Risk Score: {score:.1f} — طبيعي")

        except Exception as e:
            log.error(f"❌ خطأ: {e}")

        time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# ملخص تاريخي
# ══════════════════════════════════════════════════════════════════════════════

def summary_mode():
    """ملخص لكل ملفات risk الموجودة"""
    risk_files = sorted(REPORTS_DIR.glob("risk_*.csv"))

    if not risk_files:
        print("❌ لا توجد تقارير — شغّل risk_engine.py أولاً")
        return

    print(f"\n{'='*70}")
    print(f"📊 ملخص تاريخي — NetGuard-AI Risk Engine")
    print(f"{'='*70}")
    print(f"  {'الملف':<30} {'طبيعي':>8} {'مشبوه':>8} {'خطر':>8} {'هجوم':>8} {'Max':>8}")
    print(f"{'─'*70}")

    for rf in risk_files:
        try:
            df = pd.read_csv(rf)
            if "risk_level" not in df.columns:
                continue
            n = (df["risk_level"] == "NORMAL").sum()
            i = (df["risk_level"] == "INVESTIGATE").sum()
            a = (df["risk_level"] == "ALERT").sum()
            c = (df["risk_level"] == "CRITICAL").sum()
            m = df["risk_score"].max() if "risk_score" in df.columns else 0
            print(f"  {rf.name:<30} {n:>8} {i:>8} {a:>8} {c:>8} {m:>8.1f}")
        except Exception:
            pass

    print(f"{'='*70}\n")


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard-AI — Risk Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  python scripts/risk_engine.py
  python scripts/risk_engine.py --date 2026-05-12
  python scripts/risk_engine.py --input data/windows/windows_2026-05-13.csv
  python scripts/risk_engine.py --live
  python scripts/risk_engine.py --summary
        """
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--live",    "-l", action="store_true",
                       help="وضع المراقبة المستمرة (كل 30 ثانية)")
    group.add_argument("--summary", "-s", action="store_true",
                       help="ملخص تاريخي لكل التقارير")

    parser.add_argument("--input",  "-i", default=None,
                        help="ملف windows CSV (افتراضي: windows اليوم)")
    parser.add_argument("--output", "-o", default=None,
                        help="ملف CSV للحفظ (افتراضي: data/reports/risk_YYYY-MM-DD.csv)")
    parser.add_argument("--date",   "-d", default=None,
                        help="تاريخ محدد (YYYY-MM-DD) — بديل عن --input")
    parser.add_argument("--quiet",  "-q", action="store_true",
                        help="إخفاء تفاصيل التنبيهات — الملخص فقط")

    args = parser.parse_args()

    if args.live:
        live_mode()
        return

    if args.summary:
        summary_mode()
        return

    # تحديد ملف الإدخال
    if args.input:
        input_file = Path(args.input)
    elif args.date:
        input_file = WINDOWS_DIR / f"windows_{args.date}.csv"
    else:
        today      = datetime.now().strftime("%Y-%m-%d")
        input_file = WINDOWS_DIR / f"windows_{today}.csv"

    output_file = Path(args.output) if args.output else None

    run(input_file, output_file, verbose=not args.quiet)


if __name__ == "__main__":
    main()
