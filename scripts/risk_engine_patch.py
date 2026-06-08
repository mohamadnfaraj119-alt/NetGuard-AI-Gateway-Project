"""
risk_engine_patch.py
====================
هذا ليس script تشغيله — بل توثيق التعديلات المطلوبة على risk_engine.py
اقرأه وطبّق التغييرات على ملفك الحالي.

التغييرات: 4 فقط — كل واحدة محددة بـ BEFORE/AFTER.
"""

# ══════════════════════════════════════════════════════════════════
# CHANGE 1 — في أعلى الملف: استيراد baseline_loader
# ══════════════════════════════════════════════════════════════════

# ── BEFORE ──
"""
# لا يوجد استيراد لـ baseline_loader
BASELINE = {
    "connections_30s_max":      35,
    "unique_dst_ports_30s_max":  5,
    "port_entropy_30s_max":      0.115,
    "burst_score_30s_max":       0.287,
    "dns_rate_1m_max":           2.117,
    "outbound_ratio_30s_mean":   0.5,
}
P99_BASELINE = 0.782
"""

# ── AFTER ──
"""
import baseline_loader  # per-IP baseline support

# Global baseline — مرجع فقط (يُستخدم كـ fallback)
BASELINE = {
    "connections_30s_max":      35,
    "unique_dst_ports_30s_max":  5,
    "port_entropy_30s_max":      0.115,
    "burst_score_30s_max":       0.287,
    "dns_rate_1m_max":           2.117,
    "outbound_ratio_30s_mean":   0.5,
}
P99_BASELINE = 0.782  # global fallback

# Log baseline mode at startup
_bl_summary = baseline_loader.summary()
print(f"📋 Baseline mode: {_bl_summary}")
"""


# ══════════════════════════════════════════════════════════════════
# CHANGE 2 — دالة burst_score (أو ما يعادلها)
# استبدل BASELINE["connections_30s_max"] بـ get_threshold()
# ══════════════════════════════════════════════════════════════════

# ── BEFORE ──
"""
def compute_burst_score(row):
    conn_max   = BASELINE["connections_30s_max"]
    port_max   = BASELINE["unique_dst_ports_30s_max"]
    entropy_max= BASELINE["port_entropy_30s_max"]

    c = min(row.get("connections_30s", 0)      / conn_max,    1.0)
    p = min(row.get("unique_dst_ports_30s", 0) / port_max,    1.0)
    e = min(row.get("port_entropy_30s", 0)     / entropy_max, 1.0)
    return (c + p + e) / 3
"""

# ── AFTER ──
"""
def compute_burst_score(row, src_ip: str = None):
    ip = src_ip or row.get("src_ip", "")

    conn_max    = baseline_loader.get_threshold(ip, "connections_30s")
    port_max    = baseline_loader.get_threshold(ip, "unique_dst_ports_30s")
    entropy_max = baseline_loader.get_threshold(ip, "port_entropy_30s")

    c = min(row.get("connections_30s", 0)      / max(conn_max,    0.001), 1.0)
    p = min(row.get("unique_dst_ports_30s", 0) / max(port_max,    0.001), 1.0)
    e = min(row.get("port_entropy_30s", 0)     / max(entropy_max, 0.001), 1.0)
    return (c + p + e) / 3
"""


# ══════════════════════════════════════════════════════════════════
# CHANGE 3 — دالة dns_score
# ══════════════════════════════════════════════════════════════════

# ── BEFORE ──
"""
def compute_dns_score(row):
    dns_max = BASELINE["dns_rate_1m_max"]
    rate    = row.get("dns_rate_1m", 0)
    if rate <= dns_max:
        return 0.0
    return min((rate - dns_max) / dns_max, 1.0)
"""

# ── AFTER ──
"""
def compute_dns_score(row, src_ip: str = None):
    ip      = src_ip or row.get("src_ip", "")
    dns_max = baseline_loader.get_threshold(ip, "dns_rate_1m")
    rate    = row.get("dns_rate_1m", 0)
    if rate <= dns_max:
        return 0.0
    return min((rate - dns_max) / max(dns_max, 0.001), 1.0)
"""


# ══════════════════════════════════════════════════════════════════
# CHANGE 4 — normalize anomaly_score بـ P99 خاص بكل IP
# ══════════════════════════════════════════════════════════════════

# ── BEFORE ──
"""
def normalize_anomaly(raw_score: float) -> float:
    adjusted = (raw_score - P99_BASELINE) / (1.0 - P99_BASELINE)
    return max(0.0, min(adjusted, 1.0))
"""

# ── AFTER ──
"""
def normalize_anomaly(raw_score: float, src_ip: str = "") -> float:
    p99 = baseline_loader.get_p99_anomaly(src_ip) if src_ip else P99_BASELINE
    if p99 >= 1.0:
        p99 = P99_BASELINE  # safety guard
    adjusted = (raw_score - p99) / (1.0 - p99)
    return max(0.0, min(adjusted, 1.0))
"""


# ══════════════════════════════════════════════════════════════════
# CHANGE 5 — دالة الحساب الرئيسية: مرّر src_ip لكل دالة فرعية
# ══════════════════════════════════════════════════════════════════

# ── BEFORE ──
"""
def compute_risk(row) -> dict:
    anomaly_score = normalize_anomaly(row.get("anomaly_score", 0))
    burst_s       = compute_burst_score(row)
    dns_s         = compute_dns_score(row)
    ...
"""

# ── AFTER ──
"""
def compute_risk(row) -> dict:
    src_ip        = row.get("src_ip", "")
    anomaly_score = normalize_anomaly(row.get("anomaly_score", 0), src_ip)
    burst_s       = compute_burst_score(row, src_ip)
    dns_s         = compute_dns_score(row, src_ip)
    ...
    # Optional: tag alert with baseline mode
    used_per_ip = baseline_loader.is_per_ip(src_ip)
    ...
"""


# ══════════════════════════════════════════════════════════════════
# اختبار التغييرات بعد التطبيق
# ══════════════════════════════════════════════════════════════════
"""
# 1. تحقق من تحميل الـ baseline
python -c "import baseline_loader; print(baseline_loader.summary())"

# 2. شغّل risk_engine يوماً واحداً وارصد FP
python scripts/risk_engine.py --date $(date +%Y-%m-%d) 2>/dev/null | grep -v '🟢'

# 3. قارن العدد مع ما كان قبل (كان 14/يوم — الهدف ≤5)
python scripts/risk_engine.py --date $(date +%Y-%m-%d) 2>/dev/null \
    | grep -E '🟡|🟠|🔴' | wc -l
"""
