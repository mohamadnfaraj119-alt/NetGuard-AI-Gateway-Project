"""
baseline_loader.py
==================
Helper module — import this in risk_engine.py.

Loads ip_baselines.json once and caches it in memory.
Provides get_threshold(ip, feature) with automatic global fallback.

Usage in risk_engine.py:
    from baseline_loader import get_threshold, get_p99

    # Instead of:  BASELINE["connections_30s_max"]
    # Use:         get_threshold(src_ip, "connections_30s")
"""

import json
import os

# ─── Config ───────────────────────────────────────────────────────────────────

_DEFAULT_PATH = os.path.expanduser(
    "~/zeek-ids/data/baselines/ip_baselines.json"
)

# ─── Hardcoded global fallback (mirrors GLOBAL_BASELINE in risk_engine) ───────

_GLOBAL_FALLBACK = {
    "connections_30s_max":      35.0,
    "unique_dst_ports_30s_max":  5.0,
    "port_entropy_30s_max":      0.115,
    "burst_score_30s_max":       0.287,
    "dns_rate_1m_max":           2.117,
    "outbound_ratio_30s_mean":   0.5,
    "P99_BASELINE":              0.782,
}

# ─── Cache ────────────────────────────────────────────────────────────────────

_cache:      dict | None = None
_cache_path: str  | None = None


def _load(path: str = _DEFAULT_PATH) -> dict | None:
    """Load JSON file, cache it. Returns None if file missing."""
    global _cache, _cache_path

    if _cache is not None and _cache_path == path:
        return _cache

    if not os.path.exists(path):
        return None

    try:
        with open(path) as f:
            _cache      = json.load(f)
            _cache_path = path
        return _cache
    except Exception as e:
        print(f"⚠ baseline_loader: could not load {path}: {e}")
        return None


def reload(path: str = _DEFAULT_PATH) -> None:
    """Force reload from disk (call after ip_baseline_builder runs)."""
    global _cache, _cache_path
    _cache      = None
    _cache_path = None
    _load(path)


# ─── Public API ───────────────────────────────────────────────────────────────

def get_ip_data(ip: str, path: str = _DEFAULT_PATH) -> tuple[dict, bool]:
    """
    Returns (baseline_dict, is_per_ip).

    baseline_dict:
      - per-IP  → stats dict with {feat}_p50/p90/p95/p99/max/std
      - global  → GLOBAL_BASELINE dict (same keys as old risk_engine)

    is_per_ip:
      True  → IP has its own baseline
      False → using global fallback
    """
    data = _load(path)

    if data is None:
        # File not generated yet — fall back to hardcoded global
        return _GLOBAL_FALLBACK.copy(), False

    global_bl = data.get("global_baseline", _GLOBAL_FALLBACK)
    ip_entry  = data.get("ip_baselines", {}).get(ip)

    if ip_entry is None:
        # New IP not seen during baseline build → global
        return global_bl, False

    if not ip_entry.get("use_per_ip", False):
        # IP exists but had insufficient data
        return global_bl, False

    return ip_entry, True


def get_threshold(ip: str, feature: str,
                  percentile: str = "p99",
                  path: str = _DEFAULT_PATH) -> float:
    """
    Returns the threshold for a feature for a given IP.

    For per-IP: uses the IP's own percentile (default p99).
    For global:  uses the legacy _max value.

    Examples:
        get_threshold("192.168.1.180", "connections_30s")
        → IP's own connections_30s_p99   (e.g. 42.0)

        get_threshold("192.168.1.99",  "connections_30s")
        → global  connections_30s_max    (35.0)
    """
    bl, is_per_ip = get_ip_data(ip, path)

    if is_per_ip:
        key = f"{feature}_{percentile}"
        val = bl.get(key)
        if val is not None:
            return float(val)
        # Feature missing from per-IP stats → global
        return _GLOBAL_FALLBACK.get(f"{feature}_max",
                                    _GLOBAL_FALLBACK.get(feature, 1.0))

    # Global baseline uses _max keys
    return float(bl.get(f"{feature}_max",
                         bl.get(feature, 1.0)))


def get_p99_anomaly(ip: str, path: str = _DEFAULT_PATH) -> float:
    """
    Returns the IF anomaly score P99 for an IP.
    Falls back to global P99_BASELINE (0.782).
    """
    bl, is_per_ip = get_ip_data(ip, path)
    return float(bl.get("P99_BASELINE",
                         _GLOBAL_FALLBACK["P99_BASELINE"]))


def is_per_ip(ip: str, path: str = _DEFAULT_PATH) -> bool:
    """Quick check: does this IP have a per-IP baseline?"""
    _, flag = get_ip_data(ip, path)
    return flag


def summary(path: str = _DEFAULT_PATH) -> dict:
    """Return counts for logging."""
    data = _load(path)
    if data is None:
        return {"status": "file_missing", "per_ip": 0, "global_fallback": 0}

    entries    = data.get("ip_baselines", {})
    per_ip_n   = sum(1 for v in entries.values() if v.get("use_per_ip"))
    global_n   = sum(1 for v in entries.values() if not v.get("use_per_ip"))
    return {
        "status":          "loaded",
        "generated_at":    data.get("generated_at", "?"),
        "per_ip":          per_ip_n,
        "global_fallback": global_n,
        "total_ips":       len(entries),
    }


# ─── CLI sanity check ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else _DEFAULT_PATH
    info = summary(path)
    print(f"📋 Baseline status: {info}")

    test_ips = ["192.168.1.180", "192.168.1.156", "192.168.1.99"]
    for ip in test_ips:
        t    = get_threshold(ip, "connections_30s")
        flag = is_per_ip(ip)
        mode = "per-IP" if flag else "global"
        print(f"  {ip:<18}  connections_30s threshold = {t:<8}  [{mode}]")
