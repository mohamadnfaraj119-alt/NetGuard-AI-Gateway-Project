#!/usr/bin/env python3
"""
state_tracker.py — NetGuard-AI v3.0
Temporal State Correlation Engine

التغيير الجوهري في v3.0:
  INBOUND لا يعتمد على src_ip (غير موثوق مع NAT/Router)
  بدلاً من ذلك: يحلل ما وصل للـ VM نفسه (dst=LOCAL_IP)
  هذا ما تفعله IDS الاحترافية (Snort/Suricata)

نوعان من التحليل:
  VICTIM  : ماذا حدث للـ VM؟ (منافذ وُصلت، failed conns، SSH attacks)
  OUTBOUND: ماذا يفعل الـ VM؟ (recon, exfiltration, lateral)

الأنماط المكتشفة:
  [VICTIM]   victim_port_scan  : منافذ مختلفة وُصلت على الـ VM في وقت قصير
  [VICTIM]   victim_fail_burst : failed connections كثيرة على الـ VM
  [VICTIM]   victim_ssh_brute  : محاولات SSH فاشلة متكررة
  [OUTBOUND] recon             : DNS كثير بدون اتصال حقيقي
  [OUTBOUND] new_external      : تواصل مع IPs خارجية جديدة كثيرة
  [OUTBOUND] lateral           : حركة أفقية داخل الشبكة

الاستخدام:
  python scripts/state_tracker.py --analyze
  python scripts/state_tracker.py --analyze --date 2026-05-13
  python scripts/state_tracker.py --analyze --hours 6
  python scripts/state_tracker.py --live
  python scripts/state_tracker.py --report
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

# ─── المسارات ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "processed"
REPORTS_DIR = BASE_DIR / "data" / "reports"
LOGS_DIR    = BASE_DIR / "logs"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOGS_DIR / "state_tracker.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─── Noise Filter ────────────────────────────────────────────────────────────
NOISE_DST_IPS = {
    "224.0.0.251", "224.0.0.1",
    "192.168.68.255", "192.168.1.255", "255.255.255.255",
    "ff02::fb", "ff02::1:3", "ff02::1", "ff02::2", "ff02::16",
}
NOISE_PORTS = {137, 138, 139, 5353, 1900, 5355}

# ─── منافذ حساسة تستحق مراقبة خاصة ──────────────────────────────────────────
SENSITIVE_PORTS = {
    22,    # SSH
    23,    # Telnet
    21,    # FTP
    3389,  # RDP
    445,   # SMB
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    27017, # MongoDB
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
}

# ─── معاملات الكشف — تُعيَّر بعد Live Testing ────────────────────────────────
CONFIG = {
    # VICTIM — Port Scan على الـ VM
    "victim_scan_ports_30s":   5,    # منافذ مختلفة في 30 ثانية
    "victim_scan_ports_5m":    10,   # منافذ مختلفة في 5 دقائق
    "victim_scan_ports_1h":    20,   # منافذ مختلفة في ساعة (slow scan)

    # VICTIM — Failed Connections على الـ VM
    "victim_fail_30s":         10,   # فشل في 30 ثانية (burst)
    "victim_fail_5m":          20,   # فشل في 5 دقائق
    "victim_fail_1h":          40,   # فشل في ساعة (incremental)

    # VICTIM — SSH Brute Force
    "victim_ssh_fail_5m":      5,    # محاولات SSH فاشلة في 5 دقائق
    "victim_ssh_fail_1h":      15,   # محاولات SSH فاشلة في ساعة

    # OUTBOUND — Recon
    "recon_dns_min":           50,   # DNS queries بدون اتصال حقيقي
    "recon_real_conn_max":     10,   # اتصالات حقيقية مسموح بها

    # OUTBOUND — New External
    "new_external_per_hour":   15,   # IPs خارجية جديدة في ساعة

    # OUTBOUND — Lateral Movement
    "lateral_internal":        4,    # IPs داخلية جديدة

    # Memory
    "memory_hours":            24,

    # Risk Weights
    "w_victim_scan":   0.50,   # port scan على الـ VM — خطر عالٍ
    "w_victim_fail":   0.40,   # failed connections
    "w_victim_ssh":    0.45,   # SSH brute force — خطر عالٍ
    "w_recon":         0.20,
    "w_external":      0.25,
    "w_lateral":       0.35,
}


# ══════════════════════════════════════════════════════════════════════════════
# قراءة IPs الجهاز تلقائياً
# ══════════════════════════════════════════════════════════════════════════════

def get_local_ips() -> set:
    """
    يقرأ IPs الجهاز من الشبكة تلقائياً.
    يعمل مع أي IP أو شبكة — لا hardcode.
    """
    ips = {"::1", "::", "127.0.0.1"}
    try:
        result = subprocess.run(
            ["ip", "addr", "show", "enp0s3"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                ips.add(line.split()[1].split("/")[0])
            elif line.startswith("inet6 "):
                ips.add(line.split()[1].split("/")[0])
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, timeout=3
        )
        for ip in result.stdout.strip().split():
            ips.add(ip)
    except Exception:
        pass
    return ips


LOCAL_IPS = get_local_ips()


# ══════════════════════════════════════════════════════════════════════════════
# ذاكرة الـ VM (VICTIM state)
# ══════════════════════════════════════════════════════════════════════════════

class VictimState:
    """
    يتذكر ما وصل للـ VM عبر الزمن.
    لا يهم من أين جاء (src_ip غير موثوق مع NAT).
    يهم ماذا حدث للـ VM.
    """

    def __init__(self):
        # كل منفذ وُصل مع توقيته [(ts, port)]
        self.ports_touched: list = []

        # كل failed connection وُصل [(ts, port)]
        self.failed_conns: list = []

        # محاولات SSH فاشلة [(ts)]
        self.ssh_failures: list = []

        self.first_seen = None
        self.last_seen  = None

    def update(self, row: pd.Series):
        ts       = float(row["ts"])
        dst_port = int(row.get("dst_port", 0))

        if dst_port in NOISE_PORTS:
            return

        self._update_times(ts)

        # تسجيل المنفذ
        self.ports_touched.append((ts, dst_port))

        # failed connection
        is_failed = (
            row.get("conn_state_S0",  0) == 1 or
            row.get("conn_state_REJ", 0) == 1
        )
        if is_failed:
            self.failed_conns.append((ts, dst_port))

            # SSH فاشل تحديداً
            if dst_port == 22:
                self.ssh_failures.append(ts)

    def prune(self, cutoff_ts: float):
        self.ports_touched = [(t, p) for t, p in self.ports_touched if t >= cutoff_ts]
        self.failed_conns  = [(t, p) for t, p in self.failed_conns  if t >= cutoff_ts]
        self.ssh_failures  = [t for t in self.ssh_failures if t >= cutoff_ts]

    def _update_times(self, ts: float):
        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts


# ══════════════════════════════════════════════════════════════════════════════
# ذاكرة الـ OUTBOUND
# ══════════════════════════════════════════════════════════════════════════════

class OutboundState:
    """يتذكر ماذا يفعل الـ VM خارجياً"""

    def __init__(self, ip: str):
        self.ip              = ip
        self.dns_queries:  list = []
        self.successful_conns: int = 0
        self.external_ips: set = set()
        self.internal_ips: set = set()
        self.first_seen    = None
        self.last_seen     = None

    def update(self, row: pd.Series):
        ts     = float(row["ts"])
        dst_ip = str(row.get("dst_ip", ""))

        if self.first_seen is None:
            self.first_seen = ts
        self.last_seen = ts

        if row.get("is_dns", 0) == 1:
            self.dns_queries.append((ts, dst_ip))
        elif (row.get("conn_state_SF", 0) == 1 or
              row.get("is_http",  0) == 1 or
              row.get("is_https", 0) == 1):
            self.successful_conns += 1

        if dst_ip and dst_ip not in NOISE_DST_IPS:
            if row.get("is_external", 0) == 1:
                self.external_ips.add(dst_ip)
            else:
                self.internal_ips.add(dst_ip)

    def prune(self, cutoff_ts: float):
        self.dns_queries = [(t, i) for t, i in self.dns_queries if t >= cutoff_ts]


# ══════════════════════════════════════════════════════════════════════════════
# محرك الكشف
# ══════════════════════════════════════════════════════════════════════════════

class StateTracker:

    def __init__(self):
        self.victim   = VictimState()
        self.outbound: dict[str, OutboundState] = {}

    def process_flow(self, row: pd.Series):
        src_ip = str(row.get("src_ip", ""))
        dst_ip = str(row.get("dst_ip", ""))
        ts     = float(row["ts"])
        cutoff = ts - CONFIG["memory_hours"] * 3600

        if not src_ip or src_ip == "nan":
            return
        if dst_ip in NOISE_DST_IPS:
            return

        # VICTIM: أي flow وجهته الـ VM
        if dst_ip in LOCAL_IPS:
            self.victim.update(row)
            self.victim.prune(cutoff)

        # OUTBOUND: الـ VM يتصل بالخارج
        elif src_ip in LOCAL_IPS:
            if src_ip not in self.outbound:
                self.outbound[src_ip] = OutboundState(src_ip)
            state = self.outbound[src_ip]
            state.update(row)
            state.prune(cutoff)

    def analyze(self, as_of_ts: float) -> list:
        results = []

        # تحليل الـ VICTIM
        v = self._analyze_victim(as_of_ts)
        if v["risk_score"] > 0:
            results.append(v)

        # تحليل الـ OUTBOUND
        for ip, state in self.outbound.items():
            r = self._analyze_outbound(ip, state, as_of_ts)
            if r["risk_score"] > 0:
                results.append(r)

        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results

    # ── VICTIM Analysis ───────────────────────────────────────────────────────

    def _analyze_victim(self, as_of_ts: float) -> dict:
        state     = self.victim
        patterns  = []
        risk      = 0.0
        evidence  = []

        # 1. Port Scan على الـ VM
        ps = _victim_port_scan(state, as_of_ts)
        if ps["detected"]:
            patterns.append("victim_port_scan")
            risk += CONFIG["w_victim_scan"] * ps["severity"]
            evidence.append(ps["desc"])

        # 2. Failed Connection Burst
        fb = _victim_fail_burst(state, as_of_ts)
        if fb["detected"]:
            patterns.append("victim_fail_burst")
            risk += CONFIG["w_victim_fail"] * fb["severity"]
            evidence.append(fb["desc"])

        # 3. SSH Brute Force
        ssh = _victim_ssh_brute(state, as_of_ts)
        if ssh["detected"]:
            patterns.append("victim_ssh_brute")
            risk += CONFIG["w_victim_ssh"] * ssh["severity"]
            evidence.append(ssh["desc"])

        return {
            "ip":         "VM (victim)",
            "direction":  "VICTIM",
            "risk_score": round(min(risk, 1.0), 4),
            "patterns":   patterns,
            "evidence":   evidence,
            "first_seen": _fmt(state.first_seen),
            "last_seen":  _fmt(state.last_seen),
            "ports":      len(set(p for _, p in state.ports_touched)),
            "fails":      len(state.failed_conns),
            "dns":        0,
            "ext_ips":    0,
        }

    # ── OUTBOUND Analysis ─────────────────────────────────────────────────────

    def _analyze_outbound(self, ip: str, state: OutboundState,
                          as_of_ts: float) -> dict:
        patterns = []
        risk     = 0.0
        evidence = []

        r = _recon(state, as_of_ts)
        if r["detected"]:
            patterns.append("recon")
            risk += CONFIG["w_recon"] * r["severity"]
            evidence.append(r["desc"])

        e = _new_external(state, as_of_ts)
        if e["detected"]:
            patterns.append("new_external")
            risk += CONFIG["w_external"] * e["severity"]
            evidence.append(e["desc"])

        l = _lateral(state, as_of_ts)
        if l["detected"]:
            patterns.append("lateral")
            risk += CONFIG["w_lateral"] * l["severity"]
            evidence.append(l["desc"])

        return {
            "ip":         ip,
            "direction":  "OUTBOUND",
            "risk_score": round(min(risk, 1.0), 4),
            "patterns":   patterns,
            "evidence":   evidence,
            "first_seen": _fmt(state.first_seen),
            "last_seen":  _fmt(state.last_seen),
            "ports":      0,
            "fails":      0,
            "dns":        len(state.dns_queries),
            "ext_ips":    len(state.external_ips),
        }


# ══════════════════════════════════════════════════════════════════════════════
# دوال الكشف — VICTIM
# ══════════════════════════════════════════════════════════════════════════════

def _victim_port_scan(state: VictimState, as_of_ts: float) -> dict:
    """
    Port Scan على الـ VM:
    منافذ مختلفة وُصلت في نوافذ زمنية مختلفة.
    نكتشف: fast scan (30s) | medium (5m) | slow (1h)
    """
    def unique_ports_in(seconds):
        cutoff = as_of_ts - seconds
        recent = [p for t, p in state.ports_touched if t >= cutoff]
        return len(set(recent))

    p30s = unique_ports_in(30)
    p5m  = unique_ports_in(300)
    p1h  = unique_ports_in(3600)

    detected  = False
    severity  = 0.0
    desc_parts = []

    if p30s >= CONFIG["victim_scan_ports_30s"]:
        detected = True
        severity = max(severity, min(p30s / 50, 1.0))
        desc_parts.append(f"{p30s} ports/30s (fast scan)")

    if p5m >= CONFIG["victim_scan_ports_5m"]:
        detected = True
        severity = max(severity, min(p5m / 100, 1.0))
        desc_parts.append(f"{p5m} ports/5m (medium scan)")

    if p1h >= CONFIG["victim_scan_ports_1h"]:
        detected = True
        severity = max(severity, min(p1h / 200, 1.0))
        desc_parts.append(f"{p1h} ports/1h (slow scan)")

    if not detected:
        return {"detected": False}

    # أكثر المنافذ الحساسة وُصلت
    sensitive_hit = [
        p for _, p in state.ports_touched
        if p in SENSITIVE_PORTS
    ]
    if sensitive_hit:
        severity = min(severity * 1.3, 1.0)
        desc_parts.append(f"sensitive ports: {set(sensitive_hit)}")

    return {
        "detected": True,
        "severity": round(severity, 4),
        "desc":     f"Port scan on VM: {' | '.join(desc_parts)}"
    }


def _victim_fail_burst(state: VictimState, as_of_ts: float) -> dict:
    """Failed connections متراكمة على الـ VM"""
    def count_fails(seconds):
        cutoff = as_of_ts - seconds
        return sum(1 for t, _ in state.failed_conns if t >= cutoff)

    f30s = count_fails(30)
    f5m  = count_fails(300)
    f1h  = count_fails(3600)

    detected  = False
    severity  = 0.0
    parts     = []

    if f30s >= CONFIG["victim_fail_30s"]:
        detected = True
        severity = max(severity, min(f30s / 50, 1.0))
        parts.append(f"{f30s} fails/30s")

    if f5m >= CONFIG["victim_fail_5m"]:
        detected = True
        severity = max(severity, min(f5m / 100, 1.0))
        parts.append(f"{f5m} fails/5m")

    if f1h >= CONFIG["victim_fail_1h"]:
        detected = True
        severity = max(severity, min(f1h / 200, 1.0))
        parts.append(f"{f1h} fails/1h")

    if not detected:
        return {"detected": False}

    return {
        "detected": True,
        "severity": round(severity, 4),
        "desc":     f"Failed connections on VM: {' | '.join(parts)}"
    }


def _victim_ssh_brute(state: VictimState, as_of_ts: float) -> dict:
    """SSH Brute Force على الـ VM"""
    def count_ssh(seconds):
        cutoff = as_of_ts - seconds
        return sum(1 for t in state.ssh_failures if t >= cutoff)

    s5m = count_ssh(300)
    s1h = count_ssh(3600)

    detected = False
    severity = 0.0
    parts    = []

    if s5m >= CONFIG["victim_ssh_fail_5m"]:
        detected = True
        severity = max(severity, min(s5m / 20, 1.0))
        parts.append(f"{s5m} SSH fails/5m")

    if s1h >= CONFIG["victim_ssh_fail_1h"]:
        detected = True
        severity = max(severity, min(s1h / 50, 1.0))
        parts.append(f"{s1h} SSH fails/1h")

    if not detected:
        return {"detected": False}

    return {
        "detected": True,
        "severity": round(severity, 4),
        "desc":     f"SSH brute force on VM: {' | '.join(parts)}"
    }


# ══════════════════════════════════════════════════════════════════════════════
# دوال الكشف — OUTBOUND
# ══════════════════════════════════════════════════════════════════════════════

def _recon(state: OutboundState, as_of_ts: float) -> dict:
    cutoff     = as_of_ts - 3600
    recent_dns = sum(1 for t, _ in state.dns_queries if t >= cutoff)

    if (recent_dns >= CONFIG["recon_dns_min"] and
            state.successful_conns <= CONFIG["recon_real_conn_max"]):
        return {
            "detected": True,
            "severity": round(min(recent_dns / 200, 1.0), 4),
            "desc":     (f"Recon: {recent_dns} DNS queries, "
                         f"{state.successful_conns} real connections")
        }
    return {"detected": False}


def _new_external(state: OutboundState, as_of_ts: float) -> dict:
    count = len(state.external_ips)
    if count >= CONFIG["new_external_per_hour"]:
        return {
            "detected": True,
            "severity": round(min(count / 50, 1.0), 4),
            "desc":     f"New external reach: {count} unique external IPs"
        }
    return {"detected": False}


def _lateral(state: OutboundState, as_of_ts: float) -> dict:
    count = len(state.internal_ips)
    if count >= CONFIG["lateral_internal"]:
        return {
            "detected": True,
            "severity": round(min(count / 10, 1.0), 4),
            "desc":     f"Lateral movement: {count} internal IPs"
        }
    return {"detected": False}


# ══════════════════════════════════════════════════════════════════════════════
# تحميل البيانات
# ══════════════════════════════════════════════════════════════════════════════

def load_baseline(date_str=None, hours=24) -> pd.DataFrame:
    if date_str:
        files = [DATA_DIR / f"baseline_{date_str}.csv"]
    else:
        today     = datetime.now().strftime("%Y-%m-%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        files     = [DATA_DIR / f"baseline_{today}.csv",
                     DATA_DIR / f"baseline_{yesterday}.csv"]

    dfs = []
    for f in files:
        if f.exists():
            df = pd.read_csv(f)
            dfs.append(df)
            log.info(f"✅ {f.name}: {len(df):,} سجل")

    if not dfs:
        log.error("❌ لا توجد بيانات baseline")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True)

    # Noise Filter
    if "dst_ip" in combined.columns:
        combined = combined[~combined["dst_ip"].isin(NOISE_DST_IPS)]
    if "dst_port" in combined.columns:
        combined = combined[~combined["dst_port"].isin(NOISE_PORTS)]

    # فلترة زمنية
    cutoff   = combined["ts"].max() - hours * 3600
    combined = combined[combined["ts"] >= cutoff]
    combined = combined.sort_values("ts").reset_index(drop=True)

    log.info(f"📊 إجمالي: {len(combined):,} flow | LOCAL_IPS: {LOCAL_IPS}")
    return combined


# ══════════════════════════════════════════════════════════════════════════════
# التشغيل الرئيسي
# ══════════════════════════════════════════════════════════════════════════════

def run_analysis(date_str=None, hours=24) -> list:
    log.info("=" * 60)
    log.info("🔍 State Tracker v3.0 — Victim-Centric Analysis")
    log.info("=" * 60)

    df = load_baseline(date_str, hours)
    if df.empty:
        return []

    tracker  = StateTracker()
    as_of_ts = df["ts"].max()

    log.info(f"⏳ معالجة {len(df):,} flow...")
    for _, row in df.iterrows():
        tracker.process_flow(row)

    inbound_count = sum(
        1 for _, p in tracker.victim.ports_touched
    )
    log.info(f"✅ Flows وردت للـ VM : {inbound_count}")
    log.info(f"✅ OUTBOUND IPs      : {len(tracker.outbound)}")

    results = tracker.analyze(as_of_ts)
    _print_results(results)

    if results:
        today    = date_str or datetime.now().strftime("%Y-%m-%d")
        out_file = REPORTS_DIR / f"state_report_{today}.csv"
        pd.DataFrame(results).to_csv(out_file, index=False)
        log.info(f"💾 التقرير: {out_file}")

    return results


def _print_results(results: list):
    active = [r for r in results if r["risk_score"] > 0]

    if not active:
        print(f"\n✅ لا أنماط مشبوهة — النظام طبيعي")
        return

    print(f"\n{'='*65}")
    print(f"🔍 State Tracker v3.0 — النتائج")
    print(f"{'='*65}")

    for r in active:
        score = r["risk_score"]
        emoji = "🔴" if score >= 0.7 else "🟠" if score >= 0.4 else "🟡"
        dir_arrow = "⬅️ " if r["direction"] == "VICTIM" else "➡️ "

        print(f"\n{emoji} [{r['direction']}] {dir_arrow} {r['ip']}")
        print(f"   Risk Score : {score:.3f}")
        print(f"   الأنماط   : {', '.join(r['patterns'])}")
        for ev in r["evidence"]:
            print(f"   📋 {ev}")
        if r["direction"] == "VICTIM":
            print(f"   الإحصاء   : ports={r['ports']} | fails={r['fails']}")
        else:
            print(f"   الإحصاء   : dns={r['dns']} | ext_ips={r['ext_ips']}")
        print(f"   الفترة    : {r['first_seen']} → {r['last_seen']}")

    print(f"\n{'='*65}")


# ══════════════════════════════════════════════════════════════════════════════
# وضع المراقبة المستمرة
# ══════════════════════════════════════════════════════════════════════════════

def live_mode():
    log.info("🔴 وضع المراقبة المستمرة — Ctrl+C للإيقاف")

    tracker  = StateTracker()
    last_idx = 0

    while True:
        today = datetime.now().strftime("%Y-%m-%d")
        path  = DATA_DIR / f"baseline_{today}.csv"

        if not path.exists():
            time.sleep(60)
            continue

        try:
            df       = pd.read_csv(path)
            new_rows = df.iloc[last_idx:]

            if not new_rows.empty:
                if "dst_ip" in new_rows.columns:
                    new_rows = new_rows[
                        ~new_rows["dst_ip"].isin(NOISE_DST_IPS)
                    ]
                for _, row in new_rows.iterrows():
                    tracker.process_flow(row)
                last_idx = len(df)

            as_of_ts = df["ts"].max() if not df.empty else 0
            results  = tracker.analyze(as_of_ts)
            flagged  = [r for r in results if r["risk_score"] >= 0.3]

            ts_now = datetime.now().strftime("%H:%M:%S")
            if flagged:
                print(f"\n{'='*60}")
                for r in flagged:
                    score = r["risk_score"]
                    emoji = "🔴" if score >= 0.7 else "🟠" if score >= 0.4 else "🟡"
                    print(f"{emoji} [{ts_now}] {r['direction']:8s} "
                          f"{r['ip']:25s} Risk={score:.3f} "
                          f"| {', '.join(r['patterns'])}")
            else:
                print(f"🟢 [{ts_now}] طبيعي | "
                      f"victim_ports={len(set(p for _,p in tracker.victim.ports_touched))} "
                      f"outbound={len(tracker.outbound)}")

        except Exception as e:
            log.error(f"❌ {e}")

        time.sleep(60)


def report_mode():
    files = sorted(REPORTS_DIR.glob("state_report_*.csv"))
    if not files:
        print("❌ لا توجد تقارير — شغّل --analyze أولاً")
        return

    print(f"\n{'='*65}")
    print(f"📊 ملخص تاريخي — State Tracker v3.0")
    print(f"{'='*65}")
    for f in files:
        try:
            df   = pd.read_csv(f)
            high = (df["risk_score"] >= 0.7).sum()
            med  = ((df["risk_score"] >= 0.4) & (df["risk_score"] < 0.7)).sum()
            low  = ((df["risk_score"] > 0) & (df["risk_score"] < 0.4)).sum()
            print(f"  {f.name:<40} 🔴{high} 🟠{med} 🟡{low}")
        except Exception:
            pass
    print(f"{'='*65}\n")


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _fmt(ts) -> str:
    if ts is None:
        return "N/A"
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


# ══════════════════════════════════════════════════════════════════════════════
# نقطة الدخول
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="NetGuard-AI — State Tracker v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python scripts/state_tracker.py --analyze
  python scripts/state_tracker.py --analyze --date 2026-05-13
  python scripts/state_tracker.py --analyze --hours 6
  python scripts/state_tracker.py --live
  python scripts/state_tracker.py --report
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analyze", action="store_true",
                       help="تحليل البيانات")
    group.add_argument("--live",    action="store_true",
                       help="مراقبة مستمرة")
    group.add_argument("--report",  action="store_true",
                       help="ملخص تاريخي")

    parser.add_argument("--date",  "-d", default=None,
                        help="تاريخ YYYY-MM-DD")
    parser.add_argument("--hours", "-t", type=int, default=24,
                        help="عدد الساعات (افتراضي: 24)")

    args = parser.parse_args()

    if args.analyze:
        run_analysis(args.date, args.hours)
    elif args.live:
        live_mode()
    elif args.report:
        report_mode()


if __name__ == "__main__":
    main()