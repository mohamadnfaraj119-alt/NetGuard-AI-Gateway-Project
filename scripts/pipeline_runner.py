#!/usr/bin/env python3
"""
pipeline_runner.py — NetGuard-AI Gateway
==========================================
يُشغِّل الـ pipeline الكامل تلقائياً كل 30 ثانية:
  collector    ← يعمل بالفعل كـ service مستقل
  window_engine ← يُشغَّل هنا كل 30 ثانية
  risk_engine   ← يُشغَّل هنا بعد window_engine مباشرة
  alerts.log    ← يكتب التنبيهات الفورية

الاستخدام:
  python scripts/pipeline_runner.py          # تشغيل مستمر
  python scripts/pipeline_runner.py --once   # تشغيل مرة واحدة فقط
  python scripts/pipeline_runner.py --status # عرض آخر النتائج

Version: 1.0.0 — NetGuard-AI Gateway v7.4
"""

import os
import sys
import json
import time
import logging
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# ─── مسارات المشروع ──────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
DATA_DIR    = BASE_DIR / "data"
LOG_DIR     = BASE_DIR / "logs"
REPORT_DIR  = DATA_DIR / "reports"
VENV_PYTHON = BASE_DIR / "venv" / "bin" / "python"

LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

ALERTS_LOG    = LOG_DIR / "alerts.log"
PIPELINE_LOG  = LOG_DIR / "pipeline_runner.log"

# ─── الفاصل الزمني ───────────────────────────────────────────────────────────
INTERVAL_SECONDS = 30   # كل 30 ثانية — نفس window_engine

# ─── Logger ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(PIPELINE_LOG),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("pipeline_runner")

# ─── Python في الـ venv ──────────────────────────────────────────────────────
def _python() -> str:
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    return sys.executable


# ─── تشغيل script مع timeout ────────────────────────────────────────────────
def _run(script: str, args: list = [], timeout: int = 120) -> tuple:
    """
    يُشغِّل script ويرجع (success, stdout, stderr).
    """
    cmd = [_python(), str(SCRIPTS_DIR / script)] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(BASE_DIR),
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log.error(f"⏰ timeout: {script} تجاوز {timeout}s")
        return False, "", "timeout"
    except Exception as e:
        log.error(f"❌ خطأ في تشغيل {script}: {e}")
        return False, "", str(e)


# ─── استخراج التنبيهات من مخرج risk_engine ──────────────────────────────────
def _extract_alerts(risk_output: str) -> list:
    """
    يستخرج سطور التنبيه من مخرج risk_engine
    (سطور تحتوي 🟡 أو 🟠 أو 🔴)
    """
    alerts = []
    for line in risk_output.splitlines():
        if any(icon in line for icon in ["🟡", "🟠", "🔴"]) and "IP:" in line:
            alerts.append(line.strip())
    return alerts


# ─── كتابة التنبيهات إلى alerts.log ─────────────────────────────────────────
def _write_alerts(alerts: list) -> None:
    if not alerts:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERTS_LOG, "a") as f:
        for alert in alerts:
            f.write(f"[{ts}] {alert}\n")
    log.warning(f"🚨 {len(alerts)} تنبيه جديد — انظر logs/alerts.log")


# ─── دورة واحدة كاملة ───────────────────────────────────────────────────────
def run_cycle() -> dict:
    """
    يُشغِّل دورة كاملة:
    window_engine → risk_engine → alerts
    يرجع ملخص النتائج.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = {
        "ts":           ts,
        "window_ok":    False,
        "risk_ok":      False,
        "alerts":       [],
        "windows":      0,
        "risk_max":     0.0,
        "risk_mean":    0.0,
    }

    # ─── 1. window_engine ────────────────────────────────────────────────────
    ok, stdout, stderr = _run("window_engine.py", timeout=90)
    if not ok:
        log.error(f"❌ window_engine فشل: {stderr[:200]}")
        return result
    result["window_ok"] = True

    # استخراج عدد النوافذ من المخرج
    for line in stdout.splitlines():
        if "إجمالي النوافذ" in line:
            parts = line.split("/")
            if len(parts) > 1:
                result["windows"] = int(parts[-1].strip().split()[0])

    # ─── 2. risk_engine ──────────────────────────────────────────────────────
    ok, stdout, stderr = _run("risk_engine.py", timeout=90)
    if not ok:
        log.error(f"❌ risk_engine فشل: {stderr[:200]}")
        return result
    result["risk_ok"] = True

    # استخراج إحصائيات من المخرج
    for line in stdout.splitlines():
        if "Risk Score mean" in line:
            try:
                result["risk_mean"] = float(line.split(":")[-1].strip())
            except Exception:
                pass
        if "Risk Score max" in line:
            try:
                result["risk_max"] = float(line.split(":")[-1].strip())
            except Exception:
                pass

    # ─── 3. استخراج التنبيهات وكتابتها ──────────────────────────────────────
    alerts = _extract_alerts(stdout)
    result["alerts"] = alerts
    _write_alerts(alerts)

    # ─── 4. تسجيل ملخص الدورة ───────────────────────────────────────────────
    status = "🟢" if not alerts else ("🔴" if any("🔴" in a for a in alerts) else "🟠")
    log.info(
        f"{status} دورة مكتملة | "
        f"نوافذ={result['windows']} | "
        f"max={result['risk_max']:.1f} | "
        f"تنبيهات={len(alerts)}"
    )

    return result


# ─── --status ─────────────────────────────────────────────────────────────────
def print_status() -> None:
    """يعرض آخر التنبيهات من alerts.log"""
    if not ALERTS_LOG.exists():
        print("✅ لا توجد تنبيهات مسجلة بعد")
        return

    lines = ALERTS_LOG.read_text().splitlines()
    if not lines:
        print("✅ ملف التنبيهات فارغ")
        return

    print(f"\n{'─'*60}")
    print(f"  آخر {min(20, len(lines))} تنبيه من alerts.log")
    print(f"{'─'*60}")
    for line in lines[-20:]:
        print(f"  {line}")
    print(f"{'─'*60}")
    print(f"  إجمالي التنبيهات: {len(lines)}\n")


# ─── الحلقة الرئيسية ─────────────────────────────────────────────────────────
def run_loop() -> None:
    log.info(
        f"🚀 NetGuard Pipeline Runner بدأ | "
        f"فاصل={INTERVAL_SECONDS}s"
    )
    log.info(f"   التنبيهات → {ALERTS_LOG}")

    cycle = 0
    while True:
        cycle += 1
        log.info(f"▶ دورة #{cycle}")
        try:
            run_cycle()
        except Exception as e:
            log.error(f"❌ خطأ غير متوقع في الدورة: {e}")

        time.sleep(INTERVAL_SECONDS)


# ─── Entry Point ─────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetGuard Pipeline Runner — تشغيل تلقائي كامل"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="شغّل دورة واحدة فقط ثم أخرج"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="عرض آخر التنبيهات والخروج"
    )
    args = parser.parse_args()

    if args.status:
        print_status()
        return

    if args.once:
        result = run_cycle()
        print(f"\n✅ دورة مكتملة:")
        print(f"   window_engine : {'✅' if result['window_ok'] else '❌'}")
        print(f"   risk_engine   : {'✅' if result['risk_ok'] else '❌'}")
        print(f"   التنبيهات     : {len(result['alerts'])}")
        print(f"   Risk max      : {result['risk_max']:.1f}")
        return

    run_loop()


if __name__ == "__main__":
    main()
