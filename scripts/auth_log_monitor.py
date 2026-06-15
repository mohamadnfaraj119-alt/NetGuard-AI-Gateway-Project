#!/usr/bin/env python3
"""
auth_log_monitor.py — NetGuard-AI Gateway
==========================================
يراقب /var/log/auth.log لكشف SSH Brute Force الذي يفوت Zeek
(conn_state=OTH — اتصالات قصيرة لا يسجلها Zeek).

الإجراء عند الكشف:
  1. تسجيل في logs/auth_monitor.log
  2. تغذية state_tracker (victim_ssh_brute)
  3. إنتاج تنبيه في data/reports/auth_alerts_YYYY-MM-DD.json
  4. حظر IP تلقائياً عبر iptables (قابل للتعطيل)

التكامل مع Pipeline:
  - يقرأ get_local_ips() من collector.py (لا hardcode)
  - يكتب إلى نفس مجلدات reports/ التي تقرأها risk_engine
  - يتبع نفس Noise Filter المشترك في كل scripts

الاستخدام:
  python scripts/auth_log_monitor.py          # تشغيل مستمر
  python scripts/auth_log_monitor.py --dry-run # بدون حظر iptables
  python scripts/auth_log_monitor.py --status  # ملخص المحظورين

Version: 1.0.0 — NetGuard-AI Gateway v7.4
"""

import re
import os
import sys
import json
import time
import logging
import argparse
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# ─── مسارات المشروع ──────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
LOG_DIR    = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "data" / "reports"
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

AUTH_LOG   = Path("/var/log/auth.log")
MONITOR_LOG = LOG_DIR / "auth_monitor.log"
BANNED_FILE = BASE_DIR / "data" / "baselines" / "banned_ips.json"

# ─── العتبات — قابلة للضبط ───────────────────────────────────────────────────
# عدد محاولات الفشل خلال النافذة الزمنية قبل الإنذار
THRESHOLDS = {
    "warn":  3,   # 🟡 مشبوه — تسجيل فقط
    "alert": 5,   # 🟠 خطر  — تنبيه + state_tracker
    "ban":   10,  # 🔴 حظر  — iptables block
}

WINDOW_SECONDS = 60      # النافذة الزمنية لحساب المحاولات
UNBAN_HOURS    = 24      # رفع الحظر تلقائياً بعد N ساعة
POLL_INTERVAL  = 1.0     # ثوان بين كل قراءة للـ log

# ─── Regex لتحليل auth.log ───────────────────────────────────────────────────
# يطابق أنماط الفشل في OpenSSH
_FAIL_PATTERNS = [
    # Failed password for root from 1.2.3.4 port 12345 ssh2
    re.compile(
        r"Failed (?:password|publickey) for (?:invalid user )?(\S+) "
        r"from ([\d\.]+) port \d+"
    ),
    # Invalid user admin from 1.2.3.4 port 12345
    re.compile(
        r"Invalid user (\S+) from ([\d\.]+) port \d+"
    ),
    # Connection closed by invalid user ... (بعض إصدارات OpenSSH)
    re.compile(
        r"Disconnecting invalid user (\S+) ([\d\.]+) port \d+"
    ),
]

# يطابق تسجيل الدخول الناجح
_SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port \d+"
)

# تاريخ ووقت سطر auth.log — مثال: Jun 14 03:22:11
_TIMESTAMP_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# ─── Logger ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(MONITOR_LOG),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("auth_monitor")


# ─── الحصول على IPs المحلية (نفس منطق collector.py — لا hardcode) ─────────────
def get_local_ips() -> set:
    """يرصد 192.168.1.x تلقائياً من واجهات الشبكة الفعلية."""
    local = {"127.0.0.1", "::1"}
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            m = re.search(r"inet ([\d\.]+)/", line)
            if m:
                local.add(m.group(1))
    except Exception:
        pass
    # إضافة نطاق 192.168.1.x كله كـ local (أجهزة المنزل)
    local.update(f"192.168.1.{i}" for i in range(1, 255))
    return local


LOCAL_IPS = get_local_ips()


# ─── iptables ─────────────────────────────────────────────────────────────────
def _iptables_block(ip: str) -> bool:
    """يضيف قاعدة DROP لـ IP — يرجع True عند النجاح."""
    try:
        # تحقق إذا القاعدة موجودة بالفعل
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            return True  # موجودة بالفعل

        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=10
        )
        log.warning(f"🔴 iptables BLOCK → {ip}")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"iptables error for {ip}: {e}")
        return False


def _iptables_unblock(ip: str) -> bool:
    """يزيل قاعدة DROP لـ IP."""
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, timeout=10
        )
        log.info(f"✅ iptables UNBLOCK → {ip}")
        return True
    except subprocess.CalledProcessError:
        return False


# ─── حفظ/تحميل المحظورين ─────────────────────────────────────────────────────
def _load_banned() -> dict:
    """يحمل قائمة المحظورين من الملف."""
    if BANNED_FILE.exists():
        try:
            with open(BANNED_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_banned(banned: dict) -> None:
    BANNED_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(BANNED_FILE, "w") as f:
        json.dump(banned, f, indent=2, ensure_ascii=False)


# ─── تغذية state_tracker ──────────────────────────────────────────────────────
def _update_state_tracker(attacker_ip: str, victim_ip: str, count: int) -> None:
    """
    يكتب حدث SSH Brute Force إلى ملف يقرأه state_tracker.
    state_tracker v3.0 يراقب victim_ssh_brute:
      - حد 5m: 5 محاولات فاشلة → تنبيه
      - حد 1h: 15 محاولة       → تنبيه حرج
    """
    event_file = REPORT_DIR / f"ssh_events_{datetime.now():%Y-%m-%d}.jsonl"
    event = {
        "ts":          datetime.now().isoformat(),
        "type":        "ssh_brute_force",
        "src_ip":      attacker_ip,
        "dst_ip":      victim_ip,
        "fail_count":  count,
        "window_sec":  WINDOW_SECONDS,
        "source":      "auth_log_monitor",
    }
    with open(event_file, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


# ─── إنتاج تنبيه ─────────────────────────────────────────────────────────────
def _write_alert(attacker_ip: str, victim_ip: str, count: int,
                 usernames: list, level: str, banned: bool) -> None:
    """يكتب تنبيهاً إلى data/reports/ بنفس تنسيق risk_engine."""
    alert_file = REPORT_DIR / f"auth_alerts_{datetime.now():%Y-%m-%d}.json"

    # تحميل التنبيهات الموجودة أو بدء قائمة جديدة
    alerts = []
    if alert_file.exists():
        try:
            with open(alert_file) as f:
                alerts = json.load(f)
        except Exception:
            alerts = []

    icons = {"warn": "🟡", "alert": "🟠", "ban": "🔴"}
    alert = {
        "ts":          datetime.now().isoformat(),
        "level":       level,
        "icon":        icons.get(level, "🟠"),
        "type":        "SSH_BRUTE_FORCE",
        "src_ip":      attacker_ip,
        "dst_ip":      victim_ip,
        "fail_count":  count,
        "window_sec":  WINDOW_SECONDS,
        "usernames":   list(set(usernames))[:10],  # أول 10 أسماء فريدة
        "banned":      banned,
        "source":      "auth_log_monitor",
        "message": (
            f"{icons.get(level, '🟠')} SSH Brute Force | "
            f"{attacker_ip} → {victim_ip} | "
            f"{count} محاولة/{WINDOW_SECONDS}s | "
            f"{'محظور ✅' if banned else 'مراقب'}"
        ),
    }
    alerts.append(alert)

    with open(alert_file, "w") as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)

    log.warning(alert["message"])


# ─── تحليل سطر auth.log ──────────────────────────────────────────────────────
def _parse_line(line: str):
    """
    يحلل سطراً من auth.log.
    يرجع: ("fail", ip, username) | ("success", ip, username) | None
    """
    for pattern in _FAIL_PATTERNS:
        m = pattern.search(line)
        if m:
            username, ip = m.group(1), m.group(2)
            # تجاهل IPs محلية (لا نحظر أجهزة المنزل)
            if ip in LOCAL_IPS:
                return None
            return ("fail", ip, username)

    m = _SUCCESS_PATTERN.search(line)
    if m:
        username, ip = m.group(1), m.group(2)
        return ("success", ip, username)

    return None


# ─── المراقب الرئيسي ─────────────────────────────────────────────────────────
class AuthLogMonitor:
    """
    يراقب auth.log بطريقة tail -f.
    يحتفظ بنافذة زمنية متحركة لكل IP مهاجم.
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run   = dry_run
        self.banned    = _load_banned()

        # {attacker_ip: [timestamp, ...]} — قائمة أوقات المحاولات الفاشلة
        self._fail_times:  dict = defaultdict(list)
        # {attacker_ip: [username, ...]} — الأسماء المجربة
        self._usernames:   dict = defaultdict(list)
        # {attacker_ip: level} — آخر مستوى تنبيه أُرسل
        self._alerted:     dict = {}

        # تأكد أن المحظورين المحفوظين لا يزالون محظورين في iptables
        self._restore_bans()

    def _restore_bans(self) -> None:
        """يعيد تطبيق الحظر عند إعادة تشغيل الخدمة."""
        now = datetime.now()
        to_remove = []
        for ip, info in self.banned.items():
            banned_at = datetime.fromisoformat(info["banned_at"])
            if now - banned_at > timedelta(hours=UNBAN_HOURS):
                _iptables_unblock(ip)
                to_remove.append(ip)
                log.info(f"⏰ رُفع حظر {ip} (انتهت مدة {UNBAN_HOURS}h)")
            else:
                if not self.dry_run:
                    _iptables_block(ip)
                    log.info(f"♻️ استعادة حظر {ip}")
        for ip in to_remove:
            del self.banned[ip]
        if to_remove:
            _save_banned(self.banned)

    def _clean_window(self, ip: str) -> None:
        """يحذف المحاولات الأقدم من النافذة الزمنية."""
        cutoff = time.time() - WINDOW_SECONDS
        self._fail_times[ip] = [t for t in self._fail_times[ip] if t > cutoff]
        if not self._fail_times[ip]:
            self._alerted.pop(ip, None)

    def _handle_fail(self, ip: str, username: str) -> None:
        """يعالج محاولة فاشلة — يقرر مستوى الإجراء."""
        now = time.time()
        self._fail_times[ip].append(now)
        self._usernames[ip].append(username)
        self._clean_window(ip)

        count = len(self._fail_times[ip])

        # لا تُعيد التنبيه على نفس المستوى مرتين متتاليتين
        current_level = (
            "ban"   if count >= THRESHOLDS["ban"]   else
            "alert" if count >= THRESHOLDS["alert"] else
            "warn"  if count >= THRESHOLDS["warn"]  else
            None
        )
        if current_level is None:
            return
        if self._alerted.get(ip) == current_level:
            return
        self._alerted[ip] = current_level

        victim_ip = "192.168.1.1"  # البوابة هي الضحية في هذا السياق
        usernames = self._usernames[ip]

        # تغذية state_tracker دائماً
        _update_state_tracker(ip, victim_ip, count)

        # إنتاج تنبيه
        banned = False
        if current_level == "ban" and ip not in self.banned:
            if not self.dry_run:
                banned = _iptables_block(ip)
            else:
                log.info(f"[DRY-RUN] سيتم حظر {ip}")
                banned = True
            if banned:
                self.banned[ip] = {
                    "banned_at": datetime.now().isoformat(),
                    "fail_count": count,
                    "usernames": list(set(usernames))[:10],
                }
                _save_banned(self.banned)

        _write_alert(ip, victim_ip, count, usernames, current_level, banned)

    def _handle_success(self, ip: str, username: str) -> None:
        """تسجيل الدخول الناجح — يُصفّر العداد لهذا الـ IP."""
        if ip in self._fail_times and self._fail_times[ip]:
            fail_count = len(self._fail_times[ip])
            log.info(
                f"✅ تسجيل دخول ناجح | {username}@{ip} "
                f"(بعد {fail_count} محاولة فاشلة)"
            )
        self._fail_times.pop(ip, None)
        self._usernames.pop(ip, None)
        self._alerted.pop(ip, None)

    def _check_unban(self) -> None:
        """يفحص المحظورين كل دقيقة ويرفع الحظر المنتهي."""
        now = datetime.now()
        to_remove = []
        for ip, info in self.banned.items():
            banned_at = datetime.fromisoformat(info["banned_at"])
            if now - banned_at > timedelta(hours=UNBAN_HOURS):
                if not self.dry_run:
                    _iptables_unblock(ip)
                to_remove.append(ip)
                log.info(f"⏰ رُفع حظر {ip} تلقائياً بعد {UNBAN_HOURS}h")
        for ip in to_remove:
            del self.banned[ip]
        if to_remove:
            _save_banned(self.banned)

    def run(self) -> None:
        """الحلقة الرئيسية — tail -f على auth.log."""
        if not AUTH_LOG.exists():
            log.error(f"لم يُعثر على {AUTH_LOG} — تأكد من تشغيل sshd")
            sys.exit(1)

        log.info(
            f"{'[DRY-RUN] ' if self.dry_run else ''}"
            f"NetGuard Auth Monitor بدأ | "
            f"عتبات: warn={THRESHOLDS['warn']} "
            f"alert={THRESHOLDS['alert']} "
            f"ban={THRESHOLDS['ban']} / {WINDOW_SECONDS}s"
        )

        last_unban_check = time.time()

        with open(AUTH_LOG, "r") as fh:
            # انتقل إلى نهاية الملف — لا نعيد تحليل السجلات القديمة
            fh.seek(0, 2)

            while True:
                line = fh.readline()

                if not line:
                    time.sleep(POLL_INTERVAL)
                    # فحص رفع الحظر كل 60 ثانية
                    if time.time() - last_unban_check >= 60:
                        self._check_unban()
                        last_unban_check = time.time()
                    continue

                line = line.strip()
                if not line:
                    continue

                parsed = _parse_line(line)
                if parsed is None:
                    continue

                event_type, ip, username = parsed

                if event_type == "fail":
                    self._handle_fail(ip, username)
                elif event_type == "success":
                    self._handle_success(ip, username)


# ─── --status ─────────────────────────────────────────────────────────────────
def print_status() -> None:
    """يطبع ملخص المحظورين الحاليين."""
    banned = _load_banned()
    if not banned:
        print("✅ لا توجد IPs محظورة حالياً")
        return

    print(f"\n{'IP':<20} {'وقت الحظر':<22} {'محاولات':<10} {'متبقي'}")
    print("-" * 70)
    now = datetime.now()
    for ip, info in banned.items():
        banned_at = datetime.fromisoformat(info["banned_at"])
        elapsed   = now - banned_at
        remaining = timedelta(hours=UNBAN_HOURS) - elapsed
        remaining_str = (
            f"{int(remaining.total_seconds() // 3600)}h "
            f"{int((remaining.total_seconds() % 3600) // 60)}m"
            if remaining.total_seconds() > 0 else "منتهي"
        )
        print(
            f"{ip:<20} {info['banned_at'][:19]:<22} "
            f"{info['fail_count']:<10} {remaining_str}"
        )
    print()


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetGuard SSH Brute Force Monitor"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="تسجيل وتنبيه فقط — بدون حظر iptables فعلي"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="عرض IPs المحظورة حالياً والخروج"
    )
    args = parser.parse_args()

    if args.status:
        print_status()
        return

    monitor = AuthLogMonitor(dry_run=args.dry_run)
    try:
        monitor.run()
    except KeyboardInterrupt:
        log.info("Auth Monitor أوقفه المستخدم")


if __name__ == "__main__":
    main()
