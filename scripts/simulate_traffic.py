#!/usr/bin/env python3
"""
simulate_traffic.py v2.0 — NetGuard-AI
Server/VM traffic profile — مناسب لـ Ubuntu VM تُدار عبر SSH
لا يعتمد على browsing يدوي — يولّد سلوك server حقيقي
"""

import subprocess
import time
import random
import logging
import signal
import sys
from datetime import datetime

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler("/home/mtech/zeek-ids/logs/simulate_traffic.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ─── Graceful shutdown ────────────────────────────────────────────────────────
def handle_exit(sig, frame):
    log.info("STOP simulator clean exit")
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_exit)
signal.signal(signal.SIGINT, handle_exit)

# ─── Constants ────────────────────────────────────────────────────────────────

# مواقع curl خفيفة — headers فقط، لا محتوى
CURL_TARGETS = [
    "https://pypi.org/simple/",
    "https://api.github.com",
    "https://www.cloudflare.com",
    "https://docs.python.org",
    "https://ubuntu.com",
    "https://security.ubuntu.com",
    "https://archive.ubuntu.com",
    "https://ntp.ubuntu.com",
]

# DNS lookups — متنوع ومنطقي لـ server
DNS_DOMAINS = [
    "security.ubuntu.com",
    "archive.ubuntu.com",
    "pypi.org",
    "github.com",
    "api.github.com",
    "google.com",
    "cloudflare.com",
    "pool.ntp.org",
    "time.cloudflare.com",
    "python.org",
]

# Ping targets — DNS + Gateway
PING_TARGETS = [
    "8.8.8.8",
    "1.1.1.1",
    "8.8.4.4",
    "192.168.68.55",   # الراوتر — طبيعي جداً لـ VM
]

# Git repos خفيفة — ls-remote سريع
GIT_REPOS = [
    "https://github.com/pypa/pip",
    "https://github.com/psf/requests",
    "https://github.com/pallets/flask",
    "https://github.com/encode/httpx",
]

# ─── Actions ─────────────────────────────────────────────────────────────────

def curl_head():
    """
    HTTP HEAD request — يشبه apt يتحقق من الـ repo
    خفيف جداً، لا يحمّل محتوى
    """
    url = random.choice(CURL_TARGETS)
    try:
        result = subprocess.run(
            [
                "curl", "-s", "-I",            # HEAD فقط
                "-o", "/dev/null",
                "-w", "%{http_code}",
                "--limit-rate", "500k",
                "--max-time", "10",
                "--connect-timeout", "5",
                url
            ],
            capture_output=True, text=True, timeout=12
        )
        code = result.stdout.strip()
        log.info(f"HTTP HEAD {url} → {code}")
    except Exception as e:
        log.warning(f"curl_head failed: {e}")


def curl_get():
    """
    HTTP GET خفيف — يشبه pip check أو package manager
    """
    url = random.choice(CURL_TARGETS)
    try:
        subprocess.run(
            [
                "curl", "-s",
                "-o", "/dev/null",
                "-w", "%{http_code}",
                "--limit-rate", "200k",        # أبطأ من HEAD — أكثر واقعية
                "--max-time", "15",
                "--connect-timeout", "5",
                url
            ],
            capture_output=True, text=True, timeout=17
        )
        log.info(f"HTTP GET {url}")
    except Exception as e:
        log.warning(f"curl_get failed: {e}")


def dns_lookup():
    """DNS query — سلوك طبيعي جداً لأي server"""
    domain = random.choice(DNS_DOMAINS)
    try:
        subprocess.run(
            ["nslookup", domain, "8.8.8.8"],
            capture_output=True, timeout=5
        )
        log.info(f"DNS {domain}")
    except Exception as e:
        log.warning(f"dns_lookup failed: {e}")


def multi_dns():
    """
    عدة DNS queries متتالية — يشبه apt-get update
    يستعلم عن عدة domains بفترات قصيرة جداً
    """
    count = random.randint(3, 7)
    domains = random.sample(DNS_DOMAINS, min(count, len(DNS_DOMAINS)))
    log.info(f"DNS burst ({count} queries) — simulating apt behavior")
    for domain in domains:
        try:
            subprocess.run(
                ["nslookup", domain],
                capture_output=True, timeout=5
            )
            time.sleep(random.uniform(0.5, 2.0))   # فترة قصيرة بين الـ queries
        except Exception:
            pass


def ping_host():
    """Ping — connectivity check طبيعي"""
    host = random.choice(PING_TARGETS)
    count = random.randint(2, 5)
    try:
        subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, timeout=20
        )
        log.info(f"PING {host} x{count}")
    except Exception as e:
        log.warning(f"ping failed: {e}")


def apt_check():
    """
    apt-get check — بدون sudo، بدون تثبيت
    يولّد DNS + TCP connections لـ ubuntu repos
    """
    try:
        subprocess.run(
            ["apt-cache", "policy"],           # لا يحتاج sudo
            capture_output=True, timeout=10
        )
        log.info("APT cache policy check")
        # بعده curl للـ repo — يشبه ما يفعله apt فعلاً
        time.sleep(random.uniform(1, 3))
        curl_head()
    except Exception as e:
        log.warning(f"apt_check failed: {e}")


def git_check():
    """git ls-remote على repo خفيف — يولّد TCP+DNS لـ github"""
    repo = random.choice(GIT_REPOS)
    try:
        subprocess.run(
            ["git", "ls-remote", "--heads", repo],
            capture_output=True, timeout=20
        )
        log.info(f"GIT ls-remote {repo.split('/')[-1]}")
    except Exception as e:
        log.warning(f"git_check failed: {e}")


def ntp_check():
    """
    NTP sync check — سلوك server أساسي
    ntpdate -q لا يغيّر الوقت، فقط يستعلم
    """
    try:
        subprocess.run(
            ["ntpdate", "-q", "pool.ntp.org"],
            capture_output=True, timeout=10
        )
        log.info("NTP query pool.ntp.org")
    except Exception:
        # إذا ntpdate غير مثبت — curl بديل
        try:
            subprocess.run(
                ["curl", "-s", "-o", "/dev/null",
                 "--max-time", "5", "https://time.cloudflare.com"],
                capture_output=True, timeout=7
            )
            log.info("NTP fallback via cloudflare time")
        except Exception as e:
            log.warning(f"ntp_check failed: {e}")


def burst_then_idle():
    """
    نشاط قصير مكثف ثم صمت طويل
    يشبه: script تشغيل → ينتهي → الجهاز يعود للخمول
    """
    count = random.randint(3, 6)
    log.info(f"BURST session ({count} actions) starting")
    for _ in range(count):
        action = random.choice([curl_head, dns_lookup, ping_host])
        action()
        time.sleep(random.uniform(1, 5))
    
    idle_duration = random.randint(120, 400)
    log.info(f"POST-BURST idle {idle_duration}s")
    time.sleep(idle_duration)


def long_idle():
    """خمول طويل — الـ VM لا يفعل شيئاً"""
    duration = random.randint(180, 600)
    log.info(f"IDLE {duration}s")
    time.sleep(duration)


def short_idle():
    """خمول قصير بين الأفعال"""
    duration = random.randint(30, 120)
    log.info(f"SHORT IDLE {duration}s")
    time.sleep(duration)


# ─── Action weights — Server/VM Profile ──────────────────────────────────────
#
# يعكس سلوك Ubuntu VM تُدار عبر SSH:
#   - معظم الوقت: خمول أو DNS/ping خفيف
#   - بعض الوقت: HTTP connections لـ repos/APIs
#   - نادراً: git أو apt أو NTP
#
ACTIONS = [
    (dns_lookup,      22),   # 22% — DNS طبيعي جداً
    (short_idle,      18),   # 18% — خمول قصير
    (curl_head,       15),   # 15% — HTTP HEAD خفيف
    (ping_host,       12),   # 12% — ping
    (long_idle,       10),   # 10% — خمول طويل
    (multi_dns,        8),   # 8%  — DNS burst (يشبه apt)
    (curl_get,         6),   # 6%  — HTTP GET
    (burst_then_idle,  4),   # 4%  — نشاط ثم صمت
    (apt_check,        2),   # 2%  — apt check
    (git_check,        2),   # 2%  — git activity
    (ntp_check,        1),   # 1%  — NTP (نادر)
]

WEIGHTS = [w for _, w in ACTIONS]
FUNCS   = [f for f, _ in ACTIONS]

# ─── Sleep between actions ────────────────────────────────────────────────────
def get_sleep_duration():
    """
    فترة انتظار بين الأفعال — موزعة بشكل واقعي
    Server/VM: أطول من Desktop — أقل نشاطاً متواصلاً
    """
    r = random.random()
    if r < 0.40:
        return random.uniform(20, 60)      # 40% → 20-60 ثانية
    elif r < 0.70:
        return random.uniform(60, 180)     # 30% → 1-3 دقائق
    elif r < 0.90:
        return random.uniform(180, 360)    # 20% → 3-6 دقائق
    else:
        return random.uniform(360, 720)    # 10% → 6-12 دقيقة (خمول حقيقي)


# ─── Main loop ────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 55)
    log.info("NetGuard-AI Traffic Simulator v2.0 — Server Profile")
    log.info(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("=" * 55)

    session_count = 0

    while True:
        action = random.choices(FUNCS, weights=WEIGHTS, k=1)[0]

        try:
            action()
        except Exception as e:
            log.error(f"ERROR in {action.__name__}: {e}")

        session_count += 1

        if session_count % 10 == 0:
            log.info(f"STATS total_actions={session_count}")

        # لا ننتظر إذا الـ action نفسه كان idle
        if action not in (long_idle, short_idle, burst_then_idle):
            sleep_time = get_sleep_duration()
            log.info(f"WAIT {sleep_time:.0f}s")
            time.sleep(sleep_time)


if __name__ == "__main__":
    main()