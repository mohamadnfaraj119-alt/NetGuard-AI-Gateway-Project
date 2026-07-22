#!/usr/bin/env bash
set -u

status=0

run_check() {
  echo "=== $1 ==="
  shift
  "$@"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    status=1
  fi
  return "$rc"
}

echo "NetGuard-AI v10.2 SOC dashboard check"

run_check "GIT STATUS" git status --short

run_check "PYTHON COMPILE" python3 -m py_compile \
  scripts/gateway_doctor.py \
  scripts/window_engine.py \
  scripts/gateway_status_server.py \
  scripts/gateway_status_smoke_test.py \
  scripts/post_training_day_audit.py \
  scripts/attack_classifier.py

run_check "DASHBOARD SHELL SYNTAX" bash -n scripts/run_gateway_dashboard.sh
run_check "FINAL CHECK SHELL SYNTAX" bash -n scripts/final_project_check.sh

run_check "V10.2 DASHBOARD FILE" test -s dashboard/index.html
run_check "V10.2 DASHBOARD LABELS" grep -E \
  "NetGuard-AI Gateway|Attack Classification|Read-only|Final Baseline|SOC Dashboard" \
  dashboard/index.html

echo "=== V10.2.5 UNIFIED ONE-PAGE DASHBOARD LAYOUT ==="
if find dashboard -maxdepth 2 -type f \( \
  -name "overview.html" -o \
  -name "threats.html" -o \
  -name "audit.html" -o \
  -name "audit-evidence.html" -o \
  -name "gateway.html" -o \
  -name "gateway-roadmap.html" -o \
  -name "evidence.html" -o \
  -name "future.html" -o \
  -name "roadmap.html" \
\) -print -quit | grep .; then
  status=1
fi

if grep -RInE "overview\.html|threats\.html|audit\.html|audit-evidence\.html|gateway\.html|gateway-roadmap\.html|evidence\.html|future\.html|roadmap\.html|href=[\"']/(overview|threats|audit|gateway|evidence|future|roadmap)|window\.location|location\.href|location\.assign|location\.replace|location\.hash\s*=|history\.pushState|window\.scrollTo|showPanel|switchPanel|setActivePanel|data-panel-target|data-panel-content" dashboard; then
  status=1
fi

if grep -RInE "\.dashboard-panel\s*\{[^}]*display\s*:\s*none|\.dashboard-panel:not|visibility\s*:\s*hidden" dashboard; then
  status=1
fi

run_check "V10.2.5 UNIFIED SECTION MARKERS" grep -E \
  "dashboard-section|Overview|Threats|Audit & Evidence|Gateway & Roadmap" \
  dashboard/index.html

run_check "SECTION INDEX NAV MARKERS" grep -E \
  "data-section-target|scrollIntoView|overview|threats|audit-evidence|gateway-roadmap" \
  dashboard/index.html

run_check "POST-TRAINING AUDIT SUMMARY" \
  python3 scripts/post_training_day_audit.py --summary-only

run_check "ATTACK CLASSIFICATION SUMMARY" \
  python3 scripts/attack_classifier.py --summary-only

run_check "ATTACK CLASSIFICATION DATE SUMMARY" \
  python3 scripts/attack_classifier.py --date 2026-06-20 --top 3 --summary-only

run_check "ATTACK CLASSIFICATION TRUSTED ADMIN SUMMARY" \
  python3 scripts/attack_classifier.py --date 2026-06-20 --top 3 --summary-only --trusted-admin-ip 192.168.1.104

echo "=== STATUS SERVER CHECK ==="
if python3 - <<'PY'
from urllib.error import URLError
from urllib.request import urlopen

try:
    with urlopen("http://127.0.0.1:8787/healthz", timeout=2) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except URLError:
    raise SystemExit(1)
PY
then
  run_check "GATEWAY STATUS SMOKE TEST" python3 scripts/gateway_status_smoke_test.py
else
  echo "Status server is not running; skipping smoke test. Start it with bash scripts/run_gateway_dashboard.sh"
  echo "After the dashboard is running, run: python3 scripts/gateway_status_smoke_test.py"
fi

echo "Dashboard manual start: bash scripts/run_gateway_dashboard.sh"

if [ "$status" -eq 0 ]; then
  echo "[RESULT] FINAL PROJECT CHECK PASSED"
else
  echo "[RESULT] FINAL PROJECT CHECK FAILED"
fi

exit "$status"
