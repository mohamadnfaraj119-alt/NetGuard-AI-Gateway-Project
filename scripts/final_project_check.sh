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

echo "NetGuard-AI v10.1 professional demo dashboard check"

run_check "GIT STATUS" git status --short

run_check "PYTHON COMPILE" python3 -m py_compile \
  scripts/gateway_doctor.py \
  scripts/gateway_status_server.py \
  scripts/gateway_status_smoke_test.py \
  scripts/post_training_day_audit.py \
  scripts/attack_classifier.py

run_check "DASHBOARD SHELL SYNTAX" bash -n scripts/run_gateway_dashboard.sh
run_check "FINAL CHECK SHELL SYNTAX" bash -n scripts/final_project_check.sh

run_check "V10.1 DASHBOARD FILE" test -s dashboard/index.html
run_check "V10.1 DASHBOARD LABELS" grep -E \
  "NetGuard-AI Gateway|Attack Classification|Read-only|Final Baseline|Demo Dashboard" \
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
