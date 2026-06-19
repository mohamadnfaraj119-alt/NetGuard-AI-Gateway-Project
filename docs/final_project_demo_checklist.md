# NetGuard-AI Final Project Demo Checklist

## Pre-Demo Checks

- `git status` is clean.
- Dashboard server can start.
- Smoke test passes.
- Post-training audit runs.

## Demo Flow

Start dashboard:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Show:

- Live status.
- Demo OK.
- Demo WARN.
- Demo FAIL.

Run smoke test:

```bash
python3 scripts/gateway_status_smoke_test.py
```

Run post-training audit:

```bash
python3 scripts/post_training_day_audit.py
```

## What to Explain During the Demo

- NetGuard-AI is not just a CSV model; it is a real pipeline.
- Zeek collects network logs.
- Python scripts extract features and windows.
- Isolation Forest detects anomalies from local baseline behavior.
- XGBoost is a supporting signature-style layer.
- Risk Engine combines indicators into a 0-100 Risk Score.
- Gateway Dashboard shows readiness safely.
- Post-training audit prevents unsafe retraining.

## Safety Points

- Localhost only.
- Read-only dashboard.
- No sudo.
- No `--apply`.
- No firewall or iptables changes.
- No service changes.
- No data or model changes.
- No Grafana in the current dashboard.
- No systemd in the current dashboard.

## Screenshot Checklist

- Dashboard live status.
- Demo OK.
- Demo WARN.
- Demo FAIL.
- Smoke test passed.
- Post-training audit output.

## Closing Message

The demo should show that v9.3 is a stable local gateway readiness and audit
workflow suitable for presentation and review.
