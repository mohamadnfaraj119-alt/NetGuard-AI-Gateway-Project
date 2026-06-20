# NetGuard-AI Final Project Demo Checklist

## Pre-Demo Checks

- `git status` is clean.
- Final project check passes.
- Dashboard server can start.
- Smoke test passes.
- Post-training audit runs.
- Attack classification summary runs.

## Demo Flow

Run final project check:

```bash
bash scripts/final_project_check.sh
```

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

Run default post-training audit:

```bash
python3 scripts/post_training_day_audit.py
```

Run a date-specific audit:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20
```

Run a summary-only audit for quick review:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only
```

Run attack classification summary:

```bash
python3 scripts/attack_classifier.py --summary-only
```

Optional date-specific classification:

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Export audit evidence for the report:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only --export-md reports/audit_exports/post_training_audit_summary.md --export-json reports/audit_exports/post_training_audit_summary.json
```

The exported Markdown and JSON files can be used as final report evidence. Do
not commit generated export files.

## What to Explain During the Demo

- NetGuard-AI is not just a CSV model; it is a real pipeline.
- Zeek collects network logs.
- Python scripts extract features and windows.
- Isolation Forest detects anomalies from local baseline behavior.
- XGBoost is a supporting signature-style layer.
- Risk Engine combines indicators into a 0-100 Risk Score.
- Gateway Dashboard shows readiness safely.
- Post-training audit shows label summary and conservative retraining recommendation.
- Attack classification gives preliminary explainable labels with confidence and reasons.
- Audit evidence export is explicit and limited to safe output paths.

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
- Final project check passed.
- Smoke test passed.
- Post-training audit output.
- Attack classification summary.
- Audit evidence export output.

## Closing Message

The demo should show that v9.8 is a stable local gateway readiness, audit,
classification, and evidence workflow suitable for presentation and review.
