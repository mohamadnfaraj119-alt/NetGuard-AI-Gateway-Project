# Professional Demo Dashboard

## Purpose

The v10.1 Professional Demo Dashboard is a presentation layer for the stable
v10.0 NetGuard-AI Gateway graduation baseline. It makes the local readiness,
audit, and classification evidence easier to show in a supervisor demo without
changing detection logic, risk scoring, model files, thresholds, Zeek
configuration, firewall rules, services, or training data.

## What The Dashboard Shows

- Gateway readiness cards from the local Gateway Doctor status API.
- Clear warning and failure counts for demo review.
- Detection pipeline overview from Zeek logs through dashboard presentation.
- Post-training audit status and retraining recommendation.
- Attack Classification summary for the saved evidence snapshot.
- Top classified events with time, source IP, attack type, confidence, risk
  score, and reason preview.
- Demo OK, Demo WARN, and Demo FAIL modes for presentation.
- Honest limitations and safety scope.

## Data Sources

- `/api/status` reads `scripts/gateway_doctor.py --json`.
- `/api/demo-summary` reads existing saved reports through read-only helper
  functions in `post_training_day_audit.py` and `attack_classifier.py`.
- The stable demo evidence date is `2026-06-20`.
- If saved evidence is unavailable, the dashboard explains what command to run
  instead of pretending live attack data exists.

## Read-Only Safety Model

- The dashboard server is local-first and intended for `127.0.0.1`.
- Supported dashboard API access is read-only.
- GET requests return status and summary data.
- POST, PUT, PATCH, and DELETE are rejected with HTTP 405.
- The dashboard does not write files.
- The dashboard does not retrain, change thresholds, alter models, modify Zeek,
  touch firewall rules, or manage services.

## Demo Workflow

Start the dashboard:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Run the smoke test in another terminal:

```bash
python3 scripts/gateway_status_smoke_test.py
```

Stop the dashboard with `Ctrl+C`.

## Screenshots To Capture

- Professional dashboard overview.
- Gateway readiness cards.
- Attack Classification summary.
- Audit and retraining recommendation panel.
- Top classified events table.
- Demo OK, Demo WARN, and Demo FAIL states.
- Smoke test passed output.

## Limitations

- This is a local dashboard, not a production monitoring platform.
- Full network visibility requires Gateway mode or SPAN/Mirror deployment.
- Attack Classification labels are preliminary and explainable, not guaranteed
  ground truth.
- Retraining is never automatic.
- The dashboard does not provide remediation, blocking, or alert delivery.

## Why Grafana Is Future Work

Grafana would be useful after durable time-series storage, authentication,
deployment hardening, and operational data retention are added. v10.1 keeps the
graduation sprint focused on a safe local presentation layer with no external
services, no new infrastructure, no network dependencies, and no production
deployment changes. Grafana remains future productization work, not part of this
read-only demo dashboard sprint.
