# Final Demo Script

Use this script as speaking notes for a supervisor demo.

## 1. Introduction

"This project is NetGuard-AI Gateway. It is a local-first network intrusion
detection and readiness workflow built around Zeek logs, behavioral windows,
anomaly scoring, risk scoring, audit evidence, and explainable classification."

## 2. Current Release

"The current release is v10.0, the Final Graduation Baseline. This freezes the
project for submission. It does not add risky runtime features; it documents
and verifies the stable workflow."

## 3. Final Project Check

Run:

```bash
bash scripts/final_project_check.sh
```

Say:

"This command compiles the Python scripts, checks shell syntax, runs the audit
summary, runs attack classification summaries, and safely skips the dashboard
smoke test unless the local status server is already running."

## 4. Audit Summary

Run:

```bash
python3 scripts/post_training_day_audit.py --summary-only
```

Say:

"The audit reviews post-training days and produces label summaries and a
conservative retraining recommendation. Suggested labels do not automatically
approve retraining."

## 5. Attack Classification

Run:

```bash
python3 scripts/attack_classifier.py --summary-only
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Say:

"The project moved beyond CSV-only ML. It analyzes real network logs, compares
behavior to the local baseline, produces a Risk Score, and adds preliminary
explainable classification with confidence and reasons."

## 6. Dashboard

Run:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Say:

"The dashboard is local and read-only. It shows gateway readiness and demo
states without making firewall, service, or system changes."

## 7. Smoke Test

In another terminal:

```bash
python3 scripts/gateway_status_smoke_test.py
```

Say:

"The smoke test verifies the local health endpoint, status API, dashboard page,
and rejected write-style requests while the dashboard is running."

## 8. Limitations

Say:

"This is a graduation-ready baseline, not a full production IDS/IPS appliance.
Full visibility requires Gateway mode or SPAN/Mirror deployment. Classification
labels are preliminary and explainable, not guaranteed ground truth. Retraining
is never automatic."

## 9. Future Product Path

Say:

"Future productization can add hardened gateway deployment, historical storage,
alerting, Grafana monitoring, Kafka streaming, multi-sensor support, packaging,
and an ML attack classifier after reviewed labels exist. Those are prepared as
future work but are not included in v10.0."
