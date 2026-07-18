# Professional Demo Dashboard

## Purpose

The v10.2 Professional SOC Dashboard is a presentation layer for the stable
NetGuard-AI Gateway graduation baseline. It makes the local readiness, audit,
and classification evidence easier to show in a supervisor demo without
changing detection logic, risk scoring, model files, thresholds, Zeek
configuration, firewall rules, services, or training data.

## v10.2 SOC / Stitch Redesign

v10.2 redesigns the local dashboard using the selected Google Stitch
cybersecurity SOC-style reference in `design_refs/stitch_dashboard/`. The PNG
reference drove the visual direction: dark SOC workspace, sidebar navigation,
neon cyan accents, glass-style panels, top metric cards, an inference pipeline,
classified events table, audit panel, readiness panel, topology card, evidence
cards, and future productization section.

This is presentation layer only. It does not change the core IDS logic,
thresholds, risk scoring, training, model files, audit logic, attack
classification logic, Zeek configuration, firewall rules, services, or data.

## v10.2.2 Navigation Polish

v10.2.2 polishes the dashboard navigation into four supervisor-demo sections:
Overview, Threats, Audit & Evidence, and Gateway & Roadmap. The sidebar now
uses stable dashboard panel switching and no longer uses jumpy scroll
navigation.

## v10.2.3 Single-Page Navigation Fix

v10.2.3 keeps the SOC dashboard as one local `dashboard/index.html` page. The
sidebar buttons switch in-page panels without page reloads, separate dashboard
HTML files, anchor scrolling, hash jumps, or scroll movement.

## v10.2.4 True Single-Page Enforcement

v10.2.4 enforces the sidebar as button-only panel navigation. All four
supervisor-demo sections already exist inside `dashboard/index.html`, and the
dashboard does not use separate section pages, hash navigation, scroll
navigation, or document reloads.

## v10.2.5 Unified One-Page Layout

v10.2.5 converts the dashboard from tab-style section switching to a unified
one-page layout where all key supervisor-demo sections are visible together:
Overview, Threats, Audit & Evidence, and Gateway & Roadmap.

## What The Dashboard Shows

- SOC-style top metric cards for Gateway Status, Risk Level, Actionable Events,
  API Health, Audit Recommendation, and Smoke Test / Verification.
- Sidebar navigation for Overview, Threats, Audit & Evidence, and Gateway &
  Roadmap.
- Active inference pipeline from Zeek Logs through Dashboard presentation.
- Post-training audit status and retraining recommendation.
- Attack Classification summary for the saved evidence snapshot.
- Recent classified events with time, source IP, attack type, confidence, risk
  score, and reason preview.
- Gateway readiness panel with OK/WARN/FAIL counts and honest NOT READY copy
  when the current environment is not ready.
- Network topology card showing Internet / Router -> NetGuard-AI Gateway ->
  Local Network Devices.
- Evidence/reporting cards for final project check, audit evidence export,
  classification evidence export, and smoke test.
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

- Unified dashboard overview.
- Threats section.
- Audit & Evidence section.
- Gateway & Roadmap section.
- Smoke test output.

## Limitations

- This is a local dashboard, not a production monitoring platform.
- Full network visibility requires Gateway mode or SPAN/Mirror deployment.
- Attack Classification labels are preliminary and explainable, not guaranteed
  ground truth.
- Retraining is never automatic.
- The dashboard does not provide remediation, blocking, or alert delivery.

## Why Grafana Is Future Work

Grafana would be useful after durable time-series storage, authentication,
deployment hardening, and operational data retention are added. v10.2 keeps the
graduation sprint focused on a safe local presentation layer with no external
services, no new infrastructure, no network dependencies, and no production
deployment changes. Grafana remains future productization work, not part of this
read-only SOC dashboard sprint.
