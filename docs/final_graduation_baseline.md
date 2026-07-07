# NetGuard-AI Gateway — Final Graduation Baseline

## 1. Purpose Of The Project

NetGuard-AI Gateway is a graduation-project IDS workflow that uses Zeek network
logs, behavioral feature windows, anomaly detection, risk scoring, readiness
checks, and evidence-oriented reporting to help review suspicious activity on a
local gateway or mirrored network path.

The purpose is to demonstrate a practical, defensible security engineering
pipeline rather than a single isolated machine-learning notebook.

## 2. What This Release Represents

v10.0 is the stable graduation-ready baseline. It freezes the current toolchain,
documentation, demo workflow, and verification process for final submission.

This release is not a full production IDS/IPS appliance. It is a local-first,
read-only, behavior-based, evidence-oriented baseline suitable for demonstration,
review, and future productization.

## 3. Current Architecture

The system is organized as a local gateway/readiness and analysis stack:

- Zeek captures and produces network logs.
- Collector and feature/window scripts prepare local behavior windows.
- The anomaly baseline scores post-training behavior.
- The risk engine produces daily risk reports.
- Audit and classification scripts summarize suspicious behavior.
- Gateway Doctor, status API, dashboard, and smoke tests verify readiness.

Full network visibility requires actual Gateway mode placement or SPAN/Mirror
deployment. Running the scripts on a host without traffic visibility limits what
can be observed.

## 4. Main Components

- Zeek log processing.
- Window and feature pipeline.
- Isolation Forest anomaly baseline.
- Risk Engine and daily risk reports.
- Gateway Doctor readiness checks.
- JSON readiness output.
- Local status API and dashboard.
- Demo OK/WARN/FAIL dashboard modes.
- Smoke test.
- Post-training day audit.
- Markdown/JSON audit evidence export.
- Explainable Attack Classification layer.
- Final project verification script.

## 5. Data Flow

Network traffic is observed by Zeek, converted into structured logs, processed
into behavioral windows, scored against the local baseline, and written into
risk reports. The audit and classification tools read those existing reports
and produce console summaries plus optional evidence exports.

The final baseline does not modify data or model files during verification.

## 6. Detection Approach

The detection approach is behavior-based. It compares post-training traffic
windows to the learned local baseline and highlights deviations through anomaly
and risk signals. This keeps the project explainable for review and avoids
claiming that a model alone proves an attack.

## 7. Risk Scoring Approach

Risk reports combine multiple indicators into a 0-100 style Risk Score. Higher
scores indicate behavior that deserves review. Risk scores support analyst
triage; they do not automatically block traffic, change system configuration, or
approve retraining.

## 8. Attack Classification Approach

The Attack Classification layer is rule-based and explainable. It labels
suspicious windows as preliminary behavior types such as port scanning, DNS
anomaly, failed connection pattern, DoS-like burst, bot-like behavior, unknown
suspicious, or low-signal review.

Classifications include confidence and reasons. They are preliminary and do not
represent guaranteed ground truth. v9.9 calibration keeps SSH brute-force
classification conservative by requiring explicit SSH evidence such as port 22
or `service=ssh`; `FAILED_CONNECTION_PATTERN` prevents overclaiming SSH when
only failed-connection behavior is visible.

## 9. Evidence And Audit Workflow

The post-training audit identifies candidate clean, suspicious, partial, or
incomplete validation days. Suggested labels are preliminary and do not
automatically approve retraining. Suspicious post-training days should block
baseline retraining until reviewed.

Evidence exports are explicit:

```bash
python3 scripts/post_training_day_audit.py --summary-only --export-md /tmp/netguard_final_audit.md --export-json /tmp/netguard_final_audit.json
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --export-md /tmp/netguard_final_classification.md --export-json /tmp/netguard_final_classification.json
```

Exports are allowed only through the script options and safe output paths.

## 10. Dashboard And Readiness Workflow

The dashboard is a local, read-only readiness view. It exposes local status API
data and demo modes for presentation. v10.1 adds a Professional Demo Dashboard
layer that also displays saved audit and Attack Classification evidence
summaries for a cleaner supervisor demo. It does not provide remediation
actions, configuration changes, firewall changes, or background automation.

Start it manually:

```bash
bash scripts/run_gateway_dashboard.sh
```

Then open:

```text
http://127.0.0.1:8787/
```

## 11. Final Verification Commands

Run the final check:

```bash
bash scripts/final_project_check.sh
```

Run audit and classification summaries:

```bash
python3 scripts/post_training_day_audit.py --summary-only
python3 scripts/attack_classifier.py --summary-only
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Run the dashboard smoke test only after the dashboard is running:

```bash
python3 scripts/gateway_status_smoke_test.py
```

## 12. Safety Model

- Read-only by default.
- No data changes during final verification.
- No model changes.
- No retraining or training run.
- No sudo requirement for final checks.
- No `--apply`.
- No firewall or iptables changes.
- No service or system file changes.
- Local dashboard only.
- Evidence export only when explicitly requested.

## 13. What Is Intentionally Not Included In v10.0

- Production IDS/IPS enforcement.
- Automatic blocking or remediation.
- Automatic retraining.
- New detection thresholds.
- New risk scoring logic.
- New attack classification logic.
- Grafana monitoring.
- Kafka streaming pipeline.
- systemd deployment.
- Production packaging.

## 14. Known limitations

- Visibility depends on Gateway mode or SPAN/Mirror deployment.
- Labels are preliminary and require analyst review.
- Attack classification is explainable but not ground truth.
- Local dashboard is not a full monitoring platform.
- Historical storage and alerting are limited.
- Retraining decisions require clean reviewed data, not script output alone.

## 15. Future Work Path Toward Productization

- Harden Gateway deployment.
- Add Sensor/SPAN deployment guidance.
- Add durable historical storage.
- Add alerting and notification workflows.
- Add Grafana monitoring after the final baseline.
- Add Kafka streaming after the final baseline.
- Support multi-sensor architecture.
- Train a supervised ML classifier after reviewed labels exist.
- Package the project for repeatable installation.

## 16. Final Baseline Conclusion

NetGuard-AI Gateway v10.0 is a stable final graduation baseline. It demonstrates
real network-log processing, local behavioral detection, risk scoring,
readiness verification, evidence export, and preliminary explainable attack
classification while keeping safety boundaries explicit.
