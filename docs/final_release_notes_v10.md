# v10.0 — Final Graduation Baseline

Release date: 2026-06-21

## Summary

v10.0 freezes NetGuard-AI Gateway as the final graduation-ready baseline. The
release finalizes documentation, operating workflow, demo script, release notes,
verification commands, limitations, and future roadmap. It adds no new risky
runtime features.

## What Is Included

- Zeek-based network log processing workflow.
- Feature/window pipeline.
- Isolation Forest anomaly baseline.
- Risk Engine and daily risk reports.
- Gateway Doctor readiness checks.
- JSON readiness output.
- Local status API and dashboard.
- Demo OK/WARN/FAIL modes.
- Smoke test.
- Post-training audit with evidence export.
- Explainable attack classification with v9.9 calibration.
- Final project verification script.
- Final baseline, workflow, demo, and release documentation.

## What Is Not Included

- Production IDS/IPS enforcement.
- Automatic blocking or remediation.
- Automatic retraining.
- New thresholds, risk logic, or classification logic.
- Zeek system configuration changes.
- Grafana, Kafka, or systemd deployment.
- Production packaging.

## Verification Commands

```bash
bash scripts/final_project_check.sh
python3 scripts/post_training_day_audit.py --summary-only
python3 scripts/attack_classifier.py --summary-only
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Evidence export examples:

```bash
python3 scripts/post_training_day_audit.py --summary-only --export-md /tmp/netguard_v10_final_audit.md --export-json /tmp/netguard_v10_final_audit.json
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --export-md /tmp/netguard_v10_final_classification.md --export-json /tmp/netguard_v10_final_classification.json
```

## Release Safety Guarantees

- Read-only by default.
- No data or model changes.
- No retraining.
- No sudo requirement for final verification.
- No `--apply`.
- No firewall or iptables changes.
- No service or system file changes.
- Export only when explicitly requested to safe paths.

## Known limitations

- Full traffic visibility requires Gateway mode or SPAN/Mirror deployment.
- Attack labels are preliminary and require analyst review.
- Local dashboard is not a full monitoring platform.
- Long-term storage and alerting are future work.
- Baseline retraining requires reviewed clean data.

## Future roadmap

- Sensor/SPAN deployment.
- Gateway deployment hardening.
- Historical storage.
- Grafana monitoring.
- Alerting.
- Multi-sensor architecture.
- Kafka streaming pipeline.
- ML attack classifier after reviewed labels.
- Product packaging.

## v10.1 Post-Baseline Dashboard Note

v10.1 is a post-baseline demo/dashboard polish release. It adds a professional
local dashboard presentation layer for readiness, audit recommendation, and
saved Attack Classification evidence visibility. It is not a replacement for
the v10.0 final graduation baseline and does not change detection logic, risk
scoring, models, thresholds, training, Zeek configuration, firewall behavior,
services, or deployment.
