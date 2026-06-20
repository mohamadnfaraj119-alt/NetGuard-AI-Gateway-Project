# Final Operational Workflow

This workflow keeps the NetGuard-AI Gateway demo and audit process explicit,
local, and safe.

## Dashboard Readiness

Start the dashboard manually:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Run the smoke test after the dashboard is running:

```bash
python3 scripts/gateway_status_smoke_test.py
```

## Audit Review

Run the post-training audit summary:

```bash
python3 scripts/post_training_day_audit.py --summary-only
```

Run the attack classification summary:

```bash
python3 scripts/attack_classifier.py --summary-only
```

Export report evidence when needed:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only --export-md reports/audit_exports/post_training_audit_summary.md --export-json reports/audit_exports/post_training_audit_summary.json
```

Export classification evidence when needed:

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --export-md reports/audit_exports/attack_classification.md --export-json reports/audit_exports/attack_classification.json
```

Do not retrain if suspicious validation days are present. Suggested labels and
recommendations are preliminary and never automatically approve retraining.
Attack classification labels are also preliminary and intended for analyst
review, not automatic retraining approval.

## Final Verification

Run:

```bash
bash scripts/final_project_check.sh
```

Grafana and systemd remain future or optional layers, not part of the current
final-project verification workflow.
