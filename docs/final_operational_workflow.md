# Final Operational Workflow

This is the final v10.0 operating workflow for demo, review, and submission,
with the v10.1 Professional Demo Dashboard used as the supervisor-facing
presentation layer. It keeps all actions explicit, local, and read-only unless an operator
explicitly exports evidence to a safe path.

## 1. Verify Repository Status

```bash
git status
```

Expected success marker: no unexpected modified files before the demo.

## 2. Run Final Project Check

```bash
bash scripts/final_project_check.sh
```

Expected success marker:

```text
[RESULT] FINAL PROJECT CHECK PASSED
```

If the status server is not running, the check skips the smoke test and prints
how to start the dashboard manually. That skip is expected for a cold terminal.

## 3. Run Post-Training Audit Summary

```bash
python3 scripts/post_training_day_audit.py --summary-only
```

Screenshot: label summary and retraining recommendation.

## 4. Export Audit Evidence

```bash
python3 scripts/post_training_day_audit.py --summary-only --export-md /tmp/netguard_final_audit.md --export-json /tmp/netguard_final_audit.json
```

Expected success markers:

```text
Exported Markdown: /tmp/netguard_final_audit.md
Exported JSON: /tmp/netguard_final_audit.json
```

## 5. Run Attack Classification Summary

```bash
python3 scripts/attack_classifier.py --summary-only
```

Screenshot: Attack Classification Summary, High Confidence Summary, and Likely
Actionable Events.

## 6. Run Focused Classification Example

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Screenshot: top classified events with confidence and reasons.

## 7. Optional Trusted/Admin IP Example

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --trusted-admin-ip 192.168.1.104
```

Use `--trusted-admin-ip` only for known management machine IPs. It does not
hide evidence and should not be used to suppress real attacks.

## 8. Start Local Dashboard

```bash
bash scripts/run_gateway_dashboard.sh
```

Then open:

```text
http://127.0.0.1:8787/
```

Screenshot: live dashboard status and demo mode views.

For v10.1, capture the Professional Demo Dashboard overview, gateway readiness
cards, Attack Classification summary, audit/retraining recommendation panel,
top classified events table, and demo mode panel.

## 9. Run Smoke Test In Another Terminal

```bash
python3 scripts/gateway_status_smoke_test.py
```

Expected success marker: all smoke test checks pass. If the status server is
not running, start it first with `bash scripts/run_gateway_dashboard.sh`.

## 10. Stop Dashboard

Use:

```text
Ctrl+C
```

## v10.1 Dashboard Workflow

1. Start the dashboard with `bash scripts/run_gateway_dashboard.sh`.
2. Open `http://127.0.0.1:8787/`.
3. Capture the overview, readiness cards, classification summary, audit panel,
   top events table, and demo mode states.
4. Run `python3 scripts/gateway_status_smoke_test.py`.
5. Stop the dashboard with `Ctrl+C`.

## Demo Screenshot Checklist

- `git status` clean.
- Final project check passed.
- Post-training audit summary.
- Attack classification summary.
- Focused classification event details.
- Dashboard live status.
- Professional dashboard overview.
- Gateway readiness cards.
- Attack classification summary.
- Audit/retraining recommendation.
- Demo mode panel.
- Dashboard Demo OK, Demo WARN, and Demo FAIL states.
- Smoke test passed.
- Evidence export success lines.

## Final Safety Reminders

- No sudo for final demo commands.
- No `--apply`.
- No retraining.
- No data or model changes.
- No firewall, iptables, service, or system changes.
- Grafana, Kafka, and systemd are future work, not the v10.0 baseline.
