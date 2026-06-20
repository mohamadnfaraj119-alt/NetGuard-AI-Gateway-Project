# Audit Operator Workflow

Use `scripts/post_training_day_audit.py` to review post-training risk reports
without changing data, models, services, firewall rules, or system state.

## Common Commands

Audit all post-training days:

```bash
python3 scripts/post_training_day_audit.py
```

Audit one suspicious day:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20
```

Audit an inclusive range:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20
```

Use summary-only mode for quick review:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only
```

Show fewer or more investigation rows:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20 --top 3
```

`--top` controls both `top_suspicious_windows` and `suspicious_ip_summary` and
accepts values from 1 to 20.

## Review Rule

Suggested labels are preliminary. Never retrain automatically from suggested
labels, label summaries, or retraining recommendations. Manual review is always
required before retraining.
