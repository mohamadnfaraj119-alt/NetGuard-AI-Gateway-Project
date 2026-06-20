# Audit Evidence Export

`scripts/post_training_day_audit.py` can optionally export post-training audit
evidence for final reports.

Markdown export:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only --export-md reports/audit_exports/post_training_audit_summary.md
```

JSON export:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20 --top 3 --export-json reports/audit_exports/audit_2026-06-20.json
```

Both can be used together:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20 --top 3 --export-md /tmp/audit.md --export-json /tmp/audit.json
```

Exports are off by default. Paths are accepted only under `/tmp/` or
`reports/audit_exports/`. Unsafe paths are rejected before files are created.

Generated export files are evidence artifacts and should not be committed.
