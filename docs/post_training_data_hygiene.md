# Post-Training Data Hygiene Policy

Purpose: define how data collected after a model training run should be
classified before it is ever considered for future retraining.

## Principles

- Data collected after training is useful, but it is not automatically clean
  training data.
- Treat new data as candidate baseline or validation data first.
- Avoid baseline poisoning by keeping suspicious or unreviewed periods out of
  clean training baselines.
- Only approved clean days may be used for future retraining.
- Suspicious days should be kept for validation and testing, not clean baseline
  training.
- Partial days should not be used until complete and reviewed.

## Classification Labels

- `CLEAN`: Full-day data that has been reviewed and approved as suitable for
  clean baseline training.
- `CANDIDATE_CLEAN`: Full or nearly full-day data that currently appears clean
  but still requires explicit review before training use.
- `PARTIAL_CANDIDATE_CLEAN`: Partial-day data that currently appears clean but
  cannot be approved until the day is complete and reviewed.
- `SUSPICIOUS_VALIDATION`: Data containing suspicious activity or unresolved
  risk points. Keep for validation, testing, and detection review only.
- `BAD_OR_TEST`: Data known to include tests, bad captures, intentionally
  generated activity, or invalid conditions. Do not use for clean baseline
  training.
- `INCOMPLETE`: Data with insufficient coverage, missing files, broken
  collection, or an unresolved integrity problem. Do not approve until fixed
  and reviewed.

## Current Post-Training Review

- Model trained at: `2026-06-16 09:38:57`
- Training windows: `145,419`
- `2026-06-17`: `CANDIDATE_CLEAN`. Nearly full coverage and no risk `>= 30`.
  Small review points remain around `02:14` and `21:33`.
- `2026-06-18`: `SUSPICIOUS_VALIDATION`. Not clean baseline data. Includes
  suspicious activity around `01:48` and `15:00-17:39`.
- `2026-06-19`: `PARTIAL_CANDIDATE_CLEAN`. Only partial coverage so far. Risk
  remains low, but the day is not approved yet.

## Recommended Next Steps

- Do not retrain immediately.
- Continue collecting data.
- Re-check full-day coverage before approving any day.
- Review risk reports and alerts before approving any day.
- Later, create a read-only audit script if needed.
