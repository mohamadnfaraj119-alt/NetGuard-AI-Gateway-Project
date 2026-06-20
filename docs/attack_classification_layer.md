# Attack Classification Layer

## Goal

`scripts/attack_classifier.py` adds an explainable rule-based layer on top of
existing NetGuard-AI risk reports. It helps analysts review suspicious windows
by assigning preliminary attack or behavior labels, confidence scores, and
reasons.

## Inputs

- `models/anomaly/baseline_stats.json` for the current training timestamp.
- `data/reports/risk_YYYY-MM-DD.csv` for existing risk report windows.

The script is read-only by default and does not modify data or models.

## Output Fields

Each classified event includes:

- `time`
- `src_ip`
- `attack_type`
- `confidence`
- `risk_score`
- `anomaly_score`
- `connections_30s`
- `failed_conn_rate_30s`
- `dns_rate_30s`
- `reasons`

## Classification Labels

- `PORT_SCAN`
- `SSH_BRUTE_FORCE_OR_LOGIN_PATTERN`
- `DNS_ANOMALY`
- `DOS_LIKE_BURST`
- `BOT_LIKE_BEHAVIOR`
- `UNKNOWN_SUSPICIOUS`
- `LOW_SIGNAL_REVIEW`

## Confidence And Reasons

Confidence is conservative and ranges from 0.0 to 1.0. Strong multi-signal
matches receive higher confidence; weak or ambiguous signals receive lower
confidence. Reasons list the signals that triggered the classification.

## Limitations

The labels are preliminary and do not represent guaranteed ground truth. Missing
columns are skipped gracefully, so classifications depend on the available risk
report fields.

## Safety Model

- Read-only by default.
- Optional Markdown/JSON export only when explicitly requested.
- Export paths are limited to `/tmp/` and `reports/audit_exports/`.
- No data changes.
- No model changes.
- No retraining.
- No firewall, service, Grafana, or systemd changes.

## Future ML Classifier Path

A future supervised classifier could be trained on reviewed labels, but the
current layer deliberately stays rule-based and explainable for final-project
review.
