# NetGuard-AI Gateway

> Network Intrusion Detection System — Gateway Mode  
> Monitors all home network traffic via Ubuntu NAT Gateway

## Architecture
Internet
↓
Main Router (192.168.68.55)
↓
Ubuntu Gateway (192.168.68.13)
├── Zeek 8.2.0        — Traffic capture
├── collector.py      — Parse + filter + store
├── window_engine.py  — Behavioral features
├── anomaly_model.py  — Isolation Forest
├── signature_model.py— XGBoost
└── risk_engine.py    — Risk Score 0-100
↓
TP-Link Access Point
↓
Home Devices (192.168.1.x)

## Stack

| Component | Version |
|-----------|---------|
| Ubuntu    | 24.04   |
| Zeek      | 8.2.0   |
| Python    | 3.x     |
| XGBoost   | latest  |

## Final Graduation Baseline — v10.0

v10.0 freezes NetGuard-AI Gateway as a stable graduation-ready baseline. It
documents the completed local gateway readiness, audit, evidence export, and
explainable attack classification workflow without adding new risky runtime
features.

Key verification commands:

```bash
bash scripts/final_project_check.sh
python3 scripts/post_training_day_audit.py --summary-only
python3 scripts/attack_classifier.py --summary-only
bash scripts/run_gateway_dashboard.sh
```

Final baseline references:

- `docs/final_graduation_baseline.md`
- `docs/final_operational_workflow.md`
- `docs/final_demo_script.md`
- `docs/final_release_notes_v10.md`

## Professional Demo Dashboard — v10.1

v10.1 adds a supervisor-ready local dashboard layer on top of the stable v10.0
baseline. It improves the visual presentation of gateway readiness, audit
status, retraining recommendation, attack classification summary, top classified
events, and demo mode states without changing detection logic, models,
thresholds, or risk scoring.

Run locally:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Optional smoke test while the dashboard is running:

```bash
python3 scripts/gateway_status_smoke_test.py
```

The dashboard is local-only/read-only and does not replace the detection
pipeline. It presents readiness and saved evidence snapshots for review.

## Professional SOC Dashboard — v10.2

v10.2 redesigns the local dashboard as a Professional SOC dashboard inspired by
the selected Google Stitch cybersecurity reference. It adds a premium dark
sidebar layout, SOC metric cards, active inference pipeline, threat
classification summary, recent classified events table, post-training audit
panel, gateway readiness panel, network topology card, evidence cards, and
future productization panel.

This dashboard update is presentation-only. It remains local-only, read-only,
offline-capable, browser-native HTML/CSS/JS, and does not change detection
logic, risk scoring, models, thresholds, training, Zeek configuration,
firewall, services, or data.

v10.2.2 polishes the SOC dashboard navigation into four stable supervisor-demo
sections: Overview, Threats, Audit & Evidence, and Gateway & Roadmap. Sidebar
clicks switch panels without scroll jumps.

v10.2.3 confirms the dashboard remains a single local `dashboard/index.html`
page with button-driven in-page panel switching and no separate dashboard page
navigation.

v10.2.4 enforces that same true single-page behavior with strict sidebar button
targets, in-DOM dashboard panels, and no hash, scroll, reload, or page-link
navigation.

v10.2.5 converts the SOC dashboard from tab-style section switching to a
unified one-page layout where Overview, Threats, Audit & Evidence, and Gateway
& Roadmap are visible together for supervisor review.

## Quick Start

```bash
# 1. تحقق من Zeek
sudo /opt/zeek/bin/zeekctl status

# 2. شغّل collector
cd ~/zeek-ids && source venv/bin/activate
nohup python -u scripts/collector.py > logs/collector.log 2>&1 &
echo $! > logs/collector.pid

# 3. Pipeline يومي
python scripts/window_engine.py
python scripts/risk_engine.py 2>/dev/null | grep -v "🟢"
python scripts/state_tracker.py --analyze
```

## Detection Layers

| Layer | Model | Purpose |
|-------|-------|---------|
| Behavioral | Isolation Forest | Anomaly detection |
| Signature  | XGBoost 99.49%  | Attack classification |
| Risk Engine| Weighted Score  | 0-100 risk score |

## v7.6 WAN Monitor Milestone

Verified on branch `v7.6-self-adaptive-gateway` at stable tag
`v7.6-wan-monitor-stable`.

- WAN monitor reads live kernel logs with
  `journalctl -k -f -o cat -n 0`.
- Added iptables LOG rule helper: `scripts/wan_iptables_rule.py`.
- Helper supports safe `--status`, `--print`, `--install`, and `--remove`
  modes, runs as dry-run by default, and requires `--apply` for real changes.
- Helper is idempotent and does not duplicate the `NETGUARD_WAN` LOG rule.
- Installed and enabled systemd service: `netguard-wan-monitor.service`.
- Service uses `ExecStartPre` to install the LOG rule on start and reboot.
- Reboot test passed.
- Final scan test after reboot generated a `wan_port_scan` alert.

Verified alert fields:

| Field | Value |
|-------|-------|
| source | `wan_log_monitor` |
| input_interface | `enp0s31f6` |
| src_ip | `192.168.68.2` |
| dst_ip | `192.168.68.13` |
| unique_dst_ports | `25` |
| window_seconds | `30` |
| severity | `high` |
| risk_score | `90.0` |

## v7.7 Self-Adaptive Thresholds Milestone

- v7.7 adds config-driven WAN monitor thresholds.
- `wan_log_monitor.py` now reads `max_unique_dst_ports_30s` from
  `config/thresholds_profile.json`.
- Current effective WAN threshold is 5 unique destination ports within 30
  seconds.
- `threshold_profile_builder.py` builds `config/thresholds_profile.json` from
  `data/baselines/ip_baselines.json`.
- For v1, the builder uses only `global_baseline` and intentionally ignores
  per-IP baselines because per-IP baselines may contain scan/test outliers.
- Builder is safe by default: dry-run unless `--apply` is passed.
- `--apply` backs up the existing thresholds profile before writing.
- Verified test: scan of ports `11000..11004` generated `wan_port_scan` with
  `unique_dst_ports=5`.

## v7.8 Portable Gateway Doctor

- New script: `scripts/gateway_doctor.py`.
- Purpose: read-only gateway readiness checker.
- Checks `network_profile`, default route, WAN interface, LAN interface, IP
  forwarding, NAT readiness, Zeek monitored interface, and systemd services.
- Usage:

```bash
python3 scripts/gateway_doctor.py
sudo python3 scripts/gateway_doctor.py
```

`sudo` is only needed when the host requires root privileges to read NAT table
status. `--apply` is intentionally blocked and applies no changes.

## v7.9 Gateway Status API + Minimal Dashboard

- `scripts/gateway_doctor.py --json` provides structured read-only gateway
  readiness output for API/dashboard use.
- `scripts/gateway_status_server.py` serves a local read-only status API and
  dashboard using Python standard library only.
- `dashboard/index.html` is the minimal browser dashboard.

Run locally:

```bash
python3 scripts/gateway_status_server.py --host 127.0.0.1 --port 8787
```

Dashboard:

```text
http://127.0.0.1:8787/
```

API test:

```bash
curl http://127.0.0.1:8787/api/status
```

Health check:

```bash
curl http://127.0.0.1:8787/healthz
```

Safety notes:

- Read-only status view.
- No system changes.
- No auto-fix behavior.
- No POST, PUT, or DELETE actions.
- `--apply` remains protected and not implemented.

## v8.0 Professional Gateway Dashboard

- `dashboard/index.html` is now a professional Gateway Control / Readiness
  Dashboard.
- The dashboard shows gateway readiness, failure and warning counts, total
  checks, and grouped OK/WARN/FAIL readiness details.
- Live mode reads from `/api/status`.
- Demo OK, Demo WARN, and Demo FAIL modes use local in-browser mock JSON only.
- The dashboard does not provide remediation actions, auto-fix controls, or
  backend write actions.

## v8.1 Dashboard Runtime Polish

Start the local read-only dashboard server:

```bash
python3 scripts/gateway_status_server.py --host 127.0.0.1 --port 8787
```

Open the dashboard:

```text
http://127.0.0.1:8787/
```

Run the same checks from the terminal:

```bash
python3 scripts/gateway_doctor.py
python3 scripts/gateway_doctor.py --json
```

API smoke tests:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/api/status
curl -I http://127.0.0.1:8787/
curl -i -X POST http://127.0.0.1:8787/api/status
```

Expected results:

- `/healthz` returns `{"status": "ok"}`.
- `/api/status` returns the structured gateway doctor JSON.
- `/` returns the dashboard HTML.
- `POST /api/status` returns `405 Method Not Allowed`.

## v8.2 Runtime Smoke Tests

The smoke test is local, read-only, and assumes the status server is already
running.

Start the local status server:

```bash
python3 scripts/gateway_status_server.py --host 127.0.0.1 --port 8787
```

Run the smoke test:

```bash
python3 scripts/gateway_status_smoke_test.py
```

Optional custom base URL:

```bash
python3 scripts/gateway_status_smoke_test.py --base-url http://127.0.0.1:8787
```

The smoke test checks:

- `GET /healthz`
- `GET /api/status`
- `GET /`
- `POST /api/status` returns `405 Method Not Allowed`

Expected success output:

```text
[RESULT] SMOKE TEST PASSED
```

Failure usually means the server is not running, the port or base URL is wrong,
the dashboard endpoint is not reachable, or the API JSON contract changed
unexpectedly.

Safety:

- Read-only.
- Does not call `--apply`.
- No firewall changes.
- No iptables changes.
- No service changes.

Troubleshooting:

- `Address already in use`: another process is already listening on the chosen
  port. Stop that process or run the server on another local port, for example
  `--port 8788`.
- `NAT readiness unknown`: this can happen when iptables NAT table inspection
  requires root permissions. The dashboard and API remain read-only; run
  `sudo python3 scripts/gateway_doctor.py` only when you want a manual local
  readiness check with permission to inspect NAT state.
- Dashboard shows demo data: select `Live` mode to read from `/api/status`.
  Demo modes are browser-only mock states for testing the interface.

Dashboard scope:

- Current dashboard: local gateway readiness and operational status.
- Future Grafana dashboard: monitoring and analytics for time-series charts,
  logs, alert trends, and longer-term observability.
- Grafana is not part of v8.1.

Screenshot notes:

- Start the local dashboard server.
- Open `http://127.0.0.1:8787/`.
- Capture Live, Demo OK, Demo WARN, and Demo FAIL states if release screenshots
  are needed.

## v8.7 Local Dashboard Run Helper

`scripts/run_gateway_dashboard.sh` starts the local read-only dashboard helper.
It binds only to `127.0.0.1` and starts `scripts/gateway_status_server.py`.

Default usage:

```bash
bash scripts/run_gateway_dashboard.sh
```

Custom port:

```bash
bash scripts/run_gateway_dashboard.sh 8788
```

Dashboard URL:

```text
http://127.0.0.1:8787/
```

Safety:

- No sudo.
- No `--apply`.
- No firewall changes.
- No iptables changes.
- No service changes.
- No data or model changes.
- No Grafana.
- No systemd.

## v8.8 Operator Quick Start

Start the local dashboard:

```bash
bash scripts/run_gateway_dashboard.sh
```

Open:

```text
http://127.0.0.1:8787/
```

Health check:

```bash
curl http://127.0.0.1:8787/healthz
```

Smoke test:

```bash
python3 scripts/gateway_status_smoke_test.py
```

Stop the server:

```text
Ctrl + C
```

Safety notes:

- Localhost only.
- Read-only.
- No sudo.
- No `--apply`.
- No firewall or iptables changes.
- No service changes.
- No data or model changes.
- No Grafana.
- No systemd.

## v8.9 Demo / Presentation Notes

Recommended demo flow:

1. Start the dashboard:

```bash
bash scripts/run_gateway_dashboard.sh
```

2. Open:

```text
http://127.0.0.1:8787/
```

3. Show Live status first.

4. Show demo modes: Demo OK, Demo WARN, and Demo FAIL.

5. Run the smoke test:

```bash
python3 scripts/gateway_status_smoke_test.py
```

6. Explain the safety model:

- Read-only dashboard.
- Localhost only.
- No sudo.
- No `--apply`.
- No firewall, iptables, or service changes.
- No data or model changes.
- No systemd.

7. Explain that Grafana is a future monitoring and analytics layer, not part of
   the current local gateway readiness dashboard.

## v9.7 Post-Training Day Audit

`scripts/post_training_day_audit.py` audits days collected after the current
model training date before considering retraining. It is read-only and uses
existing risk reports, windows files, and baseline training metadata.

Default audit for all post-training days:

```bash
python3 scripts/post_training_day_audit.py
```

Audit one date:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20
```

Audit an inclusive date range:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20
```

Limit detailed rows in `top_suspicious_windows` and `suspicious_ip_summary`:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20 --top 3
```

Show only the per-day summary, review notes, final label summary, and retraining
recommendation:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only
```

Export Markdown evidence:

```bash
python3 scripts/post_training_day_audit.py --from 2026-06-18 --to 2026-06-20 --summary-only --export-md reports/audit_exports/post_training_audit_summary.md
```

Export JSON evidence:

```bash
python3 scripts/post_training_day_audit.py --date 2026-06-20 --top 3 --export-json reports/audit_exports/audit_2026-06-20.json
```

Exports are optional and never run by default. Export paths are accepted only
under `/tmp/` or `reports/audit_exports/`; unsafe paths are rejected before any
file is created.

The audit outputs coverage hours, row counts, max risk score, suspicious
indicator counts, preliminary labels, top suspicious windows, suspicious IP
summaries, a final `Label Summary`, and a conservative `Retraining
Recommendation`.

Labels:

- `CANDIDATE_CLEAN`: appears usable for future review, but is not automatically
  approved.
- `PARTIAL_CANDIDATE_CLEAN`: partial day; needs more coverage and review.
- `SUSPICIOUS_VALIDATION`: useful for validation and testing, not clean
  baseline retraining.
- `INCOMPLETE`: missing or insufficient data.

Important: suggested labels are preliminary and do not automatically approve
retraining. The retraining recommendation is conservative and still requires
manual review.

Safety:

- Read-only.
- Python standard library only.
- No data changes.
- No model changes.
- No retraining.
- No sudo.
- No `--apply`.
- No firewall or iptables changes.
- No service changes.
- No Grafana.
- No systemd.

## v9.8 Attack Classification Layer

`scripts/attack_classifier.py` reads existing risk reports and adds an
explainable, rule-based classification layer for analyst review. It labels
suspicious windows with preliminary attack types, confidence scores, and
reasons. These labels are not guaranteed ground truth and must not approve
baseline retraining automatically.

Default classification for all post-training days:

```bash
python3 scripts/attack_classifier.py
```

Summary only:

```bash
python3 scripts/attack_classifier.py --summary-only
```

Classify one date:

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5
```

Classify an inclusive range:

```bash
python3 scripts/attack_classifier.py --from 2026-06-18 --to 2026-06-20
```

Export evidence:

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --export-md /tmp/classification.md --export-json /tmp/classification.json
```

`--top` accepts 1 to 50 and controls detailed classified events. Export paths
are accepted only under `/tmp/` or `reports/audit_exports/`.

Classification labels:

- `PORT_SCAN`
- `SSH_BRUTE_FORCE_OR_LOGIN_PATTERN`
- `FAILED_CONNECTION_PATTERN`
- `DNS_ANOMALY`
- `DOS_LIKE_BURST`
- `BOT_LIKE_BEHAVIOR`
- `UNKNOWN_SUSPICIOUS`
- `LOW_SIGNAL_REVIEW`

v9.9 calibration makes SSH classification stricter: SSH brute-force/login
classification requires explicit SSH evidence such as destination port 22 or
`service=ssh`, plus strong suspicious behavior. Failed-connection behavior
without explicit SSH evidence is classified as `FAILED_CONNECTION_PATTERN`
instead of overclaiming SSH brute force.

Trusted/admin management source IPs can be supplied explicitly:

```bash
python3 scripts/attack_classifier.py --date 2026-06-20 --top 5 --trusted-admin-ip 192.168.1.104
```

Multiple trusted IPs may also be supplied with:

```bash
NETGUARD_TRUSTED_ADMIN_IPS="192.168.1.104,192.168.1.180" python3 scripts/attack_classifier.py --summary-only
```

Trusted IPs are never persisted and never hide evidence. They add an explicit
reason and can reduce overclaiming for management traffic, but strong scan,
DNS, or burst evidence still classifies normally.

Reports now include a `High Confidence Summary` and `Likely Actionable Events`
count. Top classified events prioritize higher-confidence non-low-signal labels
so `LOW_SIGNAL_REVIEW` does not dominate when stronger classifications exist.

## Optional Telegram Alerts

`scripts/telegram_alert_notifier.py` can send Telegram notifications for new
high-confidence live suspicious events from today's risk report. Telegram is
optional; without credentials, normal NetGuard-AI monitoring and dashboard
workflows continue unchanged.

Credentials are read only from environment variables:

```bash
NETGUARD_TELEGRAM_BOT_TOKEN=replace-with-bot-token
NETGUARD_TELEGRAM_CHAT_ID=replace-with-chat-id
```

Setup:

```bash
# 1. Create a bot with @BotFather, then send /start to the bot.
# 2. Get chat_id from:
#    https://api.telegram.org/bot<token>/getUpdates

sudo mkdir -p /etc/netguard-ai
sudo cp config/telegram_alerts.env.example /etc/netguard-ai/telegram-alerts.env
sudo chown root:root /etc/netguard-ai/telegram-alerts.env
sudo chmod 600 /etc/netguard-ai/telegram-alerts.env
sudo editor /etc/netguard-ai/telegram-alerts.env
```

Test and dry run:

```bash
python3 scripts/telegram_alert_notifier.py --test
python3 scripts/telegram_alert_notifier.py --once --dry-run
```

Continuous local run:

```bash
python3 scripts/telegram_alert_notifier.py --interval 30
```

A systemd unit template is provided at
`systemd/netguard-telegram-alerts.service`. Install and start it only with
explicit administrator commands:

```bash
sudo cp systemd/netguard-telegram-alerts.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netguard-telegram-alerts.service
```

The notifier stores sent-alert fingerprints in
`logs/telegram_alert_state.json` to avoid duplicate alerts after restart. The
bot token is never stored in that state file.

## Final Demo Verification

Run the final project check before demo or submission:

```bash
bash scripts/final_project_check.sh
```

The check is safe and read-only for project state. It reports Git status,
compiles core Python scripts, validates shell syntax, runs the post-training
audit and attack classifier in summary mode, and runs the smoke test only when
the local status server is already reachable. Start the dashboard manually when
needed:

```bash
bash scripts/run_gateway_dashboard.sh
```

Then run:

```bash
python3 scripts/gateway_status_smoke_test.py
```

## Philosophy

- Risk Score — not binary decision  
- Behavioral baseline — not generic datasets  
- Explainable alerts — not black box
