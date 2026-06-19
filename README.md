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

## v9.2 Post-Training Day Audit

`scripts/post_training_day_audit.py` audits days collected after the current
model training date before considering retraining.

Run:

```bash
python3 scripts/post_training_day_audit.py
```

It reads existing risk reports, existing windows files, and baseline training
metadata. It outputs coverage hours, row counts, max risk score, suspicious
indicator counts, and a suggested preliminary label.

Labels:

- `CANDIDATE_CLEAN`: appears usable for future review, but is not automatically
  approved.
- `PARTIAL_CANDIDATE_CLEAN`: partial day; needs more coverage and review.
- `SUSPICIOUS_VALIDATION`: useful for validation and testing, not clean
  baseline retraining.
- `INCOMPLETE`: missing or insufficient data.

Important: suggested labels are preliminary and do not automatically approve
retraining.

Safety:

- Read-only.
- No data changes.
- No model changes.
- No retraining.
- No sudo.
- No `--apply`.
- No firewall or iptables changes.
- No service changes.
- No Grafana.
- No systemd.

## Philosophy

- Risk Score — not binary decision  
- Behavioral baseline — not generic datasets  
- Explainable alerts — not black box
