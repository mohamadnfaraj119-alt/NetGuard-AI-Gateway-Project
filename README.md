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

## Philosophy

- Risk Score — not binary decision  
- Behavioral baseline — not generic datasets  
- Explainable alerts — not black box
