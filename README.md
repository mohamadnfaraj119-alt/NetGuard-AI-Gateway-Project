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

## Philosophy

- Risk Score — not binary decision  
- Behavioral baseline — not generic datasets  
- Explainable alerts — not black box
