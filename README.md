# NetGuard-AI 🛡️
> AI-powered Network Intrusion Detection System

## Overview
Real-time network intrusion detection system using Zeek for packet capture
and Machine Learning for threat classification.

## Architecture
Network Traffic
↓
Zeek 8.x (Feature Extraction)
↓
Python ML Pipeline
↓
Threat Classification

## Tech Stack
- **Capture:** Zeek 8.0.5
- **ML:** Scikit-learn, XGBoost, TensorFlow
- **Pipeline:** Python, Pandas, NumPy
- **Storage:** Kafka, Elasticsearch (coming soon)
- **Dashboard:** Grafana (coming soon)

## Project Status
- [x] Zeek Setup & Configuration
- [x] Data Collection Pipeline
- [x] Feature Extraction (32 features)
- [ ] Attack Data Collection
- [ ] ML Model Training
- [ ] Real-time Detection
- [ ] Dashboard

## Features Extracted
| Category | Features |
|----------|----------|
| Basic | duration, bytes, packets |
| Derived | ratios, avg sizes |
| Protocol | tcp, udp, icmp |
| Port | http, https, dns, ssh |
| Time | hour, day, is_night |
| Direction | is_external |

## Setup
```bash
# Clone
git clone https://github.com/username/NetGuard-AI.git

# Environment
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run Collector
python scripts/collector.py
```

## Author
Manhal
