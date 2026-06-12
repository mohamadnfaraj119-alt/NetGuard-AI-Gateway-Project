# NetGuard-AI Gateway Live Testing Protocol

Purpose: validate real detection behavior before adding more models or alerting
infrastructure. Run only inside the owned home lab.

## Scope

- Gateway: `192.168.1.1`
- LAN devices: `192.168.1.100-200`
- Zeek interface: `enx00e04c6817c4`
- Tests should be run from one known LAN client whenever possible.
- Do not run scans against public IPs or third-party networks.

## Success Metrics

- Detection latency: time from test start to risk/state output.
- Recall: whether the intended behavior is visible in `risk_engine.py` or `state_tracker.py`.
- False positive impact: whether unrelated LAN devices stay normal.
- Explainability: alert must name the dominant reason: scan, brute force, DNS, burst, or anomaly.
- Evidence: save commands, timestamps, resulting rows, and risk reports.

## Preflight

Run on Ubuntu:

```bash
cd ~/zeek-ids
source venv/bin/activate

sudo systemctl status zeek --no-pager
sudo systemctl status netguard-collector --no-pager
tail -20 logs/collector.log

python scripts/integrity.py --days 1
python scripts/window_engine.py
python scripts/risk_engine.py 2>/dev/null | grep -v '🟢' || true
python scripts/state_tracker.py --analyze
```

Record:

- Date and time
- Tester source IP
- Target IP
- Current non-green alerts before testing

## Test 1: TCP Port Scan

From an authorized LAN test client:

```bash
nmap -sT -Pn -p 1-1024 192.168.1.1
```

Then on Ubuntu:

```bash
cd ~/zeek-ids && source venv/bin/activate
python scripts/window_engine.py
python scripts/risk_engine.py 2>/dev/null | grep -v '🟢' || true
python scripts/state_tracker.py --analyze
```

Expected:

- `flag_port_scan` or scan component increases for tester IP.
- Risk explanation mentions ports/scan.
- Other LAN IPs should not become alerts.

## Test 2: Aggressive Scan

From an authorized LAN test client:

```bash
nmap -A -T3 -Pn 192.168.1.1
```

Then rerun the pipeline commands from Test 1.

Expected:

- Higher scan or anomaly component than Test 1.
- If Zeek misses very short SYN/RST activity, document the blind spot.

## Test 3: Controlled SSH Failure Burst

Use a non-sensitive test account name and a tiny local wordlist. Keep the rate low
enough not to damage the gateway.

From an authorized LAN test client:

```bash
for i in $(seq 1 25); do
  ssh -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=2 \
      fakeuser@192.168.1.1 true
done
```

Then rerun the pipeline commands from Test 1.

Expected:

- `state_tracker.py` should show victim-centric SSH failures if Zeek records them.
- If Zeek records `OTH` or misses the short attempts, document it as a sensor limit.
- `risk_engine.py` may not alert unless the window features also cross thresholds.

## Test 4: DNS Burst

From an authorized LAN test client:

```bash
for i in $(seq 1 150); do
  nslookup "netguard-test-$i.example.com" 8.8.8.8 >/dev/null 2>&1
done
```

Then rerun the pipeline commands from Test 1.

Expected:

- DNS component increases for tester IP.
- Android devices should not be confused with the tester.

## Evidence Template

Create one report per session under `data/reports/live_tests/`:

```text
date:
tester_ip:
target_ip:
test_name:
command:
start_time:
end_time:

risk_engine_result:
state_tracker_result:
relevant_window_rows:

expected:
actual:
verdict: pass | partial | fail
notes:
```

## Tuning Rules

- Do not tune thresholds after one test. Require at least one benign comparison.
- Keep per-IP thresholding enabled.
- Keep `external_score = 0.0` for the NAT home network.
- If a test is missed, decide whether it is a sensor limit, feature issue, or scoring issue.
- Update this protocol when a new blind spot is found.
