#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -gt 1 ]]; then
  echo "Usage: bash scripts/run_gateway_dashboard.sh [port]"
  echo "Starts the read-only local dashboard on 127.0.0.1."
  exit 0
fi

port="${1:-8787}"

if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "Invalid port: $port" >&2
  echo "Expected a TCP port from 1 to 65535." >&2
  exit 2
fi

echo "Starting NetGuard-AI Gateway Dashboard"
echo "Host: 127.0.0.1"
echo "Port: $port"
echo "Dashboard URL: http://127.0.0.1:$port/"
echo

exec python3 scripts/gateway_status_server.py --host 127.0.0.1 --port "$port"
