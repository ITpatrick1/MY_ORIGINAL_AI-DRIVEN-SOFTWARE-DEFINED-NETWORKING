#!/bin/bash
# Tumba College SDN stop script with stale-process verification

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; }

PORTS=(6653 9090 9091 9095 9096 9097 9098 9099 9100 9101)
PROCS=(
  "ryu-manager"
  "tumba_topo.py"
  "timetable_engine.py"
  "pc_activity_manager.py"
  "auto_traffic.py"
  "ml_stub.py"
  "marl_security_agent.py"
  "ibn_engine.py"
  "data_mining.py"
  "proactive_congestion.py"
  "realtime_dataset_collector.py"
  "dashboard/app.py"
)

info "Stopping all Tumba SDN services..."

for proc in "${PROCS[@]}"; do
  pkill -f "$proc" >/dev/null 2>&1 && ok "Stopped $proc" || true
done

for port in "${PORTS[@]}"; do
  fuser -k "${port}/tcp" >/dev/null 2>&1 || true
done

sleep 2

info "Cleaning Mininet state..."
mn --clean >/dev/null 2>&1 || true

stale=0
for port in "${PORTS[@]}"; do
  if ss -tln "( sport = :$port )" | grep -q ":$port"; then
    fail "Port $port still listening"
    stale=1
  fi
done

for proc in "${PROCS[@]}"; do
  if pgrep -f "$proc" >/dev/null 2>&1; then
    fail "Process still running: $proc"
    stale=1
  fi
done

if [ "$stale" -eq 0 ]; then
  ok "All services stopped cleanly. No stale processes remain."
  exit 0
fi

fail "Stop verification found stale services."
exit 1
