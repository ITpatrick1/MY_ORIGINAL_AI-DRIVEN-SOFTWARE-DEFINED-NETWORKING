#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Tumba College SDN — Full Stack Startup
#  Starts all services in the correct order.
#  Usage:  sudo ./run.sh
# ─────────────────────────────────────────────────────────────────────────────

PROJECT="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$PROJECT"

RYU_MGR=/home/patrick/sdn-env/bin/ryu-manager
PYTHON=/home/patrick/sdn-env/bin/python3
PYTHON_SYS=python3   # system python3 has mininet in /usr/lib/python3/dist-packages
LOGS=/tmp/tumba-sdn-logs
mkdir -p "$LOGS"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ── 0. Clean previous run ────────────────────────────────────────────────────
info "Cleaning previous Mininet state..."
mn --clean 2>/dev/null | tail -1
for port in 6653 9090 9091 9093 9095 9096 9097 9098 9099; do fuser -k ${port}/tcp 2>/dev/null; done
pkill -f "ryu-manager" 2>/dev/null
pkill -f "tumba_topo.py" 2>/dev/null
pkill -f "pc_activity_manager.py" 2>/dev/null
pkill -f "timetable_engine.py" 2>/dev/null
pkill -f "auto_traffic.py" 2>/dev/null
pkill -f "marl_security_agent.py" 2>/dev/null
pkill -f "ibn_engine.py" 2>/dev/null
pkill -f "data_mining.py" 2>/dev/null
sleep 2

# ── 1. Ryu SDN Controller ───────────────────────────────────────────────────
info "Starting Ryu SDN Controller (port 6653)..."
nohup "$RYU_MGR" --ofp-tcp-listen-port 6653 \
    "$PROJECT/tumba_sdn/controller/main_controller.py" \
    > "$LOGS/ryu.log" 2>&1 &
sleep 5
if ss -tlnp | grep -q ':6653'; then ok "Ryu controller running"; else fail "Ryu failed — see $LOGS/ryu.log"; fi

# ── 2. Mininet Topology ──────────────────────────────────────────────────────
info "Starting Mininet topology (cs1→ds1/ds2→as1-as4, 24 hosts)..."
nohup "$PYTHON_SYS" "$PROJECT/tumba_sdn/topology/tumba_topo.py" \
    --no-cli --controller-ip 127.0.0.1 --controller-port 6653 --api-port 9091 \
    > "$LOGS/topology.log" 2>&1 &
sleep 8
if ss -tlnp | grep -q ':9091'; then ok "Topology API running (port 9091)"; else fail "Topology failed — see $LOGS/topology.log"; fi

# ── 3. Timetable Engine ──────────────────────────────────────────────────────
info "Starting Timetable Engine (port 9096)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/timetable/timetable_engine.py" \
    --db /tmp/campus_timetable.db \
    --state-file /tmp/campus_timetable_state.json --port 9096 \
    > "$LOGS/timetable.log" 2>&1 &
sleep 2

# ── 4. PC Activity Manager ───────────────────────────────────────────────────
info "Starting PC Activity Manager (port 9095)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/simulation/pc_activity_manager.py" \
    > "$LOGS/pcam.log" 2>&1 &
sleep 3
if ss -tlnp | grep -q ':9095'; then ok "PC Activity Manager running (port 9095)"; else fail "PCAM failed — see $LOGS/pcam.log"; fi

# ── 4b. Autonomous Traffic Engine ────────────────────────────────────────────
info "Starting Autonomous Traffic Engine (port 9097)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/simulation/auto_traffic.py" \
    > "$LOGS/auto_traffic.log" 2>&1 &
sleep 2
if ss -tlnp | grep -q ':9097'; then ok "Auto Traffic Engine running (port 9097)"; else fail "AutoTraffic failed — see $LOGS/auto_traffic.log"; fi

# ── 5. ML Action Stub (DQN Traffic Agent) ───────────────────────────────────
info "Starting ML action stub (DQN Traffic Agent)..."
nohup "$PYTHON" "$PROJECT/scripts/ml_stub.py" > "$LOGS/ml_stub.log" 2>&1 &
sleep 1

# ── 5b. MARL Security Agent ──────────────────────────────────────────────────
info "Starting MARL Security Agent (port — file-based)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/ml/marl_security_agent.py" \
    > "$LOGS/marl_security.log" 2>&1 &
sleep 1
ok "MARL Security Agent started (output: /tmp/campus_security_action.json)"

# ── 5c. IBN Engine ───────────────────────────────────────────────────────────
info "Starting IBN (Intent-Based Networking) Engine (port 9098)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/controller/ibn_engine.py" --port 9098 \
    > "$LOGS/ibn_engine.log" 2>&1 &
sleep 2
if ss -tlnp | grep -q ':9098'; then ok "IBN Engine running (port 9098)"; else fail "IBN Engine failed — see $LOGS/ibn_engine.log"; fi

# ── 5d. Data Mining Engine ───────────────────────────────────────────────────
info "Starting Data Mining Engine (port 9099)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/ml/data_mining.py" --port 9099 \
    > "$LOGS/data_mining.log" 2>&1 &
sleep 2
if ss -tlnp | grep -q ':9099'; then ok "Data Mining Engine running (port 9099)"; else fail "Data Mining failed — see $LOGS/data_mining.log"; fi

# ── 6. Web Dashboard ─────────────────────────────────────────────────────────
info "Starting Web Dashboard (port 9090)..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/dashboard/app.py" --port 9090 \
    > "$LOGS/dashboard.log" 2>&1 &
sleep 3
if ss -tlnp | grep -q ':9090'; then ok "Dashboard running at http://localhost:9090"; else fail "Dashboard failed — see $LOGS/dashboard.log"; fi

echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Tumba College SDN Stack — RUNNING"
echo "  Dashboard:      http://localhost:9090"
echo "  Topology API:   http://localhost:9091"
echo "  PCAM API:       http://localhost:9095"
echo "  AutoTraffic:    http://localhost:9097"
echo "  IBN Engine:     http://localhost:9098"
echo "  Data Mining:    http://localhost:9099"
echo ""
echo "  New Tabs:       Intelligence | IBN Control"
echo "  Logs:           $LOGS/"
echo "────────────────────────────────────────────────────────────"
 