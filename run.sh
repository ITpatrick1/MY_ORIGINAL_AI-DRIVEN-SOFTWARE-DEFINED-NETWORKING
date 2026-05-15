#!/bin/bash
# Tumba College SDN full-stack startup with health verification

set -u

PROJECT="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$PROJECT"

RYU_MGR=/home/patrick/sdn-env/bin/ryu-manager
PYTHON=/home/patrick/sdn-env/bin/python3
PYTHON_SYS=python3
LOGS=/tmp/tumba-sdn-logs
STATUS_FILE=/tmp/campus_service_status.json
FRONTEND_DIR="$PROJECT/tumba_sdn/dashboard/frontend"
FRONTEND_DIST="$FRONTEND_DIR/dist"
DATASET_ROOT="$PROJECT/datasets"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

mkdir -p "$LOGS"
ln -sf "$LOGS/pc_activity_manager.log" "$LOGS/pcam.log"

bootstrap_state_files() {
  "$PYTHON_SYS" <<'PY'
import json, os
paths = {
    '/tmp/campus_metrics.json': {},
    '/tmp/campus_pc_activities.json': {'ts': 0, 'pcs': {}, 'baseline': {}, 'profiles': {}},
    '/tmp/campus_proactive_congestion.json': {'ts': 0, 'zones': {}, 'recent_alerts': []},
    '/tmp/campus_security_action.json': {'ts': 0, 'action': 'monitor_only', 'controller_action': 'monitor'},
    '/tmp/campus_ml_action.json': {'ts': 0, 'action': 'normal_mode'},
    '/tmp/campus_timetable_state.json': {'ts': 0, 'period': 'off_hours', 'exam_flag': 0},
    '/tmp/campus_auto_traffic_state.json': {'ts': 0, 'paused': False, 'scenario': None},
    '/tmp/campus_topology_state.json': {'ts': 0, 'nodes': [], 'links': []},
    '/tmp/campus_ibn_state.json': {'ts': 0, 'active_intents': []},
    '/tmp/campus_rerouting_state.json': {'ts': 0, 'enabled': True, 'active_reroutes': [], 'status': 'monitoring'},
    '/tmp/campus_autoconfig_state.json': {'ts': 0, 'enabled': True, 'active_policies': {}, 'status': 'monitoring'},
}
for path, payload in paths.items():
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, indent=2)
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass
for path in ('/tmp/campus_service_status.json', '/tmp/campus_timetable.db'):
    if os.path.exists(path):
        try:
            if path.endswith('.db') and os.geteuid() == 0:
                os.chown(path, os.geteuid(), os.getegid())
            os.chmod(path, 0o666 if path.endswith('.db') else 0o644)
        except OSError:
            pass
PY
}

bootstrap_dataset_dirs() {
  mkdir -p "$DATASET_ROOT/realtime" "$DATASET_ROOT/archive" "$DATASET_ROOT/exports" \
           "$DATASET_ROOT/public/CICIDS2017" "$DATASET_ROOT/public/CSE_CIC_IDS2018" \
           "$DATASET_ROOT/public/UNSW_NB15" "$DATASET_ROOT/public/MAWI" \
           "$DATASET_ROOT/processed" "$DATASET_ROOT/models"
  chmod -R a+rX "$DATASET_ROOT" 2>/dev/null || true
  touch "$LOGS/dataset_collector.log"
  touch "$LOGS/rerouting.log" "$LOGS/autoconfig.log"
  chmod 644 "$LOGS/dataset_collector.log" "$LOGS/rerouting.log" "$LOGS/autoconfig.log" 2>/dev/null || true
}

prepare_frontend_build() {
  if [ ! -d "$FRONTEND_DIR" ]; then
    warn "React frontend directory missing: $FRONTEND_DIR"
    return 0
  fi

  local npm_cmd=""
  if command -v npm >/dev/null 2>&1; then
    npm_cmd="$(command -v npm)"
  elif [ -x "$PROJECT/.tools/node/bin/npm" ]; then
    export PATH="$PROJECT/.tools/node/bin:$PATH"
    npm_cmd="$PROJECT/.tools/node/bin/npm"
  fi

  if [ -z "$npm_cmd" ]; then
    if [ -f "$FRONTEND_DIST/index.html" ]; then
      warn "npm not found; using existing React build at $FRONTEND_DIST"
      return 0
    fi
    warn "npm not found and React build missing. Flask will fall back to legacy dashboard until Node/npm is installed."
    return 0
  fi

  if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
    info "Installing React dashboard dependencies..."
    (cd "$FRONTEND_DIR" && "$npm_cmd" install) || {
      warn "Frontend dependency install failed; continuing with existing dist if present"
      return 0
    }
  fi

  if [ ! -f "$FRONTEND_DIST/index.html" ] || \
     find "$FRONTEND_DIR/src" "$FRONTEND_DIR/package.json" "$FRONTEND_DIR/vite.config.ts" -newer "$FRONTEND_DIST/index.html" | grep -q .; then
    info "Building React + TypeScript dashboard..."
    (cd "$FRONTEND_DIR" && "$npm_cmd" run build) || {
      warn "Frontend build failed; continuing with existing dist if present"
      return 0
    }
    ok "React dashboard build ready"
  else
    ok "React dashboard build is up to date"
  fi
}

wait_for_port() {
  local port="$1"
  local timeout="${2:-25}"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if ss -tln "( sport = :$port )" | grep -q ":$port"; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

wait_for_health() {
  local name="$1"
  local url="$2"
  local timeout="${3:-25}"
  local elapsed=0
  while [ "$elapsed" -lt "$timeout" ]; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      ok "$name healthy ($url)"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  fail "$name health check failed ($url)"
  return 1
}

start_service() {
  local name="$1"
  local port="$2"
  local health_url="$3"
  local logfile="$4"
  shift 4

  info "Starting $name..."
  nohup "$@" > "$logfile" 2>&1 &
  sleep 1
  if ! wait_for_port "$port" 90; then
    fail "$name did not bind to port $port"
    tail -n 20 "$logfile" 2>/dev/null || true
    return 1
  fi
  ok "$name listening on port $port"
  if [ -n "$health_url" ]; then
    wait_for_health "$name" "$health_url" 90 || return 1
  fi
  return 0
}

write_status_summary() {
  "$PYTHON_SYS" <<'PY'
import json, os, sys, tempfile, time, urllib.request
services = {
    'ryu_controller': ('http://127.0.0.1:9090/api/health', '/tmp/tumba-sdn-logs/ryu.log'),
    'topology_api': ('http://127.0.0.1:9091/health', '/tmp/tumba-sdn-logs/topology.log'),
    'pc_activity_manager': ('http://127.0.0.1:9095/health', '/tmp/tumba-sdn-logs/pc_activity_manager.log'),
    'timetable_engine': ('http://127.0.0.1:9096/health', '/tmp/tumba-sdn-logs/timetable.log'),
    'auto_traffic': ('http://127.0.0.1:9097/health', '/tmp/tumba-sdn-logs/auto_traffic.log'),
    'ibn_engine': ('http://127.0.0.1:9098/health', '/tmp/tumba-sdn-logs/ibn_engine.log'),
    'data_mining': ('http://127.0.0.1:9099/health', '/tmp/tumba-sdn-logs/data_mining.log'),
    'proactive_congestion': ('http://127.0.0.1:9100/health', '/tmp/tumba-sdn-logs/proactive_congestion.log'),
    'dataset_collector': ('http://127.0.0.1:9101/health', '/tmp/tumba-sdn-logs/dataset_collector.log'),
}
status_path = '/tmp/campus_service_status.json'
summary = {'services': {}, 'ts': time.time()}
for name, (url, log_path) in services.items():
    item = {'log': log_path, 'log_exists': os.path.exists(log_path)}
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            item['health'] = json.loads(resp.read() or b'{}')
            item['online'] = True
    except Exception as exc:
        item['online'] = False
        item['error'] = str(exc)
    summary['services'][name] = item
tmp_name = None
try:
    with tempfile.NamedTemporaryFile('w', dir=os.path.dirname(status_path) or '.', delete=False, encoding='utf-8') as handle:
        json.dump(summary, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
        tmp_name = handle.name
    os.chmod(tmp_name, 0o644)
    os.replace(tmp_name, status_path)
    os.chmod(status_path, 0o644)
except Exception as exc:
    if tmp_name:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
    print(f'failed to write {status_path}: {exc}', file=sys.stderr)
    sys.exit(1)
PY
}

bootstrap_state_files
bootstrap_dataset_dirs
prepare_frontend_build

info "Cleaning previous Mininet and SDN state..."
mn --clean >/dev/null 2>&1 || true
for port in 6653 9090 9091 9095 9096 9097 9098 9099 9100 9101; do
  fuser -k "${port}/tcp" >/dev/null 2>&1 || true
done
pkill -f "ryu-manager" >/dev/null 2>&1 || true
pkill -f "tumba_topo.py" >/dev/null 2>&1 || true
pkill -f "pc_activity_manager.py" >/dev/null 2>&1 || true
pkill -f "timetable_engine.py" >/dev/null 2>&1 || true
pkill -f "auto_traffic.py" >/dev/null 2>&1 || true
pkill -f "ml_stub.py" >/dev/null 2>&1 || true
pkill -f "marl_security_agent.py" >/dev/null 2>&1 || true
pkill -f "ibn_engine.py" >/dev/null 2>&1 || true
pkill -f "data_mining.py" >/dev/null 2>&1 || true
pkill -f "proactive_congestion.py" >/dev/null 2>&1 || true
pkill -f "realtime_dataset_collector.py" >/dev/null 2>&1 || true
sleep 2

start_service "Ryu Controller" 6653 "" "$LOGS/ryu.log" \
  "$RYU_MGR" --ofp-tcp-listen-port 6653 "$PROJECT/tumba_sdn/controller/main_controller.py" || exit 1

start_service "Topology API" 9091 "http://127.0.0.1:9091/health" "$LOGS/topology.log" \
  "$PYTHON_SYS" "$PROJECT/tumba_sdn/topology/tumba_topo.py" \
  --no-cli --controller-ip 127.0.0.1 --controller-port 6653 --api-port 9091 || exit 1

start_service "Timetable Engine" 9096 "http://127.0.0.1:9096/health" "$LOGS/timetable.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/timetable/timetable_engine.py" \
  --db /tmp/campus_timetable.db --state-file /tmp/campus_timetable_state.json --port 9096 || exit 1

start_service "PC Activity Manager" 9095 "http://127.0.0.1:9095/health" "$LOGS/pc_activity_manager.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/simulation/pc_activity_manager.py" --port 9095 || exit 1

start_service "Autonomous Traffic Engine" 9097 "http://127.0.0.1:9097/health" "$LOGS/auto_traffic.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/simulation/auto_traffic.py" || exit 1

info "Starting ML stub..."
nohup "$PYTHON" "$PROJECT/scripts/ml_stub.py" > "$LOGS/ml_stub.log" 2>&1 &
sleep 2
ok "ML stub started"

info "Starting MARL Security Agent..."
nohup "$PYTHON" "$PROJECT/tumba_sdn/ml/marl_security_agent.py" > "$LOGS/marl_security.log" 2>&1 &
sleep 2
ok "MARL Security Agent started"

start_service "IBN Engine" 9098 "http://127.0.0.1:9098/health" "$LOGS/ibn_engine.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/controller/ibn_engine.py" --port 9098 || exit 1

start_service "Data Mining Engine" 9099 "http://127.0.0.1:9099/health" "$LOGS/data_mining.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/ml/data_mining.py" --port 9099 || exit 1

start_service "Proactive Congestion Engine" 9100 "http://127.0.0.1:9100/health" "$LOGS/proactive_congestion.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/controller/proactive_congestion.py" --port 9100 || exit 1

start_service "Real-Time Dataset Collector" 9101 "http://127.0.0.1:9101/health" "$LOGS/dataset_collector.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/ml/realtime_dataset_collector.py" --port 9101 || exit 1

start_service "Dashboard" 9090 "http://127.0.0.1:9090/api/health" "$LOGS/dashboard.log" \
  "$PYTHON" "$PROJECT/tumba_sdn/dashboard/app.py" --port 9090 || exit 1

if write_status_summary; then
  STATUS_WRITTEN=1
else
  STATUS_WRITTEN=0
fi

echo
echo "────────────────────────────────────────────────────────────"
echo "  Tumba College SDN Stack — RUNNING"
echo "  Dashboard:      http://localhost:9090"
echo "  Topology API:   http://localhost:9091"
echo "  PC Activity:    http://localhost:9095"
echo "  Timetable:      http://localhost:9096"
echo "  Auto Traffic:   http://localhost:9097"
echo "  IBN Engine:     http://localhost:9098"
echo "  Data Mining:    http://localhost:9099"
echo "  Proactive Cong: http://localhost:9100"
echo "  Dataset:        http://localhost:9101"
echo "  Logs:           $LOGS"
echo "  Status JSON:    $STATUS_FILE"
echo "────────────────────────────────────────────────────────────"

if [ "$STATUS_WRITTEN" -eq 1 ] && [ -f "$STATUS_FILE" ]; then
  ok "Startup status summary written to $STATUS_FILE"
else
  warn "Startup status summary was not written to $STATUS_FILE"
fi
