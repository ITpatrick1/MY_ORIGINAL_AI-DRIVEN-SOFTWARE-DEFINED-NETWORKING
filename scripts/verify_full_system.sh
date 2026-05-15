#!/bin/bash

set -u

PASS=0
FAIL=0

pass() { echo "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $*"; FAIL=$((FAIL + 1)); }

check_port() {
  local port="$1"
  if ss -tln "( sport = :$port )" | grep -q ":$port"; then
    pass "Port $port listening"
  else
    fail "Port $port not listening"
  fi
}

check_json_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    fail "Missing file $path"
    return
  fi
  if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$path" >/dev/null 2>&1; then
    pass "Valid JSON $path"
  else
    fail "Invalid JSON $path"
  fi
}

check_url() {
  local name="$1"
  local url="$2"
  if curl -fsS "$url" >/dev/null 2>&1; then
    pass "$name health OK"
  else
    fail "$name health failed ($url)"
  fi
}

echo "== Port checks =="
for port in 6653 9090 9091 9095 9096 9097 9098 9099 9100; do
  check_port "$port"
done

echo
echo "== Health checks =="
check_url "Dashboard" "http://127.0.0.1:9090/api/health"
check_url "Topology" "http://127.0.0.1:9091/health"
check_url "PC Activity Manager" "http://127.0.0.1:9095/health"
check_url "Timetable" "http://127.0.0.1:9096/health"
check_url "Auto Traffic" "http://127.0.0.1:9097/health"
check_url "IBN" "http://127.0.0.1:9098/health"
check_url "Data Mining" "http://127.0.0.1:9099/health"
check_url "Proactive Congestion" "http://127.0.0.1:9100/health"

echo
echo "== State files =="
for path in \
  /tmp/campus_metrics.json \
  /tmp/campus_pc_activities.json \
  /tmp/campus_proactive_congestion.json \
  /tmp/campus_security_action.json \
  /tmp/campus_ml_action.json \
  /tmp/campus_timetable_state.json \
  /tmp/campus_topology_state.json; do
  check_json_file "$path"
done

echo
echo "== Log files =="
for path in \
  /tmp/tumba-sdn-logs/ryu.log \
  /tmp/tumba-sdn-logs/dashboard.log \
  /tmp/tumba-sdn-logs/proactive_congestion.log \
  /tmp/tumba-sdn-logs/security.log \
  /tmp/tumba-sdn-logs/pc_activity_manager.log \
  /tmp/tumba-sdn-logs/auto_traffic.log \
  /tmp/tumba-sdn-logs/data_mining.log \
  /tmp/tumba-sdn-logs/ibn_engine.log \
  /tmp/tumba-sdn-logs/marl_security.log \
  /tmp/tumba-sdn-logs/timetable.log \
  /tmp/tumba-sdn-logs/ml_stub.log; do
  if [ -s "$path" ]; then
    pass "Log present $path"
  else
    fail "Log missing or empty $path"
  fi
done

echo
echo "== Topology check =="
TOPO_COUNTS=$(python3 - <<'PY'
import json
data = json.load(open('/tmp/campus_topology_state.json'))
nodes = data.get('nodes', [])
switches = len([n for n in nodes if n.get('type') == 'switch'])
hosts = len([n for n in nodes if n.get('type') == 'host'])
print(f"{switches},{hosts}")
PY
)
SWITCHES=${TOPO_COUNTS%,*}
HOSTS=${TOPO_COUNTS#*,}
if { [ "$SWITCHES" = "7" ] && [ "$HOSTS" = "24" ]; } || { [ "$SWITCHES" = "8" ] && [ "$HOSTS" = "25" ]; }; then
  pass "Topology has expected campus nodes (switches=$SWITCHES hosts=$HOSTS)"
else
  fail "Unexpected topology counts switches=$SWITCHES hosts=$HOSTS"
fi

echo
echo "== API action checks =="
if curl -fsS -X POST http://127.0.0.1:9090/api/set_activity -H 'Content-Type: application/json' -d '{"host":"h_wifi2","activity":"elearning"}' >/tmp/verify_set_activity.json 2>/dev/null; then
  if python3 - <<'PY'
import json
data = json.load(open('/tmp/verify_set_activity.json'))
assert data.get('ok') is True
PY
  then
    pass "Set activity API works"
  else
    fail "Set activity API returned invalid payload"
  fi
else
  fail "Set activity API request failed"
fi

if curl -fsS -X POST http://127.0.0.1:9090/api/scenario -H 'Content-Type: application/json' -d '{"scenario":"normal_traffic"}' >/tmp/verify_scenario.json 2>/dev/null; then
  if python3 - <<'PY'
import json
data = json.load(open('/tmp/verify_scenario.json'))
assert data.get('ok') is True
PY
  then
    pass "Scenario API works"
  else
    fail "Scenario API returned invalid payload"
  fi
else
  fail "Scenario API request failed"
fi

curl -fsS -X POST http://127.0.0.1:9090/api/scenario -H 'Content-Type: application/json' -d '{"scenario":"stop_reset"}' >/dev/null 2>&1 || true

echo
echo "== Summary =="
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
