#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Tumba College SDN — Full Stack Stop
#  Usage:  sudo ./stop.sh
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }

info "Stopping all Tumba SDN services..."

pkill -f "ryu-manager"           2>/dev/null && ok "Ryu controller stopped"
pkill -f "tumba_topo.py"         2>/dev/null && ok "Mininet topology stopped"
pkill -f "timetable_engine.py"   2>/dev/null && ok "Timetable engine stopped"
pkill -f "pc_activity_manager.py" 2>/dev/null && ok "PC Activity Manager stopped"
pkill -f "auto_traffic.py"       2>/dev/null && ok "Autonomous Traffic Engine stopped"
pkill -f "ml_stub.py"            2>/dev/null && ok "ML stub stopped"
pkill -f "marl_security_agent.py" 2>/dev/null && ok "MARL Security Agent stopped"
pkill -f "ibn_engine.py"         2>/dev/null && ok "IBN Engine stopped"
pkill -f "data_mining.py"        2>/dev/null && ok "Data Mining Engine stopped"
pkill -f "dashboard/app.py"      2>/dev/null && ok "Dashboard stopped"

for port in 6653 9090 9091 9093 9095 9096 9097 9098 9099; do
    fuser -k ${port}/tcp 2>/dev/null
done

info "Cleaning Mininet state..."
mn --clean 2>/dev/null | tail -1

ok "All services stopped."
