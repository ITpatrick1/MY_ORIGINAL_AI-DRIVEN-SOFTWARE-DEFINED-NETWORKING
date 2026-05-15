#!/bin/bash
# Create an Open vSwitch bridge for an external VMware VM and point it at Ryu.
#
# Usage examples:
#   sudo RYU_CONTROLLER=127.0.0.1:6653 ./scripts/setup_vmware_ovs_bridge.sh
#   sudo VM_IFACE=vmnet2 UPLINK_IFACE=enp3s0 ./scripts/setup_vmware_ovs_bridge.sh

set -euo pipefail

BRIDGE="${BRIDGE:-ovs_ext}"
RYU_CONTROLLER="${RYU_CONTROLLER:-127.0.0.1:6653}"
DPID="${DPID:-0000000000000008}"
VM_IFACE="${VM_IFACE:-}"
UPLINK_IFACE="${UPLINK_IFACE:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo so OVS can create bridges and add ports." >&2
  exit 1
fi

command -v ovs-vsctl >/dev/null 2>&1 || {
  echo "openvswitch-switch is not installed. Install it first:" >&2
  echo "  sudo apt install openvswitch-switch" >&2
  exit 1
}

ovs-vsctl --may-exist add-br "$BRIDGE"
ovs-vsctl set bridge "$BRIDGE" protocols=OpenFlow13
ovs-vsctl set bridge "$BRIDGE" other-config:datapath-id="$DPID"
ovs-vsctl set-fail-mode "$BRIDGE" secure
ovs-vsctl set-controller "$BRIDGE" "tcp:$RYU_CONTROLLER"

if [ -n "$VM_IFACE" ]; then
  ovs-vsctl --may-exist add-port "$BRIDGE" "$VM_IFACE"
fi

if [ -n "$UPLINK_IFACE" ]; then
  ovs-vsctl --may-exist add-port "$BRIDGE" "$UPLINK_IFACE"
fi

echo "OVS bridge ready:"
echo "  bridge:     $BRIDGE"
echo "  dpid:       $DPID"
echo "  controller: tcp:$RYU_CONTROLLER"
if [ -z "$VM_IFACE" ]; then
  echo "  VM port:    not attached; set VM_IFACE=<vmnet/host interface> when ready"
else
  echo "  VM port:    $VM_IFACE"
fi
if [ -z "$UPLINK_IFACE" ]; then
  echo "  uplink:     not attached; set UPLINK_IFACE=<interface> if this bridge needs upstream access"
else
  echo "  uplink:     $UPLINK_IFACE"
fi
echo
ovs-vsctl show
