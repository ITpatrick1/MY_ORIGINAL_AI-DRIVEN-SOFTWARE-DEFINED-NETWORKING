# VMware External VM Integration

This project can treat a Windows 10 VMware VM as an SDN endpoint when the VM's traffic passes through an Open vSwitch bridge controlled by Ryu.

## Default Inventory

The default external endpoint is configured in `tumba_sdn/config/external_vms.json`:

| Field | Value |
|---|---|
| Host ID | `ext_win10` |
| Label | `Windows 10 VMware VM` |
| IP | `10.50.0.10` |
| MAC | `00:50:56:00:00:10` |
| Zone | `external_vm` |
| VLAN | `50` |
| OVS bridge/switch | `ovs_ext` |
| DPID | `8` / `0000000000000008` |

Update the IP and MAC to match your Windows VM.

## Required Network Path

Ryu controls OpenFlow switches, not the Windows VM directly. The VM must send packets through OVS:

```text
Windows 10 VMware VM
        |
VMware vmnet / host-only adapter
        |
Open vSwitch bridge: ovs_ext, DPID 8
        |
Ryu controller: tcp:<ryu-ip>:6653
```

## Host Setup

Install OVS on the Linux machine or gateway VM that carries the VMware traffic:

```bash
sudo apt install openvswitch-switch
```

Create the Ryu-controlled bridge:

```bash
sudo RYU_CONTROLLER=127.0.0.1:6653 ./scripts/setup_vmware_ovs_bridge.sh
```

If you know the VMware-side interface and uplink interface:

```bash
sudo VM_IFACE=vmnet2 UPLINK_IFACE=enp3s0 RYU_CONTROLLER=127.0.0.1:6653 ./scripts/setup_vmware_ovs_bridge.sh
```

Use the actual interface names from:

```bash
ip link
ovs-vsctl show
```

## Windows 10 VM Setup

Configure the Windows VM NIC to use the VMware network that reaches `ovs_ext`.

Suggested static IPv4 settings:

```text
IP address: 10.50.0.10
Subnet mask: 255.255.255.0
Gateway: your OVS/gateway address for the external VM network
DNS: your lab DNS or 8.8.8.8
```

If you enable SSH/OpenSSH or install `iperf3` inside Windows, add these optional fields to `external_vms.json`:

```json
"management_ip": "10.50.0.10",
"ssh_user": "your-windows-user",
"ssh_key": "/home/patrick/.ssh/id_rsa"
```

Without SSH, the dashboard can still apply policy state and Ryu can still control real packets seen on OVS.

## Validation

Start the SDN stack:

```bash
sudo ./run.sh
```

Check the OVS bridge connected to Ryu:

```bash
sudo ovs-vsctl show
sudo ovs-ofctl -O OpenFlow13 show ovs_ext
```

Open the dashboard:

```text
http://localhost:9090
```

You should see:

- `External VMware (VLAN 50)` zone
- `Windows 10 VM` endpoint
- switch `ovs_ext` / DPID `8`

When Windows sends traffic through `ovs_ext`, Ryu can install OpenFlow rules for `10.50.0.10` and `00:50:56:00:00:10`.
