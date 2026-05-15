# AI-Driven SDN Framework for Adaptive Traffic Management
### Tumba College of Technology — Capstone Project 2026

An intelligent Software-Defined Networking system that uses Deep Q-Network (DQN) reinforcement learning to adaptively manage campus network traffic in real time.

---

## Project Structure

```
tumba-college-sdn/
├── run.sh                          # Start the full stack (requires sudo)
├── requirements.txt                # Python dependencies
│
├── tumba_sdn/                      # Main project package
│   ├── topology/
│   │   └── tumba_topo.py           # Mininet campus topology (7 switches, 24 hosts)
│   ├── controller/
│   │   ├── main_controller.py      # Ryu SDN controller (OpenFlow 1.3)
│   │   ├── policy_engine.py        # Zero-Trust + QoS flow rules
│   │   ├── security_module.py      # DDoS detection & mitigation
│   │   ├── self_healing.py         # Automatic fault recovery
│   │   ├── topology_manager.py     # Link state tracking
│   │   └── traffic_monitor.py      # Port statistics collection
│   ├── ml/
│   │   └── dqn_agent.py            # Deep Q-Network routing agent
│   ├── simulation/
│   │   ├── pc_activity_manager.py  # Per-PC activity engine (port 9095)
│   │   ├── traffic_generator.py    # Background traffic generation
│   │   ├── simulation_runner.py    # Automated test scenarios
│   │   └── performance_evaluator.py
│   ├── timetable/
│   │   └── timetable_engine.py     # Exam/class schedule integration
│   ├── dashboard/
│   │   ├── app.py                  # Flask + SocketIO web server (port 9090)
│   │   ├── templates/index.html    # Interactive monitoring dashboard
│   │   └── static/js/             # Local JS assets
│   └── config/
│       └── traffic_profile.json    # QoS traffic profiles
│
├── scripts/
│   └── ml_stub.py                  # DQN action simulator (demo mode)
│
├── docs/
│   ├── stakeholder_survey.csv      # Requirements survey data
│   └── stakeholder_survey_raw.pdf
│
└── results/                        # Evaluation outputs & reports
    ├── Phase_I_Analysis_Report.md
    ├── stakeholder_analysis_latest.md
    └── ...
```

---

## Campus Network Topology

```
          [ SDN Controller (cs1) ]
                   |
        ┌──────────┴──────────┐
   [Dist SW 1 (ds1)]    [Dist SW 2 (ds2)]
        |         |          |          |
  [Access SW  [Access SW  [Access SW  [Access SW
   Staff LAN]  Server]     IT Lab]    WiFi]
   Staff-PC×3  MIS/DHCP/   Lab-PC×3  Student-PC×4
               Auth/Moodle
```

**VLANs:**
| Zone | VLAN | Subnet | Switch |
|------|------|--------|--------|
| Staff LAN | 10 | 10.10.0.0/24 | as1 (dpid 4) |
| Server Zone | 20 | 10.20.0.0/24 | as2 (dpid 5) |
| IT Lab | 30 | 10.30.0.0/24 | as3 (dpid 6) |
| Student WiFi | 40 | 10.40.0.0/24 | as4 (dpid 7) |
| External VMware | 50 | 10.50.0.0/24 | ovs_ext (dpid 8) |

---

## Quick Start

```bash
# 1. Clone / navigate to the project
cd tumba-college-sdn

# 2. Start the full stack (requires sudo for Mininet)
sudo ./run.sh
```

Open **http://localhost:9090** in your browser.

---

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Ryu Controller | 6653 | OpenFlow 1.3 control plane |
| Web Dashboard | 9090 | Live monitoring UI |
| Topology API | 9091 | Link up/down, topology state |
| Timetable API | 9092 | Exam/class schedule |
| PC Activity Mgr | 9095 | Per-PC traffic control |

---

## PC Activity Simulation

Click any PC in the Topology view to open its **browser window** and assign an activity:

| Activity | Priority | Bandwidth | QoS (DSCP) |
|----------|----------|-----------|------------|
| Online Exam | CRITICAL | 5 Mbps | EF (46) |
| Video Conference | CRITICAL | 4 Mbps | CS5 (40) |
| E-Learning | HIGH | 3 Mbps | AF31 (26) |
| Video Streaming | MEDIUM | 5 Mbps | AF21 (18) |
| File Download | LOW | 10 Mbps | AF11 (10) |
| Social Media | BEST-EFFORT | 1 Mbps | BE (0) |

Pre-built scenarios: **Canonical Demo**, **Staff Heavy**, **Security Test**, **Congestion**.

---

## Technology Stack

- **Mininet** — Network emulation (virtual switches & hosts)
- **Ryu** — SDN controller (OpenFlow 1.3)
- **Open vSwitch** — Software data plane
- **DQN (PyTorch)** — Reinforcement learning routing agent
- **Flask + SocketIO** — Real-time web dashboard
- **iperf3** — Traffic generation per host namespace

---

## External VMware VM Support

The stack now includes a configurable VMware endpoint zone in
`tumba_sdn/config/external_vms.json`. The default endpoint is:

```text
Host: ext_win10
IP:   10.50.0.10
OVS:  ovs_ext, DPID 8
```

Ryu can control this Windows VM's traffic when the VM is connected through an
Open vSwitch bridge pointed at the Ryu controller. See
`docs/vmware_external_vm_integration.md` and
`scripts/setup_vmware_ovs_bridge.sh`.
