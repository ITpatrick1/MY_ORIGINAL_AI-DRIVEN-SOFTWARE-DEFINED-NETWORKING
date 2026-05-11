#!/usr/bin/env python3
"""
PC Activity Manager — Tumba College SDN

End-device-centric simulation engine. Each user PC can independently run
one of six activity types that drive realistic, differentiated traffic:

    exam           → high priority, latency-sensitive, TCP to MIS
    video_conf     → real-time, UDP to MIS
    elearning      → medium-high, TCP to Moodle
    video_streaming→ moderate, TCP to Moodle
    file_download  → bandwidth-intensive, TCP to MIS
    social_media   → low priority, TCP to Moodle

All traffic originates from actual Mininet host namespaces (ip netns exec),
not from centralized triggers. Security scenario (ddos_attack) is also
available for student WiFi hosts to demonstrate anomaly detection.

HTTP API (port 9095):
  GET  /state              → full PC activity state + baseline
  POST /set_activity       → {"host": "h_wifi1", "activity": "exam"}
  POST /capture_baseline   → snapshot current network metrics as baseline
  POST /reset_all          → set all PCs to idle
  GET  /health             → {"ok": true}
  GET  /profiles           → activity profile definitions
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ─── File paths ───────────────────────────────────────────────────────────────
PC_ACTIVITIES_FILE = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE',
                                    '/tmp/campus_pc_activities.json')
BASELINE_FILE      = os.environ.get('CAMPUS_BASELINE_FILE',
                                    '/tmp/campus_baseline.json')
METRICS_FILE       = os.environ.get('CAMPUS_METRICS_FILE',
                                    '/tmp/campus_metrics.json')

# ─── Activity profiles ────────────────────────────────────────────────────────
# Each profile defines traffic characteristics and QoS intent.
ACTIVITY_PROFILES = {
    'idle': {
        'label':        'Idle',
        'priority':     5,
        'dscp':         0,
        'bandwidth_mbps': 0.0,
        'color':        '#64748b',
        'icon':         '●',
        'description':  'No active traffic — baseline state',
    },
    'exam': {
        'label':        'Online Examination',
        'priority':     1,
        'dscp':         46,         # EF — expedited forwarding
        'bandwidth_mbps': 5.0,
        'dst_ip':       '10.20.0.1',  # h_mis (MIS Server)
        'dst_port':     5201,
        'proto':        'tcp',
        'pattern':      'burst',
        'burst_dur':    4,
        'burst_gap':    1,
        'color':        '#ef4444',
        'icon':         'E',
        'description':  'High priority, latency-sensitive exam traffic',
    },
    'video_conf': {
        'label':        'Video Conferencing',
        'priority':     1,
        'dscp':         40,         # CS5
        'bandwidth_mbps': 4.0,
        'dst_ip':       '10.20.0.1',  # h_mis (MIS Server)
        'dst_port':     5201,
        'proto':        'udp',
        'pattern':      'stream',
        'burst_dur':    8,
        'burst_gap':    1,
        'color':        '#3b82f6',
        'icon':         'V',
        'description':  'Real-time, delay-sensitive video call',
    },
    'elearning': {
        'label':        'E-learning Platform',
        'priority':     2,
        'dscp':         26,         # AF31
        'bandwidth_mbps': 3.0,
        'dst_ip':       '10.20.0.4',  # h_moodle (Moodle Server)
        'dst_port':     5204,
        'proto':        'tcp',
        'pattern':      'moderate',
        'burst_dur':    5,
        'burst_gap':    2,
        'color':        '#10b981',
        'icon':         'L',
        'description':  'Medium-high priority Moodle / LMS access',
    },
    'video_streaming': {
        'label':        'Academic Streaming',
        'priority':     3,
        'dscp':         18,         # AF21
        'bandwidth_mbps': 5.0,
        'dst_ip':       '10.20.0.4',  # h_moodle (Moodle Server)
        'dst_port':     5204,
        'proto':        'tcp',
        'pattern':      'stream',
        'burst_dur':    10,
        'burst_gap':    1,
        'color':        '#a855f7',
        'icon':         'S',
        'description':  'Moderate priority academic video stream',
    },
    'file_download': {
        'label':        'File Downloading',
        'priority':     4,
        'dscp':         10,         # AF11
        'bandwidth_mbps': 10.0,
        'dst_ip':       '10.20.0.1',  # h_mis (MIS Server)
        'dst_port':     5201,
        'proto':        'tcp',
        'pattern':      'bulk',
        'burst_dur':    12,
        'burst_gap':    1,
        'color':        '#f59e0b',
        'icon':         'D',
        'description':  'Bandwidth-intensive bulk file transfer',
    },
    'social_media': {
        'label':        'Social Media',
        'priority':     5,
        'dscp':         0,
        'bandwidth_mbps': 1.0,
        'dst_ip':       '10.20.0.4',  # h_moodle (Moodle Server)
        'dst_port':     5204,
        'proto':        'tcp',
        'pattern':      'bursty',
        'burst_dur':    2,
        'burst_gap':    4,
        'color':        '#06b6d4',
        'icon':         'M',
        'description':  'Low priority best-effort browsing',
    },
    'ddos_attack': {
        'label':        'DDoS Attack (Security)',
        'priority':     0,
        'dscp':         0,
        'bandwidth_mbps': 50.0,
        'dst_ip':       '10.20.0.1',  # h_mis (MIS Server — target)
        'dst_port':     80,
        'proto':        'tcp',
        'pattern':      'flood',
        'burst_dur':    30,
        'burst_gap':    0,
        'color':        '#dc2626',
        'icon':         '!',
        'description':  'Security scenario: simulated DDoS from this PC',
    },
    'port_scan': {
        'label':        'Port Scan (Nmap)',
        'priority':     0,
        'dscp':         0,
        'bandwidth_mbps': 0.5,
        'dst_ip':       '10.20.0.0',  # scans server subnet
        'dst_port':     0,            # varies per scan
        'proto':        'tcp',
        'pattern':      'scan',
        'burst_dur':    20,
        'burst_gap':    5,
        'color':        '#f97316',
        'icon':         'S',
        'description':  'Security scenario: TCP SYN port scan across server zone',
    },
    'network_sweep': {
        'label':        'Network Sweep (ICMP)',
        'priority':     0,
        'dscp':         0,
        'bandwidth_mbps': 0.1,
        'dst_ip':       '10.0.0.0',   # sweeps all subnets
        'dst_port':     0,
        'proto':        'icmp',
        'pattern':      'sweep',
        'burst_dur':    15,
        'burst_gap':    10,
        'color':        '#fb923c',
        'icon':         'W',
        'description':  'Security scenario: ICMP ping sweep to discover live hosts',
    },
}

# Priority label for display
PRIORITY_LABELS = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW', 5: 'BEST-EFFORT', 0: 'ATTACK'}

# ─── User PC definitions — Tumba College diagram topology ────────────────────
# Matches tumba_topo.py exactly (tumba_sdn/topology/tumba_topo.py)
# Servers (targets, not PCs): h_mis/h_dhcp/h_auth/h_moodle @ 10.20.0.x
USER_PCS: dict[str, dict] = {
    # Staff LAN — VLAN 10 — as1 (DPID 4) — 10.10.0.x  (3 PCs for clarity)
    'h_staff1': {'zone': 'staff_lan',    'ip': '10.10.0.1', 'label': 'Staff-PC1', 'role': 'staff'},
    'h_staff2': {'zone': 'staff_lan',    'ip': '10.10.0.2', 'label': 'Staff-PC2', 'role': 'staff'},
    'h_staff3': {'zone': 'staff_lan',    'ip': '10.10.0.3', 'label': 'Staff-PC3', 'role': 'staff'},
    # IT / Networking Lab — VLAN 30 — as3 (DPID 6) — 10.30.0.x  (3 PCs)
    'h_lab1':   {'zone': 'it_lab',       'ip': '10.30.0.1', 'label': 'Lab-PC1',   'role': 'student'},
    'h_lab2':   {'zone': 'it_lab',       'ip': '10.30.0.2', 'label': 'Lab-PC2',   'role': 'student'},
    'h_lab3':   {'zone': 'it_lab',       'ip': '10.30.0.3', 'label': 'Lab-PC3',   'role': 'student'},
    # Student Wi-Fi — VLAN 40 — as4 (DPID 7) — 10.40.0.x  (4 devices)
    'h_wifi1':  {'zone': 'student_wifi', 'ip': '10.40.0.1', 'label': 'Student-PC1', 'role': 'student'},
    'h_wifi2':  {'zone': 'student_wifi', 'ip': '10.40.0.2', 'label': 'Student-PC2', 'role': 'student'},
    'h_wifi3':  {'zone': 'student_wifi', 'ip': '10.40.0.3', 'label': 'Student-PC3', 'role': 'student'},
    'h_wifi4':  {'zone': 'student_wifi', 'ip': '10.40.0.4', 'label': 'Student-PC4', 'role': 'student'},
}

# ─── PC Activity Manager ──────────────────────────────────────────────────────

class PCActivityManager:
    """Manages per-PC activity state and drives corresponding traffic."""

    def __init__(self):
        self._lock = threading.Lock()
        self.running = True

        # Per-PC state
        self._activity: dict[str, str] = {pc: 'idle' for pc in USER_PCS}
        self._since_ts: dict[str, float] = {pc: time.time() for pc in USER_PCS}
        self._traffic_mbps: dict[str, float] = {pc: 0.0 for pc in USER_PCS}
        self._pkts_sent: dict[str, int] = {pc: 0 for pc in USER_PCS}

        # Per-PC traffic thread control
        self._stop_events: dict[str, threading.Event] = {
            pc: threading.Event() for pc in USER_PCS
        }
        self._threads: dict[str, threading.Thread | None] = {pc: None for pc in USER_PCS}

        # Child processes for cleanup
        self._child_procs: list[subprocess.Popen] = []
        self._server_started = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_activity(self, host: str, activity: str) -> dict:
        """Set activity for a single PC. Returns status dict."""
        if host not in USER_PCS:
            return {'ok': False, 'error': f'Unknown host: {host}'}
        if activity not in ACTIVITY_PROFILES:
            return {'ok': False, 'error': f'Unknown activity: {activity}'}

        with self._lock:
            old = self._activity[host]
            if old == activity:
                return {'ok': True, 'host': host, 'activity': activity, 'changed': False}

            # Stop current traffic thread for this PC
            self._stop_events[host].set()
            t = self._threads[host]
            if t and t.is_alive():
                t.join(timeout=3)

            # Update state
            self._activity[host] = activity
            self._since_ts[host] = time.time()
            self._traffic_mbps[host] = 0.0

            # Reset stop event and start new thread (unless idle)
            self._stop_events[host] = threading.Event()
            if activity != 'idle':
                t = threading.Thread(
                    target=self._traffic_loop,
                    args=(host, activity, self._stop_events[host]),
                    daemon=True,
                    name=f'traffic_{host}',
                )
                self._threads[host] = t
                t.start()
            else:
                self._threads[host] = None

        print(f'[pcam] {host}: {old} → {activity}')
        self._write_state()
        return {'ok': True, 'host': host, 'activity': activity, 'changed': True}

    def reset_all(self) -> dict:
        """Set all PCs to idle."""
        for host in list(USER_PCS):
            self.set_activity(host, 'idle')
        return {'ok': True, 'reset': len(USER_PCS)}

    def get_state(self) -> dict:
        """Return full state snapshot."""
        with self._lock:
            pcs = {}
            for host, meta in USER_PCS.items():
                act = self._activity[host]
                profile = ACTIVITY_PROFILES[act]
                pcs[host] = {
                    **meta,
                    'activity':       act,
                    'activity_label': profile['label'],
                    'priority':       profile['priority'],
                    'priority_label': PRIORITY_LABELS[profile['priority']],
                    'dscp':           profile['dscp'],
                    'traffic_mbps':   round(self._traffic_mbps[host], 2),
                    'since_ts':       self._since_ts[host],
                    'color':          profile['color'],
                    'icon':           profile['icon'],
                    'bw_target':      profile['bandwidth_mbps'],
                    'dst_ip':         profile.get('dst_ip', ''),
                    'dst_port':       profile.get('dst_port', 0),
                    'proto':          profile.get('proto', 'tcp'),
                }

        baseline = {}
        try:
            with open(BASELINE_FILE) as f:
                baseline = json.load(f)
        except Exception:
            pass

        return {
            'ts':       time.time(),
            'pcs':      pcs,
            'baseline': baseline,
            'profiles': ACTIVITY_PROFILES,
        }

    def capture_baseline(self) -> dict:
        """Snapshot current metrics as the baseline for comparison."""
        metrics = {}
        try:
            with open(METRICS_FILE) as f:
                metrics = json.load(f)
        except Exception:
            pass

        # Summarise active activities at capture time
        with self._lock:
            active = {h: a for h, a in self._activity.items() if a != 'idle'}

        baseline = {
            'captured_ts': time.time(),
            'active_pcs':  len(active),
            'metrics':     metrics,
            'activities':  active,
        }
        try:
            tmp = BASELINE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(baseline, f, indent=2)
            os.replace(tmp, BASELINE_FILE)
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        return {'ok': True, 'captured_ts': baseline['captured_ts']}

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self):
        """Start background writer and iperf servers."""
        self._ensure_iperf_servers()
        writer = threading.Thread(target=self._state_writer, daemon=True)
        writer.start()
        print(f'[pcam] Activity manager started — {len(USER_PCS)} PCs registered')

    def stop(self):
        """Stop all traffic threads and cleanup."""
        self.running = False
        for host in USER_PCS:
            self._stop_events[host].set()
        for p in self._child_procs:
            try:
                p.terminate()
            except Exception:
                pass
        print('[pcam] Stopped.')

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _ensure_iperf_servers(self):
        """Start iperf3 servers on tumba server-zone hosts (idempotent)."""
        if self._server_started:
            return
        # Tumba topology servers (as2, VLAN 20, DPID 5)
        servers = {
            'h_mis':    5201,   # MIS Server     — exam, video_conf, file_download
            'h_dhcp':   5202,   # DHCP Server    — spare
            'h_auth':   5203,   # Auth Server    — spare
            'h_moodle': 5204,   # Moodle Server  — elearning, video_streaming, social_media
        }
        for host, port in servers.items():
            try:
                p = subprocess.Popen(
                    ['sudo', 'ip', 'netns', 'exec', host,
                     'iperf3', '-s', '-p', str(port), '-D'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self._child_procs.append(p)
                print(f'[pcam] iperf3 server on {host}:{port}')
            except Exception as e:
                print(f'[pcam] WARNING: could not start iperf3 server on {host}: {e}')
        time.sleep(0.5)
        self._server_started = True

    def _traffic_loop(self, host: str, activity: str, stop_event: threading.Event):
        """Traffic generation loop for one PC — runs until stop_event set."""
        profile = ACTIVITY_PROFILES.get(activity, {})
        pattern   = profile.get('pattern', 'burst')
        dst_ip    = profile.get('dst_ip', '10.20.0.1')
        dst_port  = profile.get('dst_port', 5201)
        proto     = profile.get('proto', 'tcp')
        bw_mbps   = profile.get('bandwidth_mbps', 1.0)
        burst_dur = profile.get('burst_dur', 5)
        burst_gap = profile.get('burst_gap', 1)

        while not stop_event.is_set():
            # Verify activity hasn't changed (re-check state)
            with self._lock:
                if self._activity.get(host) != activity:
                    break

            if pattern == 'scan':
                measured = self._run_port_scan(host, stop_event)
            elif pattern == 'sweep':
                measured = self._run_network_sweep(host, stop_event)
            else:
                measured = self._run_iperf(host, dst_ip, dst_port, proto,
                                           bw_mbps, burst_dur)
            with self._lock:
                if self._activity.get(host) == activity:
                    self._traffic_mbps[host] = measured
                    self._pkts_sent[host] += 1

            # Gap between bursts (skip for stream/flood patterns)
            if burst_gap > 0 and pattern not in ('stream', 'flood', 'scan', 'sweep'):
                stop_event.wait(timeout=burst_gap)

        # Zero out traffic on exit
        with self._lock:
            if self._activity.get(host) == 'idle':
                self._traffic_mbps[host] = 0.0

    def _run_iperf(self, host: str, dst_ip: str, port: int, proto: str,
                   bw_mbps: float, duration: int) -> float:
        """
        Run a single iperf3 session from the host's network namespace.
        Returns measured throughput in Mbps.
        """
        cmd = [
            'sudo', 'ip', 'netns', 'exec', host,
            'iperf3', '-c', dst_ip, '-p', str(port),
            '-t', str(duration),
            '-b', f'{bw_mbps}M',
            '-J',                        # JSON output for parsing
            '--connect-timeout', '2000',
        ]
        if proto == 'udp':
            cmd.append('-u')

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration + 10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                end = data.get('end', {})
                # TCP: sum sent bits_per_second; UDP: sum bits_per_second
                if proto == 'tcp':
                    bps = end.get('sum_sent', {}).get('bits_per_second', 0)
                else:
                    bps = end.get('sum', {}).get('bits_per_second', 0)
                return round(bps / 1_000_000, 2)
        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception:
            pass
        # Return target if we couldn't measure (namespace not yet ready, etc.)
        return bw_mbps * 0.8

    def _run_port_scan(self, host: str, stop_event: threading.Event) -> float:
        """Simulate TCP SYN port scan — probes sequential ports on server zone.
        Each nc -z sends a TCP SYN, triggering controller packet_in for detection."""
        import random
        targets = ['10.20.0.1', '10.20.0.4', '10.10.0.1', '10.30.0.1']
        ports   = list(range(20, 140))  # 120 ports
        random.shuffle(ports)
        probed = 0
        for port in ports:
            if stop_event.is_set():
                break
            target = random.choice(targets)
            cmd = [
                'sudo', 'ip', 'netns', 'exec', host,
                'bash', '-c',
                f'echo "" | nc -w 0 -z {target} {port} 2>/dev/null; true',
            ]
            try:
                subprocess.run(cmd, timeout=1, capture_output=True)
                probed += 1
            except Exception:
                pass
        print(f'[pcam] {host}: port scan — {probed} ports probed')
        stop_event.wait(timeout=5)
        return 0.4

    def _run_network_sweep(self, host: str, stop_event: threading.Event) -> float:
        """Simulate ICMP network sweep — pings across all campus subnets."""
        targets = (
            [f'10.10.0.{i}' for i in range(1, 5)] +
            [f'10.20.0.{i}' for i in range(1, 5)] +
            [f'10.30.0.{i}' for i in range(1, 5)] +
            [f'10.40.0.{i}' for i in range(1, 6)]
        )
        alive = 0
        for ip in targets:
            if stop_event.is_set():
                break
            cmd = ['sudo', 'ip', 'netns', 'exec', host,
                   'ping', '-c', '1', '-W', '1', ip]
            try:
                r = subprocess.run(cmd, timeout=2, capture_output=True)
                if r.returncode == 0:
                    alive += 1
            except Exception:
                pass
        print(f'[pcam] {host}: network sweep — {alive}/{len(targets)} hosts alive')
        stop_event.wait(timeout=10)
        return 0.1

    def _state_writer(self):
        """Background thread: writes state file every 2 seconds."""
        while self.running:
            self._write_state()
            time.sleep(2)

    def _write_state(self):
        state = self.get_state()
        try:
            tmp = PC_ACTIVITIES_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, PC_ACTIVITIES_FILE)
        except Exception as e:
            print(f'[pcam] state write error: {e}')


# ─── HTTP API handler ─────────────────────────────────────────────────────────

def make_handler(manager: PCActivityManager):
    class Handler(BaseHTTPRequestHandler):
        _mgr = manager

        def log_message(self, *args):
            pass  # suppress request logs

        def _json(self, data, code=200):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get('Content-Length', 0))
            return json.loads(self.rfile.read(n)) if n > 0 else {}

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()

        def do_GET(self):
            if self.path == '/health':
                self._json({'ok': True, 'service': 'pc_activity_manager',
                            'pcs': len(USER_PCS)})
            elif self.path == '/state':
                self._json(self._mgr.get_state())
            elif self.path == '/profiles':
                self._json(ACTIVITY_PROFILES)
            else:
                self._json({'error': 'not found'}, 404)

        def do_POST(self):
            if self.path == '/set_activity':
                body = self._body()
                host = body.get('host', '')
                activity = body.get('activity', 'idle')
                result = self._mgr.set_activity(host, activity)
                self._json(result)
            elif self.path == '/capture_baseline':
                self._json(self._mgr.capture_baseline())
            elif self.path == '/reset_all':
                self._json(self._mgr.reset_all())
            elif self.path == '/set_scenario':
                # Accept either {"scenario": "canonical"} or {"assignments": [...]}
                body = self._body()
                scenario_name = body.get('scenario')
                if scenario_name and scenario_name in DEMO_SCENARIOS:
                    assignments = DEMO_SCENARIOS[scenario_name]
                else:
                    assignments = body.get('assignments', [])
                results = []
                for a in assignments:
                    r = self._mgr.set_activity(a.get('host', ''), a.get('activity', 'idle'))
                    results.append(r)
                ok = all(r.get('ok') for r in results)
                self._json({'ok': ok, 'scenario': scenario_name, 'results': results})
            else:
                self._json({'error': 'not found'}, 404)

    return Handler


# ─── Pre-defined demonstration scenarios ─────────────────────────────────────

DEMO_SCENARIOS = {
    'canonical': [
        # 3 staff + 3 WiFi students, one activity each type
        {'host': 'h_staff1', 'activity': 'exam'},
        {'host': 'h_staff2', 'activity': 'video_conf'},
        {'host': 'h_staff3', 'activity': 'elearning'},
        {'host': 'h_wifi1',  'activity': 'video_streaming'},
        {'host': 'h_wifi2',  'activity': 'file_download'},
        {'host': 'h_wifi3',  'activity': 'social_media'},
    ],
    'staff_heavy': [
        {'host': 'h_staff1', 'activity': 'exam'},
        {'host': 'h_staff2', 'activity': 'video_conf'},
        {'host': 'h_staff3', 'activity': 'file_download'},
        {'host': 'h_lab1',   'activity': 'elearning'},
        {'host': 'h_lab2',   'activity': 'video_streaming'},
    ],
    'security_test': [
        {'host': 'h_staff1', 'activity': 'exam'},
        {'host': 'h_wifi3',  'activity': 'ddos_attack'},
        {'host': 'h_wifi4',  'activity': 'ddos_attack'},
        {'host': 'h_staff2', 'activity': 'video_conf'},
        {'host': 'h_lab1',   'activity': 'elearning'},
    ],
    'congestion': [
        {'host': 'h_wifi1',  'activity': 'file_download'},
        {'host': 'h_wifi2',  'activity': 'video_streaming'},
        {'host': 'h_wifi3',  'activity': 'video_conf'},
        {'host': 'h_wifi4',  'activity': 'file_download'},
        {'host': 'h_lab1',   'activity': 'video_streaming'},
        {'host': 'h_lab2',   'activity': 'exam'},
    ],
}


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description='PC Activity Manager')
    parser.add_argument('--port', type=int, default=9095)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()

    manager = PCActivityManager()
    manager.start()

    # Graceful shutdown
    def _shutdown(sig, frame):
        print('\n[pcam] Shutting down...')
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server = ThreadingHTTPServer((args.host, args.port), make_handler(manager))
    print(f'[pcam] HTTP API: http://{args.host}:{args.port}')
    print(f'[pcam] State file: {PC_ACTIVITIES_FILE}')
    print(f'[pcam] Endpoints: GET /state  POST /set_activity  POST /capture_baseline')
    server.serve_forever()


if __name__ == '__main__':
    main()
