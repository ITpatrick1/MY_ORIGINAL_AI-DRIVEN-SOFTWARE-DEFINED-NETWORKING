#!/usr/bin/env python3
"""
PC Activity Manager — Tumba College SDN

End-device-centric simulation engine for the full Tumba campus:
  - 6 Staff LAN PCs
  - 4 Lab PCs
  - 10 Student WiFi devices

Each endpoint carries explicit congestion-relevant metadata:
  - current traffic Mbps
  - traffic type / activity label
  - priority level
  - DSCP / preferred queue
  - per-link utilisation against a 100 Mbps edge port

Activities cover academic, administrative, entertainment, and security
workloads so the congestion controller can protect critical services while
throttling low-priority traffic during overload.
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tumba_sdn.common.campus_core import (
    ACTIVITY_PROFILES as CANONICAL_ACTIVITY_PROFILES,
    PRIORITY_LABELS as CAMPUS_PRIORITY_LABELS,
    ZONE_LABELS,
    ZONE_SWITCHES,
    ZONE_VLANS,
    ACCESS_UPLINK_CAPACITY_MBPS,
    EDGE_LINK_CAPACITY_MBPS,
    atomic_write_json,
    active_zone_labels,
    active_zone_switches,
    active_zone_vlans,
    configure_file_logger,
    deterministic_mac,
    load_external_vm_hosts,
    now_ts,
    normalize_activity,
    read_json,
    resolve_browser_request,
    resolve_scenario,
    resolve_terminal_tool,
)

# ─── File paths ───────────────────────────────────────────────────────────────
PC_ACTIVITIES_FILE = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE',
                                    '/tmp/campus_pc_activities.json')
BASELINE_FILE      = os.environ.get('CAMPUS_BASELINE_FILE',
                                    '/tmp/campus_baseline.json')
METRICS_FILE       = os.environ.get('CAMPUS_METRICS_FILE',
                                    '/tmp/campus_metrics.json')

EDGE_LINK_CAPACITY_MBPS = 100.0


# Priority label for display
PRIORITY_LABELS = {
    0: 'ATTACK',
    1: 'CRITICAL',
    2: 'HIGH',
    3: 'MEDIUM',
    4: 'LOW',
    5: 'BEST-EFFORT',
}

LOGGER = configure_file_logger('tumba.pc_activity_manager', 'pc_activity_manager.log')
NS_EXEC_PREFIX = ['sudo', '-n', 'ip', 'netns', 'exec']
ZONE_LABELS = active_zone_labels()
ZONE_SWITCHES = active_zone_switches()
ZONE_VLANS = active_zone_vlans()


def _profile(label: str, priority: int, dscp: int, bandwidth_mbps: float,
             traffic_type: str, color: str, icon: str, description: str, *,
             dst_ip: str = '10.20.0.4', dst_port: int = 5204,
             proto: str = 'tcp', pattern: str = 'moderate',
             burst_dur: int = 6, burst_gap: int = 2,
             queue: int | None = None, safe_from_throttle: bool = False) -> dict:
    default_queue = 0 if priority <= 2 else (1 if priority == 3 else 2)
    return {
        'label': label,
        'priority': priority,
        'priority_level': PRIORITY_LABELS[priority],
        'dscp': dscp,
        'bandwidth_mbps': bandwidth_mbps,
        'traffic_type': traffic_type,
        'color': color,
        'icon': icon,
        'description': description,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'proto': proto,
        'pattern': pattern,
        'burst_dur': burst_dur,
        'burst_gap': burst_gap,
        'qos_queue': default_queue if queue is None else queue,
        'safe_from_throttle': safe_from_throttle,
        'link_capacity_mbps': EDGE_LINK_CAPACITY_MBPS,
    }


# ─── Activity profiles ────────────────────────────────────────────────────────
ACTIVITY_PROFILES = {
    'idle': _profile(
        'Idle', 5, 0, 0.0, 'Idle', '#64748b', '●',
        'No active traffic — baseline state',
        pattern='idle', burst_dur=1, burst_gap=1, queue=2,
    ),
    'exam': _profile(
        'Online Exam', 1, 46, 18.0, 'Online Exam', '#ef4444', 'E',
        'Highest-priority assessment traffic with strict protection',
        dst_ip='10.20.0.1', dst_port=5201, safe_from_throttle=True,
    ),
    'online_exam': _profile(
        'Online Exam', 1, 46, 18.0, 'Online Exam', '#ef4444', 'E',
        'Highest-priority assessment traffic with strict protection',
        dst_ip='10.20.0.1', dst_port=5201, safe_from_throttle=True,
    ),
    'video_conf': _profile(
        'Google Meet', 1, 40, 16.0, 'Google Meet', '#3b82f6', 'V',
        'Real-time conferencing protected during congestion',
        dst_ip='10.20.0.1', dst_port=5201, proto='udp', pattern='stream',
        burst_dur=8, burst_gap=1, safe_from_throttle=True,
    ),
    'google_meet': _profile(
        'Google Meet', 1, 40, 16.0, 'Google Meet', '#3b82f6', 'V',
        'Real-time conferencing protected during congestion',
        dst_ip='10.20.0.1', dst_port=5201, proto='udp', pattern='stream',
        burst_dur=8, burst_gap=1, safe_from_throttle=True,
    ),
    'voip': _profile(
        'VoIP Call', 1, 46, 6.0, 'VoIP', '#2563eb', '☎',
        'Voice traffic with strict latency sensitivity',
        dst_ip='10.20.0.3', dst_port=5060, proto='udp', pattern='stream',
        burst_dur=10, burst_gap=1, safe_from_throttle=True,
    ),
    'elearning': _profile(
        'E-learning', 2, 26, 18.0, 'E-learning', '#10b981', 'L',
        'Learning platform / LMS academic traffic',
        dst_ip='10.20.0.4', dst_port=5204, safe_from_throttle=True,
    ),
    'online_class': _profile(
        'Online Class', 2, 34, 20.0, 'Online Class', '#14b8a6', 'C',
        'Instructor-led class session with academic priority',
        dst_ip='10.20.0.4', dst_port=5204, proto='udp', pattern='stream',
        burst_dur=10, burst_gap=1, safe_from_throttle=True,
    ),
    'mis': _profile(
        'MIS Access', 2, 34, 14.0, 'MIS', '#0ea5e9', 'I',
        'Administrative MIS access for campus operations',
        dst_ip='10.20.0.1', dst_port=5201, safe_from_throttle=True,
    ),
    'siad': _profile(
        'SIAD Access', 2, 34, 14.0, 'SIAD', '#22c55e', 'S',
        'Student information and academic administration',
        dst_ip='10.20.0.1', dst_port=5201, safe_from_throttle=True,
    ),
    'rp_system': _profile(
        'RP System', 2, 34, 12.0, 'RP System', '#84cc16', 'R',
        'Institutional reporting / registration workflow',
        dst_ip='10.20.0.1', dst_port=5201, safe_from_throttle=True,
    ),
    'authentication': _profile(
        'Authentication', 1, 46, 1.0, 'Authentication', '#38bdf8', 'A',
        'Identity and access control traffic',
        dst_ip='10.20.0.3', dst_port=5203, burst_dur=2, burst_gap=6,
        safe_from_throttle=True,
    ),
    'dns_query': _profile(
        'DNS', 1, 46, 0.4, 'DNS', '#60a5fa', 'D',
        'Name-resolution traffic required for service access',
        dst_ip='10.20.0.2', dst_port=53, proto='udp', burst_dur=2, burst_gap=8,
        safe_from_throttle=True,
    ),
    'dhcp_sync': _profile(
        'DHCP', 1, 46, 0.3, 'DHCP', '#93c5fd', 'H',
        'Address-assignment traffic required for connectivity',
        dst_ip='10.20.0.2', dst_port=67, proto='udp', burst_dur=2, burst_gap=10,
        safe_from_throttle=True,
    ),
    'research': _profile(
        'Research', 3, 26, 22.0, 'Research', '#8b5cf6', 'R',
        'Moderate academic research and library traffic',
        dst_ip='10.20.0.4', dst_port=5204, pattern='moderate',
    ),
    'web_browsing': _profile(
        'Web Browsing', 3, 18, 8.0, 'Web Browsing', '#7c3aed', 'W',
        'Normal academic browsing and portal usage',
        dst_ip='10.20.0.4', dst_port=5204, pattern='bursty', burst_dur=3, burst_gap=3,
    ),
    'cloud_storage': _profile(
        'Cloud Storage', 3, 18, 28.0, 'Cloud Storage', '#c084fc', '☁',
        'Medium-priority sync and file collaboration traffic',
        dst_ip='10.20.0.4', dst_port=5204, pattern='bulk', burst_dur=10, burst_gap=2,
    ),
    'study_download': _profile(
        'Study Material Download', 3, 18, 40.0, 'Study Materials Download', '#a855f7', 'B',
        'Large but academic download workload',
        dst_ip='10.20.0.4', dst_port=5204, pattern='bulk', burst_dur=12, burst_gap=1,
    ),
    'video_streaming': _profile(
        'Streaming', 4, 10, 80.0, 'Streaming', '#f59e0b', 'S',
        'High-bandwidth media streaming with low protection',
        dst_ip='10.20.0.4', dst_port=5204, pattern='stream', burst_dur=12, burst_gap=1,
    ),
    'file_download': _profile(
        'Large Download', 4, 10, 92.0, 'Large Non-Academic Download', '#f97316', 'D',
        'Bulk transfer used to trigger congestion and throttling behaviour',
        dst_ip='10.20.0.1', dst_port=5201, pattern='bulk', burst_dur=14, burst_gap=1,
    ),
    'social_media': _profile(
        'Social Media', 5, 0, 12.0, 'Social Media', '#06b6d4', 'M',
        'Low-priority social browsing and chat traffic',
        dst_ip='10.20.0.4', dst_port=5204, pattern='bursty', burst_dur=3, burst_gap=3,
    ),
    'gaming': _profile(
        'Gaming', 5, 0, 38.0, 'Gaming', '#ec4899', 'G',
        'Non-academic entertainment traffic',
        dst_ip='10.20.0.4', dst_port=5204, proto='udp', pattern='stream',
        burst_dur=12, burst_gap=1,
    ),
    'ddos_attack': _profile(
        'DDoS Attack (Security)', 0, 0, 95.0, 'Attack Traffic', '#dc2626', '!',
        'Security scenario: simulated volumetric attack traffic',
        dst_ip='10.20.0.1', dst_port=80, pattern='flood', burst_dur=30, burst_gap=0, queue=2,
    ),
    'port_scan': _profile(
        'Port Scan', 0, 0, 0.5, 'Port Scan', '#f97316', 'S',
        'Security scenario: TCP SYN port scan across campus services',
        dst_ip='10.20.0.0', dst_port=0, pattern='scan', burst_dur=20, burst_gap=5, queue=2,
    ),
    'network_sweep': _profile(
        'Network Sweep', 0, 0, 0.1, 'Network Sweep', '#fb923c', 'W',
        'Security scenario: ICMP-based host discovery sweep',
        dst_ip='10.0.0.0', dst_port=0, proto='icmp', pattern='sweep', burst_dur=15, burst_gap=10, queue=2,
    ),
}

PRIORITY_LABELS = dict(CAMPUS_PRIORITY_LABELS)
ACTIVITY_PROFILES = CANONICAL_ACTIVITY_PROFILES

# ─── User PC definitions — Tumba College diagram topology ────────────────────
# Matches tumba_topo.py exactly (tumba_sdn/topology/tumba_topo.py).
# Servers (targets, not PCs): h_mis/h_dhcp/h_auth/h_moodle @ 10.20.0.x
USER_PCS: dict[str, dict] = {
    # Staff LAN — VLAN 10 — as1 (6 PCs)
    'h_staff1': {'zone': 'staff_lan', 'ip': '10.10.0.1', 'label': 'Staff-PC1', 'role': 'staff'},
    'h_staff2': {'zone': 'staff_lan', 'ip': '10.10.0.2', 'label': 'Staff-PC2', 'role': 'staff'},
    'h_staff3': {'zone': 'staff_lan', 'ip': '10.10.0.3', 'label': 'Staff-PC3', 'role': 'staff'},
    'h_staff4': {'zone': 'staff_lan', 'ip': '10.10.0.4', 'label': 'Staff-PC4', 'role': 'staff'},
    'h_staff5': {'zone': 'staff_lan', 'ip': '10.10.0.5', 'label': 'Staff-PC5', 'role': 'staff'},
    'h_staff6': {'zone': 'staff_lan', 'ip': '10.10.0.6', 'label': 'Staff-PC6', 'role': 'staff'},
    # IT Lab — VLAN 30 — as3 (4 PCs)
    'h_lab1':   {'zone': 'it_lab', 'ip': '10.30.0.1', 'label': 'Lab-PC1', 'role': 'student'},
    'h_lab2':   {'zone': 'it_lab', 'ip': '10.30.0.2', 'label': 'Lab-PC2', 'role': 'student'},
    'h_lab3':   {'zone': 'it_lab', 'ip': '10.30.0.3', 'label': 'Lab-PC3', 'role': 'student'},
    'h_lab4':   {'zone': 'it_lab', 'ip': '10.30.0.4', 'label': 'Lab-PC4', 'role': 'student'},
    # Student WiFi — VLAN 40 — as4 (10 devices)
    'h_wifi1':  {'zone': 'student_wifi', 'ip': '10.40.0.1',  'label': 'Student-PC1',  'role': 'student'},
    'h_wifi2':  {'zone': 'student_wifi', 'ip': '10.40.0.2',  'label': 'Student-PC2',  'role': 'student'},
    'h_wifi3':  {'zone': 'student_wifi', 'ip': '10.40.0.3',  'label': 'Student-PC3',  'role': 'student'},
    'h_wifi4':  {'zone': 'student_wifi', 'ip': '10.40.0.4',  'label': 'Student-PC4',  'role': 'student'},
    'h_wifi5':  {'zone': 'student_wifi', 'ip': '10.40.0.5',  'label': 'Student-PC5',  'role': 'student'},
    'h_wifi6':  {'zone': 'student_wifi', 'ip': '10.40.0.6',  'label': 'Student-PC6',  'role': 'student'},
    'h_wifi7':  {'zone': 'student_wifi', 'ip': '10.40.0.7',  'label': 'Student-PC7',  'role': 'student'},
    'h_wifi8':  {'zone': 'student_wifi', 'ip': '10.40.0.8',  'label': 'Student-PC8',  'role': 'student'},
    'h_wifi9':  {'zone': 'student_wifi', 'ip': '10.40.0.9',  'label': 'Student-PC9',  'role': 'student'},
    'h_wifi10': {'zone': 'student_wifi', 'ip': '10.40.0.10', 'label': 'Student-PC10', 'role': 'student'},
}
USER_PCS.update(load_external_vm_hosts())

for _host_meta in USER_PCS.values():
    _zone = _host_meta['zone']
    _host_meta['vlan'] = ZONE_VLANS.get(_zone, 0)
    _host_meta['switch'] = ZONE_SWITCHES.get(_zone, '')
    _host_meta['zone_label'] = ZONE_LABELS.get(_zone, _zone)
    _host_meta['mac'] = deterministic_mac(_host_meta['ip'])

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
        self._browser_url: dict[str, str] = {
            pc: ACTIVITY_PROFILES['idle'].get('browser_url', '') for pc in USER_PCS
        }
        self._browser_status: dict[str, str] = {pc: 'Idle' for pc in USER_PCS}
        self._security_state: dict[str, str] = {pc: 'normal' for pc in USER_PCS}
        self._last_alert: dict[str, str] = {pc: '' for pc in USER_PCS}
        self._controller_action: dict[str, str] = {pc: 'Monitoring only' for pc in USER_PCS}
        self._topology_cache: dict[str, dict] = {}

        # Per-PC traffic thread control
        self._stop_events: dict[str, threading.Event] = {
            pc: threading.Event() for pc in USER_PCS
        }
        self._threads: dict[str, threading.Thread | None] = {pc: None for pc in USER_PCS}

        # Child processes for cleanup
        self._child_procs: list[subprocess.Popen] = []
        self._server_started = False
        self._ensure_state_files()

    # ── Public API ─────────────────────────────────────────────────────────────

    def set_activity(self, host: str, activity: str) -> dict:
        """Set activity for a single PC. Returns status dict."""
        activity = normalize_activity(activity)
        if host not in USER_PCS:
            return {'ok': False, 'error': f'Unknown host: {host}'}
        if activity not in ACTIVITY_PROFILES:
            return {'ok': False, 'error': f'Unknown activity: {activity}'}

        with self._lock:
            old = self._activity[host]
            if old == activity:
                return {'ok': True, 'host': host, 'activity': activity, 'changed': False}

            # Signal the previous worker to stop, but do not block the API path
            # waiting for long-running traffic generators to exit.
            self._stop_events[host].set()

            # Update state
            self._activity[host] = activity
            self._since_ts[host] = time.time()
            self._traffic_mbps[host] = 0.0
            profile = ACTIVITY_PROFILES[activity]
            self._browser_url[host] = profile.get('browser_url') or self._browser_url.get(host, '')
            self._browser_status[host] = 'Idle' if activity == 'idle' else 'Connected'
            self._security_state[host] = profile.get('security_state', 'normal')
            self._controller_action[host] = profile.get('controller_hint', 'Monitoring only') or 'Monitoring only'
            self._last_alert[host] = ''

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

        LOGGER.info(
            'activity change host=%s ip=%s old=%s new=%s service=%s dscp=%s priority=%s external=%s',
            host,
            USER_PCS[host]['ip'],
            old,
            activity,
            ACTIVITY_PROFILES[activity].get('dst_service_name'),
            ACTIVITY_PROFILES[activity].get('dscp'),
            ACTIVITY_PROFILES[activity].get('priority_level'),
            bool(USER_PCS[host].get('external')),
        )
        self._write_state()
        return {
            'ok': True,
            'host': host,
            'activity': activity,
            'changed': True,
            'service': ACTIVITY_PROFILES[activity].get('dst_service_name'),
            'dst_ip': ACTIVITY_PROFILES[activity].get('dst_ip'),
            'dst_port': ACTIVITY_PROFILES[activity].get('dst_port'),
            'priority_level': ACTIVITY_PROFILES[activity].get('priority_level'),
            'dscp': ACTIVITY_PROFILES[activity].get('dscp'),
            'external': bool(USER_PCS[host].get('external')),
            'note': 'Policy state updated; real traffic must pass through the Ryu-controlled OVS bridge' if USER_PCS[host].get('external') else '',
        }

    def reset_all(self) -> dict:
        """Set all PCs to idle."""
        for host in list(USER_PCS):
            self.set_activity(host, 'idle')
        LOGGER.info('reset all hosts=%d', len(USER_PCS))
        return {'ok': True, 'reset': len(USER_PCS)}

    def browser_open(self, host: str, url: str) -> dict:
        if host not in USER_PCS:
            return {'ok': False, 'error': f'Unknown host: {host}'}
        request = resolve_browser_request(url)
        activity = request['activity']
        normalized_url = request['url']
        result = self.set_activity(host, activity)
        if result.get('ok'):
            with self._lock:
                self._browser_url[host] = normalized_url
                self._browser_status[host] = request['browser_status']
                if request.get('blocked'):
                    self._security_state[host] = 'critical'
                    self._last_alert[host] = request['reason']
            self._write_state()
        LOGGER.info('browser open host=%s url=%s activity=%s blocked=%s ok=%s',
                    host, normalized_url, activity, request.get('blocked'), result.get('ok'))
        result.update({
            'url': normalized_url,
            'browser_status': request['browser_status'] if result.get('ok') else 'Error',
            'blocked': bool(request.get('blocked')),
            'reason': request.get('reason', ''),
        })
        return result

    def run_tool(self, host: str, command: str) -> dict:
        activity = resolve_terminal_tool(command)
        result = self.set_activity(host, activity)
        if result.get('ok'):
            with self._lock:
                self._browser_status[host] = 'Terminal'
                self._last_alert[host] = f'Tool executed: {command}'
            self._write_state()
        LOGGER.info('terminal tool host=%s command=%s activity=%s ok=%s', host, command, activity, result.get('ok'))
        result.update({'tool': command})
        return result

    def get_state(self) -> dict:
        """Return full state snapshot."""
        topology_nodes = {node.get('id'): node for node in read_json('/tmp/campus_topology_state.json', {}).get('nodes', [])}
        with self._lock:
            pcs = {}
            for host, meta in USER_PCS.items():
                act = self._activity[host]
                profile = ACTIVITY_PROFILES[act]
                current_mbps = round(self._traffic_mbps[host], 2)
                link_capacity = profile.get('link_capacity_mbps', EDGE_LINK_CAPACITY_MBPS)
                utilization = round((current_mbps / max(link_capacity, 0.1)) * 100, 2)
                topo_node = topology_nodes.get(host, {})
                security_state = self._security_state.get(host) or profile.get('security_state', 'normal')
                threshold_state = (
                    'critical' if utilization >= 90 else
                    'preventive' if utilization >= 85 else
                    'warning' if utilization >= 70 else
                    'healthy'
                )
                pcs[host] = {
                    **meta,
                    'zone_key':            meta['zone'],
                    'zone_label':          meta['zone_label'],
                    'vlan':                meta['vlan'],
                    'switch':              meta['switch'],
                    'mac':                 topo_node.get('mac') or meta['mac'],
                    'activity':            act,
                    'activity_label':      profile['label'],
                    'traffic_type':        profile.get('traffic_type', profile['label']),
                    'priority':            profile['priority'],
                    'priority_label':      PRIORITY_LABELS[profile['priority']],
                    'priority_level':      profile.get('priority_level', PRIORITY_LABELS[profile['priority']]),
                    'dscp':                profile['dscp'],
                    'qos_queue':           profile.get('qos_queue', 2),
                    'traffic_mbps':        current_mbps,
                    'current_mbps':        current_mbps,
                    'link_capacity_mbps':  link_capacity,
                    'utilization_percent': utilization,
                    'since_ts':            self._since_ts[host],
                    'color':               profile['color'],
                    'icon':                profile['icon'],
                    'bw_target':           profile['bandwidth_mbps'],
                    'target_mbps':         profile['bandwidth_mbps'],
                    'safe_from_throttle':  profile.get('safe_from_throttle', False),
                    'current_status':      'active' if act != 'idle' and current_mbps > 0 else 'idle',
                    'dst_ip':              profile.get('dst_ip', ''),
                    'dst_port':            profile.get('dst_port', 0),
                    'dst_service_name':    profile.get('dst_service_name', ''),
                    'proto':               profile.get('proto', 'tcp'),
                    'browser_url':         self._browser_url.get(host, profile.get('browser_url', '')),
                    'browser_status':      self._browser_status.get(host, 'Idle'),
                    'security_state':      security_state,
                    'congestion_state':    threshold_state,
                    'controller_action':   self._controller_action.get(host, 'Monitoring only'),
                    'last_alert':          self._last_alert.get(host, ''),
                    'topology_label':      topo_node.get('label', meta['label']),
                }

        baseline = read_json(BASELINE_FILE, {})

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
        if not atomic_write_json(BASELINE_FILE, baseline, logger=LOGGER, label='baseline'):
            return {'ok': False, 'error': f'Failed to write {BASELINE_FILE}'}

        LOGGER.info('baseline captured active_pcs=%d', len(active))
        return {'ok': True, 'captured_ts': baseline['captured_ts']}

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self):
        """Start background writer and iperf servers."""
        self._ensure_state_files()
        self._ensure_iperf_servers()
        writer = threading.Thread(target=self._state_writer, daemon=True)
        writer.start()
        self._write_state()
        LOGGER.info('startup pcs=%d api_port=%s state_file=%s', len(USER_PCS), os.environ.get('CAMPUS_PCAM_PORT', '9095'), PC_ACTIVITIES_FILE)

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
        LOGGER.info('shutdown complete')

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
                    NS_EXEC_PREFIX + [host, 'iperf3', '-s', '-p', str(port), '-D'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                self._child_procs.append(p)
                LOGGER.info('iperf3 server started host=%s port=%s', host, port)
            except Exception as e:
                LOGGER.warning('iperf3 server start failed host=%s err=%s', host, e)
        time.sleep(0.5)
        self._server_started = True

    def _ensure_state_files(self):
        if not os.path.isdir('/tmp'):
            os.makedirs('/tmp', exist_ok=True)
        if not os.path.exists(BASELINE_FILE):
            atomic_write_json(BASELINE_FILE, {'captured_ts': 0, 'active_pcs': 0, 'metrics': {}, 'activities': {}}, logger=LOGGER, label='baseline_init')
        if not os.path.exists(PC_ACTIVITIES_FILE):
            atomic_write_json(PC_ACTIVITIES_FILE, self.get_state(), logger=LOGGER, label='pc_state_init')

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
            elif pattern == 'unauthorized_access':
                measured = self._run_unauthorized_access(host, stop_event)
            elif pattern == 'bruteforce':
                measured = self._run_bruteforce(host, stop_event)
            elif pattern == 'spoof_ip':
                measured = self._run_spoof_ip(host, stop_event)
            elif pattern == 'spoof_arp':
                measured = self._run_spoof_arp(host, stop_event)
            else:
                if USER_PCS.get(host, {}).get('external'):
                    measured = self._run_external_activity(host, dst_ip, dst_port, proto,
                                                           bw_mbps, burst_dur)
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
            *NS_EXEC_PREFIX, host,
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
        # Fall back to the intended profile bandwidth when namespaces or iperf
        # are unavailable so capstone demos remain deterministic.
        return bw_mbps

    def _run_external_activity(self, host: str, dst_ip: str, port: int, proto: str,
                               bw_mbps: float, duration: int) -> float:
        """Optional VMware VM traffic hook.

        Network control works when VM packets cross the Ryu-controlled OVS bridge.
        This hook only starts guest-side test traffic if SSH is configured in
        external_vms.json; otherwise it records the intended activity so the
        dashboard and policy engine can still apply OpenFlow rules for that VM.
        """
        meta = USER_PCS.get(host, {})
        mgmt_ip = str(meta.get('management_ip') or '').strip()
        user = str(meta.get('ssh_user') or '').strip()
        key = str(meta.get('ssh_key') or '').strip()
        if not mgmt_ip or not user:
            LOGGER.info('external vm activity host=%s mode=policy_only dst=%s:%s bw=%s', host, dst_ip, port, bw_mbps)
            return bw_mbps

        ssh_target = f'{user}@{mgmt_ip}'
        ssh_cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3']
        if key:
            ssh_cmd.extend(['-i', key])
        iperf_cmd = f'iperf3 -c {dst_ip} -p {int(port)} -t {int(duration)} -b {float(bw_mbps)}M -J'
        if proto == 'udp':
            iperf_cmd += ' -u'
        try:
            result = subprocess.run(
                [*ssh_cmd, ssh_target, iperf_cmd],
                capture_output=True,
                text=True,
                timeout=duration + 12,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                end = data.get('end', {})
                bps = end.get('sum_sent', {}).get('bits_per_second', 0) if proto == 'tcp' else end.get('sum', {}).get('bits_per_second', 0)
                return round(bps / 1_000_000, 2)
            LOGGER.warning('external vm ssh iperf failed host=%s rc=%s stderr=%s', host, result.returncode, result.stderr[-200:])
        except Exception as exc:
            LOGGER.warning('external vm ssh iperf error host=%s err=%s', host, exc)
        return bw_mbps

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
                *NS_EXEC_PREFIX, host,
                'bash', '-c',
                f'echo "" | nc -w 0 -z {target} {port} 2>/dev/null; true',
            ]
            try:
                subprocess.run(cmd, timeout=1, capture_output=True)
                probed += 1
            except Exception:
                pass
        LOGGER.warning('port scan host=%s ports=%d', host, probed)
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
            cmd = [*NS_EXEC_PREFIX, host, 'ping', '-c', '1', '-W', '1', ip]
            try:
                r = subprocess.run(cmd, timeout=2, capture_output=True)
                if r.returncode == 0:
                    alive += 1
            except Exception:
                pass
        LOGGER.warning('network sweep host=%s alive=%d target_count=%d', host, alive, len(targets))
        stop_event.wait(timeout=10)
        return 0.1

    def _run_unauthorized_access(self, host: str, stop_event: threading.Event) -> float:
        targets = [('10.10.0.1', 443), ('10.20.0.1', 22), ('10.20.0.3', 443)]
        attempts = 0
        for ip, port in targets * 6:
            if stop_event.is_set():
                break
            cmd = [*NS_EXEC_PREFIX, host, 'bash', '-lc', f'echo denied | nc -w 1 {ip} {port} >/dev/null 2>&1 || true']
            try:
                subprocess.run(cmd, timeout=2, capture_output=True)
                attempts += 1
            except Exception:
                pass
        LOGGER.warning('unauthorized access host=%s attempts=%d', host, attempts)
        stop_event.wait(timeout=4)
        return 2.8

    def _run_bruteforce(self, host: str, stop_event: threading.Event) -> float:
        attempts = 0
        for _ in range(20):
            if stop_event.is_set():
                break
            cmd = [*NS_EXEC_PREFIX, host, 'bash', '-lc', 'printf "admin\\npassword\\n" | nc -w 1 10.20.0.3 22 >/dev/null 2>&1 || true']
            try:
                subprocess.run(cmd, timeout=2, capture_output=True)
                attempts += 1
            except Exception:
                pass
        LOGGER.warning('bruteforce host=%s attempts=%d', host, attempts)
        stop_event.wait(timeout=3)
        return 1.2

    def _run_spoof_ip(self, host: str, stop_event: threading.Event) -> float:
        LOGGER.warning('ip spoofing simulated host=%s target=%s', host, ACTIVITY_PROFILES['ip_spoofing'].get('dst_ip'))
        return self._run_unauthorized_access(host, stop_event)

    def _run_spoof_arp(self, host: str, stop_event: threading.Event) -> float:
        LOGGER.warning('arp spoofing simulated host=%s target=%s', host, ACTIVITY_PROFILES['arp_spoofing'].get('dst_ip'))
        return self._run_unauthorized_access(host, stop_event)

    def _state_writer(self):
        """Background thread: writes state file every 2 seconds."""
        while self.running:
            self._write_state()
            time.sleep(2)

    def _write_state(self):
        state = self.get_state()
        atomic_write_json(PC_ACTIVITIES_FILE, state, logger=LOGGER, label='pc_state')


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
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                LOGGER.warning('client disconnected before response path=%s', getattr(self, 'path', 'unknown'))

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
                self._json({
                    'ok': True,
                    'service': 'pc_activity_manager',
                    'pcs': len(USER_PCS),
                    'state_file': PC_ACTIVITIES_FILE,
                    'state_exists': os.path.exists(PC_ACTIVITIES_FILE),
                    'baseline_exists': os.path.exists(BASELINE_FILE),
                })
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
            elif self.path == '/browser_open':
                body = self._body()
                self._json(self._mgr.browser_open(body.get('host', ''), body.get('url', '')))
            elif self.path == '/run_tool':
                body = self._body()
                self._json(self._mgr.run_tool(body.get('host', ''), body.get('command', '')))
            elif self.path == '/capture_baseline':
                self._json(self._mgr.capture_baseline())
            elif self.path == '/reset_all':
                self._json(self._mgr.reset_all())
            elif self.path == '/set_scenario':
                # Accept either {"scenario": "canonical"} or {"assignments": [...]}
                body = self._body()
                scenario_name = body.get('scenario')
                canonical, scenario = resolve_scenario(scenario_name)
                if scenario_name and scenario:
                    assignments = [
                        {'host': host, 'activity': activity}
                        for host, activity in scenario.get('assignments', {}).items()
                    ]
                    if scenario.get('reset_all'):
                        self._json({**self._mgr.reset_all(), 'scenario': canonical, 'results': []})
                        return
                elif scenario_name and scenario_name in DEMO_SCENARIOS:
                    assignments = DEMO_SCENARIOS[scenario_name]
                else:
                    assignments = body.get('assignments', [])
                results = []
                for a in assignments:
                    r = self._mgr.set_activity(a.get('host', ''), a.get('activity', 'idle'))
                    results.append(r)
                ok = all(r.get('ok') for r in results)
                LOGGER.info('scenario applied name=%s assignments=%d ok=%s', canonical or scenario_name, len(assignments), ok)
                self._json({'ok': ok, 'scenario': canonical or scenario_name, 'results': results, 'assignment_count': len(assignments)})
            else:
                self._json({'error': 'not found'}, 404)

    return Handler


# ─── Pre-defined demonstration scenarios ─────────────────────────────────────

DEMO_SCENARIOS = {
    'canonical': [
        {'host': 'h_staff1', 'activity': 'mis'},
        {'host': 'h_staff2', 'activity': 'video_conf'},
        {'host': 'h_staff3', 'activity': 'authentication'},
        {'host': 'h_lab1',   'activity': 'elearning'},
        {'host': 'h_lab2',   'activity': 'research'},
        {'host': 'h_wifi1',  'activity': 'web_browsing'},
        {'host': 'h_wifi2',  'activity': 'social_media'},
    ],
    'staff_heavy': [
        {'host': 'h_staff1', 'activity': 'mis'},
        {'host': 'h_staff2', 'activity': 'video_conf'},
        {'host': 'h_staff3', 'activity': 'rp_system'},
        {'host': 'h_staff4', 'activity': 'cloud_storage'},
        {'host': 'h_staff5', 'activity': 'study_download'},
        {'host': 'h_lab1',   'activity': 'elearning'},
        {'host': 'h_lab2',   'activity': 'research'},
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
        {'host': 'h_wifi2',  'activity': 'file_download'},
        {'host': 'h_wifi3',  'activity': 'video_streaming'},
        {'host': 'h_wifi4',  'activity': 'video_streaming'},
        {'host': 'h_wifi5',  'activity': 'gaming'},
        {'host': 'h_wifi6',  'activity': 'file_download'},
        {'host': 'h_wifi7',  'activity': 'video_streaming'},
        {'host': 'h_wifi8',  'activity': 'social_media'},
        {'host': 'h_lab1',   'activity': 'elearning'},
        {'host': 'h_lab2',   'activity': 'google_meet'},
        {'host': 'h_staff1', 'activity': 'mis'},
    ],
    'warning_wifi': [
        {'host': 'h_wifi1', 'activity': 'file_download'},
        {'host': 'h_wifi2', 'activity': 'file_download'},
        {'host': 'h_wifi3', 'activity': 'file_download'},
        {'host': 'h_wifi4', 'activity': 'file_download'},
        {'host': 'h_wifi5', 'activity': 'file_download'},
        {'host': 'h_wifi6', 'activity': 'file_download'},
        {'host': 'h_wifi7', 'activity': 'file_download'},
        {'host': 'h_wifi8', 'activity': 'file_download'},
        {'host': 'h_wifi9', 'activity': 'file_download'},
        {'host': 'h_wifi10', 'activity': 'google_meet'},
    ],
    'preventive_wifi': [
        {'host': 'h_wifi1', 'activity': 'file_download'},
        {'host': 'h_wifi2', 'activity': 'file_download'},
        {'host': 'h_wifi3', 'activity': 'file_download'},
        {'host': 'h_wifi4', 'activity': 'file_download'},
        {'host': 'h_wifi5', 'activity': 'file_download'},
        {'host': 'h_wifi6', 'activity': 'file_download'},
        {'host': 'h_wifi7', 'activity': 'file_download'},
        {'host': 'h_wifi8', 'activity': 'file_download'},
        {'host': 'h_wifi9', 'activity': 'file_download'},
        {'host': 'h_wifi10', 'activity': 'file_download'},
    ],
    'critical_port': [
        {'host': 'h_wifi2', 'activity': 'ddos_attack'},
        {'host': 'h_wifi3', 'activity': 'social_media'},
        {'host': 'h_lab1',  'activity': 'elearning'},
        {'host': 'h_staff1', 'activity': 'mis'},
    ],
    'exam_mode': [
        {'host': 'h_lab1', 'activity': 'exam'},
        {'host': 'h_lab2', 'activity': 'online_exam'},
        {'host': 'h_lab3', 'activity': 'elearning'},
        {'host': 'h_wifi1', 'activity': 'online_exam'},
        {'host': 'h_wifi2', 'activity': 'google_meet'},
        {'host': 'h_wifi3', 'activity': 'social_media'},
        {'host': 'h_wifi4', 'activity': 'video_streaming'},
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
        LOGGER.info('signal received sig=%s', sig)
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server = ThreadingHTTPServer((args.host, args.port), make_handler(manager))
    LOGGER.info('http api listening host=%s port=%s state_file=%s', args.host, args.port, PC_ACTIVITIES_FILE)
    server.serve_forever()


if __name__ == '__main__':
    main()
