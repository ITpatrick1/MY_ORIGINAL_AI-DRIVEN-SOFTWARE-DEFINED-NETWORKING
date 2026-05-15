#!/usr/bin/env python3
"""
Autonomous Traffic Simulation Engine — Tumba College SDN

Simulates realistic campus user behaviour based on:
  - Academic timetable period (exam / lecture / lab / admin / off)
  - Zone & role (staff / student)
  - Time-of-day variation
  - Random scenario injection (DDoS, congestion burst)

Runs as a background daemon. Every CYCLE_SECONDS it re-evaluates each PC
and probabilistically assigns or changes its activity, then POSTs to the
PC Activity Manager API so real iperf3 traffic flows in Mininet.

HTTP API (port 9097):
  GET  /state        → current auto-traffic state
  POST /pause        → stop autonomous changes
  POST /resume       → restart autonomous changes
  POST /scenario     → {"name": "exam" | "congestion" | "ddos" | "off_peak"}
"""

import json
import os
import random
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tumba_sdn.common.campus_core import (
    SCENARIO_LIBRARY,
    atomic_write_json,
    configure_file_logger,
    read_json,
    resolve_scenario,
)

# ─── Config ───────────────────────────────────────────────────────────────────
PCAM_API        = os.environ.get('CAMPUS_PCAM_API', 'http://127.0.0.1:9095')
TIMETABLE_FILE  = os.environ.get('CAMPUS_TIMETABLE_STATE', '/tmp/campus_timetable_state.json')
METRICS_FILE    = os.environ.get('CAMPUS_METRICS_FILE', '/tmp/campus_metrics.json')
STATE_FILE      = '/tmp/campus_auto_traffic_state.json'
API_PORT        = int(os.environ.get('CAMPUS_AUTO_TRAFFIC_PORT', '9097'))
LOGGER = configure_file_logger('tumba.auto_traffic', 'auto_traffic.log')

CYCLE_SECONDS   = 25   # How often each PC may change activity
JITTER          = 10   # ± random seconds added to cycle

# ─── PC definitions ──────────────────────────────────────────────────────────
PCS = [
    {'id': 'h_staff1', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff2', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff3', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff4', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff5', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff6', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_lab1',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_lab2',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_lab3',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_lab4',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_wifi1',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi2',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi3',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi4',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi5',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi6',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi7',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi8',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi9',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi10', 'zone': 'student_wifi', 'role': 'student'},
]

# ─── Behaviour profiles ───────────────────────────────────────────────────────
# weights: activity → relative probability for each (period, role)
PROFILES = {
    'exam': {
        'staff':   {'mis': 20, 'video_conf': 25, 'authentication': 10, 'elearning': 20, 'idle': 25},
        'student': {'exam': 45, 'online_exam': 20, 'elearning': 20, 'google_meet': 10, 'idle': 5},
    },
    'lecture': {
        'staff':   {'video_conf': 25, 'mis': 20, 'siad': 15, 'cloud_storage': 10, 'idle': 30},
        'student': {'elearning': 28, 'online_class': 18, 'research': 18, 'web_browsing': 16, 'social_media': 10, 'idle': 10},
    },
    'lab': {
        'staff':   {'video_conf': 15, 'cloud_storage': 20, 'rp_system': 15, 'idle': 50},
        'student': {'study_download': 22, 'research': 22, 'elearning': 20, 'cloud_storage': 14, 'social_media': 8, 'idle': 14},
    },
    'admin': {
        'staff':   {'mis': 28, 'siad': 22, 'rp_system': 18, 'cloud_storage': 12, 'idle': 20},
        'student': {'web_browsing': 28, 'social_media': 18, 'video_streaming': 16, 'elearning': 16, 'idle': 22},
    },
    'evening_study': {
        'staff':   {'idle': 70, 'web_browsing': 10, 'mis': 10, 'cloud_storage': 10},
        'student': {'elearning': 25, 'research': 20, 'study_download': 18, 'social_media': 17, 'video_streaming': 10, 'idle': 10},
    },
    'off': {
        'staff':   {'idle': 88, 'web_browsing': 8, 'mis': 4},
        'student': {'idle': 55, 'social_media': 18, 'gaming': 10, 'video_streaming': 9, 'web_browsing': 8},
    },
}

# Small chance a student PC performs a port scan during any period (for detection demo)
SCAN_PROBABILITY = 0.04   # 4% chance per cycle
# Fall back to this if timetable period not found
DEFAULT_PERIOD  = 'evening_study'

# ─── Named demo scenarios (override autonomous behaviour temporarily) ──────────
SCENARIOS = {
    'normal_traffic': {
        'duration_s': 120,
        'overrides': {
            'h_staff1': 'mis', 'h_staff2': 'video_conf', 'h_staff3': 'web_browsing',
            'h_lab1': 'elearning', 'h_lab2': 'research', 'h_lab3': 'study_download',
            'h_wifi1': 'web_browsing', 'h_wifi2': 'social_media', 'h_wifi3': 'elearning',
            'h_wifi4': 'idle',
        },
    },
    'exam': {
        'duration_s': 120,
        'overrides': {
            'h_staff1': 'mis', 'h_staff2': 'video_conf', 'h_staff3': 'authentication',
            'h_lab1': 'exam', 'h_lab2': 'online_exam', 'h_lab3': 'exam', 'h_lab4': 'elearning',
            'h_wifi1': 'online_exam', 'h_wifi2': 'exam', 'h_wifi3': 'elearning', 'h_wifi4': 'google_meet',
            'h_wifi5': 'online_exam', 'h_wifi6': 'elearning',
        },
    },
    'warning_wifi': {
        'duration_s': 90,
        'overrides': {
            'h_wifi1': 'file_download', 'h_wifi2': 'file_download', 'h_wifi3': 'file_download',
            'h_wifi4': 'file_download', 'h_wifi5': 'file_download', 'h_wifi6': 'file_download',
            'h_wifi7': 'file_download', 'h_wifi8': 'file_download', 'h_wifi9': 'file_download',
            'h_wifi10': 'google_meet',
        },
    },
    'preventive_wifi': {
        'duration_s': 90,
        'overrides': {
            'h_wifi1': 'file_download', 'h_wifi2': 'file_download', 'h_wifi3': 'file_download',
            'h_wifi4': 'file_download', 'h_wifi5': 'file_download', 'h_wifi6': 'file_download',
            'h_wifi7': 'file_download', 'h_wifi8': 'file_download', 'h_wifi9': 'file_download',
            'h_wifi10': 'file_download',
        },
    },
    'congestion': {
        'duration_s': 120,
        'overrides': {
            'h_wifi1': 'file_download', 'h_wifi2': 'file_download', 'h_wifi3': 'video_streaming',
            'h_wifi4': 'video_streaming', 'h_wifi5': 'file_download', 'h_wifi6': 'gaming',
            'h_wifi7': 'video_streaming', 'h_wifi8': 'social_media', 'h_wifi9': 'elearning',
            'h_wifi10': 'google_meet', 'h_lab1': 'research', 'h_lab2': 'study_download',
            'h_staff1': 'mis', 'h_staff2': 'video_conf',
        },
    },
    'critical_port': {
        'duration_s': 75,
        'overrides': {
            'h_wifi2': 'ddos_attack', 'h_wifi3': 'social_media',
            'h_lab1': 'elearning', 'h_staff1': 'mis',
        },
    },
    'academic_priority': {
        'duration_s': 90,
        'overrides': {
            'h_wifi1': 'elearning', 'h_wifi2': 'google_meet', 'h_wifi3': 'social_media',
            'h_wifi4': 'video_streaming', 'h_wifi5': 'file_download', 'h_wifi6': 'gaming',
            'h_lab1': 'online_class', 'h_lab2': 'research',
        },
    },
    'low_priority_control': {
        'duration_s': 90,
        'overrides': {
            'h_wifi1': 'social_media', 'h_wifi2': 'video_streaming', 'h_wifi3': 'gaming',
            'h_wifi4': 'file_download', 'h_wifi5': 'social_media', 'h_wifi6': 'video_streaming',
            'h_lab1': 'elearning', 'h_staff1': 'mis',
        },
    },
    'ddos': {
        'duration_s': 60,
        'overrides': {
            'h_wifi3': 'ddos_attack', 'h_wifi4': 'ddos_attack',
            'h_wifi5': 'ddos_attack',
            'h_staff1': 'exam', 'h_staff2': 'video_conf',
            'h_lab1': 'elearning',
        },
    },
    'off_peak': {
        'duration_s': 90,
        'overrides': {pc['id']: 'idle' for pc in PCS},
    },
    'staff_heavy': {
        'duration_s': 90,
        'overrides': {
            'h_staff1': 'mis', 'h_staff2': 'video_conf', 'h_staff3': 'rp_system',
            'h_staff4': 'cloud_storage', 'h_staff5': 'study_download', 'h_staff6': 'mis',
            'h_lab1': 'elearning', 'h_lab2': 'research',
        },
    },
    'scanning': {
        'duration_s': 60,
        'overrides': {
            'h_wifi3': 'port_scan', 'h_wifi4': 'network_sweep',
            'h_lab3':  'port_scan', 'h_lab4': 'network_sweep',
            'h_staff1': 'elearning', 'h_staff2': 'video_conf',
        },
    },
    # P2: Scalability — simulates 200% user growth by maxing all zones simultaneously.
    # The DQN agent must load-balance and throttle to maintain Staff/Server SLOs
    # despite the full network being saturated. Demonstrates adaptive capacity management.
    'scalability_stress': {
        'duration_s': 120,
        'overrides': {
            'h_wifi1': 'file_download', 'h_wifi2': 'file_download', 'h_wifi3': 'video_streaming',
            'h_wifi4': 'video_streaming', 'h_wifi5': 'file_download', 'h_wifi6': 'video_streaming',
            'h_wifi7': 'gaming', 'h_wifi8': 'file_download', 'h_wifi9': 'video_streaming',
            'h_wifi10': 'gaming',
            'h_lab1': 'study_download', 'h_lab2': 'cloud_storage', 'h_lab3': 'research', 'h_lab4': 'study_download',
            'h_staff1': 'video_conf', 'h_staff2': 'mis', 'h_staff3': 'rp_system',
            'h_staff4': 'cloud_storage', 'h_staff5': 'study_download', 'h_staff6': 'mis',
        },
    },
    # P5: Intelligent routing — test that DQN selects load_balance_ds1_ds2 and
    # DSCP marking redirects traffic correctly when one distribution link is loaded.
    'routing_test': {
        'duration_s': 90,
        'overrides': {
            'h_staff1': 'cloud_storage', 'h_staff2': 'study_download', 'h_staff3': 'video_conf',
            'h_staff4': 'mis', 'h_staff5': 'rp_system',
            'h_lab1': 'idle', 'h_lab2': 'idle', 'h_lab3': 'research', 'h_lab4': 'idle',
            'h_wifi1': 'idle', 'h_wifi2': 'elearning', 'h_wifi3': 'idle', 'h_wifi4': 'social_media',
        },
    },
}

for _scenario_name, _scenario in SCENARIO_LIBRARY.items():
    SCENARIOS[_scenario_name] = {
        'duration_s': int(_scenario.get('duration_s', 90)),
        'overrides': dict(_scenario.get('assignments', {})),
        'reset_all': bool(_scenario.get('reset_all', False)),
        'description': _scenario.get('description', ''),
    }


def _weighted_choice(weights: dict) -> str:
    """Pick a random key using integer weights."""
    population = []
    for act, w in weights.items():
        population.extend([act] * int(w))
    return random.choice(population)


def _read_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _pcam_set(host: str, activity: str) -> bool:
    """POST /set_activity to the PC Activity Manager."""
    try:
        payload = json.dumps({'host': host, 'activity': activity}).encode()
        req = urllib.request.Request(
            f'{PCAM_API}/set_activity',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as exc:
        LOGGER.warning('pcam set failed host=%s activity=%s err=%s', host, activity, exc)
        return False


def _pcam_reset() -> bool:
    try:
        req = urllib.request.Request(
            f'{PCAM_API}/reset_all',
            data=b'{}',
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as exc:
        LOGGER.warning('pcam reset failed err=%s', exc)
        return False


class AutoTrafficEngine:
    def __init__(self):
        self.paused          = False
        self.scenario_name   = None
        self.scenario_until  = 0.0
        self.scenario_overrides: dict = {}
        self.pc_next_change  = {pc['id']: time.time() + random.uniform(5, 30) for pc in PCS}
        self.pc_activity     = {pc['id']: 'idle' for pc in PCS}
        self.change_log      = []   # last 100 changes
        self._lock           = threading.Lock()
        self._thread         = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        LOGGER.info('engine started cycle=%ss jitter=%ss', CYCLE_SECONDS, JITTER)

    # ── Public API ────────────────────────────────────────────────────────────
    def pause(self):
        with self._lock:
            self.paused = True

    def resume(self):
        with self._lock:
            self.paused = False

    def trigger_scenario(self, name: str) -> dict:
        canonical, resolved = resolve_scenario(name)
        sc = SCENARIOS.get(canonical) or SCENARIOS.get(name)
        if not sc:
            return {'ok': False, 'error': f'Unknown scenario: {name}', 'available': sorted(SCENARIOS.keys())}
        if sc.get('reset_all'):
            ok = _pcam_reset()
            with self._lock:
                self.scenario_name = None
                self.scenario_until = 0.0
                self.scenario_overrides = {}
                self.paused = False
            self._write_state()
            LOGGER.info('scenario reset requested name=%s ok=%s', canonical or name, ok)
            return {'ok': ok, 'scenario': canonical or name, 'duration_s': 0, 'reset_all': True}
        with self._lock:
            self.scenario_name     = canonical or name
            self.scenario_until    = time.time() + sc['duration_s']
            self.scenario_overrides = {pc['id']: 'idle' for pc in PCS}
            self.scenario_overrides.update(dict(sc['overrides']))
        # Apply immediately
        self._apply_overrides(self.scenario_overrides)
        LOGGER.info(
            'scenario triggered name=%s duration=%s explicit_assignments=%d reset_to_idle=%d',
            canonical or name,
            sc['duration_s'],
            len(sc.get('overrides', {})),
            len(self.scenario_overrides) - len(sc.get('overrides', {})),
        )
        return {
            'ok': True,
            'scenario': canonical or name,
            'duration_s': sc['duration_s'],
            'assignment_count': len(sc.get('overrides', {})),
            'reset_to_idle_count': len(self.scenario_overrides) - len(sc.get('overrides', {})),
            'description': sc.get('description', ''),
        }

    def state(self) -> dict:
        with self._lock:
            return {
                'ts':              time.time(),
                'paused':          self.paused,
                'scenario':        self.scenario_name,
                'scenario_active': time.time() < self.scenario_until,
                'activities':      dict(self.pc_activity),
                'recent_changes':  self.change_log[-20:],
            }

    # ── Internal loop ─────────────────────────────────────────────────────────
    def _loop(self):
        while True:
            time.sleep(2)
            with self._lock:
                paused = self.paused
                scenario_active = time.time() < self.scenario_until

            if paused:
                continue

            if scenario_active:
                continue   # scenario overrides handle everything

            # Scenario just expired — resume autonomous
            if self.scenario_name and time.time() >= self.scenario_until:
                with self._lock:
                    self.scenario_name     = None
                    self.scenario_overrides = {}
                LOGGER.info('scenario expired, autonomous mode resumed')

            self._autonomous_tick()

    def _autonomous_tick(self):
        """For each PC whose timer has expired, pick a new activity."""
        timetable  = _read_json(TIMETABLE_FILE)
        period     = timetable.get('period', DEFAULT_PERIOD)
        exam_flag  = bool(timetable.get('exam_flag', 0))

        if exam_flag:
            period = 'exam'

        profile = PROFILES.get(period, PROFILES[DEFAULT_PERIOD])
        now     = time.time()

        for pc in PCS:
            pid = pc['id']
            if now < self.pc_next_change.get(pid, 0):
                continue

            role    = pc['role']
            weights = profile.get(role, profile.get('student', {'idle': 100}))
            activity = _weighted_choice(weights)

            # Small chance of a random congestion spike on WiFi
            if pc['zone'] == 'student_wifi' and random.random() < 0.08:
                activity = random.choice(['file_download', 'video_streaming'])

            # Rare port scan / sweep from student zones (anomaly injection)
            if pc['zone'] in ('student_wifi', 'it_lab') and random.random() < SCAN_PROBABILITY:
                activity = random.choice(['port_scan', 'network_sweep'])

            # Only push if changed
            if activity != self.pc_activity.get(pid):
                ok = _pcam_set(pid, activity)
                if ok:
                    with self._lock:
                        self.pc_activity[pid] = activity
                        self.change_log.append({
                            'ts':       now,
                            'host':     pid,
                            'activity': activity,
                            'period':   period,
                        })
                        self.change_log = self.change_log[-100:]

            # Schedule next change with jitter
            self.pc_next_change[pid] = now + CYCLE_SECONDS + random.uniform(-JITTER, JITTER)

    def _apply_overrides(self, overrides: dict):
        """Push scenario overrides to PCAM immediately."""
        for host, activity in overrides.items():
            ok = _pcam_set(host, activity)
            if ok:
                with self._lock:
                    self.pc_activity[host] = activity
                    self.change_log.append({
                        'ts': time.time(), 'host': host,
                        'activity': activity, 'period': 'scenario',
                    })
                LOGGER.info('override applied host=%s activity=%s', host, activity)
        self._write_state()

    def _write_state(self):
        atomic_write_json(STATE_FILE, self.state(), logger=LOGGER, label='auto_traffic_state')


# ─── HTTP API ─────────────────────────────────────────────────────────────────
def make_handler(engine: AutoTrafficEngine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _json(self, data, code=200):
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            n = int(self.headers.get('Content-Length', 0))
            return json.loads(self.rfile.read(n)) if n else {}

        def do_GET(self):
            if self.path == '/state':
                self._json(engine.state())
            elif self.path == '/health':
                state = engine.state()
                self._json({
                    'ok': True,
                    'service': 'auto_traffic',
                    'paused': state.get('paused', False),
                    'scenario': state.get('scenario'),
                    'state_file': STATE_FILE,
                    'state_exists': os.path.exists(STATE_FILE),
                })
            elif self.path == '/scenarios':
                self._json({'scenarios': list(SCENARIOS.keys())})
            else:
                self._json({'error': 'not found'}, 404)

        def do_POST(self):
            if self.path == '/pause':
                engine.pause()
                self._json({'ok': True, 'paused': True})
            elif self.path == '/resume':
                engine.resume()
                self._json({'ok': True, 'paused': False})
            elif self.path == '/scenario':
                body = self._body()
                result = engine.trigger_scenario(body.get('name', ''))
                self._json(result)
            else:
                self._json({'error': 'not found'}, 404)

    return Handler


def main():
    engine  = AutoTrafficEngine()
    engine._write_state()
    server  = ThreadingHTTPServer(('0.0.0.0', API_PORT), make_handler(engine))
    LOGGER.info('http api listening host=0.0.0.0 port=%s', API_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
