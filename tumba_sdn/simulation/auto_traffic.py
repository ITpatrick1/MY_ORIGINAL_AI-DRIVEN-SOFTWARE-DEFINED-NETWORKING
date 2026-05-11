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

# ─── Config ───────────────────────────────────────────────────────────────────
PCAM_API        = os.environ.get('CAMPUS_PCAM_API', 'http://127.0.0.1:9095')
TIMETABLE_FILE  = os.environ.get('CAMPUS_TIMETABLE_STATE', '/tmp/campus_timetable_state.json')
METRICS_FILE    = os.environ.get('CAMPUS_METRICS_FILE', '/tmp/campus_metrics.json')
STATE_FILE      = '/tmp/campus_auto_traffic_state.json'
API_PORT        = int(os.environ.get('CAMPUS_AUTO_TRAFFIC_PORT', '9097'))

CYCLE_SECONDS   = 25   # How often each PC may change activity
JITTER          = 10   # ± random seconds added to cycle

# ─── PC definitions ──────────────────────────────────────────────────────────
PCS = [
    {'id': 'h_staff1', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff2', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_staff3', 'zone': 'staff_lan',    'role': 'staff'},
    {'id': 'h_lab1',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_lab2',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_lab3',   'zone': 'it_lab',       'role': 'student'},
    {'id': 'h_wifi1',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi2',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi3',  'zone': 'student_wifi', 'role': 'student'},
    {'id': 'h_wifi4',  'zone': 'student_wifi', 'role': 'student'},
]

# ─── Behaviour profiles ───────────────────────────────────────────────────────
# weights: activity → relative probability for each (period, role)
PROFILES = {
    'exam': {
        'staff':   {'video_conf': 30, 'elearning': 25, 'file_download': 20, 'idle': 25},
        'student': {'exam': 70, 'elearning': 20, 'idle': 10},
    },
    'lecture': {
        'staff':   {'video_conf': 35, 'elearning': 25, 'file_download': 15, 'idle': 25},
        'student': {'elearning': 45, 'social_media': 25, 'video_streaming': 15, 'idle': 15},
    },
    'lab': {
        'staff':   {'video_conf': 20, 'file_download': 30, 'elearning': 25, 'idle': 25},
        'student': {'file_download': 40, 'elearning': 30, 'social_media': 15, 'idle': 15},
    },
    'admin': {
        'staff':   {'video_conf': 30, 'file_download': 25, 'elearning': 20, 'idle': 25},
        'student': {'social_media': 40, 'video_streaming': 25, 'elearning': 15, 'idle': 20},
    },
    'evening_study': {
        'staff':   {'idle': 65, 'elearning': 20, 'file_download': 15},
        'student': {'elearning': 35, 'social_media': 30, 'video_streaming': 20, 'idle': 15},
    },
    'off': {
        'staff':   {'idle': 85, 'elearning': 15},
        'student': {'idle': 55, 'social_media': 30, 'video_streaming': 15},
    },
}

# Small chance a student PC performs a port scan during any period (for detection demo)
SCAN_PROBABILITY = 0.04   # 4% chance per cycle
# Fall back to this if timetable period not found
DEFAULT_PERIOD  = 'evening_study'

# ─── Named demo scenarios (override autonomous behaviour temporarily) ──────────
SCENARIOS = {
    'exam': {
        'duration_s': 120,
        'overrides': {
            'h_staff1': 'video_conf', 'h_staff2': 'elearning', 'h_staff3': 'elearning',
            'h_lab1': 'exam', 'h_lab2': 'exam', 'h_lab3': 'exam',
            'h_wifi1': 'exam', 'h_wifi2': 'exam', 'h_wifi3': 'elearning', 'h_wifi4': 'exam',
        },
    },
    'congestion': {
        'duration_s': 90,
        'overrides': {
            'h_wifi1': 'file_download', 'h_wifi2': 'video_streaming',
            'h_wifi3': 'file_download', 'h_wifi4': 'video_streaming',
            'h_lab1':  'file_download', 'h_lab2':  'video_streaming', 'h_lab3': 'file_download',
            'h_staff1': 'video_conf',   'h_staff2': 'video_conf',
        },
    },
    'ddos': {
        'duration_s': 60,
        'overrides': {
            'h_wifi3': 'ddos_attack', 'h_wifi4': 'ddos_attack',
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
            'h_staff1': 'video_conf', 'h_staff2': 'video_conf', 'h_staff3': 'file_download',
            'h_lab1': 'elearning', 'h_lab2': 'elearning',
        },
    },
    'scanning': {
        'duration_s': 60,
        'overrides': {
            'h_wifi3': 'port_scan', 'h_wifi4': 'network_sweep',
            'h_lab3':  'port_scan',
            'h_staff1': 'elearning', 'h_staff2': 'video_conf',
        },
    },
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
    except Exception:
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
        print(f'[AutoTraffic] Engine started — cycle={CYCLE_SECONDS}s ±{JITTER}s')

    # ── Public API ────────────────────────────────────────────────────────────
    def pause(self):
        with self._lock:
            self.paused = True

    def resume(self):
        with self._lock:
            self.paused = False

    def trigger_scenario(self, name: str) -> dict:
        sc = SCENARIOS.get(name)
        if not sc:
            return {'ok': False, 'error': f'Unknown scenario: {name}'}
        with self._lock:
            self.scenario_name     = name
            self.scenario_until    = time.time() + sc['duration_s']
            self.scenario_overrides = dict(sc['overrides'])
        # Apply immediately
        self._apply_overrides(sc['overrides'])
        return {'ok': True, 'scenario': name, 'duration_s': sc['duration_s']}

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
                print('[AutoTraffic] Scenario expired — resuming autonomous mode')

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
        self._write_state()

    def _write_state(self):
        try:
            tmp = STATE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(self.state(), f, indent=2)
            os.replace(tmp, STATE_FILE)
        except Exception:
            pass


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
                self._json({'ok': True})
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
    server  = ThreadingHTTPServer(('0.0.0.0', API_PORT), make_handler(engine))
    print(f'[AutoTraffic] API listening on http://0.0.0.0:{API_PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
