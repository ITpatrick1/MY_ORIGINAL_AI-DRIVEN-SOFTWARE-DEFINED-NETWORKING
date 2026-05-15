#!/usr/bin/env python3
"""
IBN Engine — Intent-Based Networking for Tumba College SDN

Implements the "what not how" paradigm: operators express high-level
network intentions in plain English; the engine translates them into
concrete SDN actions (written to the ML action file + policy overrides).

Supported Intents (via POST /intent):
  "Prioritize Staff LAN"            → boost_staff_lan action + priority-1 queue
  "Prioritize Labs"                 → boost_lab_zone + academic-first policy
  "Exam Mode"                       → exam_mode action + timetable override
  "Block Student WiFi"              → security_isolation_wifi action
  "Load Balance"                    → load_balance_ds1_ds2 action
  "Emergency Lockdown"              → emergency_lockdown via security agent
  "Restore Normal"                  → normal_mode + restore_normal
  "Throttle WiFi <pct>"             → throttle_wifi_30/70/90pct
  "Protect Server Zone"             → emergency_server_protection
  "Academic First"                  → throttle_social_boost_academic

Intent history, active intents, and conflict detection are maintained.

REST API (default port 9098):
  GET  /health         → liveness check
  GET  /intents        → list all active intents
  GET  /intents/history→ full intent log
  POST /intent         → submit new intent  { "text": "...", "duration_s": 3600 }
  DELETE /intent/<id>  → cancel an intent
  GET  /actions        → action catalogue
"""

import argparse
import json
import os
import re
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tumba_sdn.common.campus_core import atomic_write_json, configure_file_logger

ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE', '/tmp/campus_ml_action.json')
TIMETABLE_API  = os.environ.get('CAMPUS_TIMETABLE_API',  'http://127.0.0.1:9096')
IBN_STATE_FILE = os.environ.get('CAMPUS_IBN_STATE_FILE', '/tmp/campus_ibn_state.json')

DEFAULT_PORT = int(os.environ.get('CAMPUS_IBN_PORT', '9098'))
LOGGER = configure_file_logger('tumba.ibn', 'ibn_engine.log')

# ── Intent → Action mapping ────────────────────────────────────────────────────

INTENT_RULES: list[dict] = [
    {
        'id': 'prioritize_elearning',
        'patterns': [r'prioriti[sz]e\s*e-?learning', r'e-?learning\s*(first|priority|traffic)',
                     r'moodle\s*(first|priority)', r'lms\s*(first|priority)'],
        'action': 'throttle_social_boost_academic',
        'description': 'Boosts E-learning/Moodle and academic traffic while suppressing entertainment traffic',
        'policy_hint': 'elearning_priority',
        'conflicts_with': [],
    },
    {
        'id': 'prioritize_staff',
        'patterns': [r'prioriti[sz]e staff', r'staff\s*(lan|priority|first)'],
        'action': 'boost_staff_lan',
        'description': 'Guarantees minimum 40 Mbps and priority queue 0 for Staff LAN',
        'policy_hint': 'staff_guaranteed_bandwidth',
        'conflicts_with': ['prioritize_labs', 'academic_first'],
    },
    {
        'id': 'prioritize_labs',
        'patterns': [r'prioriti[sz]e lab', r'lab\s*(first|priority|zone)'],
        'action': 'boost_lab_zone',
        'description': 'Elevates IT Lab to priority 1 — for lab sessions',
        'policy_hint': 'lab_priority',
        'conflicts_with': ['prioritize_staff'],
    },
    {
        'id': 'exam_mode',
        'patterns': [r'exam(\s*mode)?', r'examination', r'test\s*mode'],
        'action': 'exam_mode',
        'description': 'Activates exam policy: MIS elevated, social media restricted',
        'policy_hint': 'exam_active',
        'conflicts_with': [],
    },
    {
        'id': 'block_wifi',
        'patterns': [r'block\s*student\s*wi.?fi', r'isolat[ei]\s*wifi',
                     r'block\s*wifi', r'wifi\s*block'],
        'action': 'security_isolation_wifi',
        'description': 'Blocks all Student WiFi traffic — emergency use only',
        'policy_hint': 'wifi_blocked',
        'conflicts_with': ['restore_normal'],
    },
    {
        'id': 'load_balance',
        'patterns': [r'load\s*balan', r'balance\s*(traffic|load)', r'spread\s*traffic'],
        'action': 'load_balance_ds1_ds2',
        'description': 'Distributes traffic evenly across DS1 and DS2 uplinks',
        'policy_hint': 'load_balanced',
        'conflicts_with': [],
    },
    {
        'id': 'emergency_lockdown',
        'patterns': [r'emergency\s*(lockdown|lock)', r'lockdown', r'security\s*emergency'],
        'action': 'emergency_staff_protection',
        'description': 'Emergency: protects Staff LAN and Server Zone, blocks all others',
        'policy_hint': 'emergency',
        'conflicts_with': ['restore_normal'],
    },
    {
        'id': 'restore_normal',
        'patterns': [r'restor[ei]?\s*normal', r'clear\s*(all)?\s*polic',
                     r'reset\s*network', r'normal\s*mode'],
        'action': 'normal_mode',
        'description': 'Clears all intent overrides and returns to baseline DQN control',
        'policy_hint': 'normal',
        'conflicts_with': ['block_wifi', 'emergency_lockdown', 'exam_mode'],
    },
    {
        'id': 'throttle_wifi_light',
        'patterns': [r'throttle\s*wifi\s*30', r'light\s*throttle', r'reduce\s*wifi\s*30'],
        'action': 'throttle_wifi_30pct',
        'description': 'Reduces Student WiFi capacity to 30% — light congestion response',
        'policy_hint': 'wifi_throttled_30',
        'conflicts_with': ['throttle_wifi_heavy'],
    },
    {
        'id': 'throttle_wifi_heavy',
        'patterns': [r'throttle\s*wifi\s*70', r'throttle\s*wifi\s*90',
                     r'heavy\s*throttle', r'reduce\s*wifi\s*70'],
        'action': 'throttle_wifi_70pct',
        'description': 'Reduces Student WiFi capacity to 70% — heavy congestion response',
        'policy_hint': 'wifi_throttled_70',
        'conflicts_with': ['throttle_wifi_light'],
    },
    {
        'id': 'protect_server',
        'patterns': [r'protect\s*server', r'server\s*priority', r'mis\s*priority'],
        'action': 'emergency_server_protection',
        'description': 'Guarantees MIS/Moodle server bandwidth — exam & critical ops',
        'policy_hint': 'server_protected',
        'conflicts_with': [],
    },
    {
        'id': 'academic_first',
        'patterns': [r'academic\s*first', r'restrict\s*social', r'block\s*social\s*media',
                     r'prioriti[sz]e\s*academic', r'reduce\s*streaming',
                     r'throttle\s*streaming', r'streaming.*congestion'],
        'action': 'throttle_social_boost_academic',
        'description': 'Throttles social media, boosts academic traffic (Moodle, research)',
        'policy_hint': 'academic_priority',
        'conflicts_with': ['prioritize_staff'],
    },
    {
        'id': 'peak_hour',
        'patterns': [r'peak\s*hour', r'lecture\s*mode', r'class\s*mode'],
        'action': 'peak_hour_mode',
        'description': 'Activates peak-hour policy matching typical lecture-period demand',
        'policy_hint': 'peak_hour',
        'conflicts_with': [],
    },
]

ACTION_CATALOGUE = [
    {'action': r['action'], 'intent_id': r['id'], 'description': r['description']}
    for r in INTENT_RULES
]


# ── State manager ──────────────────────────────────────────────────────────────

class IBNState:
    def __init__(self):
        self._lock          = threading.Lock()
        self.active_intents: list[dict] = []
        self.history:        list[dict] = []
        self._counter       = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"INT-{self._counter:04d}"

    def submit(self, text: str, duration_s: int = 3600,
               source: str = 'api') -> dict:
        text_lower = text.lower().strip()

        # Match intent rule
        matched_rule = None
        for rule in INTENT_RULES:
            for pat in rule['patterns']:
                if re.search(pat, text_lower):
                    matched_rule = rule
                    break
            if matched_rule:
                break

        if not matched_rule:
            return {
                'ok': False,
                'error': f'Intent not recognised: "{text}"',
                'hint': ('Try: "Prioritize Staff LAN", "Exam Mode", "Load Balance", '
                         '"Block Student WiFi", "Restore Normal", "Academic First"'),
                'available': [r['id'] for r in INTENT_RULES],
            }

        now     = time.time()
        expires = now + duration_s if duration_s > 0 else 0

        intent = {
            'id':         self._next_id(),
            'text':       text,
            'intent_id':  matched_rule['id'],
            'action':     matched_rule['action'],
            'description':matched_rule['description'],
            'policy_hint':matched_rule['policy_hint'],
            'source':     source,
            'submitted':  now,
            'expires':    expires,
            'duration_s': duration_s,
            'status':     'active',
        }

        with self._lock:
            # Remove conflicting active intents
            conflicts = matched_rule.get('conflicts_with', [])
            removed = []
            self.active_intents = [
                i for i in self.active_intents
                if i['intent_id'] not in conflicts
                or (removed.append(i['intent_id']) or False)
            ]

            self.active_intents.append(intent)
            self.history.append({**intent, 'conflicts_removed': removed})
            if len(self.history) > 200:
                self.history = self.history[-200:]

        # Apply: write action file for controller to pick up
        self._apply_action(intent)
        self._persist()

        return {
            'ok':              True,
            'intent':          intent,
            'conflicts_removed': removed,
            'message': (f'Intent "{matched_rule["id"]}" → action "{matched_rule["action"]}" '
                        f'applied for {duration_s}s'),
        }

    def cancel(self, intent_id: str) -> dict:
        with self._lock:
            before = len(self.active_intents)
            self.active_intents = [
                i for i in self.active_intents if i['id'] != intent_id
            ]
            removed = before - len(self.active_intents)

        if removed:
            # Restore normal when all intents cleared
            if not self.active_intents:
                self._write_action('normal_mode', 'intent_cancelled')
            self._persist()
            return {'ok': True, 'message': f'Intent {intent_id} cancelled'}
        return {'ok': False, 'error': f'Intent {intent_id} not found'}

    def cleanup_expired(self) -> None:
        now = time.time()
        with self._lock:
            before = [i for i in self.active_intents if i['expires'] > 0 and i['expires'] < now]
            self.active_intents = [
                i for i in self.active_intents
                if i['expires'] == 0 or i['expires'] >= now
            ]
            if before and not self.active_intents:
                self._write_action('normal_mode', 'intent_expired')
        if before:
            self._persist()

    def get_active(self) -> list[dict]:
        self.cleanup_expired()
        with self._lock:
            return list(self.active_intents)

    def get_history(self) -> list[dict]:
        with self._lock:
            return list(self.history)

    def _apply_action(self, intent: dict) -> None:
        self._write_action(intent['action'], intent['id'])

        # Timetable override for exam mode
        if intent['intent_id'] == 'exam_mode':
            try:
                import urllib.request
                body = json.dumps({
                    'type': 'exam_mode', 'zone': '', 'value': '1',
                    'duration_s': intent['duration_s'],
                }).encode()
                req = urllib.request.Request(
                    f'{TIMETABLE_API}/override', data=body,
                    headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                LOGGER.exception('timetable override failed for intent=%s', intent.get('id'))

    @staticmethod
    def _write_action(action: str, source: str) -> None:
        payload = {
            'ts':      time.time(),
            'action':  action,
            'note':    f'ibn_engine:{source}',
            'reward':  0,
            'epsilon': 0,
            'ibn':     True,
        }
        atomic_write_json(ML_ACTION_FILE, payload, logger=LOGGER, label='ibn_ml_action')
        LOGGER.info('ml action write action=%s source=%s', action, source)

    def _persist(self) -> None:
        with self._lock:
            state = {
                'ts':             time.time(),
                'active_intents': self.active_intents,
                'history_count':  len(self.history),
                'total_submitted':self._counter,
            }
        atomic_write_json(IBN_STATE_FILE, state, logger=LOGGER, label='ibn_state')


# ── HTTP handler ───────────────────────────────────────────────────────────────

_ibn_state = IBNState()


class IBNHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data, indent=2).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get('Content-Length', 0))
        if n > 0:
            raw = self.rfile.read(n)
            return json.loads(raw)
        return {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == '/health':
            active = _ibn_state.get_active()
            LOGGER.info('api health active_intents=%d', len(active))
            self._json({
                'ok': True, 'service': 'ibn_engine',
                'active_intents': len(active),
                'ts': time.time(),
            })
        elif self.path == '/intents':
            LOGGER.info('api intents requested')
            active = _ibn_state.get_active()
            self._json({
                'active_intents': active,
                'intents': active,
                'history_count': len(_ibn_state.get_history()),
                'total_submitted': _ibn_state._counter,
                'ts': time.time(),
            })
        elif self.path == '/intents/history':
            LOGGER.info('api intent history requested')
            self._json({'history': _ibn_state.get_history()})
        elif self.path == '/actions':
            LOGGER.info('api actions requested count=%d', len(ACTION_CATALOGUE))
            self._json({'actions': ACTION_CATALOGUE, 'count': len(ACTION_CATALOGUE)})
        else:
            self._json({'error': 'not found'}, 404)

    def do_POST(self) -> None:
        if self.path == '/intent':
            body = self._body()
            text       = (body.get('text') or body.get('intent') or body.get('command') or '').strip()
            duration_s = int(body.get('duration_s', 3600))
            source     = body.get('source', 'api')
            if not text:
                self._json({'ok': False, 'error': 'text field required', 'accepted_fields': ['text', 'intent', 'command']}, 400)
                return
            result = _ibn_state.submit(text, duration_s=duration_s, source=source)
            LOGGER.info('api intent text=%s ok=%s action=%s', text, result.get('ok'), result.get('action'))
            self._json(result, 200 if result.get('ok') else 400)
        else:
            self._json({'error': 'not found'}, 404)

    def do_DELETE(self) -> None:
        m = re.match(r'^/intent/(INT-\d+)$', self.path)
        if m:
            self._json(_ibn_state.cancel(m.group(1)))
        else:
            self._json({'error': 'not found'}, 404)


# ── Background expiry loop ─────────────────────────────────────────────────────

def _expiry_loop() -> None:
    while True:
        time.sleep(30)
        _ibn_state.cleanup_expired()


def main() -> None:
    p = argparse.ArgumentParser(description='IBN Engine — Tumba College SDN')
    p.add_argument('--port', type=int, default=DEFAULT_PORT)
    args = p.parse_args()

    _ibn_state._persist()
    threading.Thread(target=_expiry_loop, daemon=True).start()

    server = ThreadingHTTPServer(('0.0.0.0', args.port), IBNHandler)
    LOGGER.info('startup host=0.0.0.0 port=%s state_file=%s', args.port, IBN_STATE_FILE)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    LOGGER.info('shutdown')


if __name__ == '__main__':
    main()
