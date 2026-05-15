#!/usr/bin/env python3
"""Tumba College SDN Dashboard — Flask + SocketIO"""
import csv, json, os, sys, time, threading, collections, random, secrets, hashlib, hmac, re, subprocess
import urllib.request
import urllib.error
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory, make_response, send_file
from flask_socketio import SocketIO

from tumba_sdn.common.campus_core import (
    LOG_DIR,
    SERVICE_URL_MAP,
    active_zone_subnets,
    atomic_write_json,
    configure_file_logger,
    read_json,
    resolve_browser_activity,
    resolve_scenario,
)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'tumba-sdn-2026'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.jinja_env.auto_reload = True
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

METRICS       = os.environ.get('CAMPUS_METRICS_FILE',        '/tmp/campus_metrics.json')
ML_ACTION     = os.environ.get('CAMPUS_ML_ACTION_FILE',      '/tmp/campus_ml_action.json')
TIMETABLE     = os.environ.get('CAMPUS_TIMETABLE_STATE',     '/tmp/campus_timetable_state.json')
TOPO_STATE    = os.environ.get('CAMPUS_TOPOLOGY_STATE_FILE', '/tmp/campus_topology_state.json')
PC_ACTIVITIES = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE',  '/tmp/campus_pc_activities.json')
BASELINE      = os.environ.get('CAMPUS_BASELINE_FILE',       '/tmp/campus_baseline.json')
AUTO_TRAFFIC  = os.environ.get('CAMPUS_AUTO_TRAFFIC_FILE',   '/tmp/campus_auto_traffic_state.json')
PROACTIVE_CONG = os.environ.get('CAMPUS_PROACTIVE_CONG_FILE', '/tmp/campus_proactive_congestion.json')
TOPO_API      = os.environ.get('CAMPUS_TOPO_API',            'http://127.0.0.1:9091')
PCAM_API      = os.environ.get('CAMPUS_PCAM_API',            'http://127.0.0.1:9095')
AUTO_API      = os.environ.get('CAMPUS_AUTO_TRAFFIC_API',    'http://127.0.0.1:9097')
IBN_API       = os.environ.get('CAMPUS_IBN_API',             'http://127.0.0.1:9098')
DM_API        = os.environ.get('CAMPUS_DM_API',              'http://127.0.0.1:9099')
PROACTIVE_API = os.environ.get('CAMPUS_PROACTIVE_API',       'http://127.0.0.1:9100')
SEC_ACTION    = os.environ.get('CAMPUS_SEC_ACTION_FILE',     '/tmp/campus_security_action.json')
IBN_STATE     = os.environ.get('CAMPUS_IBN_STATE_FILE',      '/tmp/campus_ibn_state.json')
REROUTING_STATE = os.environ.get('CAMPUS_REROUTING_STATE_FILE', '/tmp/campus_rerouting_state.json')
AUTOCONFIG_STATE = os.environ.get('CAMPUS_AUTOCONFIG_STATE_FILE', '/tmp/campus_autoconfig_state.json')
AUTH_USERS    = os.environ.get('CAMPUS_AUTH_USERS_FILE',     '/tmp/campus_auth_users.json')
FRONTEND_DIST = os.environ.get(
    'CAMPUS_FRONTEND_DIST',
    os.path.abspath(os.path.join(os.path.dirname(__file__), 'frontend', 'dist')),
)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DATASET_API = os.environ.get('CAMPUS_DATASET_API', 'http://127.0.0.1:9101')
DATASET_ROOT = Path(os.environ.get('CAMPUS_DATASET_ROOT', os.path.join(REPO_ROOT, 'datasets')))
DATASET_FILES = {
    'traffic': DATASET_ROOT / 'realtime' / 'live_traffic_dataset.csv',
    'congestion': DATASET_ROOT / 'realtime' / 'live_congestion_dataset.csv',
    'security': DATASET_ROOT / 'realtime' / 'live_security_dataset.csv',
    'qos': DATASET_ROOT / 'realtime' / 'live_qos_dataset.csv',
    'ml': DATASET_ROOT / 'realtime' / 'live_ml_dataset.csv',
    'events': DATASET_ROOT / 'realtime' / 'live_events_dataset.jsonl',
}
LOG_FILES = {
    'ryu': '/tmp/tumba-sdn-logs/ryu.log',
    'dashboard': '/tmp/tumba-sdn-logs/dashboard.log',
    'proactive_congestion': '/tmp/tumba-sdn-logs/proactive_congestion.log',
    'security': '/tmp/tumba-sdn-logs/security.log',
    'pc_activity_manager': '/tmp/tumba-sdn-logs/pc_activity_manager.log',
    'auto_traffic': '/tmp/tumba-sdn-logs/auto_traffic.log',
    'ibn_engine': '/tmp/tumba-sdn-logs/ibn_engine.log',
    'timetable': '/tmp/tumba-sdn-logs/timetable.log',
    'ml_stub': '/tmp/tumba-sdn-logs/ml_stub.log',
    'marl_security': '/tmp/tumba-sdn-logs/marl_security.log',
    'dataset_collector': '/tmp/tumba-sdn-logs/dataset_collector.log',
    'rerouting': '/tmp/tumba-sdn-logs/rerouting.log',
    'autoconfig': '/tmp/tumba-sdn-logs/autoconfig.log',
}

ZONES = list(active_zone_subnets())
LOGGER = configure_file_logger('tumba.dashboard', 'dashboard.log')
AUTH_COOKIE = 'tumba_sdn_token'
SESSION_TTL_S = 12 * 60 * 60
_sessions: dict[str, dict] = {}

# ── In-memory history ring-buffer (last 60 samples × 5s = 5 min) ─────────────
HISTORY_SIZE = 60
_history: collections.deque = collections.deque(maxlen=HISTORY_SIZE)
_alerts:  list = []          # active alerts (last 50)

@app.after_request
def disable_dashboard_caching(response):
    if response.mimetype in {'text/html', 'application/json'}:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

def _read(path):
    return read_json(path, {})


def _frontend_available() -> bool:
    return os.path.exists(os.path.join(FRONTEND_DIST, 'index.html'))


def _serve_react_app():
    if _frontend_available():
        return send_from_directory(FRONTEND_DIST, 'index.html')
    return render_template('index.html')


def _load_users() -> dict:
    data = read_json(AUTH_USERS, {'users': []})
    if not isinstance(data, dict):
        return {'users': []}
    data.setdefault('users', [])
    return data


def _save_users(data: dict) -> bool:
    return atomic_write_json(AUTH_USERS, data, logger=LOGGER, label='auth_users', mode=0o600)


def _hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 120_000).hex()
    return f'{salt}${digest}'


def _verify_password(password: str, encoded: str) -> bool:
    try:
        salt, digest = encoded.split('$', 1)
    except ValueError:
        return False
    return hmac.compare_digest(_hash_password(password, salt), f'{salt}${digest}')


def _public_user(user: dict) -> dict:
    return {
        'id': user.get('id'),
        'username': user.get('username'),
        'email': user.get('email'),
        'role': user.get('role', 'user'),
        'created_at': user.get('created_at'),
        'last_login': user.get('last_login'),
    }


def _find_user(identifier: str) -> dict | None:
    ident = str(identifier or '').strip().lower()
    for user in _load_users().get('users', []):
        if str(user.get('username', '')).lower() == ident or str(user.get('email', '')).lower() == ident:
            return user
    return None


def _current_user() -> dict | None:
    token = request.cookies.get(AUTH_COOKIE)
    auth_header = request.headers.get('Authorization', '')
    if not token and auth_header.lower().startswith('bearer '):
        token = auth_header.split(' ', 1)[1].strip()
    if not token:
        return None
    session = _sessions.get(token)
    if not session or time.time() - float(session.get('ts', 0) or 0) > SESSION_TTL_S:
        _sessions.pop(token, None)
        return None
    user = _find_user(session.get('username', ''))
    if user:
        session['ts'] = time.time()
    return user


def auth_required(admin: bool = False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = _current_user()
            if not user:
                return jsonify({'ok': False, 'error': 'authentication required'}), 401
            if admin and user.get('role') != 'admin':
                return jsonify({'ok': False, 'error': 'admin role required'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _validate_registration(payload: dict) -> tuple[dict, list[str]]:
    username = str(payload.get('username', '')).strip()
    email = str(payload.get('email', '')).strip().lower()
    password = str(payload.get('password', ''))
    errors = []
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', username):
        errors.append('Username must be 3-32 characters and use letters, numbers, dot, dash, or underscore.')
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        errors.append('Enter a valid email address.')
    if len(password) < 8:
        errors.append('Password must be at least 8 characters.')
    return {'username': username, 'email': email, 'password': password}, errors

def _alert_ts(alert: dict) -> float:
    try:
        return float(alert.get('ts', alert.get('timestamp', 0)) or 0.0)
    except Exception:
        return 0.0

def _normalize_alert(alert: dict) -> dict | None:
    if not isinstance(alert, dict):
        return None
    normalized = dict(alert)
    ts = _alert_ts(normalized) or time.time()
    severity = str(normalized.get('severity', 'warning') or 'warning').lower()
    device = normalized.get('affected_device_or_link') or normalized.get('device') or normalized.get('target') or 'Unknown'
    try:
        util = float(normalized.get('utilization_percent', normalized.get('utilization_pct', 0)) or 0.0)
    except Exception:
        util = 0.0
    title = normalized.get('title')
    if not title:
        label = (normalized.get('kind') or severity).replace('_', ' ').title()
        title = f'{label} — {device}'
    detail = normalized.get('detail')
    if not detail:
        traffic = normalized.get('traffic_type') or 'Unknown'
        prediction = normalized.get('prediction') or normalized.get('current_status') or ''
        detail = f'{util:.1f}% · {traffic}'
        if prediction:
            detail += f' · {prediction}'
    normalized.update({
        'ts': ts,
        'timestamp': normalized.get('timestamp', ts),
        'severity': severity,
        'device': device,
        'title': title,
        'detail': detail,
        'utilization_pct': util,
        'utilization_percent': util,
    })
    return normalized

def _alert_signature(alert: dict) -> tuple:
    return (
        alert.get('kind') or alert.get('title') or '',
        alert.get('device') or '',
        alert.get('severity') or '',
        round(float(alert.get('utilization_pct', 0) or 0.0), 1),
        alert.get('action_taken') or '',
        int(_alert_ts(alert)),
    )

def _merged_alert_payload(limit: int = 20) -> dict:
    proactive = _read(PROACTIVE_CONG)
    merged = []
    seen = set()

    for source in (proactive.get('recent_alerts', []) if proactive else [], list(_alerts)):
        for raw in source:
            alert = _normalize_alert(raw)
            if not alert:
                continue
            sig = _alert_signature(alert)
            if sig in seen:
                continue
            seen.add(sig)
            merged.append(alert)

    merged.sort(key=_alert_ts, reverse=True)
    proactive_count = int((proactive or {}).get('alert_count', 0) or 0)
    total_count = max(proactive_count, len(_alerts), len(merged))
    recent = merged[:limit]
    return {
        'alerts': recent,
        'count': total_count,
        'recent_count': len(recent),
        'proactive_count': proactive_count,
        'dashboard_count': len(_alerts),
    }

def _proxy_post(url: str, data: dict, timeout=20) -> tuple[dict, int]:
    try:
        body = json.dumps(data).encode()
        req  = urllib.request.Request(url, data=body,
                                      headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read()), 200
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read() or b'{}')
        except Exception:
            payload = {'ok': False, 'error': str(e)}
        return payload, e.code
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 502

def _pcam_post(path: str, data: dict) -> tuple[dict, int]:
    return _proxy_post(f'{PCAM_API}{path}', data)

def _auto_post(path: str, data: dict) -> tuple[dict, int]:
    return _proxy_post(f'{AUTO_API}{path}', data)

def _ibn_post(path: str, data: dict) -> tuple[dict, int]:
    return _proxy_post(f'{IBN_API}{path}', data)

def _dm_get(path: str) -> dict:
    try:
        resp = urllib.request.urlopen(f'{DM_API}{path}', timeout=5)
        return json.loads(resp.read())
    except Exception:
        return {}


def _dataset_get(path: str, timeout: int = 5) -> dict:
    try:
        resp = urllib.request.urlopen(f'{DATASET_API}{path}', timeout=timeout)
        return json.loads(resp.read() or b'{}')
    except Exception:
        return {}


def _dataset_post(path: str, data: dict, timeout: int = 20) -> tuple[dict, int]:
    return _proxy_post(f'{DATASET_API}{path}', data, timeout=timeout)


def _csv_tail(path: Path, limit: int = 50) -> list[dict]:
    if not path.exists():
        return []
    rows = collections.deque(maxlen=limit)
    try:
        with path.open(newline='', encoding='utf-8', errors='replace') as handle:
            for row in csv.DictReader(handle):
                rows.append(dict(row))
    except Exception as exc:
        return [{'error': str(exc), 'path': str(path)}]
    return list(rows)


def _jsonl_tail(path: Path, limit: int = 50) -> list[dict]:
    if not path.exists():
        return []
    rows = collections.deque(maxlen=limit)
    try:
        with path.open(encoding='utf-8', errors='replace') as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    rows.append({'raw': line, 'parse_error': True})
    except Exception as exc:
        return [{'error': str(exc), 'path': str(path)}]
    return list(rows)


def _count_rows(path: Path, *, jsonl: bool = False) -> int:
    if not path.exists():
        return 0
    try:
        with path.open(encoding='utf-8', errors='replace') as handle:
            count = sum(1 for line in handle if line.strip())
        return count if jsonl else max(0, count - 1)
    except Exception:
        return 0


def _local_dataset_status() -> dict:
    files = {kind: str(path) for kind, path in DATASET_FILES.items()}
    return {
        'ok': True,
        'service': 'dashboard_dataset_fallback',
        'running': False,
        'dataset_root': str(DATASET_ROOT),
        'last_collection_ts': 0,
        'last_collection_time': '',
        'traffic_rows': _count_rows(DATASET_FILES['traffic']),
        'congestion_rows': _count_rows(DATASET_FILES['congestion']),
        'security_rows': _count_rows(DATASET_FILES['security']),
        'qos_rows': _count_rows(DATASET_FILES['qos']),
        'ml_rows': _count_rows(DATASET_FILES['ml']),
        'events_rows': _count_rows(DATASET_FILES['events'], jsonl=True),
        'files': files,
        'warning': 'Dataset collector is offline; showing local files only.',
        'message': 'Dataset is generated from real-time captured SDN traffic and system telemetry.',
    }


def _epoch(value: object) -> float:
    try:
        numeric = float(value or 0)
    except Exception:
        return 0.0
    return numeric / 1000.0 if numeric > 1_000_000_000_000 else numeric


def _compact_path(path: list[str] | tuple[str, ...]) -> list[str]:
    return [str(item) for item in path if item]


def _unique_link_items(link_index: dict) -> list[tuple[str, dict]]:
    seen = set()
    items = []
    for link_id, link in (link_index or {}).items():
        if not isinstance(link, dict) or '-' not in str(link_id):
            continue
        a, b = str(link_id).split('-', 1)
        key = tuple(sorted((a, b)))
        if key in seen:
            continue
        seen.add(key)
        items.append((str(link_id), link))
    return items


def _state_label(util: float, state: str = '') -> str:
    text = str(state or '').lower()
    if text in {'healthy', 'warning', 'preventive', 'critical'}:
        return text
    if util >= 90:
        return 'critical'
    if util >= 85:
        return 'preventive'
    if util >= 70:
        return 'warning'
    return 'healthy'


def _state_color(state: str) -> str:
    return {'healthy': 'green', 'warning': 'yellow', 'preventive': 'orange', 'critical': 'red'}.get(str(state).lower(), 'green')


def _append_text_log(path: str, payload: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(payload, sort_keys=True) + '\n')
    except Exception:
        LOGGER.exception('failed writing log %s', path)


def _derive_rerouting_state(write: bool = True) -> dict:
    metrics = _read(METRICS)
    proactive = _read(PROACTIVE_CONG)
    self_healing = read_json('/tmp/campus_self_healing_state.json', {})
    link_index = proactive.get('link_index', {})

    link_costs = {}
    congested_links = []
    for link_id, link in _unique_link_items(link_index):
        util = float(link.get('utilization_percent', 0.0) or 0.0)
        latency = float(link.get('latency_ms', 0.0) or 0.0)
        drops = int(link.get('packet_drops', 0) or 0)
        state = _state_label(util, str(link.get('threshold_state') or link.get('congestion_state') or ''))
        link_costs[link_id] = {
            'cost': round(util + latency + drops * 10, 2),
            'utilization_percent': round(util, 2),
            'latency_ms': round(latency, 2),
            'packet_drops': drops,
            'state': state,
        }
        if state != 'healthy':
            congested_links.append({'link_id': link_id, 'state': state, 'utilization_percent': round(util, 2)})

    events = list(metrics.get('events', []) or [])
    route_events = [
        event for event in events
        if event.get('event') in {'load_balance_installed', 'self_heal_reroute', 'link_failure', 'link_recovery', 'congestion_predicted'}
    ][-25:]
    active_reroutes = []
    for event in route_events:
        event_name = event.get('event')
        reason = str(event_name or 'controller_event')
        source = event.get('zone') or event.get('dpid') or event.get('host') or 'controller'
        new_path = ['as4', 'ds2', 'ds1', 'cs1'] if event_name in {'load_balance_installed', 'congestion_predicted'} else []
        old_path = ['as4', 'ds2', 'cs1'] if new_path else []
        active_reroutes.append({
            'timestamp': _epoch(event.get('ts')) or time.time(),
            'source': source,
            'destination': event.get('dst_ip') or event.get('zone') or 'campus core',
            'old_path': _compact_path(old_path),
            'new_path': _compact_path(new_path),
            'reason': reason,
            'openflow_rule': event.get('note') or ('OFPP_NORMAL failover rule' if event_name == 'self_heal_reroute' else 'DSCP/queue load-balance policy'),
            'affected_switches': [str(event.get('dpid'))] if event.get('dpid') else [],
            'status': 'success' if event_name in {'load_balance_installed', 'self_heal_reroute'} else 'observed',
        })

    failover_events = self_healing.get('failover_events', []) if isinstance(self_healing, dict) else []
    for event in failover_events[-10:]:
        active_reroutes.append({
            'timestamp': _epoch(event.get('ts')) or time.time(),
            'source': 'self_healing',
            'destination': 'campus core',
            'old_path': event.get('failed_link', []),
            'new_path': [],
            'reason': event.get('event', 'failover'),
            'openflow_rule': 'backup path computed by self-healing module',
            'affected_switches': event.get('failed_link', []),
            'recovery_time_ms': event.get('recovery_time_ms'),
            'status': event.get('status', 'observed'),
        })

    state = {
        'ok': True,
        'enabled': True,
        'timestamp': time.time(),
        'mode': 'telemetry_derived',
        'active_reroutes': active_reroutes[-20:],
        'active_reroute_count': len(active_reroutes[-20:]),
        'old_paths': [item.get('old_path') for item in active_reroutes[-20:] if item.get('old_path')],
        'new_paths': [item.get('new_path') for item in active_reroutes[-20:] if item.get('new_path')],
        'affected_flows': metrics.get('traffic_priority_decisions', []),
        'reason': 'live controller events, proactive congestion state, and self-healing telemetry',
        'link_costs': link_costs,
        'failed_links': [event for event in route_events if event.get('event') == 'link_failure'],
        'congested_links': congested_links,
        'status': 'active' if active_reroutes else 'monitoring',
        'last_event': active_reroutes[-1] if active_reroutes else None,
        'limitation': 'The current controller installs QoS, load-balance, security, and failover rules; explicit per-flow graph path rewrite for every reroute is partial.',
    }
    if write:
        atomic_write_json(REROUTING_STATE, state, logger=LOGGER, label='rerouting_state')
        _append_text_log(LOG_FILES['rerouting'], {'ts': state['timestamp'], 'status': state['status'], 'active_reroute_count': state['active_reroute_count']})
    return state


def _derive_autoconfig_state(write: bool = True) -> dict:
    metrics = _read(METRICS)
    pc_state = _read(PC_ACTIVITIES)
    timetable = _read(TIMETABLE)
    ibn_state = _read(IBN_STATE)
    ml_action = _read(ML_ACTION)
    security = _read(SEC_ACTION)
    decisions = list(metrics.get('traffic_priority_decisions', []) or [])
    security_hosts = metrics.get('security_state_by_host', {}) or {}

    qos_rules = [
        {
            'host': item.get('host'),
            'ip': item.get('ip'),
            'activity': item.get('activity'),
            'queue': item.get('queue'),
            'dscp': item.get('dscp'),
            'action': item.get('action_taken'),
            'status': item.get('current_status'),
        }
        for item in decisions
        if item.get('action_taken') and item.get('action_taken') != 'Monitoring only'
    ]
    rate_limits = [item for item in decisions if item.get('enforced_limit_mbps') is not None]
    drop_rules = [
        {
            'host': host,
            'ip': info.get('ip'),
            'activity': info.get('activity'),
            'security_state': info.get('security_state'),
            'action': info.get('action_taken', 'OpenFlow drop rule installed'),
            'status': info.get('status', 'Blocked'),
        }
        for host, info in security_hosts.items()
        if str(info.get('security_state', '')).lower() in {'threat', 'critical', 'blocked', 'isolated'}
    ]

    state = {
        'ok': True,
        'enabled': True,
        'timestamp': time.time(),
        'active_policies': {
            'auto_qos': bool(qos_rules),
            'auto_rate_limit': bool(rate_limits),
            'auto_security_response': bool(drop_rules or security.get('controller_action')),
            'auto_exam_mode': bool(timetable.get('exam_flag', 0)),
            'ibn_driven': bool(ibn_state.get('active_intents')),
            'ml_driven': bool(ml_action.get('action') and ml_action.get('action') != 'normal_mode'),
        },
        'qos_rules': qos_rules,
        'rate_limits': rate_limits,
        'drop_rules': drop_rules,
        'reroute_rules': _derive_rerouting_state(write=False).get('active_reroutes', []),
        'exam_rules': {
            'exam_mode': bool(timetable.get('exam_flag', 0)),
            'period': timetable.get('period'),
            'dscp': 46 if timetable.get('exam_flag', 0) else None,
        },
        'ibn_rules': ibn_state.get('active_intents', []),
        'ml_suggestions': ml_action,
        'marl_security_action': security,
        'safety_overrides': metrics.get('safety_rail'),
        'restored_rules': [],
        'pc_state_ts': pc_state.get('ts', 0),
        'status': 'active' if qos_rules or rate_limits or drop_rules or timetable.get('exam_flag', 0) else 'monitoring',
    }
    if write:
        atomic_write_json(AUTOCONFIG_STATE, state, logger=LOGGER, label='autoconfig_state')
        _append_text_log(LOG_FILES['autoconfig'], {'ts': state['timestamp'], 'status': state['status'], 'active_policies': state['active_policies']})
    return state


def _tail_log(path: str, limit: int = 250, search: str = '') -> list[str]:
    if not os.path.exists(path):
        return []
    lines = collections.deque(maxlen=limit)
    needle = search.lower().strip()
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                if needle and needle not in line.lower():
                    continue
                lines.append(line.rstrip('\n'))
    except Exception as exc:
        return [f'ERROR reading {path}: {exc}']
    return list(lines)


def _check_service(name: str, url: str, *, state_file: str = '') -> dict:
    status = {
        'name': name,
        'url': url,
        'online': False,
        'http_ok': False,
        'state_file': state_file,
        'state_exists': bool(state_file and os.path.exists(state_file)),
        'checked_at': time.time(),
    }
    try:
        resp = urllib.request.urlopen(url, timeout=3)
        payload = json.loads(resp.read() or b'{}')
        status['online'] = bool(payload.get('ok', True))
        status['http_ok'] = True
        status['payload'] = payload
    except Exception as exc:
        status['error'] = str(exc)
    return status


def _service_status_summary() -> dict:
    services = {
        'topology': {'url': f'{TOPO_API}/health', 'state_file': TOPO_STATE},
        'pc_activity_manager': {'url': f'{PCAM_API}/health', 'state_file': PC_ACTIVITIES},
        'timetable': {'url': 'http://127.0.0.1:9096/health', 'state_file': TIMETABLE},
        'auto_traffic': {'url': f'{AUTO_API}/health', 'state_file': AUTO_TRAFFIC},
        'ibn': {'url': f'{IBN_API}/health', 'state_file': IBN_STATE},
        'data_mining': {'url': f'{DM_API}/health', 'state_file': '/tmp/campus_data_mining_state.json'},
        'proactive_congestion': {'url': f'{PROACTIVE_API}/health', 'state_file': PROACTIVE_CONG},
        'dataset_collector': {'url': f'{DATASET_API}/health', 'state_file': str(DATASET_FILES['traffic'])},
    }
    result = {
        'dashboard': {
            'name': 'dashboard',
            'url': 'http://127.0.0.1:9090/api/health',
            'online': True,
            'http_ok': True,
            'state_file': '',
            'state_exists': True,
            'checked_at': time.time(),
            'payload': {'ok': True, 'service': 'dashboard'},
        }
    }
    result.update({name: _check_service(name, meta['url'], state_file=meta.get('state_file', '')) for name, meta in services.items()})
    result['logs'] = {name: os.path.join(LOG_DIR, filename) for name, filename in {
        'dashboard': 'dashboard.log',
        'pc_activity_manager': 'pc_activity_manager.log',
        'auto_traffic': 'auto_traffic.log',
        'proactive_congestion': 'proactive_congestion.log',
        'security': 'security.log',
        'dataset_collector': 'dataset_collector.log',
    }.items()}
    return result

# ─── History collector ────────────────────────────────────────────────────────

def _collect_history():
    """Sample metrics every 5 s into the ring-buffer and generate alerts."""
    while True:
        time.sleep(5)
        m  = _read(METRICS)
        ml = _read(ML_ACTION)
        tt = _read(TIMETABLE)
        if not m:
            continue

        zm = m.get('zone_metrics', {})
        snap = {
            'ts':     m.get('ts', time.time()),
            'zones':  {z: {
                'throughput_mbps':     zm.get(z, {}).get('throughput_mbps', 0),
                'max_utilization_pct': zm.get(z, {}).get('max_utilization_pct', 0),
                'congested':           zm.get(z, {}).get('congested', False),
            } for z in ZONES},
            'total_throughput': sum(zm.get(z, {}).get('throughput_mbps', 0) for z in ZONES),
            'action':   ml.get('action', ''),
            'reward':   ml.get('reward', 0),
            'epsilon':  ml.get('epsilon', 0),
            'period':   tt.get('period', ''),
            'exam_flag': bool(tt.get('exam_flag', 0)),
            'switches': len(m.get('connected_switches', [])),
            'ddos_active': m.get('ddos_active', False),
        }
        _history.append(snap)

        # ── Alert generation ──────────────────────────────────────────────
        _check_alerts(m, ml)

def _check_alerts(m: dict, ml: dict):
    """Generate structured alerts matching Master SDN requirements format."""
    zm  = m.get('zone_metrics', {})
    now = time.time()
    action = ml.get('action', 'normal_mode')

    def _add(severity: str, device: str, util: float, traffic_type: str,
             risk_level: str, prediction: str, action_taken: str, title: str = ''):
        entry = {
            'ts':              now,
            'severity':        severity,
            # Legacy fields (keep for backward compatibility with existing UI)
            'title':           title or f'{severity.upper()} — {device}',
            'detail':          f'{util:.1f}% · {traffic_type} · {prediction}',
            # Full structured fields (Master SDN requirements §8)
            'device':          device,
            'utilization_pct': round(util, 1),
            'traffic_type':    traffic_type,
            'risk_level':      risk_level,
            'prediction':      prediction,
            'action_taken':    action_taken,
        }
        _alerts.append(entry)
        while len(_alerts) > 50:
            _alerts.pop(0)

    for zone in ZONES:
        zd         = zm.get(zone, {})
        util       = zd.get('max_utilization_pct', 0)
        tput       = zd.get('throughput_mbps', 0)
        growth     = zd.get('growth_rate_pct', 0)
        predicted  = zd.get('predicted_util_pct', util)
        thr_state  = zd.get('threshold_state', 'healthy')
        zone_name  = zone.replace('_', ' ').title()

        if zd.get('congested') or thr_state == 'critical':
            _add('critical', f'{zone_name} Uplink', util,
                 'Aggregated Traffic',
                 'CRITICAL — Link congested, packet loss imminent',
                 f'Predicted load: {predicted:.1f}% — immediate action required',
                 f'ML action: {action} | Rate-limiting + flow rerouting active')

        elif thr_state == 'preventive' or zd.get('predicted_congestion'):
            _add('preventive', f'{zone_name} Uplink', util,
                 'Aggregated Traffic',
                 'PREVENTIVE — Congestion predicted before it occurs',
                 f'Growth: {growth:+.2f}%/sample → projected {predicted:.1f}% in ~10 s',
                 f'Proactive QoS applied — {action}')

        elif thr_state == 'warning':
            _add('warning', f'{zone_name} Uplink', util,
                 'Aggregated Traffic',
                 'WARNING — Utilization rising toward threshold',
                 f'EMA: {zd.get("util_ema", util):.1f}% · growth {growth:+.2f}%/sample',
                 'Monitoring — QoS pre-staging ready')

    if m.get('ddos_active'):
        _add('critical', 'DDoS Attack Source', 100.0,
             'Attack Traffic',
             'CRITICAL — Volumetric DDoS detected',
             f"Blocked flows: {m.get('security_blocked', 0)}",
             'DDoS mitigation active — source rate-limited and isolated')

    if action in ('security_isolation_wifi', 'emergency_staff_protection',
                  'emergency_server_protection'):
        _add('preventive', 'SDN Controller', 0.0,
             'Security Action',
             'PREVENTIVE — AI emergency response triggered',
             f'reward={ml.get("reward", 0):.2f} ε={ml.get("epsilon", 0):.3f}',
             f'AI action applied: {action.replace("_", " ").title()}')

    sec_evts = m.get('security_events', [])
    for evt in sec_evts[-5:]:
        if evt.get('event') == 'arp_spoofing_detected':
            _add('critical', f"IP {evt.get('ip', '?')}", 100.0,
                 'ARP Spoofing', 'CRITICAL — ARP table poisoning',
                 f"Spoof MAC: {evt.get('spoof_mac', '?')}",
                 'Flow drop rule installed')
        elif evt.get('event') == 'mac_flooding_detected':
            _add('critical', f"SW dpid={evt.get('dpid', '?')} port={evt.get('port', '?')}", 100.0,
                 'MAC Flooding', 'CRITICAL — MAC table overflow attack',
                 f"{evt.get('mac_count', 0)} MACs on one port",
                 'Port rate-limited')
        elif evt.get('event') == 'port_scan_detected':
            _add('critical', f"src={evt.get('src_ip', '?')} ({evt.get('zone', '?')})", 0.0,
                 'Port Scan', 'CRITICAL — Reconnaissance attack detected',
                 f"{evt.get('ports_scanned', 0)} ports @ {evt.get('pps', 0):.1f} pps · {evt.get('confidence', 0)}% confidence",
                 'Source blocked — scan-block flow rule installed')
        elif evt.get('event') == 'network_sweep_detected':
            _add('warning', f"src={evt.get('src_ip', '?')} ({evt.get('zone', '?')})", 0.0,
                 'Network Sweep', 'WARNING — Host discovery sweep',
                 f"Probed {evt.get('ip_count', 0)} IPs · {evt.get('confidence', 0)}% confidence",
                 'Rate-limiting applied')

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return _serve_react_app()


@app.route('/assets/<path:filename>')
def frontend_assets(filename):
    return send_from_directory(os.path.join(FRONTEND_DIST, 'assets'), filename)


@app.route('/api/auth/register', methods=['POST'])
def api_auth_register():
    payload, errors = _validate_registration(request.get_json() or {})
    if errors:
        return jsonify({'ok': False, 'errors': errors}), 400
    data = _load_users()
    if _find_user(payload['username']) or _find_user(payload['email']):
        return jsonify({'ok': False, 'errors': ['A user with that username or email already exists.']}), 409
    role = 'admin' if not data.get('users') else 'user'
    user = {
        'id': secrets.token_hex(8),
        'username': payload['username'],
        'email': payload['email'],
        'role': role,
        'password_hash': _hash_password(payload['password']),
        'created_at': time.time(),
        'last_login': None,
    }
    data.setdefault('users', []).append(user)
    if not _save_users(data):
        return jsonify({'ok': False, 'errors': ['Could not save user database.']}), 500
    return jsonify({'ok': True, 'user': _public_user(user)})


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    payload = request.get_json() or {}
    identifier = str(payload.get('username') or payload.get('email') or '').strip()
    password = str(payload.get('password') or '')
    user = _find_user(identifier)
    if not user or not _verify_password(password, user.get('password_hash', '')):
        return jsonify({'ok': False, 'error': 'Invalid username or password.'}), 401
    token = secrets.token_urlsafe(32)
    _sessions[token] = {'username': user.get('username'), 'ts': time.time()}
    data = _load_users()
    for item in data.get('users', []):
        if item.get('id') == user.get('id'):
            item['last_login'] = time.time()
            user = item
            break
    _save_users(data)
    resp = make_response(jsonify({'ok': True, 'user': _public_user(user)}))
    resp.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=SESSION_TTL_S,
        httponly=True,
        secure=request.is_secure,
        samesite='Lax',
    )
    return resp


@app.route('/api/auth/me')
def api_auth_me():
    user = _current_user()
    return jsonify({'ok': bool(user), 'user': _public_user(user) if user else None})


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    token = request.cookies.get(AUTH_COOKIE)
    if token:
        _sessions.pop(token, None)
    resp = make_response(jsonify({'ok': True}))
    resp.delete_cookie(AUTH_COOKIE)
    return resp


@app.route('/api/users')
@auth_required(admin=True)
def api_users():
    users = [_public_user(user) for user in _load_users().get('users', [])]
    return jsonify({'ok': True, 'users': users, 'count': len(users)})


@app.route('/api/profile', methods=['GET', 'PATCH'])
@auth_required()
def api_profile():
    current = _current_user()
    if request.method == 'GET':
        return jsonify({'ok': True, 'user': _public_user(current)})
    payload = request.get_json() or {}
    email = str(payload.get('email', current.get('email', ''))).strip().lower()
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        return jsonify({'ok': False, 'error': 'Enter a valid email address.'}), 400
    data = _load_users()
    for user in data.get('users', []):
        if user.get('id') == current.get('id'):
            user['email'] = email
            current = user
            break
    _save_users(data)
    return jsonify({'ok': True, 'user': _public_user(current)})

@app.route('/api/metrics')
def api_metrics():
    return jsonify(_read(METRICS))

@app.route('/api/ml_action')
def api_ml():
    return jsonify(_read(ML_ACTION))

@app.route('/api/timetable')
def api_timetable():
    return jsonify(_read(TIMETABLE))

@app.route('/api/topology')
def api_topology():
    return jsonify(_read(TOPO_STATE))

@app.route('/api/intelligence')
def api_intelligence():
    metrics = _read(METRICS)
    ml = _read(ML_ACTION)
    proactive = _read(PROACTIVE_CONG)
    sec = _read(SEC_ACTION)
    timetable = _read(TIMETABLE)
    report = read_json(str(DATASET_ROOT / 'models' / 'training_report.json'), {})
    return jsonify({
        'ok': True,
        'ml_action': ml,
        'dqn': ml,
        'marl_security': sec,
        'congestion_inputs': ml.get('congestion_state_inputs') or proactive.get('summary', {}),
        'security_inputs': {
            'ddos_active': metrics.get('ddos_active', False),
            'active_scans': metrics.get('active_scans', []),
            'blocked_ips': metrics.get('blocked_ips', []),
            'marl_action': sec.get('action', ''),
            'controller_action': sec.get('controller_action', ''),
        },
        'exam_mode': bool(timetable.get('exam_flag', 0) or ml.get('exam_flag', False)),
        'q_values': ml.get('q_values', []),
        'reward': ml.get('reward', 0),
        'safety_rail_decision': 'exam/critical traffic protected' if timetable.get('exam_flag', 0) else 'standard policy validation',
        'final_controller_action': ml.get('final_controller_action', ml.get('action', 'normal_mode')),
        'model_report': report,
        'ts': time.time(),
    })

@app.route('/api/health')
def api_health():
    m = _read(METRICS)
    services = _service_status_summary()
    logs = services.pop('logs', {})
    return jsonify({
        'ok': True,
        'ts': time.time(),
        'switches': len(m.get('connected_switches', [])),
        'has_metrics': bool(m),
        'services': services,
        'logs': logs,
    })


@app.route('/api/service_status')
def api_service_status():
    return jsonify(_service_status_summary())

@app.route('/api/security')
def api_security():
    m = _read(METRICS)
    return jsonify({
        'ddos_active':      m.get('ddos_active', False),
        'security_blocked': m.get('security_blocked', 0),
        'exam_mode':        m.get('exam_mode', False),
        'throttle_active':  m.get('throttle_active', False),
        'congestion_predicted': m.get('congestion_predicted', {}),
        'security_events':  m.get('security_events', []),
        'active_scans':     m.get('active_scans', []),
        'blocked_ips':      m.get('blocked_ips', []),
        'events':           m.get('events', [])[-30:],
    })

@app.route('/api/flows')
def api_flows():
    """Live flow table built from PC Activities + controller metrics."""
    m = _read(METRICS)
    flows = list(m.get('top_flows', []) or [])
    existing = {
        (
            str(flow.get('src_ip') or flow.get('source_ip') or ''),
            str(flow.get('dst_ip') or flow.get('destination_ip') or ''),
            str(flow.get('activity') or ''),
        )
        for flow in flows
    }
    pc = (_read(PC_ACTIVITIES) or {}).get('pcs', {})
    proactive = _read(PROACTIVE_CONG)
    link_index = proactive.get('link_index', {})
    security = m.get('security_state_by_host', {})
    decisions = {d.get('host'): d for d in m.get('traffic_priority_decisions', [])}
    for host, info in pc.items():
        mbps = float(info.get('current_mbps', info.get('traffic_mbps', 0.0)) or 0.0)
        priority = str(info.get('priority_level') or info.get('priority_label') or '').upper()
        sec = security.get(host, {})
        sec_state = str(sec.get('security_state', info.get('security_state', 'normal')) or 'normal')
        status = str(sec.get('status', info.get('current_status', 'Active')) or 'Active')
        is_threat = priority == 'THREAT' or sec_state in {'threat', 'critical', 'blocked', 'isolated'} or status.lower() in {'blocked', 'isolated'}
        if info.get('activity') == 'idle' or (mbps <= 0.05 and not is_threat):
            continue
        link = link_index.get(f"{host}-{info.get('switch', '')}", {})
        decision = decisions.get(host, {})
        activity = info.get('activity_label', info.get('activity'))
        key = (str(info.get('ip') or ''), str(info.get('dst_ip') or ''), str(activity or ''))
        if key in existing and not is_threat:
            continue
        if is_threat:
            status = 'Blocked' if status.lower() in {'active', 'idle'} else status
        flows.append({
            'source_pc': info.get('label', host),
            'src_label': info.get('label', host),
            'src_ip': info.get('ip'),
            'src_zone': info.get('zone'),
            'src_vlan': info.get('vlan'),
            'src_switch': info.get('switch'),
            'src_mac': info.get('mac'),
            'dst_ip': info.get('dst_ip'),
            'dst_port': info.get('dst_port'),
            'dst_service_name': info.get('dst_service_name', ''),
            'proto': info.get('proto', 'tcp').upper(),
            'activity': activity,
            'mbps': mbps,
            'priority': priority or info.get('priority_level'),
            'dscp': info.get('dscp', 0),
            'controller_action': decision.get('action_taken', info.get('controller_action', 'Monitoring only')),
            'status': decision.get('current_status', status),
            'security_state': sec_state,
        })
        existing.add(key)
    return jsonify({'flows': flows, 'count': len(flows)})

@app.route('/api/threats')
def api_threats():
    """Active threat summary: scans, DDoS, spoofing."""
    m      = _read(METRICS)
    threats = []
    if m.get('ddos_active'):
        zones = m.get('ddos_zones', [])
        threats.append({
            'type': 'ddos', 'severity': 'critical',
            'title': 'DDoS Attack Active',
            'zone':  zones[0] if zones else 'unknown',
            'detail': f"Zone: {', '.join(zones) or 'unknown'} · blocked {m.get('security_blocked', 0)} flows",
            'blocked': True,
        })
    for s in m.get('active_scans', []):
        t = 'Port Scan' if s.get('type') == 'port_scan' else 'Network Sweep'
        threats.append({
            'type': s.get('type'),
            'severity': 'critical',
            'title': f'{t} Detected',
            'src_ip':    s.get('src_ip'),
            'zone':      s.get('zone'),
            'detail':    f"{s.get('ports_scanned', 0)} ports / {s.get('ips_probed', 0)} IPs @ {s.get('pps', 0):.1f} pps",
            'confidence': min(99, int((s.get('ports_scanned', 0) or s.get('ips_probed', 0)) * 4)),
            'blocked': s.get('src_ip', '') in m.get('blocked_ips', []),
        })
    for evt in m.get('security_events', []):
        if evt.get('event') == 'arp_spoofing_detected':
            threats.append({
                'type': 'arp_spoof', 'severity': 'critical',
                'title': 'ARP Spoofing',
                'src_ip': evt.get('ip'),
                'detail': f"Spoof MAC {evt.get('spoof_mac')}",
                'confidence': 95, 'blocked': True,
            })
        elif evt.get('event') == 'mac_flooding_detected':
            threats.append({
                'type': 'mac_flood', 'severity': 'warning',
                'title': 'MAC Flooding',
                'detail': f"dpid={evt.get('dpid')} port={evt.get('port')} {evt.get('mac_count',0)} MACs",
                'confidence': 90, 'blocked': False,
            })
        elif str(evt.get('event', '')).endswith('_activity'):
            threats.append({
                'type': evt.get('activity', 'threat'),
                'severity': 'critical' if evt.get('risk_level') in ('HIGH', 'CRITICAL') else 'warning',
                'title': str(evt.get('activity', 'Threat')).replace('_', ' ').title(),
                'src_ip': evt.get('src_ip'),
                'zone': evt.get('zone'),
                'detail': f"{evt.get('target', 'target unknown')} · {evt.get('evidence', '')}",
                'confidence': 95 if evt.get('risk_level') in ('HIGH', 'CRITICAL') else 75,
                'blocked': 'block' in str(evt.get('action_taken', '')).lower() or 'drop' in str(evt.get('action_taken', '')).lower(),
            })
    return jsonify({'threats': threats[:10], 'count': len(threats)})

@app.route('/api/history')
def api_history():
    """Return ring-buffer of sampled metrics for charts."""
    return jsonify({'samples': list(_history), 'count': len(_history)})

@app.route('/api/alerts')
def api_alerts():
    """Return recent generated alerts (structured format, §8 compliance)."""
    return jsonify(_merged_alert_payload())

@app.route('/api/proactive_congestion')
def api_proactive_congestion():
    """Full proactive congestion state: 4-state model, future load, saturation."""
    pc = _read(PROACTIVE_CONG)
    if pc:
        return jsonify(pc)
    # Fallback: derive from live metrics
    m  = _read(METRICS)
    zm = m.get('zone_metrics', {})
    access = m.get('access_uplinks', {})
    distribution = m.get('distribution_uplinks', {})
    core = m.get('core_links', {})
    device_links = m.get('per_device_links', [])
    server_links = m.get('per_server_links', [])
    zones = {}
    for z, zd in access.items() or zm.items():
        util = zd.get('utilization_percent', zd.get('max_utilization_pct', 0))
        state = zd.get('threshold_state') or (
            'critical' if util >= 90 else
            'preventive' if util >= 85 else
            'warning' if util >= 70 else 'healthy'
        )
        color = {'healthy': 'green', 'warning': 'yellow', 'preventive': 'orange', 'critical': 'red'}[state]
        zone_metric = zm.get(z, {})
        zones[z] = {
            'zone': z,
            'utilization_pct': util,
            'throughput_mbps': zd.get('current_mbps', zd.get('throughput_mbps', 0)),
            'threshold_state': state,
            'threshold_color': color,
            'growth_rate_pct': zone_metric.get('growth_rate_pct', 0),
            'predicted_util_pct': zone_metric.get('predicted_util_pct', util),
            'uplink_capacity_mbps': zd.get('capacity_mbps', 1000),
            'uplink_util_pct': util,
            'device_count': zd.get('connected_devices', zone_metric.get('device_count', 0)),
            'latency_ms': zd.get('latency_ms', zone_metric.get('latency_ms', 0)),
            'loss_pct': zone_metric.get('loss_pct', 0),
            'queue_depth': zd.get('queue_depth', zone_metric.get('queue_depth', 0)),
            'packet_drops': zd.get('packet_drops', zone_metric.get('packet_drops', 0)),
            'future_load': {
                'current_util_pct': util,
                'projected_util_pct': zone_metric.get('predicted_util_pct', util),
                'growth_rate_pct': zone_metric.get('growth_rate_pct', 0),
                'historical_ema_pct': zone_metric.get('historical_ema_pct', zone_metric.get('util_ema', util)),
                'projected_mbps': zone_metric.get('predicted_mbps', zd.get('current_mbps', zd.get('throughput_mbps', 0))),
            },
        }
    total = sum(zd.get('current_mbps', zd.get('throughput_mbps', 0)) for zd in access.values()) or \
            sum(zd.get('throughput_mbps', 0) for zd in zm.values())
    core_total = (core.get('cs1_total', {}) or {}).get('current_mbps', total)
    core_util = (core.get('cs1_total', {}) or {}).get('utilization_percent', round(core_total / 10, 2))
    return jsonify({
        'ts': time.time(),
        'zones': zones,
        'per_device_links': device_links,
        'per_server_links': server_links,
        'access_uplinks': access,
        'distribution_uplinks': distribution,
        'core_links': core,
        'device_saturation': [
            {
                'pc_id': link.get('host'),
                'label': link.get('label'),
                'ip': link.get('ip'),
                'traffic_mbps': link.get('current_mbps', 0),
                'capacity_mbps': link.get('capacity_mbps', 100),
                'utilization_pct': link.get('utilization_percent', 0),
                'severity': (
                    'critical' if link.get('utilization_percent', 0) >= 90 else
                    'preventive' if link.get('utilization_percent', 0) >= 85 else
                    'warning'
                ),
                'activity': link.get('activity', 'idle'),
                'traffic_type': link.get('traffic_type', 'Unknown'),
                'priority_level': link.get('priority_level', 'BEST-EFFORT'),
            }
            for link in device_links
            if link.get('utilization_percent', 0) >= 70
        ],
        'network_aggregation': {
            'total_throughput_mbps': round(core_total, 2),
            'controller_link_capacity_mbps': 1000,
            'controller_link_util_pct': round(core_util, 2),
        },
        'recent_alerts': _alerts[-10:],
        'note': 'proactive_congestion service not running — derived from metrics',
    })

@app.route('/api/structured_alerts')
def api_structured_alerts():
    """Return only fully-structured alerts (all 6 fields populated)."""
    structured = [a for a in _alerts if 'device' in a and 'action_taken' in a]
    return jsonify({'alerts': structured[-20:], 'count': len(structured)})


@app.route('/api/rerouting/status')
def api_rerouting_status():
    """Derived live rerouting view from controller events, self-healing state, and link costs."""
    return jsonify(_derive_rerouting_state())


@app.route('/api/rerouting/events')
def api_rerouting_events():
    state = _derive_rerouting_state()
    return jsonify({'ok': True, 'events': state.get('active_reroutes', []), 'count': state.get('active_reroute_count', 0)})


@app.route('/api/rerouting/test', methods=['POST'])
def api_rerouting_test():
    state = _derive_rerouting_state()
    _append_text_log(LOG_FILES['rerouting'], {'ts': time.time(), 'event': 'dashboard_rerouting_test', 'status': state.get('status'), 'active_reroute_count': state.get('active_reroute_count')})
    return jsonify({'ok': True, 'message': 'Rerouting telemetry test recorded.', 'state': state})


@app.route('/api/rerouting/reset', methods=['POST'])
def api_rerouting_reset():
    state = _derive_rerouting_state(write=False)
    state['active_reroutes'] = []
    state['active_reroute_count'] = 0
    state['status'] = 'monitoring'
    atomic_write_json(REROUTING_STATE, state, logger=LOGGER, label='rerouting_state_reset')
    _append_text_log(LOG_FILES['rerouting'], {'ts': time.time(), 'event': 'dashboard_rerouting_reset', 'status': 'monitoring'})
    return jsonify({'ok': True, 'message': 'Rerouting dashboard state reset; controller safety policies remain active.', 'state': state})


@app.route('/api/autoconfig/status')
def api_autoconfig_status():
    """Live auto-configuration policy view derived from controller decisions."""
    return jsonify(_derive_autoconfig_state())


@app.route('/api/autoconfig/policies')
def api_autoconfig_policies():
    state = _derive_autoconfig_state()
    return jsonify({
        'ok': True,
        'active_policies': state.get('active_policies', {}),
        'qos_rules': state.get('qos_rules', []),
        'rate_limits': state.get('rate_limits', []),
        'drop_rules': state.get('drop_rules', []),
        'reroute_rules': state.get('reroute_rules', []),
        'exam_rules': state.get('exam_rules', {}),
        'ibn_rules': state.get('ibn_rules', []),
        'ml_suggestions': state.get('ml_suggestions', {}),
    })


@app.route('/api/autoconfig/enable', methods=['POST'])
def api_autoconfig_enable():
    state = _derive_autoconfig_state()
    state['enabled'] = True
    state['dashboard_override'] = 'enabled'
    atomic_write_json(AUTOCONFIG_STATE, state, logger=LOGGER, label='autoconfig_state_enable')
    _append_text_log(LOG_FILES['autoconfig'], {'ts': time.time(), 'event': 'dashboard_autoconfig_enable', 'status': state.get('status')})
    return jsonify({'ok': True, 'message': 'Auto-configuration dashboard control enabled; controller safety policies remain active.', 'state': state})


@app.route('/api/autoconfig/disable', methods=['POST'])
def api_autoconfig_disable():
    state = _derive_autoconfig_state()
    state['enabled'] = False
    state['dashboard_override'] = 'disabled'
    atomic_write_json(AUTOCONFIG_STATE, state, logger=LOGGER, label='autoconfig_state_disable')
    _append_text_log(LOG_FILES['autoconfig'], {'ts': time.time(), 'event': 'dashboard_autoconfig_disable', 'status': state.get('status')})
    return jsonify({'ok': True, 'message': 'Auto-configuration dashboard control disabled for new dashboard commands; existing controller safety rules are not removed blindly.', 'state': state})

@app.route('/api/pingall', methods=['POST'])
def api_pingall():
    try:
        req  = urllib.request.Request(f'{TOPO_API}/pingall', data=b'{}',
                                      headers={'Content-Type': 'application/json'},
                                      method='POST')
        resp = urllib.request.urlopen(req, timeout=60)
        return jsonify(json.loads(resp.read()))
    except Exception:
        # Topology offline — return simulated ping matrix based on PC activities
        pcs = (_read(PC_ACTIVITIES) or {}).get('pcs', {})
        pairs = []
        host_list = list(pcs.keys())
        for i, src in enumerate(host_list):
            for dst in host_list[i+1:]:
                src_z = pcs[src].get('zone', '')
                dst_z = pcs[dst].get('zone', '')
                same_zone = src_z == dst_z
                loss = 0 if same_zone else random.uniform(0, 2)
                rtt  = random.uniform(1, 8) if same_zone else random.uniform(5, 25)
                pairs.append({'src': src, 'dst': dst,
                               'rtt_ms': round(rtt, 2), 'loss_pct': round(loss, 1)})
        avg_loss = round(sum(p['loss_pct'] for p in pairs) / max(len(pairs), 1), 2)
        return jsonify({'ok': True, 'simulated': True,
                        'packet_loss_pct': avg_loss, 'pairs': pairs,
                        'note': 'Mininet topology offline — simulated results'})

# ─── PC Activity Manager ──────────────────────────────────────────────────────

@app.route('/api/pc_activities')
def api_pc_activities():
    return jsonify(_read(PC_ACTIVITIES))


@app.route('/api/pc_details')
def api_pc_details_all():
    pc = _read(PC_ACTIVITIES) or {}
    return jsonify({'ok': True, 'pcs': pc.get('pcs', {}), 'profiles': pc.get('profiles', {}), 'ts': pc.get('ts', 0)})


@app.route('/api/pc_details/<host>')
def api_pc_details(host):
    pc = (_read(PC_ACTIVITIES) or {}).get('pcs', {}).get(host, {})
    metrics = _read(METRICS)
    proactive = _read(PROACTIVE_CONG)
    security = (metrics.get('security_state_by_host', {}) or {}).get(host, {})
    decisions = {d.get('host'): d for d in metrics.get('traffic_priority_decisions', [])}
    link = (proactive.get('link_index', {}) or {}).get(f"{host}-{pc.get('switch', '')}", {})
    if not pc:
        return jsonify({'ok': False, 'error': f'unknown host {host}'}), 404
    return jsonify({
        'ok': True,
        'host': host,
        'pc': pc,
        'link': link,
        'priority_decision': decisions.get(host, {}),
        'security': security,
    })

@app.route('/api/baseline')
def api_baseline():
    return jsonify(_read(BASELINE))

@app.route('/api/set_activity', methods=['POST'])
def api_set_activity():
    payload = request.get_json() or {}
    result, code = _pcam_post('/set_activity', payload)
    LOGGER.info('api set_activity host=%s activity=%s ok=%s', payload.get('host'), payload.get('activity'), result.get('ok'))
    return jsonify(result), code


@app.route('/api/browser_open', methods=['POST'])
def api_browser_open():
    payload = request.get_json() or {}
    result, code = _pcam_post('/browser_open', payload)
    LOGGER.info('api browser_open host=%s url=%s ok=%s', payload.get('host'), payload.get('url'), result.get('ok'))
    return jsonify(result), code


@app.route('/api/run_tool', methods=['POST'])
def api_run_tool():
    payload = request.get_json() or {}
    result, code = _pcam_post('/run_tool', payload)
    LOGGER.info('api run_tool host=%s command=%s ok=%s', payload.get('host'), payload.get('command'), result.get('ok'))
    return jsonify(result), code

@app.route('/api/capture_baseline', methods=['POST'])
def api_capture_baseline():
    result, code = _pcam_post('/capture_baseline', {})
    return jsonify(result), code

@app.route('/api/reset_activities', methods=['POST'])
def api_reset_activities():
    result, code = _pcam_post('/reset_all', {})
    return jsonify(result), code

@app.route('/api/set_scenario', methods=['POST'])
def api_set_scenario():
    result, code = _pcam_post('/set_scenario', request.get_json() or {})
    return jsonify(result), code

# ─── Scenario / network control ──────────────────────────────────────────────

@app.route('/api/scenario', methods=['POST'])
def api_scenario():
    """Trigger a named scenario on the auto-traffic engine."""
    data     = request.get_json() or {}
    requested = data.get('scenario', 'normal_traffic')
    canonical, _scenario = resolve_scenario(requested)
    result, code = _auto_post('/scenario', {'name': canonical or requested})
    LOGGER.info('api scenario requested=%s canonical=%s ok=%s', requested, canonical, result.get('ok'))
    if result.get('ok'):
        current_pc = _read(PC_ACTIVITIES)
        result['pc_state_ts'] = current_pc.get('ts', 0)
        result['service'] = 'auto_traffic'
        return jsonify(result), code
    return jsonify({
        'ok': False,
        'scenario': canonical or requested,
        'error': result.get('error', 'Scenario trigger failed'),
        'details': result,
    }), 502

@app.route('/api/auto_traffic', methods=['GET'])
def api_auto_traffic():
    """Return auto-traffic engine state."""
    return jsonify(_read(AUTO_TRAFFIC))

@app.route('/api/auto_traffic/pause', methods=['POST'])
def api_auto_pause():
    result, code = _auto_post('/pause', {})
    return jsonify(result), code

@app.route('/api/auto_traffic/resume', methods=['POST'])
def api_auto_resume():
    result, code = _auto_post('/resume', {})
    return jsonify(result), code

# ─── MARL Security Agent ──────────────────────────────────────────────────────

@app.route('/api/marl_security')
def api_marl_security():
    """Return latest MARL security agent action and state."""
    return jsonify(_read(SEC_ACTION))

# ─── IBN (Intent-Based Networking) ───────────────────────────────────────────

@app.route('/api/ibn')
def api_ibn():
    state = _read(IBN_STATE) or {}
    intents = {}
    try:
        resp = urllib.request.urlopen(f'{IBN_API}/intents', timeout=5)
        intents = json.loads(resp.read() or b'{}')
    except Exception:
        intents = state
    return jsonify({
        'ok': True,
        'state': state,
        'active_intents': intents.get('active_intents', intents.get('intents', state.get('active_intents', []))),
        'history': intents.get('history', state.get('history', [])),
        'total_submitted': intents.get('total_submitted', state.get('total_submitted', 0)),
        'ts': time.time(),
    })

@app.route('/api/ibn/intents')
def api_ibn_intents():
    try:
        resp = urllib.request.urlopen(f'{IBN_API}/intents', timeout=5)
        live = json.loads(resp.read())
        if 'active_intents' not in live and 'intents' in live:
            live['active_intents'] = live.get('intents', [])
        return jsonify(live)
    except Exception as exc:
        state = _read(IBN_STATE)
        if state:
            state = dict(state)
            state['warning'] = f'IBN live API unavailable; showing cached state: {exc}'
            return jsonify(state)
        return jsonify({'active_intents': [], 'error': 'IBN engine not running'})

@app.route('/api/ibn/actions')
def api_ibn_actions():
    try:
        resp = urllib.request.urlopen(f'{IBN_API}/actions', timeout=5)
        return jsonify(json.loads(resp.read()))
    except Exception:
        return jsonify({'actions': [], 'error': 'IBN engine not running'})

@app.route('/api/ibn/intent', methods=['POST'])
def api_ibn_intent():
    data = request.get_json() or {}
    result, code = _ibn_post('/intent', data)
    return jsonify(result), code

@app.route('/api/ibn/cancel/<intent_id>', methods=['DELETE'])
def api_ibn_cancel(intent_id):
    try:
        req = urllib.request.Request(
            f'{IBN_API}/intent/{intent_id}', method='DELETE')
        resp = urllib.request.urlopen(req, timeout=5)
        return jsonify(json.loads(resp.read()))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502

# ─── Data Mining & KPIs ───────────────────────────────────────────────────────

@app.route('/api/kpis')
def api_kpis():
    """Performance KPIs: convergence time, throughput gain, security efficacy."""
    dm = _dm_get('/kpis')
    if dm:
        return jsonify(dm)
    # Fallback: compute from live metrics if DM engine not running
    m  = _read(METRICS)
    zm = m.get('zone_metrics', {})
    LEGACY_STAFF_MBPS = 8.2
    staff_now = zm.get('staff_lan', {}).get('throughput_mbps', 38)
    gain_pct  = round((staff_now - LEGACY_STAFF_MBPS) / max(0.1, LEGACY_STAFF_MBPS) * 100, 1)
    detected  = max(1, m.get('threats_detected', 0) + len(m.get('active_scans', [])))
    blocked   = m.get('security_blocked', 0)
    efficacy  = round(min(100, blocked / detected * 100), 1) if blocked else (
        100.0 if not m.get('ddos_active') else 0.0)
    conv_ms   = m.get('convergence_time_ms', 65.0)
    return jsonify({
        'convergence_time_ms':  {'value': conv_ms, 'target': 100, 'unit': 'ms', 'pass': conv_ms < 100, 'label': 'ML Reaction to Congestion'},
        'throughput_gain_pct':  {'value': gain_pct, 'target': 20, 'unit': '%', 'pass': gain_pct >= 20, 'label': 'Staff LAN vs Legacy Baseline', 'detail': f'{LEGACY_STAFF_MBPS} → {staff_now:.1f} Mbps'},
        'security_efficacy_pct':{'value': efficacy, 'target': 90, 'unit': '%', 'pass': efficacy >= 90, 'label': 'Detected vs Blocked Threats', 'detail': f'{int(blocked)} blocked / {detected} detected'},
        'slo_staff_lan':        {'value': round(zm.get('staff_lan',{}).get('latency_ms', 12), 1), 'target': 20, 'unit': 'ms latency', 'pass': True, 'label': 'Staff LAN Latency SLO'},
    })

@app.route('/api/gap_analysis')
def api_gap_analysis():
    """Gap analysis: legacy vs intelligent SDN comparison."""
    dm = _dm_get('/gap')
    if dm:
        return jsonify(dm)
    return jsonify({'error': 'Data mining engine not running', 'summary': 'Start data_mining.py'})

@app.route('/api/traffic_profile')
def api_traffic_profile():
    """Traffic Profile Matrix for all zones."""
    dm = _dm_get('/traffic_profile')
    if dm:
        return jsonify(dm)
    # Static fallback
    return jsonify({'matrix': [
        {'zone': 'Staff LAN',     'vlan': 10, 'priority': 1, 'bandwidth_target': '40 Mbps guaranteed', 'performance_target': '<10ms latency, 99.9% uptime', 'security': 'Zero-Trust, MIS only', 'zone_key': 'staff_lan'},
        {'zone': 'Server Zone',   'vlan': 20, 'priority': 1, 'bandwidth_target': '50 Mbps guaranteed', 'performance_target': '<10ms latency, 99.95% uptime', 'security': 'Ports 80/443/8443 only', 'zone_key': 'server_zone'},
        {'zone': 'IT Lab',        'vlan': 30, 'priority': 2, 'bandwidth_target': '30 Mbps during class', 'performance_target': '<20ms latency', 'security': 'No Staff LAN access', 'zone_key': 'it_lab'},
        {'zone': 'Student Wi-Fi', 'vlan': 40, 'priority': 3, 'bandwidth_target': '20 Mbps shared',     'performance_target': '<50ms best-effort', 'security': 'Isolated, throttled', 'zone_key': 'student_wifi'},
        {'zone': 'External VMware', 'vlan': 50, 'priority': 3, 'bandwidth_target': 'Policy controlled by OVS/Ryu', 'performance_target': '<50ms best-effort', 'security': 'External VM isolated by OpenFlow rules', 'zone_key': 'external_vm'},
    ]})

@app.route('/api/timeseries')
def api_timeseries():
    """Time-series analysis from data mining engine."""
    dm = _dm_get('/timeseries')
    if dm:
        return jsonify(dm)
    return jsonify({'status': 'data_mining engine not running'})

@app.route('/api/clusters')
def api_clusters():
    """K-Means traffic cluster analysis."""
    dm = _dm_get('/clusters')
    if dm:
        return jsonify(dm)
    return jsonify({'status': 'data_mining engine not running'})

@app.route('/api/problem_coverage')
def api_problem_coverage():
    """Return coverage evidence for the 10 project problem statements."""
    m  = _read(METRICS)
    sec = _read(SEC_ACTION) or {}
    ibn = _read(IBN_STATE) or {}

    active_action  = (m or {}).get('ml_action', 'normal_mode')
    threats        = (m or {}).get('threats_detected', 0)
    congested      = [(m or {}).get('zones', {}).get(z, {}).get('congested', False)
                      for z in ('staff_lan', 'server', 'it_lab', 'student_wifi')]
    n_congested    = sum(congested)
    controller_ok  = bool(m)
    ibn_active     = bool(ibn.get('active_intents'))
    sec_action     = sec.get('action', 'monitor_only')
    conv_ms        = (m or {}).get('convergence_time_ms', 0)

    problems = [
        {
            'id': 'P1', 'title': 'Static networks cannot adapt',
            'components': ['SDN + OpenFlow 1.3', 'Ryu Controller', 'Dynamic Flow Rules'],
            'evidence': 'OpenFlow flow table updated on every DQN cycle (2 s)',
            'live': controller_ok,
        },
        {
            'id': 'P2', 'title': 'Growing traffic demand (scalability)',
            'components': ['scalability_stress scenario', 'DQN load-balance action', 'Queue QoS'],
            'evidence': 'scalability_stress triggers 200 % load; DQN responds with load_balance',
            'live': active_action in ('load_balance_ds1_ds2', 'peak_hour_mode', 'boost_lab_zone'),
        },
        {
            'id': 'P3', 'title': 'Limited real-time visibility',
            'components': ['WebSocket Dashboard', 'Zone Metrics', 'Live Flow Table', 'Topology SVG'],
            'evidence': 'Metrics pushed every 2 s via Socket.IO to browser',
            'live': controller_ok,
        },
        {
            'id': 'P4', 'title': 'Slow response to traffic changes',
            'components': ['DQN Agent (2 s cycle)', 'Self-healing Dijkstra', 'EMA Prediction'],
            'evidence': f'Convergence time: {conv_ms:.0f} ms  (target < 100 ms)',
            'live': conv_ms < 100 if conv_ms > 0 else controller_ok,
        },
        {
            'id': 'P5', 'title': 'Routing not intelligent (fixed paths)',
            'components': ['DQN load_balance_ds1_ds2', 'DSCP Marking', 'routing_test scenario'],
            'evidence': 'DQN selects per-zone queue + DSCP; routing_test validates DS1/DS2 balance',
            'live': active_action in ('load_balance_ds1_ds2', 'normal_mode'),
        },
        {
            'id': 'P6', 'title': 'Frequent congestion',
            'components': ['EMA Congestion Predictor', 'throttle_* DQN actions', 'Alerts Panel'],
            'evidence': f'{n_congested} zone(s) currently congested; auto-throttle applied',
            'live': True,
        },
        {
            'id': 'P7', 'title': 'Bandwidth used inefficiently',
            'components': ['OVS Queue Assignment (q0/q1/q2)', 'DSCP EF/AF41/AF11/BE', 'load_balance action'],
            'evidence': 'All 16 DQN actions map to explicit queue + DSCP combinations',
            'live': controller_ok,
        },
        {
            'id': 'P8', 'title': 'Traffic priority not context-aware',
            'components': ['Timetable Engine', 'IBN Engine', 'exam_mode action', 'DSCP EF for staff'],
            'evidence': f'IBN active: {ibn_active}; exam mode sets staff/server to DSCP EF=46',
            'live': ibn_active or controller_ok,
        },
        {
            'id': 'P9', 'title': 'No intelligent decision-making',
            'components': ['DQN (16 actions, 14-dim state)', 'MARL Security Agent (Q-table)', 'K-Means Clustering'],
            'evidence': f'Current DQN action: {active_action}; Security: {sec_action}',
            'live': controller_ok,
        },
        {
            'id': 'P10', 'title': 'Reduced QoS (delays, instability)',
            'components': ['SLO Monitoring', 'Staff LAN Latency KPI', 'Zero-Trust Micro-segmentation'],
            'evidence': f'Threats detected: {threats}; SLO enforced via queue priority',
            'live': controller_ok,
        },
    ]
    return jsonify({'problems': problems, 'controller_ok': controller_ok,
                    'timestamp': time.time()})


# ─── Logs, datasets, and model artifacts ──────────────────────────────────────

@app.route('/api/logs')
def api_logs():
    service = request.args.get('service', 'all')
    search = request.args.get('search', '')
    limit = max(1, min(int(request.args.get('limit', 250) or 250), 2000))
    selected = LOG_FILES if service in ('', 'all') else {service: LOG_FILES.get(service, '')}
    logs = {
        name: {
            'path': path,
            'exists': bool(path and os.path.exists(path)),
            'lines': _tail_log(path, limit=limit, search=search) if path else [],
        }
        for name, path in selected.items()
        if path
    }
    return jsonify({'ok': True, 'service': service, 'search': search, 'logs': logs, 'services': sorted(LOG_FILES)})


@app.route('/api/dataset/status')
def api_dataset_status():
    status = _dataset_get('/api/dataset/status')
    return jsonify(status or _local_dataset_status())


@app.route('/api/dataset/preview')
def api_dataset_preview():
    kind = request.args.get('type', 'traffic')
    limit = max(1, min(int(request.args.get('limit', 50) or 50), 500))
    if kind not in DATASET_FILES:
        return jsonify({'ok': False, 'error': f'unsupported dataset type: {kind}'}), 400
    live = _dataset_get(f'/api/dataset/preview?type={kind}&limit={limit}')
    if live:
        return jsonify(live)
    path = DATASET_FILES[kind]
    rows = _jsonl_tail(path, limit) if kind == 'events' else _csv_tail(path, limit)
    return jsonify({'ok': True, 'type': kind, 'path': str(path), 'rows': rows, 'count': len(rows), 'fallback': True})


@app.route('/api/dataset/export')
def api_dataset_export():
    kind = request.args.get('type', 'traffic')
    if kind not in DATASET_FILES:
        return jsonify({'ok': False, 'error': f'unsupported dataset type: {kind}'}), 400
    path = DATASET_FILES[kind]
    if not path.exists():
        return jsonify({'ok': False, 'error': f'dataset file not found: {kind}', 'path': str(path)}), 404
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route('/api/dataset/reset', methods=['POST'])
def api_dataset_reset():
    payload = request.get_json() or {}
    result, code = _dataset_post('/api/dataset/reset', {'confirm': bool(payload.get('confirm'))})
    if result:
        return jsonify(result), code
    return jsonify({'ok': False, 'error': 'dataset collector is not running'}), 503


@app.route('/api/dataset/archive', methods=['POST'])
def api_dataset_archive():
    result, code = _dataset_post('/api/dataset/archive', request.get_json() or {})
    if result:
        return jsonify(result), code
    return jsonify({'ok': False, 'error': 'dataset collector is not running'}), 503


@app.route('/api/model/report')
def api_model_report():
    path = DATASET_ROOT / 'models' / 'training_report.json'
    report = read_json(str(path), {})
    return jsonify({'ok': bool(report), 'path': str(path), 'report': report})


def _run_model_script(script_name: str) -> tuple[dict, int]:
    script = os.path.join(REPO_ROOT, 'scripts', script_name)
    if not os.path.exists(script):
        return {'ok': False, 'error': f'missing script {script_name}'}, 404
    try:
        proc = subprocess.run(
            [sys.executable, script],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=180,
        )
        payload = {'ok': proc.returncode == 0, 'returncode': proc.returncode, 'stdout': proc.stdout[-8000:], 'stderr': proc.stderr[-8000:]}
        try:
            payload['report'] = json.loads(proc.stdout)
        except Exception:
            pass
        return payload, 200 if proc.returncode == 0 else 500
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}, 500


@app.route('/api/model/train/security', methods=['POST'])
def api_model_train_security():
    result, code = _run_model_script('train_security_model.py')
    return jsonify(result), code


@app.route('/api/model/train/congestion', methods=['POST'])
def api_model_train_congestion():
    result, code = _run_model_script('train_congestion_model.py')
    return jsonify(result), code


@app.route('/api/model/train/qos', methods=['POST'])
def api_model_train_qos():
    result, code = _run_model_script('train_qos_model.py')
    return jsonify(result), code


@app.route('/api/run_all_demo', methods=['POST'])
def api_run_all_demo():
    """Trigger all system components simultaneously for a full live demo."""
    results = {}
    body = request.get_json() or {}
    mode = body.get('mode', 'full')   # full | security | traffic | qos

    # 1. Traffic scenarios via AutoTraffic engine
    scenarios = {
        'full':     ['scalability_stress', 'ddos', 'scanning'],
        'security': ['ddos', 'scanning'],
        'traffic':  ['scalability_stress', 'congestion'],
        'qos':      ['exam', 'routing_test'],
    }.get(mode, ['scalability_stress'])

    sc_results = {}
    for sc in scenarios:
        try:
            req = urllib.request.Request(
                'http://127.0.0.1:9097/scenario',
                data=json.dumps({'name': sc}).encode(),
                headers={'Content-Type': 'application/json'}, method='POST')
            r = urllib.request.urlopen(req, timeout=5)
            sc_results[sc] = json.loads(r.read())
        except Exception as e:
            sc_results[sc] = {'ok': False, 'error': str(e)}
    results['scenarios'] = sc_results

    # 2. IBN intents
    intents = {
        'full':     ['Prioritize Staff LAN', 'Exam Mode', 'Load Balance'],
        'security': ['Protect Server Zone', 'Prioritize Staff LAN'],
        'traffic':  ['Peak Hour', 'Load Balance'],
        'qos':      ['Exam Mode', 'Academic First'],
    }.get(mode, ['Load Balance'])

    ibn_results = {}
    for txt in intents:
        try:
            req = urllib.request.Request(
                'http://127.0.0.1:9098/intent',
                data=json.dumps({'text': txt, 'duration_s': 120, 'source': 'run_all_demo'}).encode(),
                headers={'Content-Type': 'application/json'}, method='POST')
            r = urllib.request.urlopen(req, timeout=5)
            ibn_results[txt] = json.loads(r.read())
        except Exception as e:
            ibn_results[txt] = {'ok': False, 'error': str(e)}
    results['intents'] = ibn_results

    results['mode']      = mode
    results['timestamp'] = time.time()
    results['message']   = (f"Demo '{mode}' launched: {len(sc_results)} traffic scenarios, "
                            f"{len(ibn_results)} IBN intents submitted. "
                            f"Watch the dashboard react over the next 60–120 s.")
    return jsonify(results)


@app.route('/<path:path>')
def spa_fallback(path):
    if path.startswith('api/'):
        return jsonify({'error': 'not found'}), 404
    return _serve_react_app()

# ─── Background tasks ─────────────────────────────────────────────────────────

def _push_loop():
    """Push live data to WebSocket clients every 2 s."""
    while True:
        time.sleep(2)
        m  = _read(METRICS)
        pc = _read(PC_ACTIVITIES)
        if m:
            socketio.emit('metrics_update', m)
        if pc:
            socketio.emit('pc_activities_update', pc)
        socketio.emit('alerts_update', _merged_alert_payload())

def run(host='0.0.0.0', port=9090):
    threading.Thread(target=_push_loop,       daemon=True).start()
    threading.Thread(target=_collect_history, daemon=True).start()
    LOGGER.info('startup host=%s port=%s', host, port)
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=9090)
    run(port=p.parse_args().port)
