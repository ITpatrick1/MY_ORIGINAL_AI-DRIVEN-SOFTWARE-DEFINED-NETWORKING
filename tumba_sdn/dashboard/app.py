#!/usr/bin/env python3
"""Tumba College SDN Dashboard — Flask + SocketIO"""
import json, os, time, threading, collections
import urllib.request
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'tumba-sdn-2026'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

METRICS       = os.environ.get('CAMPUS_METRICS_FILE',        '/tmp/campus_metrics.json')
ML_ACTION     = os.environ.get('CAMPUS_ML_ACTION_FILE',      '/tmp/campus_ml_action.json')
TIMETABLE     = os.environ.get('CAMPUS_TIMETABLE_STATE',     '/tmp/campus_timetable_state.json')
TOPO_STATE    = os.environ.get('CAMPUS_TOPOLOGY_STATE_FILE', '/tmp/campus_topology_state.json')
PC_ACTIVITIES = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE',  '/tmp/campus_pc_activities.json')
BASELINE      = os.environ.get('CAMPUS_BASELINE_FILE',       '/tmp/campus_baseline.json')
AUTO_TRAFFIC  = os.environ.get('CAMPUS_AUTO_TRAFFIC_FILE',   '/tmp/campus_auto_traffic_state.json')
TOPO_API      = os.environ.get('CAMPUS_TOPO_API',            'http://127.0.0.1:9091')
PCAM_API      = os.environ.get('CAMPUS_PCAM_API',            'http://127.0.0.1:9095')
AUTO_API      = os.environ.get('CAMPUS_AUTO_TRAFFIC_API',    'http://127.0.0.1:9097')

ZONES = ['staff_lan', 'server_zone', 'it_lab', 'student_wifi']

# ── In-memory history ring-buffer (last 60 samples × 5s = 5 min) ─────────────
HISTORY_SIZE = 60
_history: collections.deque = collections.deque(maxlen=HISTORY_SIZE)
_alerts:  list = []          # active alerts (last 50)

def _read(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}

def _proxy_post(url: str, data: dict, timeout=10) -> tuple[dict, int]:
    try:
        body = json.dumps(data).encode()
        req  = urllib.request.Request(url, data=body,
                                      headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(resp.read()), 200
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 502

def _pcam_post(path: str, data: dict) -> tuple[dict, int]:
    return _proxy_post(f'{PCAM_API}{path}', data)

def _auto_post(path: str, data: dict) -> tuple[dict, int]:
    return _proxy_post(f'{AUTO_API}{path}', data)

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
    zm  = m.get('zone_metrics', {})
    now = time.time()

    def _add_alert(severity: str, title: str, detail: str):
        _alerts.append({'ts': now, 'severity': severity, 'title': title, 'detail': detail})
        while len(_alerts) > 50:
            _alerts.pop(0)

    for zone in ZONES:
        zd = zm.get(zone, {})
        util = zd.get('max_utilization_pct', 0)
        tput = zd.get('throughput_mbps', 0)
        if zd.get('congested'):
            _add_alert('critical', f'Congestion — {zone.replace("_"," ").title()}',
                       f'{util:.1f}% utilisation · {tput:.2f} Mbps')
        elif zd.get('predicted_congestion'):
            _add_alert('warning', f'Congestion Predicted — {zone.replace("_"," ").title()}',
                       f'EMA {zd.get("util_ema",0):.1f}% trending up')

    if m.get('ddos_active'):
        _add_alert('critical', 'DDoS Detected',
                   f"Blocked: {m.get('security_blocked',0)} flows")

    action = ml.get('action', '')
    if action in ('security_isolation_wifi', 'emergency_staff_protection',
                  'emergency_server_protection'):
        _add_alert('warning', f'AI Action: {action.replace("_"," ").title()}',
                   f'reward={ml.get("reward",0):.2f} ε={ml.get("epsilon",0):.3f}')

    sec_evts = m.get('security_events', [])
    for evt in sec_evts[-3:]:
        if evt.get('event') == 'arp_spoofing_detected':
            _add_alert('critical', 'ARP Spoofing Detected',
                       f"IP {evt.get('ip')} — spoof MAC {evt.get('spoof_mac')}")
        elif evt.get('event') == 'mac_flooding_detected':
            _add_alert('critical', 'MAC Flooding Detected',
                       f"dpid={evt.get('dpid')} port={evt.get('port')} "
                       f"{evt.get('mac_count',0)} MACs")

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/api/health')
def api_health():
    m = _read(METRICS)
    return jsonify({'ok': True, 'ts': time.time(),
                    'switches': len(m.get('connected_switches', [])),
                    'has_metrics': bool(m)})

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
        'events':           m.get('events', [])[-30:],
    })

@app.route('/api/history')
def api_history():
    """Return ring-buffer of sampled metrics for charts."""
    return jsonify({'samples': list(_history), 'count': len(_history)})

@app.route('/api/alerts')
def api_alerts():
    """Return recent generated alerts."""
    return jsonify({'alerts': _alerts[-20:], 'count': len(_alerts)})

@app.route('/api/pingall', methods=['POST'])
def api_pingall():
    try:
        req  = urllib.request.Request(f'{TOPO_API}/pingall', data=b'{}',
                                      headers={'Content-Type': 'application/json'},
                                      method='POST')
        resp = urllib.request.urlopen(req, timeout=120)
        return jsonify(json.loads(resp.read()))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 502

# ─── PC Activity Manager ──────────────────────────────────────────────────────

@app.route('/api/pc_activities')
def api_pc_activities():
    return jsonify(_read(PC_ACTIVITIES))

@app.route('/api/baseline')
def api_baseline():
    return jsonify(_read(BASELINE))

@app.route('/api/set_activity', methods=['POST'])
def api_set_activity():
    result, code = _pcam_post('/set_activity', request.get_json() or {})
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
    scenario = data.get('scenario', 'congestion')
    try:
        # Forward to auto-traffic engine
        result, code = _auto_post('/scenario', {'name': scenario})
        if result.get('ok'):
            return jsonify(result), code
    except Exception:
        pass
    # Fallback: write trigger file for controller
    try:
        with open('/tmp/campus_scenario_trigger.json', 'w') as f:
            json.dump({'scenario': scenario, 'ts': time.time()}, f)
        return jsonify({'ok': True, 'scenario': scenario, 'note': 'trigger file written'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

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
        if _alerts:
            socketio.emit('alerts_update', {'alerts': _alerts[-5:]})

def run(host='0.0.0.0', port=9090):
    threading.Thread(target=_push_loop,       daemon=True).start()
    threading.Thread(target=_collect_history, daemon=True).start()
    print(f'Dashboard: http://{host}:{port}')
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=9090)
    run(port=p.parse_args().port)
