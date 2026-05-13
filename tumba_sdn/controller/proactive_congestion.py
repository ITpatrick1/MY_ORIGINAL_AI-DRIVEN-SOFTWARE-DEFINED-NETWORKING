#!/usr/bin/env python3
"""
Proactive Congestion Management Engine — Tumba College SDN

Implements the full Master SDN Proactive Congestion Management requirements:
  - 4-state utilization threshold model (Healthy / Warning / Preventive / Critical)
  - Congestion prediction: Future Load = Current + Growth Rate + Historical Trend
  - Per-device (PC) saturation detection at 100 Mbps port capacity
  - Structured alert generation with all required fields
  - Access switch uplink aggregation verification
  - Distribution switch uplink aggregation
  - REST API on port 9100

Output: /tmp/campus_proactive_congestion.json
"""
import json
import os
import time
import threading
import collections
from flask import Flask, jsonify
from flask_socketio import SocketIO

# ── File paths ────────────────────────────────────────────────────────────────
METRICS_FILE   = os.environ.get('CAMPUS_METRICS_FILE',        '/tmp/campus_metrics.json')
PC_ACT_FILE    = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE',  '/tmp/campus_pc_activities.json')
TIMETABLE_FILE = os.environ.get('CAMPUS_TIMETABLE_STATE',     '/tmp/campus_timetable_state.json')
ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE',      '/tmp/campus_ml_action.json')
OUTPUT_FILE    = os.environ.get('CAMPUS_PROACTIVE_CONG_FILE', '/tmp/campus_proactive_congestion.json')

# ── Threshold model ───────────────────────────────────────────────────────────
THRESHOLD_HEALTHY    = 70.0   # 0–70 %  → Monitor only          (Green)
THRESHOLD_WARNING    = 85.0   # 70–85 % → Predict congestion     (Yellow)
THRESHOLD_PREVENTIVE = 90.0   # 85–90 % → Apply control actions  (Orange)
# 90–100 %                                → Aggressive mitigation (Red)

# ── Link capacities ───────────────────────────────────────────────────────────
PC_LINK_CAPACITY_MBPS       = 100    # PC ↔ Access Switch
ACCESS_UPLINK_CAPACITY_MBPS = 1000   # Access Switch ↔ Distribution Switch
DIST_UPLINK_CAPACITY_MBPS   = 1000   # Distribution ↔ Controller

# ── PC saturation thresholds ──────────────────────────────────────────────────
PC_SATURATION_WARN_MBPS = 85    # 85 Mbps / 100 Mbps → warning
PC_SATURATION_CRIT_MBPS = 95    # 95 Mbps / 100 Mbps → critical "port saturation"

# ── Zone → access switch mapping ─────────────────────────────────────────────
ZONE_DISPLAY = {
    'staff_lan':    'Staff LAN (Access SW)',
    'server_zone':  'Server Zone (Access SW)',
    'it_lab':       'IT Lab (Access SW)',
    'student_wifi': 'Student WiFi (Access SW)',
}

# ── Traffic-type mapping from activity names ──────────────────────────────────
ACTIVITY_TRAFFIC_TYPE = {
    'elearning':       'E-learning',
    'exam':            'E-learning',
    'video_conf':      'Video Conferencing',
    'video_streaming': 'Streaming',
    'social_media':    'Social Media',
    'file_download':   'File Transfer',
    'web_browsing':    'Web Browsing',
    'mis':             'MIS',
    'idle':            'Idle',
    'ddos_attack':     'Attack Traffic',
}

# ── History for growth-rate calculation ──────────────────────────────────────
_zone_util_history: dict = {z: collections.deque(maxlen=20) for z in ZONE_DISPLAY}
_zone_mbps_history: dict = {z: collections.deque(maxlen=20) for z in ZONE_DISPLAY}
_alerts: list = []          # latest structured alerts (last 100)
_state:  dict = {}          # full computed state written to file

app = Flask(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _threshold_state(util_pct: float) -> str:
    """Return the 4-state label for a utilization percentage."""
    if util_pct >= THRESHOLD_PREVENTIVE:
        return 'critical'
    if util_pct >= THRESHOLD_WARNING:
        return 'preventive'
    if util_pct >= THRESHOLD_HEALTHY:
        return 'warning'
    return 'healthy'


def _threshold_color(state: str) -> str:
    return {'healthy': 'green', 'warning': 'yellow', 'preventive': 'orange', 'critical': 'red'}[state]


def _threshold_action(state: str) -> str:
    return {
        'healthy':    'Monitor only',
        'warning':    'Predict congestion — prepare QoS',
        'preventive': 'Apply proactive control actions',
        'critical':   'Aggressive mitigation — rate-limit & reroute',
    }[state]


def _compute_future_load(zone: str, current_util: float, current_mbps: float) -> dict:
    """
    Future Load = Current Traffic + Traffic Growth Rate + Historical Trend
    Projects 5 samples (≈10 s) forward.
    """
    hist_util = list(_zone_util_history[zone])
    hist_mbps = list(_zone_mbps_history[zone])

    # Growth rate: slope of last 5 samples
    growth_rate_mbps = 0.0
    growth_rate_pct  = 0.0
    if len(hist_mbps) >= 5:
        slope_mbps = (hist_mbps[-1] - hist_mbps[-5]) / 5
        growth_rate_mbps = round(slope_mbps, 3)
    if len(hist_util) >= 5:
        slope_pct = (hist_util[-1] - hist_util[-5]) / 5
        growth_rate_pct = round(slope_pct, 3)

    # Historical trend (EMA of last 10 samples)
    ema_util = 0.0
    if hist_util:
        alpha = 0.3
        ema = hist_util[0]
        for v in hist_util[1:]:
            ema = alpha * v + (1 - alpha) * ema
        ema_util = round(ema, 2)

    # 5-step projection
    projected_mbps = round(current_mbps + growth_rate_mbps * 5, 2)
    projected_util = round(current_util + growth_rate_pct * 5, 2)
    projected_util = max(0.0, projected_util)

    return {
        'current_mbps':     round(current_mbps, 2),
        'current_util_pct': round(current_util, 2),
        'growth_rate_mbps': growth_rate_mbps,
        'growth_rate_pct':  growth_rate_pct,
        'historical_ema_pct': ema_util,
        'projected_mbps':   projected_mbps,
        'projected_util_pct': projected_util,
        'risk': projected_util > THRESHOLD_WARNING and projected_util > current_util,
    }


def _add_alert(severity: str, device: str, utilization_pct: float,
               traffic_type: str, risk_level: str, prediction: str,
               action_taken: str):
    """Append a fully structured alert."""
    alert = {
        'ts':              time.time(),
        'severity':        severity,           # healthy / warning / preventive / critical
        'device':          device,
        'utilization_pct': round(utilization_pct, 1),
        'traffic_type':    traffic_type,
        'risk_level':      risk_level,
        'prediction':      prediction,
        'action_taken':    action_taken,
    }
    _alerts.append(alert)
    # Keep last 100
    while len(_alerts) > 100:
        _alerts.pop(0)
    return alert


# ── Main computation loop ─────────────────────────────────────────────────────

def _compute_cycle():
    """Run one full proactive congestion analysis cycle."""
    metrics   = _read(METRICS_FILE)
    pc_acts   = _read(PC_ACT_FILE)
    timetable = _read(TIMETABLE_FILE)
    ml_action = _read(ML_ACTION_FILE)

    zm = metrics.get('zone_metrics', {})
    pcs = pc_acts.get('pcs', {}) if pc_acts else {}
    current_ml_action = ml_action.get('action', 'normal_mode')

    new_alerts = []

    # ── 1. Per-zone 4-state analysis + future load ────────────────────────────
    zone_analysis = {}
    for zone, display_name in ZONE_DISPLAY.items():
        zd   = zm.get(zone, {})
        mbps = zd.get('throughput_mbps', 0.0)
        util = zd.get('max_utilization_pct', 0.0)

        # Push to history
        _zone_util_history[zone].append(util)
        _zone_mbps_history[zone].append(mbps)

        state      = _threshold_state(util)
        color      = _threshold_color(state)
        action_rec = _threshold_action(state)
        future     = _compute_future_load(zone, util, mbps)

        # Access uplink aggregation: SUM of device traffic in this zone
        zone_devices = [
            pc for pc in pcs.values()
            if pc.get('zone') == zone or pc.get('zone_key') == zone
        ]
        device_total_mbps = sum(
            pc.get('traffic_mbps', pc.get('bandwidth_mbps', 0.0))
            for pc in zone_devices
        )
        uplink_util_pct = round(device_total_mbps / ACCESS_UPLINK_CAPACITY_MBPS * 100, 2)

        analysis = {
            'zone':              zone,
            'display_name':      display_name,
            'throughput_mbps':   round(mbps, 2),
            'utilization_pct':   round(util, 2),
            'threshold_state':   state,
            'threshold_color':   color,
            'recommended_action': action_rec,
            'uplink_capacity_mbps':   ACCESS_UPLINK_CAPACITY_MBPS,
            'uplink_util_pct':        uplink_util_pct,
            'device_aggregated_mbps': round(device_total_mbps, 2),
            'device_count':           len(zone_devices),
            'congested':         zd.get('congested', False),
            'predicted_congestion': zd.get('predicted_congestion', False),
            'latency_ms':        zd.get('latency_ms', 0.0),
            'loss_pct':          zd.get('loss_pct', 0.0),
            'future_load':       future,
        }
        zone_analysis[zone] = analysis

        # Generate zone-level structured alerts
        if state == 'critical' or zd.get('congested'):
            new_alerts.append(_add_alert(
                severity       = 'critical',
                device         = display_name,
                utilization_pct= util,
                traffic_type   = _dominant_traffic_type(zone_devices),
                risk_level     = 'CRITICAL — Congestion active',
                prediction     = f"Projected: {future['projected_util_pct']:.1f}% in 10 s",
                action_taken   = f"ML: {current_ml_action} | Flow rerouting / rate-limit active",
            ))
        elif state == 'preventive' or future['risk']:
            projected = future['projected_util_pct']
            new_alerts.append(_add_alert(
                severity       = 'preventive',
                device         = display_name,
                utilization_pct= util,
                traffic_type   = _dominant_traffic_type(zone_devices),
                risk_level     = 'PREVENTIVE — Imminent congestion risk',
                prediction     = f"Will reach {projected:.1f}% in ~10 s if trend continues",
                action_taken   = f"Proactive control triggered — {action_rec}",
            ))
        elif state == 'warning':
            new_alerts.append(_add_alert(
                severity       = 'warning',
                device         = display_name,
                utilization_pct= util,
                traffic_type   = _dominant_traffic_type(zone_devices),
                risk_level     = 'WARNING — Rising utilization',
                prediction     = f"Growth rate: {future['growth_rate_pct']:+.2f}%/sample",
                action_taken   = 'Monitoring — QoS pre-staging ready',
            ))

    # ── 2. Per-device saturation detection ───────────────────────────────────
    device_saturation = []
    for pc_id, pc in pcs.items():
        bw = pc.get('traffic_mbps', pc.get('bandwidth_mbps', 0.0))
        if bw <= 0:
            continue
        util_pct = round(bw / PC_LINK_CAPACITY_MBPS * 100, 1)
        if bw >= PC_SATURATION_CRIT_MBPS:
            sev = 'critical'
            risk = 'PORT SATURATION — near 100 Mbps limit'
            action = 'Immediate rate-limit + QoS enforcement'
            device_saturation.append({
                'pc_id': pc_id, 'label': pc.get('label', pc_id),
                'traffic_mbps': round(bw, 2), 'capacity_mbps': PC_LINK_CAPACITY_MBPS,
                'utilization_pct': util_pct, 'severity': sev,
                'activity': pc.get('activity', 'unknown'),
            })
            new_alerts.append(_add_alert(
                severity       = 'critical',
                device         = f"{pc.get('label', pc_id)} (Port Saturation)",
                utilization_pct= util_pct,
                traffic_type   = ACTIVITY_TRAFFIC_TYPE.get(pc.get('activity', ''), 'Unknown'),
                risk_level     = risk,
                prediction     = f"{bw:.1f} Mbps / 100 Mbps — port at {util_pct:.0f}%",
                action_taken   = action,
            ))
        elif bw >= PC_SATURATION_WARN_MBPS:
            device_saturation.append({
                'pc_id': pc_id, 'label': pc.get('label', pc_id),
                'traffic_mbps': round(bw, 2), 'capacity_mbps': PC_LINK_CAPACITY_MBPS,
                'utilization_pct': util_pct, 'severity': 'warning',
                'activity': pc.get('activity', 'unknown'),
            })
            new_alerts.append(_add_alert(
                severity       = 'warning',
                device         = f"{pc.get('label', pc_id)}",
                utilization_pct= util_pct,
                traffic_type   = ACTIVITY_TRAFFIC_TYPE.get(pc.get('activity', ''), 'Unknown'),
                risk_level     = 'WARNING — High single-port usage',
                prediction     = f"{bw:.1f} Mbps approaching 100 Mbps limit",
                action_taken   = 'QoS monitoring active — rate-limit ready',
            ))

    # ── 3. Distribution-to-controller aggregation ────────────────────────────
    total_network_mbps = sum(
        za['throughput_mbps'] for za in zone_analysis.values()
    )
    ctrl_util_pct = round(total_network_mbps / DIST_UPLINK_CAPACITY_MBPS * 100, 2)
    ctrl_state    = _threshold_state(ctrl_util_pct)

    # ── 4. Assemble full state ────────────────────────────────────────────────
    state_doc = {
        'ts':              time.time(),
        'zones':           zone_analysis,
        'device_saturation': device_saturation,
        'network_aggregation': {
            'total_throughput_mbps':   round(total_network_mbps, 2),
            'controller_link_capacity_mbps': DIST_UPLINK_CAPACITY_MBPS,
            'controller_link_util_pct': ctrl_util_pct,
            'controller_link_state':    ctrl_state,
            'controller_link_color':    _threshold_color(ctrl_state),
        },
        'current_ml_action': current_ml_action,
        'exam_mode':  bool(timetable.get('exam_flag', 0)),
        'timetable_period': timetable.get('period', 'unknown'),
        'alert_count': len(_alerts),
        'new_alerts_this_cycle': len(new_alerts),
        'recent_alerts': _alerts[-20:],
    }

    # Atomic write
    try:
        tmp = OUTPUT_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(state_doc, f, indent=2)
        os.replace(tmp, OUTPUT_FILE)
    except Exception as e:
        print(f'[ProactiveCongestion] write error: {e}')

    return state_doc


def _dominant_traffic_type(devices: list) -> str:
    """Return the most common traffic type among active devices."""
    counts: dict = {}
    for dev in devices:
        act = dev.get('activity', 'idle')
        tt  = ACTIVITY_TRAFFIC_TYPE.get(act, 'Unknown')
        counts[tt] = counts.get(tt, 0) + 1
    if not counts:
        return 'Mixed'
    return max(counts, key=lambda k: counts[k])


# ── Background polling loop ───────────────────────────────────────────────────

def _poll_loop():
    while True:
        try:
            _compute_cycle()
        except Exception as e:
            print(f'[ProactiveCongestion] cycle error: {e}')
        time.sleep(2)


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route('/status')
def api_status():
    return jsonify(_read(OUTPUT_FILE))


@app.route('/zones')
def api_zones():
    d = _read(OUTPUT_FILE)
    return jsonify({'zones': d.get('zones', {}), 'ts': d.get('ts', 0)})


@app.route('/alerts')
def api_alerts():
    return jsonify({'alerts': _alerts[-50:], 'count': len(_alerts)})


@app.route('/device_saturation')
def api_saturation():
    d = _read(OUTPUT_FILE)
    return jsonify(d.get('device_saturation', []))


@app.route('/aggregation')
def api_aggregation():
    d = _read(OUTPUT_FILE)
    return jsonify(d.get('network_aggregation', {}))


@app.route('/health')
def api_health():
    return jsonify({'ok': True, 'ts': time.time(), 'service': 'proactive_congestion'})


# ── Entry point ───────────────────────────────────────────────────────────────

def run(port: int = 9100):
    threading.Thread(target=_poll_loop, daemon=True).start()
    print(f'[ProactiveCongestion] service starting on port {port}')
    app.run(host='0.0.0.0', port=port, threaded=True)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--port', type=int, default=9100)
    run(port=p.parse_args().port)
