#!/usr/bin/env python3
"""
State-Driven ML Action Stub — Tumba College SDN

Reads live metrics & timetable, applies a heuristic DQN-like policy,
writes the decision to /tmp/campus_ml_action.json every 3 seconds.
Actions mirror the 16-action space in tumba_sdn/ml/dqn_agent.py.
"""
import json, os, time, random

METRICS_FILE   = '/tmp/campus_metrics.json'
TIMETABLE_FILE = '/tmp/campus_timetable_state.json'
ML_OUT_FILE    = '/tmp/campus_ml_action.json'

ACTIONS = [
    'normal_mode', 'throttle_wifi_30pct', 'throttle_wifi_70pct', 'throttle_wifi_90pct',
    'boost_staff_lan', 'boost_server_zone', 'boost_lab_zone', 'exam_mode',
    'peak_hour_mode', 'throttle_wifi_boost_staff', 'throttle_wifi_boost_server',
    'throttle_social_boost_academic', 'emergency_staff_protection',
    'emergency_server_protection', 'security_isolation_wifi', 'load_balance_ds1_ds2',
]
ZONES = ['staff_lan', 'server_zone', 'it_lab', 'student_wifi']

episode, epsilon, epsilon_min = 0, 0.30, 0.05
prev_util = {z: 0.0 for z in ZONES}


def _read(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}


def _q_values(zm, tt, ddos):
    wifi  = zm.get('student_wifi', {}).get('max_utilization_pct', 0)
    staff = zm.get('staff_lan',    {}).get('max_utilization_pct', 0)
    srv   = zm.get('server_zone',  {}).get('max_utilization_pct', 0)
    lab   = zm.get('it_lab',       {}).get('max_utilization_pct', 0)
    exam  = bool(tt.get('exam_flag', 0))
    period = tt.get('period', 'off')
    cong  = any(zm.get(z, {}).get('congested') for z in ZONES)

    q = [
        0.8 - (wifi + staff + srv) / 300,           # 0 normal_mode
        (wifi - 40) / 100 if wifi > 40 else -0.3,   # 1 throttle_wifi_30pct
        (wifi - 60) / 100 if wifi > 60 else -0.5,   # 2 throttle_wifi_70pct
        (wifi - 80) / 100 if wifi > 80 else -0.7,   # 3 throttle_wifi_90pct
        (staff - 50) / 100 + (wifi - 50) / 200,     # 4 boost_staff_lan
        (srv   - 50) / 100,                          # 5 boost_server_zone
        0.5 if period == 'lab'   else -0.2,          # 6 boost_lab_zone
        0.95 if exam             else -0.8,          # 7 exam_mode
        0.7  if period in ('lecture','lab') else -0.3, # 8 peak_hour_mode
        (wifi - 55) / 100 + (staff - 30) / 200,     # 9 throttle_wifi_boost_staff
        (wifi - 55) / 100 + (srv   - 30) / 200,     # 10 throttle_wifi_boost_server
        0.75 if period in ('lecture','exam','lab') else -0.4, # 11 throttle_social_boost_academic
        0.9  if staff > 85 else -0.6,                # 12 emergency_staff_protection
        0.9  if srv   > 85 else -0.6,                # 13 emergency_server_protection
        0.95 if ddos           else -0.9,            # 14 security_isolation_wifi
        0.6  if cong           else -0.2,            # 15 load_balance_ds1_ds2
    ]
    return [round(v + random.gauss(0, 0.03), 3) for v in q]


def _reward(zm):
    cur = sum(zm.get(z, {}).get('max_utilization_pct', 0) for z in ZONES) / 4
    prv = sum(prev_util.get(z, 0) for z in ZONES) / 4
    pen = -0.3 * sum(1 for z in ZONES if zm.get(z, {}).get('congested'))
    return round(max(-1.0, min(1.0, 0.5 + (prv - cur) / 100 + pen)), 3)


while True:
    metrics   = _read(METRICS_FILE)
    timetable = _read(TIMETABLE_FILE)
    zm   = metrics.get('zone_metrics', {})
    ddos = metrics.get('ddos_active', False)

    episode += 1
    epsilon  = max(epsilon_min, epsilon * 0.9995)
    q = _q_values(zm, timetable, ddos)

    if random.random() < epsilon:
        idx = random.randint(0, len(ACTIONS) - 1)
    else:
        idx = q.index(max(q))

    rew = _reward(zm)
    prev_util.update({z: zm.get(z, {}).get('max_utilization_pct', 0) for z in ZONES})

    out = {
        'ts': time.time(), 'action': ACTIONS[idx], 'action_index': idx,
        'q_values': q, 'reward': rew, 'episode': episode,
        'epsilon': round(epsilon, 4),
        'zone_utilization': {z: round(zm.get(z, {}).get('max_utilization_pct', 0), 1) for z in ZONES},
        'zone_throughput':  {z: round(zm.get(z, {}).get('throughput_mbps', 0), 2)     for z in ZONES},
        'ddos_active': ddos,
        'period': timetable.get('period', 'off'),
        'exam_flag': bool(timetable.get('exam_flag', 0)),
    }
    tmp = ML_OUT_FILE + '.tmp'
    with open(tmp, 'w') as f: json.dump(out, f, indent=2)
    os.replace(tmp, ML_OUT_FILE)
    time.sleep(3)
