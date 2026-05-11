#!/usr/bin/env python3
"""
State-Driven ML Action Stub — Tumba College SDN

Reads live metrics & timetable, applies a heuristic DQN-like policy,
writes the decision to /tmp/campus_ml_action.json every 3 seconds.
Actions mirror the 16-action space in tumba_sdn/ml/dqn_agent.py.

Improvements over baseline:
  - Non-linear (exponential) SLO reward — stronger penalty above threshold
  - XAI attribution — top-3 features that drove the chosen action
  - Scan-aware Q-values — security state shifts action priorities
"""
import json, math, os, random, time

METRICS_FILE    = '/tmp/campus_metrics.json'
TIMETABLE_FILE  = '/tmp/campus_timetable_state.json'
ML_OUT_FILE     = '/tmp/campus_ml_action.json'
PC_ACT_FILE     = '/tmp/campus_pc_activities.json'

# Zone bandwidth capacities (Mbps) used for synthetic metrics generation
ZONE_CAPACITY = {'staff_lan': 30.0, 'server_zone': 100.0, 'it_lab': 30.0, 'student_wifi': 40.0}
ZONE_HOSTS = {
    'staff_lan':    ['h_staff1', 'h_staff2', 'h_staff3'],
    'server_zone':  ['h_mis', 'h_moodle', 'h_web', 'h_lib'],
    'it_lab':       ['h_lab1', 'h_lab2', 'h_lab3'],
    'student_wifi': ['h_wifi1', 'h_wifi2', 'h_wifi3', 'h_wifi4'],
}

ACTIONS = [
    'normal_mode', 'throttle_wifi_30pct', 'throttle_wifi_70pct', 'throttle_wifi_90pct',
    'boost_staff_lan', 'boost_server_zone', 'boost_lab_zone', 'exam_mode',
    'peak_hour_mode', 'throttle_wifi_boost_staff', 'throttle_wifi_boost_server',
    'throttle_social_boost_academic', 'emergency_staff_protection',
    'emergency_server_protection', 'security_isolation_wifi', 'load_balance_ds1_ds2',
]
ZONES = ['staff_lan', 'server_zone', 'it_lab', 'student_wifi']

# SLO weights per zone (must sum to 1.0)
SLO_WEIGHTS = {'staff_lan': 0.40, 'server_zone': 0.30, 'it_lab': 0.15, 'student_wifi': 0.10}
SLO_THRESHOLD  = 70.0   # utilisation % at which SLO is considered met
REWARD_SCALE   = 20.0   # exponential denominator — 1 unit = 20 pp above threshold

episode, epsilon, epsilon_min = 0, 0.30, 0.05
prev_util = {z: 0.0 for z in ZONES}


def _read(path):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return {}


# ── Non-linear (exponential) reward ──────────────────────────────────────────

def _nonlinear_reward(zm, tt, ddos, scans):
    """
    Per-zone SLO reward using exponential penalty above threshold:
      R_zone = +w              if util ≤ threshold
      R_zone = -w * (e^excess - 1) clamped to [-w, 0]   where excess=(util-T)/scale
    Security events carry a flat penalty.
    Total reward is clamped to [-1, +1].
    """
    reward = 0.0
    for zone, w in SLO_WEIGHTS.items():
        util = zm.get(zone, {}).get('max_utilization_pct', 0)
        if util <= SLO_THRESHOLD:
            reward += w
        else:
            excess  = (util - SLO_THRESHOLD) / REWARD_SCALE
            penalty = min(1.0, math.exp(excess) - 1.0)
            reward -= w * penalty

    # Security penalties
    if ddos:
        reward -= 0.20
    if scans:
        reward -= 0.10

    return round(max(-1.0, min(1.0, reward)), 3)


# ── XAI — top-3 feature attribution ──────────────────────────────────────────

def _xai_explain(zm, tt, ddos, scans):
    """
    Sensitivity-based attribution: each feature's contribution is proportional
    to its deviation from the neutral baseline (50% util / flag=False).
    Returns a list of the 3 most influential features for the current decision.
    """
    wifi  = zm.get('student_wifi', {}).get('max_utilization_pct', 0)
    staff = zm.get('staff_lan',    {}).get('max_utilization_pct', 0)
    srv   = zm.get('server_zone',  {}).get('max_utilization_pct', 0)
    lab   = zm.get('it_lab',       {}).get('max_utilization_pct', 0)
    exam  = bool(tt.get('exam_flag', 0))
    period = tt.get('period', 'off')

    # Raw feature values (scaled to 0-100 for display consistency)
    values = {
        'wifi_util':       wifi,
        'staff_util':      staff,
        'server_util':     srv,
        'lab_util':        lab,
        'exam_flag':       100.0 if exam else 0.0,
        'ddos_active':     100.0 if ddos else 0.0,
        'scan_active':     100.0 if scans else 0.0,
        'period_academic': 100.0 if period in ('lecture', 'lab', 'exam') else 0.0,
    }

    # Impact = how far each feature deviates from its neutral baseline
    impacts = {
        'wifi_util':       abs(wifi - 50) / 50,
        'staff_util':      abs(staff - 50) / 50,
        'server_util':     abs(srv - 50) / 50,
        'lab_util':        abs(lab - 50) / 50,
        'exam_flag':       1.0 if exam else 0.0,
        'ddos_active':     1.5 if ddos else 0.0,   # higher weight for critical threats
        'scan_active':     1.2 if scans else 0.0,
        'period_academic': 0.8 if period in ('lecture', 'lab', 'exam') else 0.0,
    }

    top3 = sorted(impacts.items(), key=lambda x: x[1], reverse=True)[:3]
    return [
        {'feature': k, 'value': round(values[k], 1), 'impact': round(v, 3)}
        for k, v in top3
    ]


# ── Q-value computation (scan/DDoS aware) ────────────────────────────────────

def _q_values(zm, tt, ddos, scans):
    wifi  = zm.get('student_wifi', {}).get('max_utilization_pct', 0)
    staff = zm.get('staff_lan',    {}).get('max_utilization_pct', 0)
    srv   = zm.get('server_zone',  {}).get('max_utilization_pct', 0)
    lab   = zm.get('it_lab',       {}).get('max_utilization_pct', 0)
    exam  = bool(tt.get('exam_flag', 0))
    period = tt.get('period', 'off')
    cong  = any(zm.get(z, {}).get('congested') for z in ZONES)

    # Security pressure term — boosts defensive actions
    sec_pressure = 0.5 if ddos else (0.3 if scans else 0.0)

    q = [
        0.8 - (wifi + staff + srv) / 300,            # 0 normal_mode
        (wifi - 40) / 100 if wifi > 40 else -0.3,    # 1 throttle_wifi_30pct
        (wifi - 60) / 100 if wifi > 60 else -0.5,    # 2 throttle_wifi_70pct
        (wifi - 80) / 100 if wifi > 80 else -0.7,    # 3 throttle_wifi_90pct
        (staff - 50) / 100 + (wifi - 50) / 200,      # 4 boost_staff_lan
        (srv   - 50) / 100,                           # 5 boost_server_zone
        0.5 if period == 'lab'    else -0.2,          # 6 boost_lab_zone
        0.95 if exam              else -0.8,          # 7 exam_mode
        0.7  if period in ('lecture', 'lab') else -0.3, # 8 peak_hour_mode
        (wifi - 55) / 100 + (staff - 30) / 200,      # 9 throttle_wifi_boost_staff
        (wifi - 55) / 100 + (srv   - 30) / 200,      # 10 throttle_wifi_boost_server
        0.75 if period in ('lecture', 'exam', 'lab') else -0.4, # 11 throttle_social_boost_academic
        0.9  if staff > 85 else -0.6,                 # 12 emergency_staff_protection
        0.9  if srv   > 85 else -0.6,                 # 13 emergency_server_protection
        -0.9 + sec_pressure * 2.0,                   # 14 security_isolation_wifi — elevated by threats
        0.6  if cong          else -0.2,              # 15 load_balance_ds1_ds2
    ]
    return [round(v + random.gauss(0, 0.03), 3) for v in q]


# ── Synthetic metrics builder (used when controller has no switches) ──────────

def _synthetic_metrics(ml_action: str) -> dict:
    """Build zone metrics from pc_activities when Mininet/controller is offline."""
    pcs_data = _read(PC_ACT_FILE)
    pcs = pcs_data.get('pcs', {})
    zone_metrics = {}
    ddos_active = False
    active_scans = []
    for zone, cap in ZONE_CAPACITY.items():
        hosts = ZONE_HOSTS.get(zone, [])
        throughput = sum(pcs.get(h, {}).get('traffic_mbps', 0.0) for h in hosts)
        for h in hosts:
            act = pcs.get(h, {}).get('activity', '')
            if act == 'ddos_attack':
                ddos_active = True
            elif act in ('port_scan', 'network_sweep'):
                if h not in active_scans:
                    active_scans.append(h)
        util = min(100.0, (throughput / cap * 100) if cap > 0 else 0.0)
        util = max(0.0, util + random.gauss(0, 1.2))
        congested = util > 75.0
        if util < 30:
            lat = random.uniform(2, 8)
        elif util < 60:
            lat = random.uniform(8, 20)
        elif util < 80:
            lat = random.uniform(20, 55)
        else:
            lat = random.uniform(55, 200)
        loss = round(max(0.0, (util - 70) / 100), 3) if util > 70 else 0.0
        zone_metrics[zone] = {
            'throughput_mbps':      round(throughput, 2),
            'max_utilization_pct':  round(util, 1),
            'util_ema':             round(util * 0.75 + random.gauss(0, 2), 1),
            'congested':            congested,
            'latency_ms':           round(lat, 1),
            'packet_loss_pct':      loss,
            'host_count':           len(hosts),
        }
    threats = len(active_scans) + (1 if ddos_active else 0)
    return {
        'ts': time.time(),
        'zone_metrics': zone_metrics,
        'switches': [
            {'dpid': '1', 'id': 'cs1', 'ports': 4, 'flows': 12 + random.randint(0, 5)},
            {'dpid': '2', 'id': 'ds1', 'ports': 4, 'flows':  8 + random.randint(0, 3)},
            {'dpid': '3', 'id': 'ds2', 'ports': 4, 'flows':  8 + random.randint(0, 3)},
            {'dpid': '4', 'id': 'as1', 'ports': 6, 'flows': 15 + random.randint(0, 4)},
            {'dpid': '5', 'id': 'as2', 'ports': 6, 'flows': 10 + random.randint(0, 4)},
            {'dpid': '6', 'id': 'as3', 'ports': 5, 'flows': 12 + random.randint(0, 4)},
            {'dpid': '7', 'id': 'as4', 'ports': 6, 'flows': 14 + random.randint(0, 4)},
        ],
        'ml_action':            ml_action,
        'ddos_active':          ddos_active,
        'active_scans':         active_scans,
        'blocked_ips':          [],
        'threats_detected':     threats,
        'convergence_time_ms':  round(random.uniform(40, 95), 1),
        'ddos_response_ms':     round(random.uniform(55, 140), 1) if ddos_active else 0.0,
        'failover_time_ms':     0.0,
        'security_flows_blocked': len(active_scans),
        'source':               'ml_stub_synthetic',
    }


# ── Main loop ─────────────────────────────────────────────────────────────────

while True:
    metrics   = _read(METRICS_FILE)
    # Use synthetic metrics when controller hasn't written any (no switches connected)
    if not metrics.get('zone_metrics'):
        metrics = {}          # will be rebuilt after action is chosen below
    timetable = _read(TIMETABLE_FILE)
    zm    = metrics.get('zone_metrics', {})
    ddos  = metrics.get('ddos_active', False)
    scans = bool(metrics.get('active_scans', []))
    blocked_count = len(metrics.get('blocked_ips', []))

    episode += 1
    epsilon  = max(epsilon_min, epsilon * 0.9995)
    q = _q_values(zm, timetable, ddos, scans)

    if random.random() < epsilon:
        idx = random.randint(0, len(ACTIONS) - 1)
    else:
        idx = q.index(max(q))

    rew = _nonlinear_reward(zm, timetable, ddos, scans)
    xai = _xai_explain(zm, timetable, ddos, scans)
    prev_util.update({z: zm.get(z, {}).get('max_utilization_pct', 0) for z in ZONES})

    out = {
        'ts': time.time(), 'action': ACTIONS[idx], 'action_index': idx,
        'q_values': q, 'reward': rew, 'episode': episode,
        'epsilon': round(epsilon, 4),
        'zone_utilization': {z: round(zm.get(z, {}).get('max_utilization_pct', 0), 1) for z in ZONES},
        'zone_throughput':  {z: round(zm.get(z, {}).get('throughput_mbps', 0), 2)     for z in ZONES},
        'ddos_active':  ddos,
        'scan_active':  scans,
        'blocked_count': blocked_count,
        'period':       timetable.get('period', 'off'),
        'exam_flag':    bool(timetable.get('exam_flag', 0)),
        'xai': {
            'top_features': xai,
            'reward_breakdown': {
                zone: {
                    'util':   round(zm.get(zone, {}).get('max_utilization_pct', 0), 1),
                    'slo_met': zm.get(zone, {}).get('max_utilization_pct', 0) <= SLO_THRESHOLD,
                    'weight': SLO_WEIGHTS[zone],
                }
                for zone in ZONES
            },
            'security_penalty': (-0.20 if ddos else 0) + (-0.10 if scans else 0),
            'reward_fn': 'nonlinear_exponential',
        },
    }
    tmp = ML_OUT_FILE + '.tmp'
    with open(tmp, 'w') as f: json.dump(out, f, indent=2)
    os.replace(tmp, ML_OUT_FILE)

    # Write synthetic zone metrics when the controller is not connected to any switches
    real = _read(METRICS_FILE)
    if not real.get('zone_metrics'):
        syn = _synthetic_metrics(ACTIONS[idx])
        tmp2 = METRICS_FILE + '.tmp'
        try:
            with open(tmp2, 'w') as f: json.dump(syn, f, indent=2)
            os.replace(tmp2, METRICS_FILE)
        except Exception:
            pass

    time.sleep(3)
