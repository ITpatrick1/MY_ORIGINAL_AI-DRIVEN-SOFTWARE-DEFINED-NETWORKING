#!/usr/bin/env python3
"""
Proactive Congestion Management Engine — Tumba College SDN

Builds a professional, link-aware congestion view from controller metrics,
PC activity state, timetable context, and ML actions. The engine:
  - models per-device edge links, access uplinks, distribution uplinks, and core uplinks
  - predicts congestion using traffic growth plus EMA trend
  - classifies congestion with utilization, latency, queue depth, and drops
  - explains priority protections and low-priority throttling decisions
  - writes full structured state to /tmp/campus_proactive_congestion.json
  - logs evidence to /tmp/tumba-sdn-logs/proactive_congestion.log
"""

from __future__ import annotations

import collections
import json
import logging
import os
import threading
import time
from typing import Any

from flask import Flask, jsonify

from tumba_sdn.common.campus_core import (
    active_zone_labels,
    active_zone_switches,
    external_zone_metadata,
    atomic_write_json,
)

# ── File paths ────────────────────────────────────────────────────────────────
METRICS_FILE = os.environ.get('CAMPUS_METRICS_FILE', '/tmp/campus_metrics.json')
PC_ACT_FILE = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE', '/tmp/campus_pc_activities.json')
TIMETABLE_FILE = os.environ.get('CAMPUS_TIMETABLE_STATE', '/tmp/campus_timetable_state.json')
ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE', '/tmp/campus_ml_action.json')
OUTPUT_FILE = os.environ.get('CAMPUS_PROACTIVE_CONG_FILE', '/tmp/campus_proactive_congestion.json')
LOG_DIR = '/tmp/tumba-sdn-logs'
LOG_FILE = os.path.join(LOG_DIR, 'proactive_congestion.log')

# ── Capacities ────────────────────────────────────────────────────────────────
EDGE_LINK_CAPACITY_MBPS = 100.0
ACCESS_UPLINK_CAPACITY_MBPS = 1000.0
CORE_LINK_CAPACITY_MBPS = 1000.0

# ── Thresholds ────────────────────────────────────────────────────────────────
THRESHOLD_HEALTHY = 70.0
THRESHOLD_WARNING = 70.0
THRESHOLD_PREVENTIVE = 85.0
THRESHOLD_CRITICAL = 90.0
HIGH_GROWTH_PCT = 2.5
VERY_HIGH_LATENCY_MS = 80.0
VERY_HIGH_QUEUE = 220
WARNING_QUEUE = 140

ZONE_LABELS = active_zone_labels()
ZONE_ACCESS_SWITCH = active_zone_switches()
DIST_LINKS = {
    'ds1': ['staff_lan', 'server_zone'],
    'ds2': ['it_lab', 'student_wifi'],
}
EXTERNAL_ZONE = external_zone_metadata()
if EXTERNAL_ZONE:
    DIST_LINKS.setdefault(EXTERNAL_ZONE.get('distribution', 'ds2'), []).append(EXTERNAL_ZONE['key'])
SERVER_HOSTS = {
    '10.20.0.1': {'host': 'h_mis', 'label': 'MIS Server'},
    '10.20.0.2': {'host': 'h_dhcp', 'label': 'DHCP Server'},
    '10.20.0.3': {'host': 'h_auth', 'label': 'Auth Server'},
    '10.20.0.4': {'host': 'h_moodle', 'label': 'Moodle LMS'},
}

STATE_COLORS = {
    'healthy': 'green',
    'warning': 'yellow',
    'preventive': 'orange',
    'critical': 'red',
}

_mbps_history: dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=20))
_util_history: dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=20))
_alerts: list[dict[str, Any]] = []
_state: dict[str, Any] = {}

os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger('tumba.proactive_congestion')
if not logger.handlers:
    logger.setLevel(logging.INFO)
    try:
        handler = logging.FileHandler(LOG_FILE)
    except PermissionError:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    logger.propagate = False

app = Flask(__name__)


def _read(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _threshold_action(state: str) -> str:
    return {
        'healthy': 'Monitor only',
        'warning': 'Generate early warning and analyse trend',
        'preventive': 'Apply QoS, traffic shaping, and low-priority throttling',
        'critical': 'Aggressive mitigation with strong alerts and rerouting',
    }[state]


def _priority_rank(level: str) -> int:
    return {
        'CRITICAL': 1,
        'HIGH': 2,
        'MEDIUM': 3,
        'LOW': 4,
        'BEST-EFFORT': 5,
        'ATTACK': 6,
    }.get((level or '').upper(), 5)


def _future_projection(key: str, current_mbps: float, current_util: float, capacity_mbps: float) -> dict:
    mbps_hist = _mbps_history[key]
    util_hist = _util_history[key]
    mbps_hist.append(current_mbps)
    util_hist.append(current_util)

    growth_rate_mbps = 0.0
    growth_rate_pct = 0.0
    if len(mbps_hist) >= 5:
        growth_rate_mbps = round((mbps_hist[-1] - mbps_hist[-5]) / 5, 3)
    if len(util_hist) >= 5:
        growth_rate_pct = round((util_hist[-1] - util_hist[-5]) / 5, 3)

    ema_util = current_util
    if util_hist:
        alpha = 0.3
        ema_util = util_hist[0]
        for value in list(util_hist)[1:]:
            ema_util = alpha * value + (1 - alpha) * ema_util
        ema_util = round(ema_util, 2)

    ema_mbps = (ema_util / 100.0) * capacity_mbps
    historical_ema_trend = round(max(0.0, ema_mbps - current_mbps), 3)
    predicted_mbps = max(0.0, current_mbps + growth_rate_mbps * 5 + historical_ema_trend)
    predicted_util = round(min(100.0, (predicted_mbps / max(capacity_mbps, 0.1)) * 100), 2)

    return {
        'current_mbps': round(current_mbps, 2),
        'current_util_pct': round(current_util, 2),
        'growth_rate_mbps': growth_rate_mbps,
        'growth_rate_pct': growth_rate_pct,
        'historical_ema_pct': ema_util,
        'historical_ema_trend_mbps': historical_ema_trend,
        'projected_mbps': round(predicted_mbps, 2),
        'projected_util_pct': predicted_util,
        'risk': predicted_util >= THRESHOLD_WARNING and predicted_util > current_util,
    }


def _congestion_state(util_pct: float, growth_rate_pct: float, predicted_util: float,
                      latency_ms: float, queue_depth: int, packet_drops: int) -> str:
    if util_pct >= THRESHOLD_CRITICAL or (packet_drops > 0 and util_pct >= THRESHOLD_CRITICAL) or latency_ms >= VERY_HIGH_LATENCY_MS or queue_depth >= VERY_HIGH_QUEUE:
        return 'critical'
    if util_pct >= THRESHOLD_PREVENTIVE:
        return 'preventive'
    if util_pct >= THRESHOLD_WARNING or growth_rate_pct >= HIGH_GROWTH_PCT or predicted_util >= THRESHOLD_PREVENTIVE or queue_depth >= WARNING_QUEUE:
        return 'warning'
    return 'healthy'


def _dominant_traffic(items: list[dict]) -> str:
    totals: dict[str, float] = collections.defaultdict(float)
    for item in items:
        totals[item.get('traffic_type', 'Mixed')] += float(item.get('current_mbps', 0.0))
    if not totals:
        return 'Mixed'
    return max(totals, key=totals.get)


def _build_alert(kind: str, severity: str, target: str, current_mbps: float, capacity_mbps: float,
                 util_pct: float, traffic_type: str, priority_level: str, risk_level: str,
                 prediction: str, action_taken: str, current_status: str, **extra) -> dict:
    alert = {
        'timestamp': time.time(),
        'ts': time.time(),
        'kind': kind,
        'severity': severity,
        'affected_device_or_link': target,
        'device': target,
        'current_mbps': round(current_mbps, 2),
        'capacity_mbps': round(capacity_mbps, 2),
        'utilization_percent': round(util_pct, 2),
        'utilization_pct': round(util_pct, 2),
        'traffic_type': traffic_type,
        'priority_level': priority_level,
        'risk_level': risk_level,
        'prediction': prediction,
        'action_taken': action_taken,
        'current_status': current_status,
    }
    alert.update(extra)
    _alerts.append(alert)
    while len(_alerts) > 200:
        _alerts.pop(0)
    return alert


def _fallback_device_links(pc_state: dict) -> list[dict]:
    device_links = []
    for host, info in pc_state.get('pcs', {}).items():
        current_mbps = float(info.get('current_mbps', info.get('traffic_mbps', 0.0)) or 0.0)
        capacity = float(info.get('link_capacity_mbps', EDGE_LINK_CAPACITY_MBPS) or EDGE_LINK_CAPACITY_MBPS)
        util_pct = round((current_mbps / max(capacity, 0.1)) * 100, 2)
        device_links.append({
            'host': host,
            'label': info.get('label', host),
            'ip': info.get('ip', ''),
            'zone': info.get('zone') or info.get('zone_key', ''),
            'switch': ZONE_ACCESS_SWITCH.get(info.get('zone') or info.get('zone_key', ''), ''),
            'activity': info.get('activity', 'idle'),
            'activity_label': info.get('activity_label', info.get('activity', 'idle')),
            'traffic_type': info.get('traffic_type', info.get('activity_label', 'Unknown')),
            'priority_level': info.get('priority_level', info.get('priority_label', 'BEST-EFFORT')),
            'priority_rank': int(info.get('priority', 5) or 5),
            'safe_from_throttle': bool(info.get('safe_from_throttle', False)),
            'current_mbps': round(current_mbps, 2),
            'capacity_mbps': round(capacity, 2),
            'utilization_percent': util_pct,
            'queue_depth': int(max(0.0, (util_pct - 55.0) * 3.0)),
            'packet_drops': int(max(0.0, round((util_pct - 90.0) * 2.0))) if util_pct >= 90 else 0,
            'latency_ms': round(2.5 + max(0.0, (util_pct - 40.0) * 0.85), 1),
            'dscp': int(info.get('dscp', 0) or 0),
            'qos_queue': int(info.get('qos_queue', 2) or 2),
            'dst_ip': info.get('dst_ip', ''),
        })
    device_links.sort(key=lambda item: item.get('current_mbps', 0.0), reverse=True)
    return device_links


def _fallback_access_uplinks(device_links: list[dict]) -> dict:
    access = {zone: {'current_mbps': 0.0, 'items': []} for zone in ZONE_LABELS}
    server_zone_inbound = 0.0
    server_sources = set()
    for link in device_links:
        zone = link.get('zone')
        if zone in access:
            access[zone]['current_mbps'] += link.get('current_mbps', 0.0)
            access[zone]['items'].append(link)
        if str(link.get('dst_ip', '')).startswith('10.20.0.'):
            server_zone_inbound += link.get('current_mbps', 0.0)
            server_sources.add(link.get('host'))
    access['server_zone']['current_mbps'] = max(access['server_zone']['current_mbps'], server_zone_inbound)

    result = {}
    for zone, data in access.items():
        current = data['current_mbps']
        util_pct = round((current / ACCESS_UPLINK_CAPACITY_MBPS) * 100, 2)
        result[zone] = {
            'zone': zone,
            'switch': ZONE_ACCESS_SWITCH[zone],
            'label': f"{ZONE_LABELS[zone]} Uplink",
            'current_mbps': round(current, 2),
            'capacity_mbps': ACCESS_UPLINK_CAPACITY_MBPS,
            'utilization_percent': util_pct,
            'queue_depth': int(max(0.0, (util_pct - 55.0) * 3.0)),
            'packet_drops': int(max(0.0, round((util_pct - 90.0) * 3.0))) if util_pct >= 90 else 0,
            'latency_ms': round(4.0 + max(0.0, (util_pct - 45.0) * 0.45), 1),
            'connected_devices': len(server_sources) if zone == 'server_zone' else len(data['items']),
            'traffic_type': _dominant_traffic(data['items']),
            'priority_mix': collections.Counter(item.get('priority_level', 'BEST-EFFORT') for item in data['items']),
        }
    return result


def _fallback_server_links(device_links: list[dict]) -> list[dict]:
    traffic_mix = {ip: collections.defaultdict(float) for ip in SERVER_HOSTS}
    priority_mix = {ip: collections.defaultdict(int) for ip in SERVER_HOSTS}
    best_priority = {ip: (99, 'BEST-EFFORT') for ip in SERVER_HOSTS}
    aggregates = {
        ip: {
            'host': meta['host'],
            'label': meta['label'],
            'ip': ip,
            'zone': 'server_zone',
            'switch': 'as2',
            'activity': 'server_inbound',
            'activity_label': 'Idle',
            'traffic_type': 'Server Traffic',
            'priority_rank': 5,
            'priority_level': 'BEST-EFFORT',
            'safe_from_throttle': True,
            'current_mbps': 0.0,
            'capacity_mbps': EDGE_LINK_CAPACITY_MBPS,
            'utilization_percent': 0.0,
            'queue_depth': 0,
            'packet_drops': 0,
            'latency_ms': 0.0,
            'dscp': 0,
            'qos_queue': 0,
            'dst_ip': ip,
            'current_status': 'idle',
            'active_flows': 0,
        }
        for ip, meta in SERVER_HOSTS.items()
    }

    for link in device_links:
        dst_ip = str(link.get('dst_ip', ''))
        if dst_ip not in aggregates:
            continue
        mbps = float(link.get('current_mbps', 0.0) or 0.0)
        if mbps <= 0:
            continue
        target = aggregates[dst_ip]
        target['current_mbps'] += mbps
        target['active_flows'] += 1
        target['queue_depth'] = max(target['queue_depth'], int(link.get('queue_depth', 0) or 0))
        target['packet_drops'] += int(link.get('packet_drops', 0) or 0)
        target['latency_ms'] = max(target['latency_ms'], float(link.get('latency_ms', 0.0) or 0.0))
        ttype = link.get('traffic_type') or link.get('activity_label') or link.get('activity') or 'Server Traffic'
        plevel = link.get('priority_level', 'BEST-EFFORT')
        prank = int(link.get('priority_rank', 5) or 5)
        traffic_mix[dst_ip][ttype] += mbps
        priority_mix[dst_ip][plevel] += 1
        if prank < best_priority[dst_ip][0]:
            best_priority[dst_ip] = (prank, plevel)

    server_links = []
    for ip, target in aggregates.items():
        current = round(target['current_mbps'], 2)
        util_pct = round((current / max(EDGE_LINK_CAPACITY_MBPS, 0.1)) * 100, 2)
        dominant_traffic = max(traffic_mix[ip], key=traffic_mix[ip].get) if traffic_mix[ip] else 'Server Traffic'
        priority_rank, priority_level = best_priority[ip]
        target.update({
            'activity_label': f'{dominant_traffic} Inbound' if current > 0 else 'Idle',
            'traffic_type': dominant_traffic,
            'priority_rank': priority_rank if priority_rank < 99 else 5,
            'priority_level': priority_level,
            'current_mbps': current,
            'utilization_percent': util_pct,
            'latency_ms': round(target['latency_ms'], 1),
            'current_status': 'active' if current > 0 else 'idle',
            'priority_mix': dict(priority_mix[ip]),
        })
        server_links.append(target)

    server_links.sort(key=lambda item: item.get('current_mbps', 0.0), reverse=True)
    return server_links


def _fallback_distribution_uplinks(access_uplinks: dict) -> dict:
    uplinks = {}
    for dist, zones in DIST_LINKS.items():
        current = sum(access_uplinks.get(zone, {}).get('current_mbps', 0.0) for zone in zones)
        util_pct = round((current / CORE_LINK_CAPACITY_MBPS) * 100, 2)
        queue_depth = max((access_uplinks.get(zone, {}).get('queue_depth', 0) for zone in zones), default=0)
        drops = sum(access_uplinks.get(zone, {}).get('packet_drops', 0) for zone in zones)
        latency = max((access_uplinks.get(zone, {}).get('latency_ms', 0.0) for zone in zones), default=0.0)
        uplinks[dist] = {
            'switch': dist,
            'label': f"{dist.upper()} -> Core",
            'current_mbps': round(current, 2),
            'capacity_mbps': CORE_LINK_CAPACITY_MBPS,
            'utilization_percent': util_pct,
            'queue_depth': queue_depth,
            'packet_drops': drops,
            'latency_ms': round(latency, 1),
            'served_zones': zones,
        }
    return uplinks


def _fallback_core_links(distribution_uplinks: dict) -> dict:
    total = sum(item.get('current_mbps', 0.0) for item in distribution_uplinks.values())
    util_pct = round((total / CORE_LINK_CAPACITY_MBPS) * 100, 2)
    queue_depth = max((item.get('queue_depth', 0) for item in distribution_uplinks.values()), default=0)
    drops = sum(item.get('packet_drops', 0) for item in distribution_uplinks.values())
    latency = max((item.get('latency_ms', 0.0) for item in distribution_uplinks.values()), default=0.0)
    return {
        'cs1_total': {
            'switch': 'cs1',
            'label': 'Campus Core / Controller Uplink',
            'current_mbps': round(total, 2),
            'capacity_mbps': CORE_LINK_CAPACITY_MBPS,
            'utilization_percent': util_pct,
            'queue_depth': queue_depth,
            'packet_drops': drops,
            'latency_ms': round(latency, 1),
            'served_links': sorted(distribution_uplinks.keys()),
        }
    }


def _enrich_link(link_id: str, link: dict, *, kind: str, exam_mode: bool = False) -> dict:
    current = float(link.get('current_mbps', 0.0) or 0.0)
    capacity = float(link.get('capacity_mbps', ACCESS_UPLINK_CAPACITY_MBPS) or ACCESS_UPLINK_CAPACITY_MBPS)
    util_pct = round(float(link.get('utilization_percent', (current / max(capacity, 0.1)) * 100) or 0.0), 2)
    queue_depth = int(link.get('queue_depth', max(0.0, (util_pct - 55.0) * 3.0)) or 0)
    packet_drops = int(link.get('packet_drops', 0) or 0)
    latency_ms = round(float(link.get('latency_ms', 0.0) or 0.0), 1)
    traffic_type = link.get('traffic_type', 'Mixed')
    priority_level = link.get('priority_level', 'MIXED')
    future = _future_projection(link_id, current, util_pct, capacity)
    state = _congestion_state(
        util_pct,
        future['growth_rate_pct'],
        future['projected_util_pct'],
        latency_ms,
        queue_depth,
        packet_drops,
    )
    action = _threshold_action(state)
    if exam_mode and kind == 'device' and link.get('activity') in ('exam', 'online_exam'):
        action = 'Guaranteed bandwidth and high-priority queue applied'

    enriched = dict(link)
    enriched.update({
        'kind': kind,
        'current_mbps': round(current, 2),
        'capacity_mbps': round(capacity, 2),
        'utilization_percent': util_pct,
        'latency_ms': latency_ms,
        'queue_depth': queue_depth,
        'packet_drops': packet_drops,
        'threshold_state': state,
        'threshold_color': STATE_COLORS[state],
        'recommended_action': action,
        'future_load': future,
        'predicted_mbps': future['projected_mbps'],
        'predicted_utilization_percent': future['projected_util_pct'],
        'growth_rate_pct': future['growth_rate_pct'],
    })
    return enriched


def _compute_cycle() -> dict:
    metrics = _read(METRICS_FILE)
    pc_state = _read(PC_ACT_FILE)
    timetable = _read(TIMETABLE_FILE)
    ml_action = _read(ML_ACTION_FILE)
    exam_mode = bool(timetable.get('exam_flag', 0))

    device_links = metrics.get('per_device_links') or _fallback_device_links(pc_state)
    server_links = metrics.get('per_server_links') or _fallback_server_links(device_links)
    access_uplinks = metrics.get('access_uplinks') or _fallback_access_uplinks(device_links)
    distribution_uplinks = metrics.get('distribution_uplinks') or _fallback_distribution_uplinks(access_uplinks)
    core_links = metrics.get('core_links') or _fallback_core_links(distribution_uplinks)
    zone_metrics = metrics.get('zone_metrics', {})
    priority_decisions = metrics.get('traffic_priority_decisions', [])
    decision_map = {d.get('host'): d for d in priority_decisions}

    enriched_device_links = []
    enriched_server_links = []
    device_saturation = []
    new_alerts = []
    before_after_utilization = []
    traffic_priority_decisions = []

    for link in device_links:
        enriched = _enrich_link(f"device:{link.get('host')}", link, kind='device', exam_mode=exam_mode)
        decision = decision_map.get(link.get('host'))
        if decision:
            enriched['controller_action'] = decision.get('action_taken')
            enriched['controller_status'] = decision.get('current_status')
            enriched['controller_limit_mbps'] = decision.get('enforced_limit_mbps')
        enriched_device_links.append(enriched)

        util_pct = enriched['utilization_percent']
        state = enriched['threshold_state']
        if util_pct >= 70 or state != 'healthy':
            device_saturation.append({
                'pc_id': enriched.get('host'),
                'label': enriched.get('label', enriched.get('host')),
                'ip': enriched.get('ip', ''),
                'traffic_mbps': enriched['current_mbps'],
                'capacity_mbps': enriched['capacity_mbps'],
                'utilization_pct': util_pct,
                'severity': state if state != 'healthy' else 'warning',
                'activity': enriched.get('activity', 'unknown'),
                'traffic_type': enriched.get('traffic_type', 'Unknown'),
                'priority_level': enriched.get('priority_level', 'BEST-EFFORT'),
            })

        if util_pct >= 70:
            risk_level = 'Port saturation risk'
            if state == 'critical':
                risk_level = 'Port saturation'
            action = decision.get('action_taken') if decision else _threshold_action(state)
            status = decision.get('current_status') if decision else state.title()
            prediction = (
                f"May reach {enriched['predicted_utilization_percent']:.1f}% in 10 seconds"
                if enriched['predicted_utilization_percent'] > util_pct
                else f"Projected steady at {enriched['predicted_utilization_percent']:.1f}%"
            )
            new_alerts.append(_build_alert(
                'device', state if state != 'healthy' else 'warning',
                f"{enriched.get('label')} -> {ZONE_LABELS.get(enriched.get('zone', ''), 'Access Switch')}",
                enriched['current_mbps'], enriched['capacity_mbps'], util_pct,
                enriched.get('traffic_type', 'Unknown'),
                enriched.get('priority_level', 'BEST-EFFORT'),
                risk_level, prediction, action, status,
                host=enriched.get('host'), ip=enriched.get('ip'), activity=enriched.get('activity'),
            ))

        if decision and decision.get('action_taken') != 'Monitoring only':
            before_util = util_pct
            after_mbps = min(enriched['current_mbps'], float(decision.get('enforced_limit_mbps') or enriched['current_mbps']))
            after_util = round((after_mbps / max(enriched['capacity_mbps'], 0.1)) * 100, 2)
            before_after_utilization.append({
                'target': enriched.get('label'),
                'kind': 'device',
                'before_utilization_percent': before_util,
                'after_utilization_percent': after_util,
                'before_mbps': enriched['current_mbps'],
                'after_mbps': round(after_mbps, 2),
                'action_taken': decision.get('action_taken'),
            })
            traffic_priority_decisions.append({
                'host': decision.get('host'),
                'label': decision.get('label'),
                'activity': decision.get('activity'),
                'traffic_type': decision.get('traffic_type'),
                'priority_level': decision.get('priority_level'),
                'action_taken': decision.get('action_taken'),
                'current_status': decision.get('current_status'),
                'enforced_limit_mbps': decision.get('enforced_limit_mbps'),
            })

            priority_kind = 'priority_action'
            severity = 'warning'
            if decision.get('priority_level') in ('CRITICAL', 'HIGH'):
                priority_kind = 'priority_action'
                severity = 'preventive' if exam_mode else 'warning'
            elif _priority_rank(decision.get('priority_level')) >= 4:
                priority_kind = 'low_priority_control'
                severity = 'preventive' if state != 'critical' else 'critical'

            prediction = f"Link may reach {enriched['predicted_utilization_percent']:.1f}% in 10 seconds"
            if decision.get('priority_level') in ('CRITICAL', 'HIGH'):
                status = decision.get('current_status', 'Academic traffic protected')
            else:
                status = decision.get('current_status', 'Low-priority traffic controlled')
            new_alerts.append(_build_alert(
                priority_kind, severity,
                enriched.get('label', decision.get('label')),
                enriched['current_mbps'], enriched['capacity_mbps'], util_pct,
                enriched.get('traffic_type', 'Unknown'),
                decision.get('priority_level', enriched.get('priority_level', 'BEST-EFFORT')),
                'Traffic priority decision', prediction,
                decision.get('action_taken', 'Monitoring only'),
                status,
                ip=enriched.get('ip'), activity=enriched.get('activity'),
            ))

    for link in server_links:
        enriched_server_links.append(_enrich_link(f"server:{link.get('host')}", link, kind='server', exam_mode=exam_mode))

    enriched_access = {}
    zones = {}
    for zone, link in access_uplinks.items():
        enriched = _enrich_link(f"access:{zone}", link, kind='access', exam_mode=exam_mode)
        enriched_access[zone] = enriched
        zone_metric = zone_metrics.get(zone, {})
        zones[zone] = {
            'zone': zone,
            'display_name': f"{ZONE_LABELS.get(zone, zone)} (Access SW)",
            'throughput_mbps': enriched['current_mbps'],
            'utilization_pct': enriched['utilization_percent'],
            'threshold_state': enriched['threshold_state'],
            'threshold_color': enriched['threshold_color'],
            'recommended_action': enriched['recommended_action'],
            'uplink_capacity_mbps': enriched['capacity_mbps'],
            'uplink_util_pct': enriched['utilization_percent'],
            'device_aggregated_mbps': enriched['current_mbps'],
            'device_count': enriched.get('connected_devices', zone_metric.get('device_count', 0)),
            'congested': enriched['threshold_state'] in ('warning', 'preventive', 'critical'),
            'predicted_congestion': enriched['predicted_utilization_percent'] >= THRESHOLD_WARNING,
            'latency_ms': enriched['latency_ms'],
            'loss_pct': round(float(zone_metric.get('loss_pct', 0.0) or 0.0), 2),
            'queue_depth': enriched['queue_depth'],
            'packet_drops': enriched['packet_drops'],
            'traffic_type': enriched.get('traffic_type', 'Mixed'),
            'priority_mix': enriched.get('priority_mix', {}),
            'future_load': enriched['future_load'],
        }

        if enriched['threshold_state'] != 'healthy':
            prediction = f"May reach {enriched['predicted_utilization_percent']:.1f}% within 10 seconds"
            if enriched['threshold_state'] == 'critical':
                prediction = f"Congestion active; projected {enriched['predicted_utilization_percent']:.1f}%"
            dist_name = 'Distribution SW 1' if zone in DIST_LINKS['ds1'] else 'Distribution SW 2'
            new_alerts.append(_build_alert(
                'uplink', enriched['threshold_state'],
                f"Access SW {ZONE_LABELS.get(zone, zone)} -> {dist_name}",
                enriched['current_mbps'], enriched['capacity_mbps'], enriched['utilization_percent'],
                enriched.get('traffic_type', 'Mixed'),
                'MIXED', f"{enriched['threshold_state'].upper()} uplink congestion risk",
                prediction, enriched['recommended_action'], enriched['threshold_state'].title(),
                zone=zone,
            ))

    enriched_distribution = {
        dist: _enrich_link(f"dist:{dist}", link, kind='distribution', exam_mode=exam_mode)
        for dist, link in distribution_uplinks.items()
    }
    enriched_core = {
        core_id: _enrich_link(f"core:{core_id}", link, kind='core', exam_mode=exam_mode)
        for core_id, link in core_links.items()
    }

    link_index = {}
    for zone, item in enriched_access.items():
        dist = DIST_LINKS['ds1'] if zone in DIST_LINKS['ds1'] else DIST_LINKS['ds2']
        dist_name = 'ds1' if zone in DIST_LINKS['ds1'] else 'ds2'
        link_index[f"{item['switch']}-{dist_name}"] = dict(item)
        link_index[f"{dist_name}-{item['switch']}"] = dict(item)
    for dist, item in enriched_distribution.items():
        link_index[f"{dist}-cs1"] = dict(item)
        link_index[f"cs1-{dist}"] = dict(item)
    for link in enriched_device_links:
        link_index[f"{link.get('host')}-{link.get('switch')}"] = dict(link)
        link_index[f"{link.get('switch')}-{link.get('host')}"] = dict(link)
    for link in enriched_server_links:
        link_index[f"{link.get('host')}-{link.get('switch')}"] = dict(link)
        link_index[f"{link.get('switch')}-{link.get('host')}"] = dict(link)

    mitigated_access = {}
    for zone, item in enriched_access.items():
        low_pri_reduction = 0.0
        for decision in priority_decisions:
            if decision.get('zone') != zone:
                continue
            limit = decision.get('enforced_limit_mbps')
            if limit is None:
                continue
            current = float(decision.get('current_mbps', 0.0) or 0.0)
            low_pri_reduction += max(0.0, current - float(limit))
        before = item['utilization_percent']
        after_mbps = max(0.0, item['current_mbps'] - low_pri_reduction)
        after = round((after_mbps / max(item['capacity_mbps'], 0.1)) * 100, 2)
        mitigated_access[zone] = {
            'before_mbps': item['current_mbps'],
            'after_mbps': round(after_mbps, 2),
            'before_utilization_percent': before,
            'after_utilization_percent': after,
        }
        before_after_utilization.append({
            'target': item['label'],
            'kind': 'access_uplink',
            'before_mbps': item['current_mbps'],
            'after_mbps': round(after_mbps, 2),
            'before_utilization_percent': before,
            'after_utilization_percent': after,
            'action_taken': 'Priority-based mitigation estimate',
        })

    links = {
        'server': list(enriched_server_links),
        'access': list(enriched_access.values()),
        'distribution': list(enriched_distribution.values()),
        'core': list(enriched_core.values()),
    }
    all_link_items = enriched_device_links + enriched_server_links + links['access'] + links['distribution'] + links['core']
    congestion_states = {
        key: value['threshold_state']
        for key, value in link_index.items()
        if isinstance(value, dict) and 'threshold_state' in value
    }
    predictions = {
        key: {
            'current_mbps': value['current_mbps'],
            'predicted_mbps': value.get('predicted_mbps', value['current_mbps']),
            'current_utilization_percent': value['utilization_percent'],
            'predicted_utilization_percent': value.get('predicted_utilization_percent', value['utilization_percent']),
            'growth_rate_pct': value.get('growth_rate_pct', 0.0),
        }
        for key, value in link_index.items()
        if isinstance(value, dict) and 'utilization_percent' in value
    }
    current_ml_action = ml_action.get('action', 'normal_mode')
    current_core = enriched_core['cs1_total']

    actions_taken = sorted({
        current_ml_action,
        *[d.get('action_taken') for d in traffic_priority_decisions if d.get('action_taken')],
        *[item['recommended_action'] for item in enriched_access.values()],
    })

    state_doc = {
        'ts': time.time(),
        'timestamp': time.time(),
        'current_ml_action': current_ml_action,
        'exam_mode': exam_mode,
        'timetable_period': timetable.get('period', 'unknown'),
        'links': links,
        'link_index': link_index,
        'per_device_links': enriched_device_links,
        'per_server_links': enriched_server_links,
        'access_uplinks': enriched_access,
        'distribution_uplinks': enriched_distribution,
        'core_links': enriched_core,
        'zones': zones,
        'device_saturation': sorted(device_saturation, key=lambda item: item['utilization_pct'], reverse=True),
        'congestion_states': congestion_states,
        'predictions': predictions,
        'alerts': _alerts[-100:],
        'recent_alerts': new_alerts[-20:],
        'alert_count': len(_alerts),
        'new_alerts_this_cycle': len(new_alerts),
        'actions_taken': actions_taken,
        'before_after_utilization': before_after_utilization[-60:],
        'traffic_priority_decisions': traffic_priority_decisions,
        'mitigated_access_uplinks': mitigated_access,
        'network_aggregation': {
            'total_throughput_mbps': current_core['current_mbps'],
            'controller_link_capacity_mbps': current_core['capacity_mbps'],
            'controller_link_util_pct': current_core['utilization_percent'],
            'controller_link_state': current_core['threshold_state'],
            'controller_link_color': current_core['threshold_color'],
        },
        'summary': {
            'warning_links': sum(1 for item in all_link_items if item.get('threshold_state') == 'warning'),
            'preventive_links': sum(1 for item in all_link_items if item.get('threshold_state') == 'preventive'),
            'critical_links': sum(1 for item in all_link_items if item.get('threshold_state') == 'critical'),
            'protected_academic_flows': sum(1 for item in traffic_priority_decisions if _priority_rank(item.get('priority_level')) <= 2),
            'low_priority_controls': sum(1 for item in traffic_priority_decisions if _priority_rank(item.get('priority_level')) >= 4),
        },
    }

    logger.info(
        'cycle core=%.1f%% alerts=%d protected=%d lowpri=%d ml=%s',
        current_core['utilization_percent'],
        len(new_alerts),
        state_doc['summary']['protected_academic_flows'],
        state_doc['summary']['low_priority_controls'],
        current_ml_action,
    )
    for alert in new_alerts[-6:]:
        logger.info(
            'alert severity=%s target=%s util=%.1f%% action=%s',
            alert.get('severity'),
            alert.get('affected_device_or_link'),
            alert.get('utilization_percent', 0.0),
            alert.get('action_taken'),
        )

    if not atomic_write_json(OUTPUT_FILE, state_doc):
        logger.error('write error path=%s', OUTPUT_FILE)

    global _state
    _state = state_doc
    return state_doc


def _poll_loop():
    while True:
        try:
            _compute_cycle()
        except Exception as exc:
            logger.exception('cycle error: %s', exc)
        time.sleep(2)


@app.route('/status')
def api_status():
    return jsonify(_read(OUTPUT_FILE) or _state)


@app.route('/zones')
def api_zones():
    state = _read(OUTPUT_FILE) or _state
    return jsonify({'zones': state.get('zones', {}), 'ts': state.get('ts', 0)})


@app.route('/alerts')
def api_alerts():
    state = _read(OUTPUT_FILE) or _state
    return jsonify({'alerts': state.get('recent_alerts', []), 'count': state.get('alert_count', 0)})


@app.route('/links')
def api_links():
    state = _read(OUTPUT_FILE) or _state
    return jsonify(state.get('links', {}))


@app.route('/device_saturation')
def api_saturation():
    state = _read(OUTPUT_FILE) or _state
    return jsonify(state.get('device_saturation', []))


@app.route('/aggregation')
def api_aggregation():
    state = _read(OUTPUT_FILE) or _state
    return jsonify(state.get('network_aggregation', {}))


@app.route('/priority')
def api_priority():
    state = _read(OUTPUT_FILE) or _state
    return jsonify({'decisions': state.get('traffic_priority_decisions', [])})


@app.route('/health')
def api_health():
    return jsonify({'ok': True, 'ts': time.time(), 'service': 'proactive_congestion'})


def run(port: int = 9100):
    threading.Thread(target=_poll_loop, daemon=True).start()
    logger.info('service starting on port %s', port)
    app.run(host='0.0.0.0', port=port, threaded=True)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=9100)
    run(port=parser.parse_args().port)
