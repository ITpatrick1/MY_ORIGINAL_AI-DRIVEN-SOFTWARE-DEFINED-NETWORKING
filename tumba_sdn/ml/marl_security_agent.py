#!/usr/bin/env python3
"""
MARL Security Agent — Tumba College SDN
Second agent in the Multi-Agent Reinforcement Learning (MARL) framework.

The traffic DQN agent (dqn_agent.py) optimises bandwidth/QoS decisions.
This agent specialises in security decisions — a clean division that forms
the MARL system: two cooperating agents with separate state/action spaces.

Security State Vector (10 dimensions):
  - Port-scan PPS per zone   (4)  — normalised 0-1 (max 500 pps)
  - DDoS indicator per zone  (4)  — 0 or 1
  - Blocked-IP count         (1)  — normalised
  - Ctrl-plane flood ratio   (1)  — normalised

Security Action Space (8 discrete):
  0  monitor_only           — no enforcement, gather data
  1  rate_limit_wifi        — throttle student WiFi to 20 % capacity
  2  isolate_wifi           — block all WiFi→Server/Staff traffic
  3  block_src_ip           — drop traffic from suspicious source
  4  alert_ict_staff        — raise high-severity alert
  5  quarantine_lab         — isolate IT Lab from core
  6  emergency_lockdown     — block all non-essential inter-zone traffic
  7  restore_normal         — remove all temporary security rules

Writes decisions to /tmp/campus_security_action.json every 3 s.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import time
from collections import deque

METRICS_FILE   = os.environ.get('CAMPUS_METRICS_FILE',   '/tmp/campus_metrics.json')
SEC_OUT_FILE   = os.environ.get('CAMPUS_SEC_ACTION_FILE','/tmp/campus_security_action.json')
ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE', '/tmp/campus_ml_action.json')

ZONES = ['staff_lan', 'server_zone', 'it_lab', 'student_wifi']

SECURITY_ACTIONS = [
    'monitor_only',
    'rate_limit_wifi',
    'isolate_wifi',
    'block_src_ip',
    'alert_ict_staff',
    'quarantine_lab',
    'emergency_lockdown',
    'restore_normal',
]

# Thresholds
SCAN_PPS_MAX   = 500.0
DDOS_PPS_MAX   = 2000.0
BLOCK_IP_MAX   = 10.0


def _read(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _write(path: str, data: dict) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _sf(v, d=0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(d)


# ── Simple Q-table (tabular RL — no GPU needed for security agent) ────────────

class SecurityAgent:
    """
    Lightweight tabular Q-learning security agent.
    State is discretised into threat levels (none/low/medium/high/critical)
    across 3 combined dimensions to keep the table small enough for
    on-line learning without a replay buffer or neural network.
    """

    N_ACTIONS = len(SECURITY_ACTIONS)
    THREAT_LEVELS = 5  # 0=none 1=low 2=med 3=high 4=critical

    def __init__(self, lr=0.15, gamma=0.90, epsilon=0.40, epsilon_min=0.05):
        self.lr          = lr
        self.gamma       = gamma
        self.epsilon     = epsilon
        self.epsilon_min = epsilon_min

        # Q-table: (wifi_threat, server_threat, ddos_flag) → actions
        self.qtable: dict[tuple, list[float]] = {}
        self.steps   = 0
        self.episode_rewards: list[float] = []
        self.last_state: tuple | None = None
        self.last_action: int | None  = None

        # Per-zone scan tracking
        self._scan_window: dict[str, deque] = {z: deque(maxlen=30) for z in ZONES}

    # ── State extraction ────────────────────────────────────────────────────

    def _extract_state(self, metrics: dict) -> tuple[tuple, dict]:
        zm       = metrics.get('zone_metrics', {})
        scans    = metrics.get('active_scans', [])
        ddos     = metrics.get('ddos_active', False)
        blocked  = len(metrics.get('blocked_ips', []))

        # Scan threat per zone
        scan_pps = {z: 0.0 for z in ZONES}
        for s in scans:
            z = s.get('zone', '')
            if z in scan_pps:
                scan_pps[z] = max(scan_pps[z], _sf(s.get('pps', 0)))

        # Raw state vector (continuous)
        raw = {
            'wifi_scan_pps':   scan_pps.get('student_wifi', 0),
            'lab_scan_pps':    scan_pps.get('it_lab', 0),
            'server_scan_pps': scan_pps.get('server_zone', 0),
            'staff_scan_pps':  scan_pps.get('staff_lan', 0),
            'ddos_active':     1.0 if ddos else 0.0,
            'blocked_count':   min(1.0, blocked / BLOCK_IP_MAX),
            'wifi_util':       _sf(zm.get('student_wifi', {}).get('max_utilization_pct', 0)) / 100,
            'server_util':     _sf(zm.get('server_zone',  {}).get('max_utilization_pct', 0)) / 100,
        }

        # Discretise to (wifi_threat, server_threat, ddos) for Q-table key
        wifi_t   = self._threat_level(raw['wifi_scan_pps'], raw['wifi_util'], ddos)
        server_t = self._threat_level(raw['server_scan_pps'], raw['server_util'], ddos)
        ddos_f   = 4 if ddos else 0

        state_key = (wifi_t, server_t, ddos_f)
        return state_key, raw

    @staticmethod
    def _threat_level(scan_pps: float, util: float, ddos: bool) -> int:
        if ddos or scan_pps > 400:
            return 4  # critical
        if scan_pps > 200 or util > 0.85:
            return 3  # high
        if scan_pps > 80 or util > 0.70:
            return 2  # medium
        if scan_pps > 20 or util > 0.50:
            return 1  # low
        return 0      # none

    # ── Q-table helpers ─────────────────────────────────────────────────────

    def _get_q(self, state: tuple) -> list[float]:
        if state not in self.qtable:
            self.qtable[state] = [0.0] * self.N_ACTIONS
        return self.qtable[state]

    def _select_action(self, state: tuple) -> int:
        if random.random() < self.epsilon:
            return random.randrange(self.N_ACTIONS)
        q = self._get_q(state)
        return int(max(range(self.N_ACTIONS), key=lambda i: q[i]))

    def _update_q(self, s: tuple, a: int, r: float, ns: tuple) -> None:
        q     = self._get_q(s)
        q_ns  = self._get_q(ns)
        td    = r + self.gamma * max(q_ns) - q[a]
        q[a] += self.lr * td

    # ── Reward function ─────────────────────────────────────────────────────

    def _reward(self, raw: dict, action_idx: int) -> float:
        action = SECURITY_ACTIONS[action_idx]
        ddos   = raw['ddos_active'] > 0.5
        scan   = raw['wifi_scan_pps'] > 50 or raw['lab_scan_pps'] > 50
        threat = ddos or scan

        reward = 0.0

        # Correct responses earn positive reward
        if threat and action in ('block_src_ip', 'isolate_wifi', 'rate_limit_wifi',
                                 'alert_ict_staff', 'emergency_lockdown'):
            reward += 30.0
        if not threat and action == 'monitor_only':
            reward += 20.0
        if not threat and action == 'restore_normal':
            reward += 10.0

        # False-positive penalties (over-reaction when no threat)
        if not threat and action in ('emergency_lockdown', 'quarantine_lab', 'isolate_wifi'):
            reward -= 25.0

        # Under-reaction penalty (threat ignored)
        if ddos and action == 'monitor_only':
            reward -= 40.0
        if scan and action == 'monitor_only':
            reward -= 15.0

        # Server-zone protection bonus
        if raw['server_scan_pps'] > 100 and action in ('quarantine_lab', 'block_src_ip'):
            reward += 15.0

        return round(max(-50.0, min(50.0, reward)), 3)

    # ── Explainability ──────────────────────────────────────────────────────

    def _explain(self, raw: dict, action: str) -> dict:
        top = sorted(raw.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        return {
            'action_rationale': f"Chose '{action}' based on dominant features",
            'top_features': [{'feature': k, 'value': round(v, 3)} for k, v in top],
            'threat_assessment': (
                'CRITICAL' if raw['ddos_active'] > 0.5 else
                'HIGH'     if raw['wifi_scan_pps'] > 200 or raw['server_scan_pps'] > 100 else
                'MEDIUM'   if raw['wifi_scan_pps'] > 50 else
                'LOW'      if raw['wifi_scan_pps'] > 10 else 'CLEAR'
            ),
        }

    # ── Main loop ───────────────────────────────────────────────────────────

    def run(self, interval: float = 3.0, max_steps: int = 0) -> None:
        print("MARL Security Agent started")
        print(f"  metrics : {METRICS_FILE}")
        print(f"  output  : {SEC_OUT_FILE}")
        print(f"  actions : {SECURITY_ACTIONS}")

        loops = 0
        while True:
            loops += 1
            metrics = _read(METRICS_FILE)
            if not metrics:
                time.sleep(interval)
                if max_steps and loops >= max_steps:
                    break
                continue

            state_key, raw = self._extract_state(metrics)
            action_idx     = self._select_action(state_key)
            reward         = self._reward(raw, action_idx)

            # Update Q-table from previous transition
            if self.last_state is not None and self.last_action is not None:
                self._update_q(self.last_state, self.last_action, reward, state_key)

            self.last_state  = state_key
            self.last_action = action_idx
            self.steps      += 1
            self.episode_rewards.append(reward)

            # Decay epsilon
            self.epsilon = max(self.epsilon_min, self.epsilon * 0.9998)

            action_name = SECURITY_ACTIONS[action_idx]
            q_values    = self._get_q(state_key)
            explanation = self._explain(raw, action_name)

            avg50 = (sum(self.episode_rewards[-50:]) /
                     max(1, len(self.episode_rewards[-50:])))

            payload = {
                'ts':           time.time(),
                'agent':        'marl_security',
                'action_index': action_idx,
                'action':       action_name,
                'state_key':    list(state_key),
                'raw_state':    {k: round(v, 3) for k, v in raw.items()},
                'q_values':     {SECURITY_ACTIONS[i]: round(v, 4)
                                 for i, v in enumerate(q_values)},
                'reward':       reward,
                'avg_reward_50': round(avg50, 3),
                'epsilon':      round(self.epsilon, 4),
                'steps':        self.steps,
                'qtable_states': len(self.qtable),
                'explanation':  explanation,
                'threat_level': explanation['threat_assessment'],
                'cooperate_with_dqn': _read(ML_ACTION_FILE).get('action', 'unknown'),
            }

            _write(SEC_OUT_FILE, payload)

            if self.steps % 10 == 0:
                print(f"[SEC] step={self.steps} action={action_name} "
                      f"reward={reward:.1f} avg50={avg50:.1f} "
                      f"ε={self.epsilon:.4f} states={len(self.qtable)}")

            if max_steps and loops >= max_steps:
                break
            time.sleep(interval)

        print("MARL Security Agent stopped.")


def main() -> None:
    p = argparse.ArgumentParser(description='MARL Security Agent — Tumba College SDN')
    p.add_argument('--interval',   type=float, default=3.0)
    p.add_argument('--lr',         type=float, default=0.15)
    p.add_argument('--gamma',      type=float, default=0.90)
    p.add_argument('--epsilon',    type=float, default=0.40)
    p.add_argument('--max-steps',  type=int,   default=0)
    args = p.parse_args()

    agent = SecurityAgent(lr=args.lr, gamma=args.gamma, epsilon=args.epsilon)
    agent.run(interval=max(1.0, args.interval), max_steps=max(0, args.max_steps))


if __name__ == '__main__':
    main()
