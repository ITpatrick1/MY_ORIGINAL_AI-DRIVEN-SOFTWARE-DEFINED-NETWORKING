#!/usr/bin/env python3
"""ML action stub — writes simulated DQN decisions every 3 seconds."""
import json, time, random

ACTIONS = ["maintain_qos","reroute_traffic","block_ddos","increase_bandwidth","shed_load","restore_normal"]
ZONES   = ["staff_lan","server_zone","it_lab","student_wifi"]

while True:
    util = [random.uniform(20, 85) for _ in ZONES]
    idx  = util.index(max(util))
    json.dump({
        "ts":               time.time(),
        "action":           ACTIONS[min(idx, len(ACTIONS)-1)],
        "action_index":     idx,
        "q_values":         [round(random.uniform(-1,1), 3) for _ in ACTIONS],
        "reward":           round(random.uniform(0.3, 1.0), 3),
        "zone_utilization": {z: round(u, 1) for z, u in zip(ZONES, util)},
        "episode":          random.randint(500, 2000),
        "epsilon":          round(max(0.05, 0.3 - time.time() % 100 * 0.001), 3),
    }, open('/tmp/campus_ml_action.json','w'))
    time.sleep(3)
