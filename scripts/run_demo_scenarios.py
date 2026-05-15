#!/usr/bin/env python3

from __future__ import annotations

import json
import time
import urllib.request

SCENARIOS = [
    ("normal_traffic", "Normal traffic stays healthy with visible live flows"),
    ("warning_wifi", "Warning congestion shows yellow state and prediction"),
    ("preventive_wifi", "Preventive congestion throttles low priority traffic"),
    ("critical_port", "95 Mbps edge saturation becomes critical"),
    ("elearning_priority", "Academic flow receives priority protection"),
    ("streaming_throttle", "Streaming gets controlled during congestion"),
    ("exam_mode", "Exam traffic is protected with DSCP 46"),
    ("port_scan_attack", "Port scan detection blocks attacker"),
    ("ddos_attack", "DDoS/flood detection activates mitigation"),
    ("unauthorized_access", "Zero-Trust blocks restricted access attempts"),
    ("stop_reset", "All PCs return to idle"),
]


def post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read() or b"{}")


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def flow_match(flows: list[dict], *, activity: str | None = None, priority: str | None = None, dscp: int | None = None) -> bool:
    for flow in flows:
        if activity and str(flow.get("activity", "")).lower() != activity.lower():
            continue
        if priority and str(flow.get("priority", "")).upper() != priority.upper():
            continue
        if dscp is not None and int(flow.get("dscp", -1)) != dscp:
            continue
        return True
    return False


def check_scenario(name: str, result: dict, metrics: dict, proactive: dict, pc_state: dict) -> tuple[bool, dict]:
    summary = proactive.get("summary", {})
    flows = metrics.get("top_flows", [])
    pcs = pc_state.get("pcs", {})
    blocked = metrics.get("blocked_ips", [])
    events = metrics.get("security_events", [])

    evidence = {
        "scenario": result.get("scenario", name),
        "pc_ts": pc_state.get("ts"),
        "ml_action": proactive.get("current_ml_action"),
        "warning_links": summary.get("warning_links"),
        "preventive_links": summary.get("preventive_links"),
        "critical_links": summary.get("critical_links"),
        "ddos_active": metrics.get("ddos_active"),
        "blocked_ips": blocked,
    }

    if not result.get("ok"):
        evidence["why"] = "scenario api returned ok=false"
        return False, evidence

    if name == "normal_traffic":
        ok = bool(flows) and not metrics.get("ddos_active")
        evidence["flow_count"] = len(flows)
        return ok, evidence
    if name == "warning_wifi":
        ok = (summary.get("warning_links", 0) or 0) >= 1
        return ok, evidence
    if name == "preventive_wifi":
        ok = (summary.get("preventive_links", 0) or 0) >= 1
        return ok, evidence
    if name == "critical_port":
        pc = pcs.get("h_wifi2", {})
        evidence["h_wifi2"] = {
            "activity": pc.get("activity"),
            "current_mbps": pc.get("current_mbps"),
            "utilization_percent": pc.get("utilization_percent"),
            "controller_action": pc.get("controller_action"),
        }
        ok = (pc.get("current_mbps", 0) or 0) >= 90 and (pc.get("utilization_percent", 0) or 0) >= 90
        return ok, evidence
    if name == "elearning_priority":
        ok = flow_match(flows, activity="E-learning", priority="HIGH", dscp=34)
        return ok, evidence
    if name == "streaming_throttle":
        ok = flow_match(flows, activity="Streaming", priority="LOW", dscp=10) or flow_match(flows, activity="Social Media", priority="LOW", dscp=10)
        return ok, evidence
    if name == "exam_mode":
        ok = flow_match(flows, activity="Online Exam", priority="CRITICAL", dscp=46)
        return ok, evidence
    if name == "port_scan_attack":
        ok = bool(metrics.get("active_scans")) and any("port_scan" in str(evt.get("event", "")) for evt in events)
        evidence["active_scans"] = metrics.get("active_scans")
        return ok, evidence
    if name == "ddos_attack":
        ok = bool(metrics.get("ddos_active"))
        evidence["security_events"] = events[-5:]
        return ok, evidence
    if name == "unauthorized_access":
        ok = any(evt.get("activity") in ("unauthorized_server_access", "brute_force", "ip_spoofing", "arp_spoofing") for evt in events)
        evidence["security_events"] = events[-6:]
        return ok, evidence
    if name == "stop_reset":
        ok = all(pc.get("activity") == "idle" for pc in pcs.values())
        return ok, evidence
    return True, evidence


def main() -> int:
    print("Scenario verification")
    failures = 0
    for name, expectation in SCENARIOS:
        try:
            result = post_json("http://127.0.0.1:9090/api/scenario", {"scenario": name})
            time.sleep(4 if name != "stop_reset" else 2)
            metrics = read_json("/tmp/campus_metrics.json")
            proactive = read_json("/tmp/campus_proactive_congestion.json")
            pc_state = read_json("/tmp/campus_pc_activities.json")
            ok, evidence = check_scenario(name, result, metrics, proactive, pc_state)
            print(f"[{'PASS' if ok else 'FAIL'}] {name}: {expectation}")
            print(json.dumps(evidence, indent=2))
            if not ok:
                failures += 1
        except Exception as exc:
            failures += 1
            print(f"[FAIL] {name}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
