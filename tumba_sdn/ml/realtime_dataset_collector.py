#!/usr/bin/env python3
"""Real-time dataset collector for the Tumba College SDN prototype.

The collector reads live controller/state JSON files and writes normalized
datasets for ML training, reports, and dashboard previews. It does not invent
random traffic. When counters are unavailable, derived fields are calculated
from the measured/live Mbps and activity duration already exposed by the
running SDN simulation.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import os
import shutil
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from tumba_sdn.common.campus_core import configure_file_logger, read_json

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = Path(os.environ.get("CAMPUS_DATASET_ROOT", REPO_ROOT / "datasets"))
REALTIME_DIR = DATASET_ROOT / "realtime"
ARCHIVE_DIR = DATASET_ROOT / "archive"
EXPORTS_DIR = DATASET_ROOT / "exports"

STATE_FILES = {
    "metrics": os.environ.get("CAMPUS_METRICS_FILE", "/tmp/campus_metrics.json"),
    "pc": os.environ.get("CAMPUS_PC_ACTIVITIES_FILE", "/tmp/campus_pc_activities.json"),
    "proactive": os.environ.get("CAMPUS_PROACTIVE_CONG_FILE", "/tmp/campus_proactive_congestion.json"),
    "security": os.environ.get("CAMPUS_SEC_ACTION_FILE", "/tmp/campus_security_action.json"),
    "ml": os.environ.get("CAMPUS_ML_ACTION_FILE", "/tmp/campus_ml_action.json"),
    "timetable": os.environ.get("CAMPUS_TIMETABLE_STATE", "/tmp/campus_timetable_state.json"),
    "ibn": os.environ.get("CAMPUS_IBN_STATE_FILE", "/tmp/campus_ibn_state.json"),
}

LOGGER = configure_file_logger("tumba.dataset_collector", "dataset_collector.log")

TRAFFIC_FIELDS = [
    "timestamp",
    "source_pc",
    "source_ip",
    "source_mac",
    "source_vlan",
    "connected_switch",
    "destination_ip",
    "destination_port",
    "destination_service",
    "protocol",
    "activity",
    "traffic_type",
    "priority_level",
    "dscp_value",
    "current_mbps",
    "packet_count",
    "byte_count",
    "flow_duration",
    "controller_action",
    "status",
    "label",
]

CONGESTION_FIELDS = [
    "timestamp",
    "link_id",
    "link_name",
    "source_device",
    "destination_device",
    "link_type",
    "capacity_mbps",
    "current_mbps",
    "utilization_percent",
    "predicted_mbps",
    "predicted_utilization_percent",
    "traffic_growth_rate",
    "ema_trend",
    "latency_ms",
    "queue_depth",
    "packet_drops",
    "congestion_state",
    "color_state",
    "risk_level",
    "mitigation_action",
    "before_utilization",
    "after_utilization",
    "prediction_reason",
    "label",
]

SECURITY_FIELDS = [
    "timestamp",
    "attacker_pc",
    "attacker_ip",
    "attacker_mac",
    "attacker_vlan",
    "target_ip",
    "target_vlan",
    "target_service",
    "attack_type",
    "evidence",
    "packet_rate",
    "port_count",
    "scanned_ports",
    "failed_attempts",
    "risk_level",
    "security_state",
    "marl_decision",
    "controller_action",
    "openflow_rule",
    "status",
    "label",
]

QOS_FIELDS = [
    "timestamp",
    "pc_name",
    "ip_address",
    "vlan",
    "activity",
    "traffic_type",
    "priority_level",
    "dscp_value",
    "queue_id",
    "requested_bandwidth",
    "allocated_bandwidth",
    "congestion_state",
    "exam_mode",
    "controller_action",
    "reason",
    "status",
    "label",
]

ML_FIELDS = [
    "timestamp",
    "state_vector",
    "action_selected",
    "action_name",
    "reward",
    "congestion_inputs",
    "security_inputs",
    "exam_flag",
    "protected_flows",
    "throttled_flows",
    "blocked_flows",
    "safety_rail_applied",
    "final_controller_action",
    "label",
]

DATASET_FILES = {
    "traffic": ("live_traffic_dataset.csv", TRAFFIC_FIELDS, "traffic"),
    "congestion": ("live_congestion_dataset.csv", CONGESTION_FIELDS, "congestion"),
    "security": ("live_security_dataset.csv", SECURITY_FIELDS, "security"),
    "qos": ("live_qos_dataset.csv", QOS_FIELDS, "qos"),
    "ml": ("live_ml_dataset.csv", ML_FIELDS, "ml"),
    "events": ("live_events_dataset.jsonl", None, "events"),
}

SECURITY_ACTIVITY_MAP = {
    "port_scan": "port_scan",
    "network_sweep": "ping_sweep",
    "ping_sweep": "ping_sweep",
    "ddos_attack": "ddos",
    "unauthorized_server_access": "unauthorized_access",
    "ip_spoofing": "ip_spoofing",
    "arp_spoofing": "arp_spoofing",
    "brute_force": "brute_force",
}

ACTION_LABELS = {
    "drop": "block",
    "block": "block",
    "isolate": "isolate",
    "throttle": "throttle",
    "rate": "rate_limit",
    "priority": "prioritize",
    "qos": "prioritize",
    "reroute": "reroute",
    "allow": "allow",
}


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or _now()).strftime("%Y-%m-%d %H:%M:%S")


def _date(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or _now()).strftime("%Y-%m-%d")


def _sf(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _si(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _signature(payload: Any) -> str:
    return hashlib.sha1(_json(payload).encode("utf-8")).hexdigest()


def _dataset_path(kind: str) -> Path:
    return REALTIME_DIR / DATASET_FILES[kind][0]


def _archive_path(kind: str, ts: float | None = None) -> Path:
    _filename, _fields, prefix = DATASET_FILES[kind]
    ext = "jsonl" if kind == "events" else "csv"
    return ARCHIVE_DIR / f"{prefix}_{_date(ts)}.{ext}"


def _manual_archive_path(kind: str, ts: float | None = None) -> Path:
    _filename, _fields, prefix = DATASET_FILES[kind]
    ext = "jsonl" if kind == "events" else "csv"
    stamp = datetime.fromtimestamp(ts or _now()).strftime("%Y%m%d_%H%M%S")
    return ARCHIVE_DIR / f"{prefix}_{stamp}.{ext}"


def _ensure_dirs() -> None:
    for path in (REALTIME_DIR, ARCHIVE_DIR, EXPORTS_DIR, DATASET_ROOT / "public", DATASET_ROOT / "processed", DATASET_ROOT / "models"):
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o755)
        except OSError:
            pass


def _ensure_file(kind: str) -> None:
    path = _dataset_path(kind)
    _filename, fields, _prefix = DATASET_FILES[kind]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return
    if kind == "events":
        path.touch()
    else:
        with path.open("w", newline="", encoding="utf-8") as handle:
            csv.DictWriter(handle, fieldnames=fields).writeheader()
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _ensure_archive_file(kind: str, ts: float | None = None) -> Path:
    path = _archive_path(kind, ts)
    _filename, fields, _prefix = DATASET_FILES[kind]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path
    if kind == "events":
        path.touch()
    else:
        with path.open("w", newline="", encoding="utf-8") as handle:
            csv.DictWriter(handle, fieldnames=fields).writeheader()
    try:
        path.chmod(0o644)
    except OSError:
        pass
    return path


def initialize_dataset_files() -> None:
    _ensure_dirs()
    for kind in DATASET_FILES:
        _ensure_file(kind)
        _ensure_archive_file(kind)


def _append_csv(path: Path, fields: list[str], row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        if new_file:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _append_jsonl(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _csv_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return max(0, sum(1 for _ in handle) - 1)


def _jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        return sum(1 for line in handle if line.strip())


def _read_csv_tail(path: Path, limit: int = 50) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        rows = collections.deque(maxlen=limit)
        for row in reader:
            rows.append(dict(row))
        return list(rows)


def _read_jsonl_tail(path: Path, limit: int = 50) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = collections.deque(maxlen=limit)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"raw": line, "parse_error": True})
    return list(rows)


def _traffic_label(activity: str, traffic_type: str, security_state: str, priority: str) -> str:
    act = (activity or "").lower()
    traffic = (traffic_type or "").lower()
    sec = (security_state or "").lower()
    if act in SECURITY_ACTIVITY_MAP or sec in {"threat", "critical", "blocked", "isolated"}:
        return "attack"
    if any(key in act or key in traffic for key in ("mis", "siad", "admin", "rp system", "authentication")):
        return "admin"
    if any(key in act or key in traffic for key in ("stream", "social", "gaming", "large download")):
        return "entertainment"
    if any(key in act or key in traffic for key in ("dns", "dhcp", "auth")):
        return "system_service"
    if any(key in act or key in traffic for key in ("exam", "e-learning", "elearning", "research", "class", "study", "meet", "web")):
        return "academic"
    if (priority or "").upper() == "THREAT":
        return "attack"
    return "normal"


def _qos_label(priority: str, activity: str, status: str, security_state: str) -> str:
    p = (priority or "").upper()
    act = (activity or "").lower()
    st = (status or "").lower()
    sec = (security_state or "").lower()
    if p == "THREAT" or sec in {"threat", "critical", "blocked", "isolated"}:
        return "blocked" if "block" in st or sec in {"blocked", "critical"} else "throttled"
    if "exam" in act and p == "CRITICAL":
        return "critical_exam"
    if "throttle" in st or "rate" in st:
        return "throttled"
    if p == "CRITICAL":
        return "critical_exam"
    if p == "HIGH":
        return "high_priority"
    if p == "MEDIUM":
        return "medium_priority"
    return "low_priority"


def _security_label(attack_type: str, security_state: str, status: str) -> str:
    attack = (attack_type or "").lower()
    state = (security_state or "").lower()
    st = (status or "").lower()
    if "isolat" in st or state == "isolated":
        return "isolated"
    if "block" in st or state == "blocked":
        return "blocked"
    if attack in SECURITY_ACTIVITY_MAP.values():
        return attack
    if state in {"threat", "critical"}:
        return "threat"
    if state == "suspicious":
        return "suspicious"
    return "normal"


def _action_label(action: str) -> str:
    text = (action or "").lower()
    for needle, label in ACTION_LABELS.items():
        if needle in text:
            return label
    if not text or text == "monitor_only" or text == "monitoring only":
        return "monitor"
    return "monitor"


def _risk_from_state(state: str) -> str:
    return {
        "healthy": "LOW",
        "warning": "MEDIUM",
        "preventive": "HIGH",
        "critical": "CRITICAL",
    }.get((state or "").lower(), "LOW")


class RealtimeDatasetCollector:
    def __init__(self, interval: float = 2.0) -> None:
        self.interval = interval
        self.running = True
        self.lock = threading.Lock()
        self.last_collection_ts = 0.0
        self.last_error = ""
        self.row_counts: dict[str, int] = {}
        self._last_signatures: dict[str, str] = {}
        self._last_event_signatures: set[str] = set()
        self._last_pc_activity: dict[str, str] = {}
        self._last_ml_action = ""
        self._last_exam_flag = False
        self._last_intent_keys: set[str] = set()
        initialize_dataset_files()
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        self.row_counts = {
            "traffic": _csv_count(_dataset_path("traffic")),
            "congestion": _csv_count(_dataset_path("congestion")),
            "security": _csv_count(_dataset_path("security")),
            "qos": _csv_count(_dataset_path("qos")),
            "ml": _csv_count(_dataset_path("ml")),
            "events": _jsonl_count(_dataset_path("events")),
        }

    def append_row(self, kind: str, row: dict[str, Any], signature_payload: Any) -> bool:
        signature = _signature(signature_payload)
        with self.lock:
            if self._last_signatures.get(f"{kind}:{signature}") == signature:
                return False
            self._last_signatures[f"{kind}:{signature}"] = signature
            _ensure_file(kind)
            _ensure_archive_file(kind)
            if kind == "events":
                _append_jsonl(_dataset_path(kind), row)
                _append_jsonl(_archive_path(kind), row)
            else:
                _filename, fields, _prefix = DATASET_FILES[kind]
                _append_csv(_dataset_path(kind), fields, row)
                _append_csv(_archive_path(kind), fields, row)
            self.row_counts[kind] = self.row_counts.get(kind, 0) + 1
        return True

    def append_event(self, event: dict[str, Any], signature_payload: Any) -> bool:
        event.setdefault("timestamp", _iso())
        signature = _signature(signature_payload)
        if signature in self._last_event_signatures:
            return False
        self._last_event_signatures.add(signature)
        if len(self._last_event_signatures) > 5000:
            self._last_event_signatures = set(list(self._last_event_signatures)[-2500:])
        return self.append_row("events", event, signature_payload)

    def collect_once(self) -> dict[str, int]:
        now = _now()
        timestamp = _iso(now)
        state = {name: read_json(path, {}) for name, path in STATE_FILES.items()}
        metrics = state["metrics"] or {}
        pc_state = state["pc"] or {}
        proactive = state["proactive"] or {}
        security = state["security"] or {}
        ml = state["ml"] or {}
        timetable = state["timetable"] or {}
        ibn = state["ibn"] or {}

        counts = collections.Counter()
        decisions = self._decision_map(metrics, proactive)
        security_by_host = metrics.get("security_state_by_host", {}) or {}
        pcs = pc_state.get("pcs", {}) or {}
        exam_flag = bool(timetable.get("exam_flag", 0) or metrics.get("exam_mode", False))

        for host, info in sorted(pcs.items()):
            activity = str(info.get("activity", "idle") or "idle")
            current_mbps = _sf(info.get("current_mbps", info.get("traffic_mbps", 0.0)))
            if activity == "idle" and current_mbps <= 0.05:
                self._last_pc_activity[host] = activity
                continue
            decision = decisions.get(host, {})
            host_security = security_by_host.get(host, {}) if isinstance(security_by_host, dict) else {}
            if not isinstance(host_security, dict):
                host_security = {"security_state": host_security}
            priority = str(info.get("priority_level", info.get("priority_label", "BEST-EFFORT")) or "BEST-EFFORT")
            security_state = str(host_security.get("security_state", info.get("security_state", "normal")) or "normal")
            controller_action = (
                decision.get("action_taken")
                or info.get("controller_action")
                or host_security.get("controller_action")
                or ("QoS priority applied" if priority in {"CRITICAL", "HIGH"} else "Monitoring only")
            )
            status = (
                decision.get("current_status")
                or host_security.get("status")
                or info.get("browser_status")
                or info.get("current_status")
                or "Active"
            )
            label = _traffic_label(activity, info.get("traffic_type", ""), security_state, priority)
            flow_duration = round(max(0.0, now - _sf(info.get("since_ts"), now)), 2)
            byte_count = _si(info.get("byte_count"))
            packet_count = _si(info.get("packet_count"))
            if byte_count <= 0 and current_mbps > 0:
                byte_count = int((current_mbps * 1_000_000 / 8.0) * max(1.0, min(flow_duration, 300.0)))
            if packet_count <= 0 and byte_count > 0:
                packet_count = max(1, int(byte_count / 1200))
            traffic_row = {
                "timestamp": timestamp,
                "source_pc": info.get("label", host),
                "source_ip": info.get("ip", ""),
                "source_mac": info.get("mac", ""),
                "source_vlan": info.get("vlan", info.get("zone_label", "")),
                "connected_switch": info.get("switch", ""),
                "destination_ip": info.get("dst_ip", ""),
                "destination_port": info.get("dst_port", ""),
                "destination_service": info.get("dst_service_name", ""),
                "protocol": str(info.get("proto", "tcp")).upper(),
                "activity": info.get("activity_label", activity),
                "traffic_type": info.get("traffic_type", info.get("activity_label", activity)),
                "priority_level": priority,
                "dscp_value": info.get("dscp", ""),
                "current_mbps": round(current_mbps, 3),
                "packet_count": packet_count,
                "byte_count": byte_count,
                "flow_duration": flow_duration,
                "controller_action": controller_action,
                "status": status,
                "label": label,
            }
            if self.append_row(
                "traffic",
                traffic_row,
                {
                    "host": host,
                    "activity": activity,
                    "mbps": round(current_mbps, 1),
                    "dst": traffic_row["destination_ip"],
                    "status": status,
                    "action": controller_action,
                    "label": label,
                },
            ):
                counts["traffic"] += 1
                self.append_event(
                    {
                        "timestamp": timestamp,
                        "event_type": "flow_detected",
                        "device": info.get("label", host),
                        "ip": info.get("ip", ""),
                        "activity": traffic_row["activity"],
                        "traffic_type": traffic_row["traffic_type"],
                        "priority_level": priority,
                        "dscp_value": info.get("dscp", ""),
                        "current_mbps": round(current_mbps, 3),
                        "controller_action": controller_action,
                        "status": status,
                    },
                    {"event": "flow_detected", "host": host, "activity": activity, "mbps": round(current_mbps, 1), "status": status},
                )

            if self._last_pc_activity.get(host) != activity:
                self.append_event(
                    {
                        "timestamp": timestamp,
                        "event_type": "pc_activity_changed",
                        "device": info.get("label", host),
                        "ip": info.get("ip", ""),
                        "old_activity": self._last_pc_activity.get(host, "unknown"),
                        "new_activity": activity,
                        "priority_level": priority,
                        "dscp_value": info.get("dscp", ""),
                        "action_taken": controller_action,
                        "status": status,
                    },
                    {"event": "pc_activity_changed", "host": host, "activity": activity},
                )
            self._last_pc_activity[host] = activity

            qos_row = {
                "timestamp": timestamp,
                "pc_name": info.get("label", host),
                "ip_address": info.get("ip", ""),
                "vlan": info.get("vlan", ""),
                "activity": info.get("activity_label", activity),
                "traffic_type": info.get("traffic_type", ""),
                "priority_level": priority,
                "dscp_value": info.get("dscp", ""),
                "queue_id": info.get("qos_queue", ""),
                "requested_bandwidth": info.get("target_mbps", info.get("bw_target", "")),
                "allocated_bandwidth": round(_sf(decision.get("enforced_limit_mbps"), current_mbps), 3),
                "congestion_state": info.get("congestion_state", decision.get("congestion_state", "healthy")),
                "exam_mode": str(exam_flag).lower(),
                "controller_action": controller_action,
                "reason": decision.get("reason", "Priority policy from live PC activity and controller state"),
                "status": status,
                "label": _qos_label(priority, activity, status, security_state),
            }
            if self.append_row(
                "qos",
                qos_row,
                {
                    "host": host,
                    "activity": activity,
                    "priority": priority,
                    "dscp": info.get("dscp", ""),
                    "state": qos_row["congestion_state"],
                    "action": controller_action,
                    "allocated": qos_row["allocated_bandwidth"],
                },
            ):
                counts["qos"] += 1
                event_type = "qos_applied"
                if qos_row["label"] == "throttled":
                    event_type = "low_priority_throttled"
                self.append_event(
                    {
                        "timestamp": timestamp,
                        "event_type": event_type,
                        "device": info.get("label", host),
                        "ip": info.get("ip", ""),
                        "activity": qos_row["activity"],
                        "priority_level": priority,
                        "dscp_value": info.get("dscp", ""),
                        "action_taken": controller_action,
                        "status": status,
                    },
                    {"event": event_type, "host": host, "activity": activity, "priority": priority, "action": controller_action},
                )

            attack_type = SECURITY_ACTIVITY_MAP.get(activity)
            if attack_type or security_state in {"suspicious", "threat", "critical", "blocked", "isolated"}:
                security_row = self._security_row_from_pc(
                    timestamp, host, info, attack_type or "unknown", security_state, security, controller_action, status, current_mbps
                )
                if self.append_row("security", security_row, {"host": host, "attack": attack_type, "state": security_state, "status": status, "action": controller_action}):
                    counts["security"] += 1
                    self.append_event(
                        {
                            "timestamp": timestamp,
                            "event_type": "attack_detected" if security_row["label"] not in {"normal", "suspicious"} else "zero_trust_denied",
                            "device": security_row["attacker_pc"],
                            "ip": security_row["attacker_ip"],
                            "attack_type": security_row["attack_type"],
                            "risk_level": security_row["risk_level"],
                            "action_taken": security_row["controller_action"],
                            "status": security_row["status"],
                        },
                        {"event": "security", "host": host, "attack": attack_type, "state": security_state, "status": status},
                    )

        counts.update(self._collect_metric_security_events(timestamp, metrics, security))
        counts.update(self._collect_congestion(timestamp, proactive, metrics))
        counts.update(self._collect_ml(timestamp, ml, proactive, security, metrics, timetable))
        counts.update(self._collect_ibn_and_exam_events(timestamp, ibn, exam_flag))

        if counts["security"] == 0:
            counts.update(self._collect_normal_security_heartbeat(timestamp, metrics, security))

        self.last_collection_ts = now
        self.last_error = ""
        return dict(counts)

    def _decision_map(self, metrics: dict[str, Any], proactive: dict[str, Any]) -> dict[str, dict[str, Any]]:
        decisions: dict[str, dict[str, Any]] = {}
        for source in (
            metrics.get("traffic_priority_decisions", []) or [],
            proactive.get("traffic_priority_decisions", []) or [],
        ):
            if isinstance(source, dict) and source.get("host"):
                decisions[source["host"]] = source
        return decisions

    def _security_row_from_pc(
        self,
        timestamp: str,
        host: str,
        info: dict[str, Any],
        attack_type: str,
        security_state: str,
        security: dict[str, Any],
        controller_action: str,
        status: str,
        current_mbps: float,
    ) -> dict[str, Any]:
        scanned_ports = ""
        port_count = 0
        failed_attempts = 0
        if attack_type == "port_scan":
            scanned_ports = "20-139"
            port_count = 120
        elif attack_type == "brute_force":
            failed_attempts = 20
        packet_rate = round((current_mbps * 1_000_000 / 8.0) / 1200.0, 3) if current_mbps > 0 else 0
        risk = "CRITICAL" if attack_type in {"ddos", "unauthorized_access", "ip_spoofing", "arp_spoofing"} else "HIGH"
        if security_state == "suspicious":
            risk = "MEDIUM"
        action = controller_action or security.get("controller_action") or security.get("action") or "monitor"
        target_ip = info.get("dst_ip", "10.20.0.1")
        return {
            "timestamp": timestamp,
            "attacker_pc": info.get("label", host),
            "attacker_ip": info.get("ip", ""),
            "attacker_mac": info.get("mac", ""),
            "attacker_vlan": info.get("vlan", ""),
            "target_ip": target_ip,
            "target_vlan": 20 if str(target_ip).startswith("10.20.") else "",
            "target_service": info.get("dst_service_name", ""),
            "attack_type": attack_type,
            "evidence": info.get("last_alert") or info.get("traffic_type") or f"{attack_type} activity observed in PC Activity Manager",
            "packet_rate": packet_rate,
            "port_count": port_count,
            "scanned_ports": scanned_ports,
            "failed_attempts": failed_attempts,
            "risk_level": risk,
            "security_state": security_state,
            "marl_decision": security.get("action", security.get("controller_action", "")),
            "controller_action": action,
            "openflow_rule": "drop/high-priority rule" if _action_label(action) in {"block", "isolate"} else "",
            "status": "Blocked" if _action_label(action) in {"block", "isolate"} or security_state in {"critical", "blocked"} else status,
            "label": _security_label(attack_type, security_state, status),
        }

    def _collect_metric_security_events(self, timestamp: str, metrics: dict[str, Any], security: dict[str, Any]) -> collections.Counter:
        counts = collections.Counter()
        for idx, evt in enumerate(metrics.get("security_events", []) or []):
            if not isinstance(evt, dict):
                continue
            raw_type = str(evt.get("event", evt.get("type", "security_event")))
            raw_lower = raw_type.lower()
            if not any(token in raw_lower for token in (
                "port_scan",
                "sweep",
                "arp",
                "ip_spoof",
                "ddos",
                "flood",
                "brute",
                "unauthorized",
                "mac_flood",
            )):
                continue
            attack_type = (
                "port_scan" if "port_scan" in raw_lower else
                "ping_sweep" if "sweep" in raw_lower else
                "arp_spoofing" if "arp" in raw_lower else
                "ip_spoofing" if "ip_spoof" in raw_lower else
                "ddos" if "ddos" in raw_lower or "flood" in raw_lower else
                "brute_force" if "brute" in raw_lower else
                "unauthorized_access" if "unauthorized" in raw_lower else
                evt.get("attack_type", raw_type)
            )
            src_ip = evt.get("src_ip") or evt.get("ip") or evt.get("attacker_ip") or ""
            action = evt.get("action_taken") or security.get("controller_action") or security.get("action") or "monitor"
            row = {
                "timestamp": timestamp,
                "attacker_pc": evt.get("host", evt.get("device", "")),
                "attacker_ip": src_ip,
                "attacker_mac": evt.get("mac", evt.get("spoof_mac", "")),
                "attacker_vlan": evt.get("vlan", ""),
                "target_ip": evt.get("target_ip", evt.get("target", "")),
                "target_vlan": evt.get("target_vlan", ""),
                "target_service": evt.get("target_service", ""),
                "attack_type": attack_type,
                "evidence": evt.get("evidence", raw_type),
                "packet_rate": evt.get("pps", evt.get("packet_rate", "")),
                "port_count": evt.get("ports_scanned", evt.get("port_count", "")),
                "scanned_ports": evt.get("scanned_ports", ""),
                "failed_attempts": evt.get("failed_attempts", ""),
                "risk_level": evt.get("risk_level", "HIGH"),
                "security_state": evt.get("security_state", "threat"),
                "marl_decision": security.get("action", ""),
                "controller_action": action,
                "openflow_rule": evt.get("openflow_rule", "drop/high-priority rule" if _action_label(action) in {"block", "isolate"} else ""),
                "status": evt.get("status", "Blocked" if _action_label(action) in {"block", "isolate"} else "Detected"),
                "label": _security_label(str(attack_type), evt.get("security_state", "threat"), evt.get("status", "")),
            }
            if self.append_row("security", row, {"metric_event": idx, "type": raw_type, "src": src_ip, "action": action, "count": evt.get("ports_scanned", "")}):
                counts["security"] += 1
        for scan in metrics.get("active_scans", []) or []:
            if isinstance(scan, dict):
                src_ip = scan.get("src_ip", "")
                attack_type = scan.get("type", "port_scan")
                port_count = scan.get("ports_scanned", scan.get("ips_probed", ""))
                pps = scan.get("pps", "")
            else:
                src_ip = str(scan)
                attack_type = "port_scan"
                port_count = ""
                pps = ""
            row = {
                "timestamp": timestamp,
                "attacker_pc": "",
                "attacker_ip": src_ip,
                "attacker_mac": "",
                "attacker_vlan": "",
                "target_ip": "10.20.0.0/24",
                "target_vlan": 20,
                "target_service": "Server Zone",
                "attack_type": "ping_sweep" if attack_type == "network_sweep" else attack_type,
                "evidence": "active scan reported by controller metrics",
                "packet_rate": pps,
                "port_count": port_count,
                "scanned_ports": "",
                "failed_attempts": "",
                "risk_level": "HIGH",
                "security_state": "threat",
                "marl_decision": security.get("action", ""),
                "controller_action": security.get("controller_action", security.get("action", "monitor")),
                "openflow_rule": "scan-block flow rule",
                "status": "Blocked" if src_ip in (metrics.get("blocked_ips", []) or []) else "Detected",
                "label": "port_scan" if attack_type == "port_scan" else "ping_sweep",
            }
            if self.append_row("security", row, {"active_scan": src_ip, "type": attack_type, "port_count": port_count, "status": row["status"]}):
                counts["security"] += 1
        return counts

    def _collect_normal_security_heartbeat(self, timestamp: str, metrics: dict[str, Any], security: dict[str, Any]) -> collections.Counter:
        counts = collections.Counter()
        action = security.get("controller_action", security.get("action", "monitor"))
        row = {
            "timestamp": timestamp,
            "attacker_pc": "",
            "attacker_ip": "",
            "attacker_mac": "",
            "attacker_vlan": "",
            "target_ip": "",
            "target_vlan": "",
            "target_service": "Campus",
            "attack_type": "none",
            "evidence": "no active threat in live controller/security state",
            "packet_rate": 0,
            "port_count": 0,
            "scanned_ports": "",
            "failed_attempts": 0,
            "risk_level": "LOW",
            "security_state": "normal",
            "marl_decision": security.get("action", ""),
            "controller_action": action,
            "openflow_rule": "",
            "status": "Normal",
            "label": "normal",
        }
        threat_counts = {
            "ddos": bool(metrics.get("ddos_active")),
            "scans": len(metrics.get("active_scans", []) or []),
            "blocked": len(metrics.get("blocked_ips", []) or []),
            "action": action,
        }
        if self.append_row("security", row, {"normal_security": threat_counts}):
            counts["security"] += 1
        return counts

    def _collect_congestion(self, timestamp: str, proactive: dict[str, Any], metrics: dict[str, Any]) -> collections.Counter:
        counts = collections.Counter()
        before_after = proactive.get("before_after_utilization", []) or []
        ba_by_target = {str(item.get("target", "")): item for item in before_after if isinstance(item, dict)}
        links: list[dict[str, Any]] = []
        if isinstance(proactive.get("links"), dict):
            for kind, items in proactive.get("links", {}).items():
                for item in items or []:
                    if isinstance(item, dict):
                        copy = dict(item)
                        copy.setdefault("kind", kind)
                        links.append(copy)
        if not links:
            for zone, item in (metrics.get("access_uplinks") or {}).items():
                if isinstance(item, dict):
                    copy = dict(item)
                    copy.setdefault("zone", zone)
                    copy.setdefault("kind", "access")
                    links.append(copy)
            for zone, item in (metrics.get("zone_metrics") or {}).items():
                if isinstance(item, dict) and not any(link.get("zone") == zone for link in links):
                    current = _sf(item.get("throughput_mbps"))
                    copy = {
                        "zone": zone,
                        "kind": "access",
                        "label": zone,
                        "current_mbps": current,
                        "capacity_mbps": 1000,
                        "utilization_percent": item.get("max_utilization_pct", round(current / 10, 2)),
                        "threshold_state": item.get("threshold_state", "healthy"),
                        "threshold_color": item.get("threshold_color", "green"),
                        "latency_ms": item.get("latency_ms", 0),
                        "queue_depth": item.get("queue_depth", 0),
                        "packet_drops": item.get("packet_drops", 0),
                    }
                    links.append(copy)
        for item in links:
            link_id, link_name, src, dst, link_type = self._link_identity(item)
            future = item.get("future_load", {}) or {}
            state = item.get("threshold_state") or item.get("congestion_state") or self._state_from_util(_sf(item.get("utilization_percent")))
            current = round(_sf(item.get("current_mbps", item.get("throughput_mbps"))), 3)
            capacity = round(_sf(item.get("capacity_mbps", item.get("uplink_capacity_mbps", 1000))), 3)
            util = round(_sf(item.get("utilization_percent", item.get("utilization_pct", current / max(capacity, 0.1) * 100))), 3)
            predicted_mbps = round(_sf(item.get("predicted_mbps", future.get("projected_mbps", current))), 3)
            predicted_util = round(_sf(item.get("predicted_utilization_percent", future.get("projected_util_pct", util))), 3)
            growth = round(_sf(item.get("growth_rate_pct", future.get("growth_rate_pct", 0))), 3)
            ema = round(_sf(future.get("historical_ema_trend_mbps", item.get("ema_trend", 0))), 3)
            color = item.get("threshold_color") or {"healthy": "green", "warning": "yellow", "preventive": "orange", "critical": "red"}.get(state, "green")
            target_key = str(item.get("label") or link_name)
            ba = ba_by_target.get(target_key, {})
            action = item.get("recommended_action") or item.get("controller_action") or item.get("action_taken") or "Monitor only"
            row = {
                "timestamp": timestamp,
                "link_id": link_id,
                "link_name": link_name,
                "source_device": src,
                "destination_device": dst,
                "link_type": link_type,
                "capacity_mbps": capacity,
                "current_mbps": current,
                "utilization_percent": util,
                "predicted_mbps": predicted_mbps,
                "predicted_utilization_percent": predicted_util,
                "traffic_growth_rate": growth,
                "ema_trend": ema,
                "latency_ms": item.get("latency_ms", 0),
                "queue_depth": item.get("queue_depth", 0),
                "packet_drops": item.get("packet_drops", 0),
                "congestion_state": state,
                "color_state": color,
                "risk_level": _risk_from_state(state),
                "mitigation_action": action,
                "before_utilization": ba.get("before_utilization_percent", util),
                "after_utilization": ba.get("after_utilization_percent", util),
                "prediction_reason": f"current={util}% predicted={predicted_util}% growth={growth}%/sample",
                "label": state,
            }
            if self.append_row("congestion", row, {"link": link_id, "util": round(util, 1), "pred": round(predicted_util, 1), "state": state, "action": action}):
                counts["congestion"] += 1
                if state in {"warning", "preventive", "critical"}:
                    event_type = {
                        "warning": "congestion_warning",
                        "preventive": "preventive_action",
                        "critical": "critical_congestion",
                    }[state]
                    self.append_event(
                        {
                            "timestamp": timestamp,
                            "event_type": event_type,
                            "link_id": link_id,
                            "link_name": link_name,
                            "current_mbps": current,
                            "capacity_mbps": capacity,
                            "utilization_percent": util,
                            "predicted_utilization_percent": predicted_util,
                            "action_taken": action,
                            "status": state.title(),
                        },
                        {"event": event_type, "link": link_id, "util": round(util, 1), "pred": round(predicted_util, 1), "action": action},
                    )
        return counts

    def _link_identity(self, item: dict[str, Any]) -> tuple[str, str, str, str, str]:
        kind = str(item.get("kind", "") or "")
        host = item.get("host") or item.get("pc_id")
        switch = item.get("switch") or item.get("source_switch") or ""
        zone = item.get("zone") or item.get("zone_key") or ""
        label = item.get("label") or item.get("display_name") or host or zone or switch or kind or "link"
        if kind == "device" or host:
            src, dst = str(host or label), str(switch or "access_switch")
            return f"{src}-{dst}", f"{label} -> {dst}", src, dst, "edge"
        if kind == "server":
            src, dst = str(host or label), str(switch or "as2")
            return f"{src}-{dst}", f"{label} -> {dst}", src, dst, "server"
        if kind == "access" or zone:
            dst = "ds1" if zone in {"staff_lan", "server_zone"} else "ds2"
            src = str(switch or item.get("source_device") or zone or label)
            return f"{src}-{dst}", f"{label} -> {dst}", src, dst, "access_uplink"
        if kind == "distribution":
            src = str(item.get("distribution") or item.get("id") or label)
            return f"{src}-cs1", f"{src} -> cs1", src, "cs1", "distribution_uplink"
        if kind == "core":
            return "core-cs1", "Distribution Layer -> cs1", "distribution", "cs1", "core"
        src = str(item.get("source_device") or label)
        dst = str(item.get("destination_device") or "unknown")
        return f"{src}-{dst}", f"{src} -> {dst}", src, dst, "unknown"

    def _state_from_util(self, util: float) -> str:
        if util >= 90:
            return "critical"
        if util >= 85:
            return "preventive"
        if util >= 70:
            return "warning"
        return "healthy"

    def _collect_ml(
        self,
        timestamp: str,
        ml: dict[str, Any],
        proactive: dict[str, Any],
        security: dict[str, Any],
        metrics: dict[str, Any],
        timetable: dict[str, Any],
    ) -> collections.Counter:
        counts = collections.Counter()
        action = ml.get("action") or ml.get("action_name")
        if not action:
            return counts
        q_values = ml.get("q_values", [])
        zone_util = ml.get("zone_utilization") or {
            zone: data.get("max_utilization_pct", 0)
            for zone, data in (metrics.get("zone_metrics") or {}).items()
            if isinstance(data, dict)
        }
        summary = proactive.get("summary", {}) or {}
        blocked = metrics.get("security_blocked", metrics.get("security_flows_blocked", 0))
        final_action = ml.get("final_controller_action") or ml.get("controller_action") or action
        row = {
            "timestamp": timestamp,
            "state_vector": _json({
                "zone_utilization": zone_util,
                "ddos_active": metrics.get("ddos_active", False),
                "scan_active": bool(metrics.get("active_scans", [])),
                "exam_flag": bool(timetable.get("exam_flag", 0) or ml.get("exam_flag", False)),
                "core_util": (proactive.get("network_aggregation") or {}).get("controller_link_util_pct", 0),
            }),
            "action_selected": ml.get("action_index", ""),
            "action_name": action,
            "reward": ml.get("reward", ""),
            "congestion_inputs": _json(ml.get("congestion_state_inputs") or proactive.get("summary", {})),
            "security_inputs": _json({
                "marl_action": security.get("action", ""),
                "controller_action": security.get("controller_action", ""),
                "threat_level": security.get("threat_level", ""),
                "ddos_active": metrics.get("ddos_active", False),
                "active_scans": metrics.get("active_scans", []),
            }),
            "exam_flag": str(bool(timetable.get("exam_flag", 0) or ml.get("exam_flag", False))).lower(),
            "protected_flows": summary.get("protected_academic_flows", 0),
            "throttled_flows": summary.get("low_priority_controls", 0),
            "blocked_flows": blocked,
            "safety_rail_applied": str(bool(ml.get("safety_rail_applied", False) or "exam" in str(action).lower())).lower(),
            "final_controller_action": final_action,
            "label": _action_label(str(final_action)),
        }
        if self.append_row("ml", row, {"action": action, "reward": ml.get("reward", ""), "q": q_values, "blocked": blocked, "protected": row["protected_flows"], "throttled": row["throttled_flows"]}):
            counts["ml"] += 1
        if self._last_ml_action != action:
            self.append_event(
                {
                    "timestamp": timestamp,
                    "event_type": "ml_action_selected",
                    "action_selected": ml.get("action_index", ""),
                    "action_name": action,
                    "reward": ml.get("reward", ""),
                    "final_controller_action": final_action,
                    "status": row["label"],
                },
                {"event": "ml_action_selected", "action": action, "reward": ml.get("reward", "")},
            )
        self._last_ml_action = str(action)
        return counts

    def _collect_ibn_and_exam_events(self, timestamp: str, ibn: dict[str, Any], exam_flag: bool) -> collections.Counter:
        counts = collections.Counter()
        intents = ibn.get("active_intents") or ibn.get("intents") or []
        current_keys = set()
        for intent in intents:
            if not isinstance(intent, dict):
                continue
            key = str(intent.get("id") or intent.get("text") or intent.get("intent") or intent.get("action") or _json(intent))
            current_keys.add(key)
            if key not in self._last_intent_keys:
                self.append_event(
                    {
                        "timestamp": timestamp,
                        "event_type": "ibn_intent_applied",
                        "intent": intent.get("text", intent.get("intent", "")),
                        "intent_status": intent.get("status", "active"),
                        "action_taken": intent.get("action", intent.get("action_applied", "")),
                    },
                    {"event": "ibn_intent_applied", "key": key, "status": intent.get("status", "")},
                )
        self._last_intent_keys = current_keys
        if exam_flag and not self._last_exam_flag:
            self.append_event(
                {
                    "timestamp": timestamp,
                    "event_type": "exam_mode_enabled",
                    "device": "timetable_engine",
                    "action_taken": "CRITICAL QoS protection enabled for exam traffic",
                    "status": "Protected",
                },
                {"event": "exam_mode_enabled", "enabled": True},
            )
        self._last_exam_flag = exam_flag
        return counts

    def loop(self) -> None:
        LOGGER.info("startup dataset_root=%s interval=%ss state_files=%s", DATASET_ROOT, self.interval, STATE_FILES)
        while self.running:
            try:
                counts = self.collect_once()
                if counts:
                    LOGGER.info("collection ok counts=%s rows=%s", dict(counts), self.row_counts)
            except Exception as exc:
                self.last_error = str(exc)
                LOGGER.exception("collection error: %s", exc)
            time.sleep(self.interval)

    def status(self) -> dict[str, Any]:
        self._refresh_counts()
        return {
            "ok": True,
            "service": "realtime_dataset_collector",
            "running": self.running,
            "dataset_root": str(DATASET_ROOT),
            "last_collection_ts": self.last_collection_ts,
            "last_collection_time": _iso(self.last_collection_ts) if self.last_collection_ts else "",
            "last_error": self.last_error,
            "traffic_rows": self.row_counts.get("traffic", 0),
            "congestion_rows": self.row_counts.get("congestion", 0),
            "security_rows": self.row_counts.get("security", 0),
            "qos_rows": self.row_counts.get("qos", 0),
            "ml_rows": self.row_counts.get("ml", 0),
            "events_rows": self.row_counts.get("events", 0),
            "files": {kind: str(_dataset_path(kind)) for kind in DATASET_FILES},
            "message": "Dataset is generated from real-time captured SDN traffic and system telemetry.",
        }

    def preview(self, kind: str, limit: int = 50) -> dict[str, Any]:
        if kind not in DATASET_FILES:
            return {"ok": False, "error": f"unsupported dataset type: {kind}"}
        path = _dataset_path(kind)
        rows = _read_jsonl_tail(path, limit) if kind == "events" else _read_csv_tail(path, limit)
        return {"ok": True, "type": kind, "path": str(path), "rows": rows, "count": len(rows)}

    def reset(self, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            return {"ok": False, "error": "reset requires confirm=true"}
        with self.lock:
            for kind in DATASET_FILES:
                path = _dataset_path(kind)
                if path.exists():
                    path.unlink()
                _ensure_file(kind)
            self._last_signatures.clear()
            self._last_event_signatures.clear()
            self._refresh_counts()
        LOGGER.warning("realtime datasets reset by API")
        return {"ok": True, "reset": True, "files": {kind: str(_dataset_path(kind)) for kind in DATASET_FILES}}

    def archive_current(self) -> dict[str, Any]:
        now = _now()
        archived = {}
        with self.lock:
            for kind in DATASET_FILES:
                src = _dataset_path(kind)
                if not src.exists():
                    continue
                dst = _manual_archive_path(kind, now)
                shutil.copy2(src, dst)
                archived[kind] = str(dst)
        LOGGER.info("manual archive created files=%s", archived)
        return {"ok": True, "archived": archived}


def make_handler(collector: RealtimeDatasetCollector):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _send_json(self, payload: dict[str, Any], code: int = 200) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0:
                return {}
            try:
                return json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                return {}

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if parsed.path in {"/health", "/api/dataset/status"}:
                self._send_json(collector.status())
                return
            if parsed.path == "/api/dataset/preview":
                kind = (params.get("type") or ["traffic"])[0]
                limit = _si((params.get("limit") or ["50"])[0], 50)
                payload = collector.preview(kind, max(1, min(limit, 500)))
                self._send_json(payload, 200 if payload.get("ok") else 400)
                return
            if parsed.path == "/api/dataset/export":
                kind = (params.get("type") or ["traffic"])[0]
                if kind not in DATASET_FILES:
                    self._send_json({"ok": False, "error": f"unsupported dataset type: {kind}"}, 400)
                    return
                path = _dataset_path(kind)
                if not path.exists():
                    self._send_json({"ok": False, "error": f"dataset file not found: {kind}"}, 404)
                    return
                body = path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/jsonl" if kind == "events" else "text/csv")
                self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._send_json({"ok": False, "error": "not found"}, 404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            body = self._read_body()
            if parsed.path == "/api/dataset/reset":
                confirm = bool(body.get("confirm")) or (params.get("confirm") or [""])[0] in {"1", "true", "yes"}
                payload = collector.reset(confirm)
                self._send_json(payload, 200 if payload.get("ok") else 400)
                return
            if parsed.path == "/api/dataset/archive":
                self._send_json(collector.archive_current())
                return
            self._send_json({"ok": False, "error": "not found"}, 404)

    return Handler


def run(port: int = 9101, interval: float = 2.0) -> None:
    collector = RealtimeDatasetCollector(interval=interval)
    worker = threading.Thread(target=collector.loop, daemon=True, name="dataset_collector_loop")
    worker.start()
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(collector))
    LOGGER.info("http api listening host=0.0.0.0 port=%s", port)
    try:
        server.serve_forever()
    finally:
        collector.running = False
        server.server_close()
        LOGGER.info("shutdown")


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-Time Dataset Collector")
    parser.add_argument("--port", type=int, default=9101)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    run(port=args.port, interval=args.interval)


if __name__ == "__main__":
    main()
