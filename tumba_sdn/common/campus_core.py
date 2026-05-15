from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from typing import Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EXTERNAL_VM_CONFIG_FILE = os.environ.get(
    "CAMPUS_EXTERNAL_VM_FILE",
    os.path.join(REPO_ROOT, "tumba_sdn", "config", "external_vms.json"),
)

LOG_DIR = "/tmp/tumba-sdn-logs"
STATE_FILE_MODE = 0o644

EDGE_LINK_CAPACITY_MBPS = 100.0
ACCESS_UPLINK_CAPACITY_MBPS = 1000.0
CORE_LINK_CAPACITY_MBPS = 1000.0

ZONE_SUBNETS = {
    "staff_lan": "10.10.0.",
    "server_zone": "10.20.0.",
    "it_lab": "10.30.0.",
    "student_wifi": "10.40.0.",
}

ZONE_DPIDS = {
    "staff_lan": 4,
    "server_zone": 5,
    "it_lab": 6,
    "student_wifi": 7,
}

ZONE_LABELS = {
    "staff_lan": "Staff LAN",
    "server_zone": "Server Zone",
    "it_lab": "IT Lab",
    "student_wifi": "Student WiFi",
    "external_vm": "External VMware",
}

ZONE_SWITCHES = {
    "staff_lan": "as1",
    "server_zone": "as2",
    "it_lab": "as3",
    "student_wifi": "as4",
    "external_vm": "ovs_ext",
}

ZONE_VLANS = {
    "staff_lan": 10,
    "server_zone": 20,
    "it_lab": 30,
    "student_wifi": 40,
    "external_vm": 50,
}

PRIORITY_LABELS = {
    0: "THREAT",
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
    5: "BEST-EFFORT",
}

PRIORITY_DSCP = {
    "THREAT": 0,
    "CRITICAL": 46,
    "HIGH": 34,
    "MEDIUM": 18,
    "LOW": 10,
    "BEST-EFFORT": 10,
}

SERVICE_TARGETS = {
    "elearning": {"ip": "10.20.0.4", "port": 443, "proto": "tcp", "name": "E-learning LMS"},
    "mis": {"ip": "10.20.0.1", "port": 443, "proto": "tcp", "name": "MIS Portal"},
    "rp_system": {"ip": "10.20.0.3", "port": 443, "proto": "tcp", "name": "RP System"},
    "siad": {"ip": "10.20.0.3", "port": 443, "proto": "tcp", "name": "SIAD"},
    "study_download": {"ip": "10.20.0.4", "port": 8080, "proto": "tcp", "name": "Study Materials"},
    "research": {"ip": "10.20.0.4", "port": 80, "proto": "tcp", "name": "Library Research"},
    "web_browsing": {"ip": "10.20.0.4", "port": 80, "proto": "tcp", "name": "Campus Web"},
    "video_conf": {"ip": "10.20.0.4", "port": 5004, "proto": "udp", "name": "Google Meet"},
    "google_meet": {"ip": "10.20.0.4", "port": 5004, "proto": "udp", "name": "Google Meet"},
    "online_class": {"ip": "10.20.0.4", "port": 5008, "proto": "udp", "name": "Online Class"},
    "video_streaming": {"ip": "10.20.0.4", "port": 5204, "proto": "tcp", "name": "Streaming Media"},
    "social_media": {"ip": "10.20.0.4", "port": 8081, "proto": "tcp", "name": "Social Media"},
    "gaming": {"ip": "10.20.0.4", "port": 5099, "proto": "udp", "name": "Gaming Traffic"},
    "file_download": {"ip": "10.20.0.4", "port": 8080, "proto": "tcp", "name": "Large Download"},
    "large_download": {"ip": "10.20.0.4", "port": 8080, "proto": "tcp", "name": "Large Download"},
    "cloud_storage": {"ip": "10.20.0.4", "port": 443, "proto": "tcp", "name": "Cloud Storage"},
    "authentication": {"ip": "10.20.0.3", "port": 389, "proto": "tcp", "name": "Auth Service"},
    "dns_query": {"ip": "10.20.0.2", "port": 53, "proto": "udp", "name": "DNS"},
    "dhcp_sync": {"ip": "10.20.0.2", "port": 67, "proto": "udp", "name": "DHCP"},
    "exam": {"ip": "10.20.0.1", "port": 5201, "proto": "tcp", "name": "Exam System"},
    "online_exam": {"ip": "10.20.0.1", "port": 5201, "proto": "tcp", "name": "Exam System"},
    "voip": {"ip": "10.20.0.3", "port": 5060, "proto": "udp", "name": "VoIP Gateway"},
    "unauthorized_server_access": {"ip": "10.20.0.1", "port": 22, "proto": "tcp", "name": "Restricted Admin Service"},
    "brute_force": {"ip": "10.20.0.3", "port": 22, "proto": "tcp", "name": "Auth Admin SSH"},
    "port_scan": {"ip": "10.20.0.0", "port": 0, "proto": "tcp", "name": "Server VLAN Scan"},
    "network_sweep": {"ip": "10.20.0.0", "port": 0, "proto": "icmp", "name": "Network Sweep"},
    "ping_sweep": {"ip": "10.20.0.0", "port": 0, "proto": "icmp", "name": "Ping Sweep"},
    "ddos_attack": {"ip": "10.20.0.1", "port": 80, "proto": "tcp", "name": "DDoS Target"},
    "ip_spoofing": {"ip": "10.20.0.1", "port": 443, "proto": "tcp", "name": "Spoofed Server Access"},
    "arp_spoofing": {"ip": "10.20.0.1", "port": 443, "proto": "tcp", "name": "ARP Poison Target"},
    "light_traffic": {"ip": "10.20.0.4", "port": 80, "proto": "tcp", "name": "Light Academic Traffic"},
    "medium_traffic": {"ip": "10.20.0.4", "port": 443, "proto": "tcp", "name": "Medium Academic Traffic"},
    "heavy_traffic": {"ip": "10.20.0.4", "port": 8080, "proto": "tcp", "name": "Heavy Academic Traffic"},
    "saturate_pc_link": {"ip": "10.20.0.4", "port": 8080, "proto": "tcp", "name": "PC Link Saturation"},
}

SERVICE_URL_MAP = {
    "http://elearning.tumba.local": "elearning",
    "https://elearning.tumba.local": "elearning",
    "https://mis.tumba.local": "mis",
    "https://siad.tumba.local": "siad",
    "https://auth.tumba.local": "authentication",
    "http://library.tumba.local": "research",
    "http://files.tumba.local": "study_download",
    "http://streaming.tumba.local": "video_streaming",
    "http://social.tumba.local": "social_media",
    "https://meet.tumba.local": "google_meet",
    "https://exam.tumba.local": "online_exam",
}

RESTRICTED_BROWSER_MARKERS = (
    "admin.tumba.local",
    "restricted.tumba.local",
    "staff.tumba.local",
    "ssh.tumba.local",
    "root.tumba.local",
)

TERMINAL_TOOL_MAP = {
    "ping sweep": "network_sweep",
    "port scan": "port_scan",
    "flood": "ddos_attack",
    "brute-force simulation": "brute_force",
    "unauthorized server access": "unauthorized_server_access",
    "ip spoofing simulation": "ip_spoofing",
    "arp spoofing simulation": "arp_spoofing",
    "stop attack": "idle",
}

ACTIVITY_ALIASES = {
    "exam_mode": "online_exam",
    "google meet": "google_meet",
    "e-learning": "elearning",
    "streaming": "video_streaming",
    "large download": "file_download",
    "ping_sweep": "network_sweep",
    "stop_traffic": "idle",
}


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def read_json(path: str, default: Any | None = None) -> Any:
    if default is None:
        default = {}
    try:
        with open(path) as handle:
            return json.load(handle)
    except Exception:
        return default


def atomic_write_json(
    path: str,
    data: Any,
    *,
    logger: logging.Logger | None = None,
    label: str = "state",
    mode: int = STATE_FILE_MODE,
) -> bool:
    ensure_parent_dir(path)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(path) or ".", delete=False, encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
            tmp_name = handle.name
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        os.chmod(path, mode)
        if logger:
            logger.info("%s write ok path=%s bytes=%d", label, path, os.path.getsize(path))
        return True
    except Exception as exc:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        if logger:
            logger.error("%s write error path=%s err=%s", label, path, exc)
        return False


def configure_file_logger(name: str, filename: str) -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    try:
        handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    except PermissionError:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def deterministic_mac(ip: str) -> str:
    parts = str(ip).split(".")
    if len(parts) >= 4:
        try:
            return "00:00:00:00:%02x:%02x" % (int(parts[2]), int(parts[3]))
        except Exception:
            pass
    return "00:00:00:00:00:00"


def load_external_vm_config(path: str | None = None) -> dict[str, Any]:
    """Load optional VMware/OVS endpoint inventory."""
    config_path = path or EXTERNAL_VM_CONFIG_FILE
    cfg = read_json(config_path, {})
    if not isinstance(cfg, dict):
        return {}
    return cfg


def external_vm_enabled(config: dict[str, Any] | None = None) -> bool:
    cfg = load_external_vm_config() if config is None else config
    return bool(cfg.get("enabled", False))


def external_zone_metadata(config: dict[str, Any] | None = None) -> dict[str, Any] | None:
    cfg = load_external_vm_config() if config is None else config
    if not external_vm_enabled(cfg):
        return None
    zone = dict(cfg.get("zone") or {})
    zone.setdefault("key", "external_vm")
    zone.setdefault("label", "External VMware")
    zone.setdefault("vlan", 50)
    zone.setdefault("subnet", "10.50.0.")
    zone.setdefault("switch", "ovs_ext")
    zone.setdefault("dpid", 8)
    zone.setdefault("distribution", "ds2")
    zone.setdefault("capacity_mbps", ACCESS_UPLINK_CAPACITY_MBPS)
    return zone


def load_external_vm_hosts(config: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    cfg = load_external_vm_config() if config is None else config
    zone = external_zone_metadata(cfg)
    if not zone:
        return {}

    hosts: dict[str, dict[str, Any]] = {}
    for idx, raw in enumerate(cfg.get("vms", []) or [], start=1):
        if not isinstance(raw, dict):
            continue
        host_id = str(raw.get("id") or raw.get("name") or f"ext_vm{idx}").strip()
        ip = str(raw.get("ip") or "").strip()
        if not host_id or not ip:
            continue
        meta = dict(raw)
        meta.update({
            "id": host_id,
            "zone": raw.get("zone") or zone["key"],
            "zone_key": raw.get("zone") or zone["key"],
            "zone_label": raw.get("zone_label") or zone["label"],
            "vlan": int(raw.get("vlan", zone["vlan"]) or zone["vlan"]),
            "switch": raw.get("switch") or zone["switch"],
            "ip": ip,
            "label": raw.get("label") or host_id,
            "role": raw.get("role") or "external_vm",
            "mac": raw.get("mac") or deterministic_mac(ip),
            "external": True,
            "managed_by": raw.get("managed_by") or "vmware_ovs",
            "link_capacity_mbps": float(raw.get("link_capacity_mbps", EDGE_LINK_CAPACITY_MBPS) or EDGE_LINK_CAPACITY_MBPS),
        })
        hosts[host_id] = meta
    return hosts


def active_zone_subnets() -> dict[str, str]:
    subnets = dict(ZONE_SUBNETS)
    zone = external_zone_metadata()
    if zone:
        subnets[zone["key"]] = zone["subnet"]
    return subnets


def active_zone_dpids() -> dict[str, int]:
    dpids = dict(ZONE_DPIDS)
    zone = external_zone_metadata()
    if zone:
        try:
            dpids[zone["key"]] = int(zone["dpid"])
        except (TypeError, ValueError):
            dpids[zone["key"]] = 8
    return dpids


def active_zone_labels() -> dict[str, str]:
    labels = dict(ZONE_LABELS)
    zone = external_zone_metadata()
    if zone:
        labels[zone["key"]] = zone["label"]
    return labels


def active_zone_switches() -> dict[str, str]:
    switches = dict(ZONE_SWITCHES)
    zone = external_zone_metadata()
    if zone:
        switches[zone["key"]] = zone["switch"]
    return switches


def active_zone_vlans() -> dict[str, int]:
    vlans = dict(ZONE_VLANS)
    zone = external_zone_metadata()
    if zone:
        vlans[zone["key"]] = int(zone["vlan"])
    return vlans


def build_activity_profiles() -> dict[str, dict[str, Any]]:
    def profile(
        key: str,
        label: str,
        priority: int,
        bandwidth_mbps: float,
        traffic_type: str,
        color: str,
        icon: str,
        description: str,
        *,
        dscp: int | None = None,
        pattern: str = "moderate",
        burst_dur: int = 6,
        burst_gap: int = 2,
        qos_queue: int | None = None,
        safe_from_throttle: bool = False,
        security_state: str = "normal",
        target_zone: str = "server_zone",
        browser_url: str = "",
        controller_hint: str = "",
        security_signature: str = "",
    ) -> dict[str, Any]:
        service = SERVICE_TARGETS.get(key, SERVICE_TARGETS.get(ACTIVITY_ALIASES.get(key, ""), {}))
        priority_level = PRIORITY_LABELS[priority]
        queue_default = 0 if priority <= 2 else (1 if priority == 3 else 2)
        resolved_dscp = PRIORITY_DSCP.get(priority_level, 10) if dscp is None else dscp
        return {
            "key": key,
            "label": label,
            "priority": priority,
            "priority_level": priority_level,
            "dscp": resolved_dscp,
            "bandwidth_mbps": bandwidth_mbps,
            "traffic_type": traffic_type,
            "color": color,
            "icon": icon,
            "description": description,
            "dst_ip": service.get("ip", ""),
            "dst_port": service.get("port", 0),
            "dst_service_name": service.get("name", label),
            "proto": service.get("proto", "tcp"),
            "pattern": pattern,
            "burst_dur": burst_dur,
            "burst_gap": burst_gap,
            "qos_queue": queue_default if qos_queue is None else qos_queue,
            "safe_from_throttle": safe_from_throttle,
            "link_capacity_mbps": EDGE_LINK_CAPACITY_MBPS,
            "security_state": security_state,
            "target_zone": target_zone,
            "browser_url": browser_url,
            "controller_hint": controller_hint,
            "security_signature": security_signature,
        }

    profiles = {
        "idle": profile("idle", "Idle", 5, 0.0, "Idle", "#64748b", "●", "No active traffic", dscp=0, pattern="idle", burst_dur=1, burst_gap=1, qos_queue=2, browser_url="https://campus.tumba.local"),
        "exam": profile("exam", "Online Exam", 1, 18.0, "Online Exam", "#ef4444", "E", "Critical exam traffic", dscp=46, safe_from_throttle=True, browser_url="https://exam.tumba.local", controller_hint="Guaranteed bandwidth and high-priority queue applied"),
        "online_exam": profile("online_exam", "Online Exam", 1, 18.0, "Online Exam", "#ef4444", "E", "Critical exam traffic", dscp=46, safe_from_throttle=True, browser_url="https://exam.tumba.local", controller_hint="Guaranteed bandwidth and high-priority queue applied"),
        "video_conf": profile("video_conf", "Google Meet", 2, 16.0, "Google Meet", "#3b82f6", "V", "High-priority conferencing", dscp=34, pattern="stream", burst_dur=10, burst_gap=1, safe_from_throttle=True, browser_url="https://meet.tumba.local"),
        "google_meet": profile("google_meet", "Google Meet", 2, 16.0, "Google Meet", "#3b82f6", "V", "High-priority conferencing", dscp=34, pattern="stream", burst_dur=10, burst_gap=1, safe_from_throttle=True, browser_url="https://meet.tumba.local"),
        "voip": profile("voip", "VoIP", 1, 6.0, "VoIP", "#2563eb", "T", "Critical voice traffic", dscp=46, pattern="stream", burst_dur=10, burst_gap=1, safe_from_throttle=True),
        "elearning": profile("elearning", "E-learning", 2, 18.0, "E-learning", "#10b981", "L", "Academic LMS access", dscp=34, safe_from_throttle=True, browser_url="http://elearning.tumba.local"),
        "online_class": profile("online_class", "Online Class", 2, 20.0, "Online Class", "#14b8a6", "C", "Live academic class", dscp=34, pattern="stream", burst_dur=10, burst_gap=1, safe_from_throttle=True),
        "mis": profile("mis", "MIS Access", 2, 14.0, "MIS Access", "#0ea5e9", "I", "Administrative MIS service", dscp=34, safe_from_throttle=True, browser_url="https://mis.tumba.local"),
        "siad": profile("siad", "SIAD Access", 2, 14.0, "SIAD Access", "#22c55e", "S", "Student administration service", dscp=34, safe_from_throttle=True, browser_url="https://siad.tumba.local"),
        "rp_system": profile("rp_system", "RP System", 2, 12.0, "RP System", "#84cc16", "R", "Registration and reporting system", dscp=34, safe_from_throttle=True),
        "authentication": profile("authentication", "Authentication", 1, 1.0, "Authentication", "#38bdf8", "A", "Directory and auth traffic", dscp=46, burst_dur=2, burst_gap=4, safe_from_throttle=True, browser_url="https://auth.tumba.local"),
        "dns_query": profile("dns_query", "DNS", 1, 0.4, "DNS", "#60a5fa", "D", "Name-resolution traffic", dscp=46, pattern="burst", burst_dur=2, burst_gap=6, safe_from_throttle=True),
        "dhcp_sync": profile("dhcp_sync", "DHCP", 1, 0.3, "DHCP", "#93c5fd", "H", "DHCP exchange", dscp=46, pattern="burst", burst_dur=2, burst_gap=8, safe_from_throttle=True),
        "research": profile("research", "Research", 3, 22.0, "Research", "#8b5cf6", "R", "Academic research traffic", dscp=18, browser_url="http://library.tumba.local"),
        "web_browsing": profile("web_browsing", "Web Browsing", 3, 8.0, "Web Browsing", "#7c3aed", "W", "Normal academic browsing", dscp=18, pattern="bursty", burst_dur=3, burst_gap=3),
        "cloud_storage": profile("cloud_storage", "Cloud Storage", 3, 28.0, "Cloud Storage", "#c084fc", "C", "Medium-priority cloud sync", dscp=18, pattern="bulk", burst_dur=10, burst_gap=2),
        "study_download": profile("study_download", "Study Material Download", 3, 40.0, "Study Material Download", "#a855f7", "B", "Academic bulk download", dscp=18, pattern="bulk", burst_dur=12, burst_gap=1, browser_url="http://files.tumba.local"),
        "video_streaming": profile("video_streaming", "Streaming", 4, 80.0, "Streaming", "#f59e0b", "S", "Low-priority streaming", dscp=10, pattern="stream", burst_dur=12, burst_gap=1, browser_url="http://streaming.tumba.local"),
        "file_download": profile("file_download", "Large Download", 4, 92.0, "Large Download", "#f97316", "D", "Non-academic bulk download", dscp=10, pattern="bulk", burst_dur=14, burst_gap=1, browser_url="http://files.tumba.local"),
        "large_download": profile("large_download", "Large Download", 4, 92.0, "Large Download", "#f97316", "D", "Non-academic bulk download", dscp=10, pattern="bulk", burst_dur=14, burst_gap=1, browser_url="http://files.tumba.local"),
        "social_media": profile("social_media", "Social Media", 4, 12.0, "Social Media", "#06b6d4", "M", "Low-priority social traffic", dscp=10, pattern="bursty", burst_dur=3, burst_gap=3, browser_url="http://social.tumba.local"),
        "gaming": profile("gaming", "Gaming", 4, 38.0, "Gaming", "#ec4899", "G", "Low-priority gaming traffic", dscp=10, pattern="stream", burst_dur=12, burst_gap=1),
        "light_traffic": profile("light_traffic", "Light Traffic", 3, 2.4, "Light Academic Traffic", "#38bdf8", "1", "Low-level academic traffic", dscp=18),
        "medium_traffic": profile("medium_traffic", "Medium Traffic", 3, 8.0, "Medium Academic Traffic", "#0ea5e9", "2", "Moderate academic traffic", dscp=18),
        "heavy_traffic": profile("heavy_traffic", "Heavy Traffic", 3, 32.0, "Heavy Academic Traffic", "#0284c7", "3", "Heavier academic traffic", dscp=18, pattern="bulk", burst_dur=10, burst_gap=1),
        "saturate_pc_link": profile("saturate_pc_link", "Saturate PC Link", 4, 95.0, "Port Saturation Test", "#dc2626", "!", "Critical edge port saturation demo", dscp=10, pattern="bulk", burst_dur=18, burst_gap=1, controller_hint="Low-priority rate-limit profile applied (50 Mbps target)"),
        "ddos_attack": profile("ddos_attack", "DDoS / Flood Attack", 0, 95.0, "DDoS Attack", "#b91c1c", "!", "Security flood attack", dscp=0, pattern="flood", burst_dur=25, burst_gap=0, qos_queue=2, security_state="critical", controller_hint="OpenFlow drop rule installed", security_signature="ddos_flood"),
        "port_scan": profile("port_scan", "Port Scan", 0, 2.1, "Port Scan", "#f97316", "S", "TCP SYN port scan", dscp=0, pattern="scan", burst_dur=12, burst_gap=4, qos_queue=2, security_state="threat", controller_hint="OpenFlow drop rule installed", security_signature="port_scan"),
        "network_sweep": profile("network_sweep", "Ping Sweep", 0, 0.6, "Ping Sweep", "#fb923c", "W", "ICMP ping sweep", dscp=0, pattern="sweep", burst_dur=10, burst_gap=4, qos_queue=2, security_state="suspicious", controller_hint="Rate limiting applied", security_signature="ping_sweep"),
        "ping_sweep": profile("ping_sweep", "Ping Sweep", 0, 0.6, "Ping Sweep", "#fb923c", "W", "ICMP ping sweep", dscp=0, pattern="sweep", burst_dur=10, burst_gap=4, qos_queue=2, security_state="suspicious", controller_hint="Rate limiting applied", security_signature="ping_sweep"),
        "unauthorized_server_access": profile("unauthorized_server_access", "Unauthorized Server Access", 0, 2.8, "Unauthorized Access", "#f43f5e", "U", "Zero-Trust restricted access attempt", dscp=0, pattern="unauthorized_access", burst_dur=8, burst_gap=2, qos_queue=2, security_state="critical", controller_hint="OpenFlow drop rule installed", security_signature="unauthorized_access"),
        "brute_force": profile("brute_force", "Brute-Force Simulation", 0, 1.2, "Brute Force", "#ef4444", "B", "Repeated auth/login attempts", dscp=0, pattern="bruteforce", burst_dur=8, burst_gap=2, qos_queue=2, security_state="threat", controller_hint="OpenFlow drop rule installed", security_signature="brute_force"),
        "ip_spoofing": profile("ip_spoofing", "IP Spoofing Simulation", 0, 1.5, "IP Spoofing", "#e11d48", "I", "Spoofed source-IP simulation", dscp=0, pattern="spoof_ip", burst_dur=8, burst_gap=2, qos_queue=2, security_state="critical", controller_hint="Attacker isolated", security_signature="ip_spoofing"),
        "arp_spoofing": profile("arp_spoofing", "ARP Spoofing Simulation", 0, 1.0, "ARP Spoofing", "#be123c", "A", "ARP poisoning simulation", dscp=0, pattern="spoof_arp", burst_dur=8, burst_gap=2, qos_queue=2, security_state="critical", controller_hint="Attacker isolated", security_signature="arp_spoofing"),
    }
    return profiles


ACTIVITY_PROFILES = build_activity_profiles()


SCENARIO_LIBRARY = {
    "normal_traffic": {
        "duration_s": 120,
        "description": "Balanced academic traffic below congestion thresholds",
        "assignments": {
            "h_staff1": "mis",
            "h_staff2": "video_conf",
            "h_lab1": "light_traffic",
            "h_lab2": "medium_traffic",
            "h_wifi1": "web_browsing",
            "h_wifi2": "elearning",
            "h_wifi3": "light_traffic",
        },
    },
    "warning_wifi": {
        "duration_s": 120,
        "description": "WiFi access uplink pushed into warning range",
        "assignments": {
            "h_wifi1": "file_download",
            "h_wifi2": "file_download",
            "h_wifi3": "file_download",
            "h_wifi4": "medium_traffic",
            "h_wifi5": "web_browsing",
            "h_wifi6": "google_meet",
        },
    },
    "preventive_wifi": {
        "duration_s": 120,
        "description": "WiFi access uplink pushed into preventive range",
        "assignments": {
            "h_wifi1": "file_download",
            "h_wifi2": "file_download",
            "h_wifi3": "file_download",
            "h_wifi4": "video_streaming",
            "h_wifi5": "file_download",
            "h_wifi6": "google_meet",
            "h_wifi7": "social_media",
            "h_wifi8": "elearning",
        },
    },
    "critical_port": {
        "duration_s": 90,
        "description": "Single edge port saturation at ~95 Mbps",
        "assignments": {
            "h_wifi2": "saturate_pc_link",
            "h_wifi3": "social_media",
            "h_lab1": "elearning",
            "h_staff1": "mis",
        },
    },
    "elearning_priority": {
        "duration_s": 120,
        "description": "Academic flow protection during congestion",
        "assignments": {
            "h_lab2": "elearning",
            "h_wifi1": "file_download",
            "h_wifi2": "video_streaming",
            "h_wifi3": "gaming",
            "h_wifi4": "social_media",
            "h_wifi5": "file_download",
            "h_staff1": "mis",
        },
    },
    "streaming_throttle": {
        "duration_s": 120,
        "description": "Low-priority streaming and social traffic throttling",
        "assignments": {
            "h_wifi5": "video_streaming",
            "h_wifi6": "social_media",
            "h_wifi7": "gaming",
            "h_wifi8": "file_download",
            "h_lab1": "elearning",
            "h_staff1": "mis",
        },
    },
    "exam_mode": {
        "duration_s": 120,
        "description": "Exam-mode QoS with critical protection",
        "assignments": {
            "h_lab1": "online_exam",
            "h_lab2": "online_exam",
            "h_lab3": "elearning",
            "h_wifi1": "online_exam",
            "h_wifi2": "google_meet",
            "h_wifi3": "social_media",
            "h_wifi4": "video_streaming",
        },
    },
    "port_scan_attack": {
        "duration_s": 90,
        "description": "Port scan and ping sweep attack traffic",
        "assignments": {
            "h_wifi4": "port_scan",
            "h_wifi5": "network_sweep",
            "h_lab4": "port_scan",
            "h_staff1": "elearning",
        },
    },
    "ddos_attack": {
        "duration_s": 90,
        "description": "DDoS / flood simulation against server zone",
        "assignments": {
            "h_wifi3": "ddos_attack",
            "h_wifi4": "ddos_attack",
            "h_wifi5": "ddos_attack",
            "h_lab1": "elearning",
            "h_staff1": "mis",
        },
    },
    "unauthorized_access": {
        "duration_s": 90,
        "description": "Unauthorized VLAN / restricted-service access attempt",
        "assignments": {
            "h_wifi2": "unauthorized_server_access",
            "h_wifi3": "brute_force",
            "h_wifi4": "ip_spoofing",
            "h_wifi5": "arp_spoofing",
        },
    },
    "stop_reset": {
        "duration_s": 1,
        "description": "Return all simulated hosts to idle",
        "assignments": {},
        "reset_all": True,
    },
}

SCENARIO_ALIASES = {
    "exam": "exam_mode",
    "congestion": "preventive_wifi",
    "ddos": "ddos_attack",
    "scanning": "port_scan_attack",
    "off_peak": "stop_reset",
    "warning_wifi_congestion": "warning_wifi",
    "preventive_wifi_congestion": "preventive_wifi",
    "critical_pc_port_saturation": "critical_port",
    "elearning_priority_test": "elearning_priority",
    "streaming_social_throttling_test": "streaming_throttle",
    "streaming_throttling_test": "streaming_throttle",
    "exam_mode_test": "exam_mode",
    "port-scan attack": "port_scan_attack",
    "ddos/flood attack": "ddos_attack",
    "unauthorized vlan/server access": "unauthorized_access",
    "stop/reset scenario": "stop_reset",
}


def normalize_activity(activity: str) -> str:
    key = str(activity or "idle").strip().lower().replace(" ", "_").replace("-", "_")
    return ACTIVITY_ALIASES.get(key, key)


def resolve_browser_activity(url: str) -> tuple[str, str]:
    normalized = str(url or "").strip()
    activity = SERVICE_URL_MAP.get(normalized)
    if activity:
        return activity, normalized
    if normalized.startswith("http://") or normalized.startswith("https://"):
        short = normalized.split("?", 1)[0].rstrip("/")
        activity = SERVICE_URL_MAP.get(short, "web_browsing")
        return activity, short
    return "web_browsing", normalized or "http://library.tumba.local"


def is_restricted_browser_url(url: str) -> bool:
    normalized = str(url or "").strip().lower()
    if not normalized:
        return False
    return (
        any(marker in normalized for marker in RESTRICTED_BROWSER_MARKERS)
        or ":22" in normalized
        or "/admin" in normalized
        or "/restricted" in normalized
    )


def resolve_browser_request(url: str) -> dict[str, Any]:
    normalized = str(url or "").strip()
    if is_restricted_browser_url(normalized):
        return {
            "activity": "unauthorized_server_access",
            "url": normalized or "https://admin.tumba.local",
            "blocked": True,
            "browser_status": "Blocked",
            "reason": "Restricted service blocked by Zero-Trust policy",
        }
    activity, normalized_url = resolve_browser_activity(normalized)
    return {
        "activity": activity,
        "url": normalized_url,
        "blocked": False,
        "browser_status": "Connected",
        "reason": "",
    }


def resolve_terminal_tool(command: str) -> str:
    normalized = str(command or "").strip().lower()
    return TERMINAL_TOOL_MAP.get(normalized, normalize_activity(normalized))


def resolve_scenario(name: str) -> tuple[str, dict[str, Any] | None]:
    key = str(name or "").strip().lower().replace(" ", "_").replace("-", "_")
    canonical = SCENARIO_ALIASES.get(key, key)
    return canonical, SCENARIO_LIBRARY.get(canonical)


def now_ts() -> float:
    return time.time()
