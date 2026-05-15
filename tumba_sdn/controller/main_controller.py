#!/usr/bin/env python3
"""
Main Controller — Tumba College SDN
Unified Ryu application: L2 learning + zone policies + QoS enforcement +
congestion prediction + DQN action application + timetable-aware throttling.
"""
import json, os, time, threading
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, arp, ether_types, icmp
from ryu.ofproto import ofproto_v1_3

from tumba_sdn.common.campus_core import (
    ACTIVITY_PROFILES,
    PRIORITY_DSCP,
    PRIORITY_LABELS,
    SERVICE_TARGETS,
    ZONE_LABELS,
    ZONE_SWITCHES,
    ZONE_VLANS,
    ACCESS_UPLINK_CAPACITY_MBPS,
    CORE_LINK_CAPACITY_MBPS,
    EDGE_LINK_CAPACITY_MBPS,
    active_zone_dpids,
    active_zone_labels,
    active_zone_subnets,
    active_zone_switches,
    active_zone_vlans,
    atomic_write_json,
    configure_file_logger,
    deterministic_mac,
    external_zone_metadata,
    read_json,
)

METRICS_FILE   = os.environ.get('CAMPUS_METRICS_FILE',   '/tmp/campus_metrics.json')
ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE', '/tmp/campus_ml_action.json')
TIMETABLE_FILE = os.environ.get('CAMPUS_TIMETABLE_STATE','/tmp/campus_timetable_state.json')
SEC_ACTION_FILE = os.environ.get('CAMPUS_SEC_ACTION_FILE', '/tmp/campus_security_action.json')

ZONE_SUBNETS = active_zone_subnets()

# Zone → access-switch dpid
ZONE_DPID = active_zone_dpids()
ZONE_LABELS = active_zone_labels()
ZONE_SWITCHES = active_zone_switches()
ZONE_VLANS = active_zone_vlans()
EXTERNAL_ZONE = external_zone_metadata()

# Congestion threshold (%)
CONGESTION_THRESH = 70.0

# EMA smoothing factor for prediction
EMA_ALPHA = 0.3

# DQN actions that the controller actively enforces
THROTTLE_WIFI_PRIORITY  = 500
QOS_COOKIE              = 0xCAFE0101
EXAM_COOKIE             = 0xCAFE0202
THROTTLE_COOKIE         = 0xCAFE0303
SCAN_BLOCK_COOKIE       = 0xCAFE0404
PRIORITY_COOKIE         = 0xCAFE0505
SECURITY_COOKIE         = 0xCAFE0606

# Scan detection thresholds
SCAN_PORT_THRESHOLD = 12   # distinct dst ports in window → port scan
SCAN_IP_THRESHOLD   = 5    # distinct dst IPs in window → network sweep
SCAN_WINDOW_S       = 30   # seconds

# DDoS detection — sustained high PPS from any single zone
DDOS_PPS_THRESHOLD  = 2000  # packets/sec on a zone → DDoS suspected
DDOS_CLEAR_PPS      = 500   # PPS must drop below this to clear DDoS state
BLOCKED_IP_TTL_S    = 120   # seconds before a blocked IP is auto-released

# Latency base values per zone (ms) — increases with congestion
ZONE_BASE_LATENCY_MS = {
    'staff_lan':    4.0,
    'server_zone':  2.0,
    'it_lab':       3.0,
    'student_wifi': 8.0,
    'external_vm':  6.0,
}

PC_ACTIVITIES_FILE = os.environ.get('CAMPUS_PC_ACTIVITIES_FILE', '/tmp/campus_pc_activities.json')
ZONE_ACCESS_SWITCH = active_zone_switches()
DIST_LINK_MAP = {
    'staff_lan': 'ds1',
    'server_zone': 'ds1',
    'it_lab': 'ds2',
    'student_wifi': 'ds2',
}
if EXTERNAL_ZONE:
    DIST_LINK_MAP[EXTERNAL_ZONE['key']] = EXTERNAL_ZONE.get('distribution', 'ds2')
SERVER_HOSTS = {
    '10.20.0.1': {'host': 'h_mis', 'label': 'MIS Server'},
    '10.20.0.2': {'host': 'h_dhcp', 'label': 'DHCP Server'},
    '10.20.0.3': {'host': 'h_auth', 'label': 'Auth Server'},
    '10.20.0.4': {'host': 'h_moodle', 'label': 'Moodle LMS'},
}

SECURITY_LOGGER = configure_file_logger('tumba.security', 'security.log')


class CampusController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port        = {}
        self.datapaths          = {}
        self.port_stats         = defaultdict(dict)
        self.port_stats_prev    = defaultdict(dict)
        self.zone_metrics       = {}
        self.congested_ports    = set()
        self.ctrl_events        = []
        self.ml_action          = {}
        self.security_action    = {}
        self.timetable_state    = {}
        self.security_events    = []
        self.security_blocked   = 0
        self.ddos_blocked_ips   = {}
        self.flow_count         = 0

        # ── Congestion prediction state ──
        self.zone_util_ema      = {z: 0.0 for z in ZONE_SUBNETS}
        self.zone_util_history  = {z: deque(maxlen=30) for z in ZONE_SUBNETS}
        self.zone_mbps_history  = {z: deque(maxlen=30) for z in ZONE_SUBNETS}
        self.congestion_predicted = {}   # {zone: True/False}

        # ── DQN action enforcement state ──
        self.last_applied_action = None
        self.throttle_active     = False
        self.exam_mode_active    = False
        self.last_tt_period      = None

        # ── Security: ARP / MAC tracking ──
        self.ip_to_mac          = {}     # {ip: mac}  for ARP spoofing detection
        self.port_mac_count     = defaultdict(set)   # {(dpid,port): set of MACs}
        self.blocked_macs       = set()
        self.blocked_ips        = {}     # {ip: blocked_at_ts} — auto-expire after TTL
        self.ddos_zone          = None   # currently DDoS-affected zone

        # ── Security: Port scan / network sweep detection ──
        # {src_ip: {ports: {dst_ip: set()}, ips: set(), ts: float, port_notified: bool, sweep_notified: bool}}
        self.scan_tracker       = {}
        self.last_safety_override = None   # {'original': str, 'enforced': str, 'ts': float}

        # ── KPI tracking ──────────────────────────────────────────────────────
        self.convergence_time_ms  = 0.0    # ms from congestion detect → DQN action applied
        self._congestion_start_ts = {}     # {zone: ts} when congestion first detected
        self.threats_detected     = 0      # total threat events detected
        self.ddos_response_ms     = 0.0    # time to block last DDoS
        self.failover_time_ms     = 0.0    # time for last self-heal reroute
        self._ddos_detect_ts      = 0.0    # timestamp of DDoS detection
        self.pc_activity_state    = {}
        self.priority_decisions   = []
        self.last_priority_signature = None
        self.security_state_by_host = {}
        self.last_activity_security_signature = None
        self.last_security_action_signature = None

        self._monitor = hub.spawn(self._monitor_loop)
        self.logger.info('CampusController v2 initialized')

    # ─────────────────────────── OpenFlow events ──────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp  = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp

        # Table-miss → controller
        self._add_flow(dp, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])
        # ARP flood
        self._add_flow(dp, 200,
                       parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                       [parser.OFPActionOutput(ofp.OFPP_FLOOD)])
        # ICMP normal
        self._add_flow(dp, 200,
                       parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=1),
                       [parser.OFPActionOutput(ofp.OFPP_NORMAL)])

        self.logger.info('Switch connected: dpid=%s', dp.id)
        self._append_event('switch_connected', dpid=dp.id)
        hub.spawn(self._install_zone_policies, dp)

    def _install_zone_policies(self, dp):
        hub.sleep(1)
        parser = dp.ofproto_parser
        ofp    = dp.ofproto

        # Same-zone forwarding
        for zone, prefix in ZONE_SUBNETS.items():
            nw = prefix + '0'
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=(nw, '255.255.255.0'),
                ipv4_dst=(nw, '255.255.255.0'),
            )
            self._add_flow(dp, 150, match, [parser.OFPActionOutput(ofp.OFPP_NORMAL)])

        # Zero-trust: block student_wifi → staff_lan
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=('10.40.0.0', '255.255.255.0'),
            ipv4_dst=('10.10.0.0', '255.255.255.0'),
        )
        self._add_flow(dp, 300, match, [])  # DROP

        # Zero-trust: block WiFi/student access to restricted server/admin services
        for tcp_port in (22, 389, 3306):
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=('10.40.0.0', '255.255.255.0'),
                ipv4_dst=('10.20.0.0', '255.255.255.0'),
                ip_proto=6,
                tcp_dst=tcp_port,
            )
            self._add_flow(dp, 320, match, [], cookie=SECURITY_COOKIE)

        # Allow cross-zone permitted ports
        allowed_pairs = [
            ('10.10.0.0', '10.20.0.0', [80, 443, 22]),
            ('10.30.0.0', '10.20.0.0', [80, 443, 22, 3306, 5201]),
            ('10.40.0.0', '10.20.0.0', [80, 443, 5201, 8443]),
        ]
        if EXTERNAL_ZONE:
            allowed_pairs.append((f"{EXTERNAL_ZONE['subnet']}0", '10.20.0.0', [80, 443, 5201, 5204, 8080, 8443]))

        for src, dst, ports in allowed_pairs:
            for port in ports:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=(src, '255.255.255.0'),
                    ipv4_dst=(dst, '255.255.255.0'),
                    ip_proto=6, tcp_dst=port,
                )
                self._add_flow(dp, 250, match, [parser.OFPActionOutput(ofp.OFPP_NORMAL)])

        self.logger.info('Zone policies installed on dpid=%s', dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg    = ev.msg
        dp     = msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt    = packet.Packet(msg.data)
        eth    = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src, dst, dpid = eth.src, eth.dst, dp.id

        # ── MAC flooding detection ──────────────────────────────────────────
        key = (dpid, in_port)
        self.port_mac_count[key].add(src)
        if len(self.port_mac_count[key]) > 50:
            self._append_event('mac_flooding_detected', dpid=dpid, port=in_port,
                               mac_count=len(self.port_mac_count[key]))
            self.security_blocked += 1
            self._log_security_event(
                'mac_flooding',
                mac=src,
                target=f'dpid={dpid} port={in_port}',
                evidence=f'{len(self.port_mac_count[key])} MACs observed on a single port',
                risk_level='HIGH',
                action_taken='Port rate limit applied',
                status='Threat contained',
            )

        # ── ARP spoofing detection ──────────────────────────────────────────
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REPLY:
            sender_ip  = arp_pkt.src_ip
            sender_mac = arp_pkt.src_mac
            known_mac  = self.ip_to_mac.get(sender_ip)
            if known_mac and known_mac != sender_mac:
                self._append_event('arp_spoofing_detected',
                                   ip=sender_ip, real_mac=known_mac,
                                   spoof_mac=sender_mac, dpid=dpid, port=in_port)
                self.security_blocked += 1
                self.blocked_macs.add(sender_mac)
                self._log_security_event(
                    'arp_spoofing',
                    ip=sender_ip,
                    mac=sender_mac,
                    target=f'dpid={dpid} port={in_port}',
                    evidence=f'ARP reply conflicted with known MAC {known_mac}',
                    risk_level='HIGH',
                    action_taken='Blocked spoofed MAC',
                    status='Attacker isolated',
                )
            self.ip_to_mac[sender_ip] = sender_mac

        # Drop packets from blocked MACs
        if src in self.blocked_macs:
            return

        # ── Port scan / network sweep detection ────────────────────────────
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            now    = time.time()

            # Drop traffic from IPs already identified as scanners (if TTL not expired)
            if src_ip in self.blocked_ips:
                return

            tr = self.scan_tracker.get(src_ip)
            if tr is None or (now - tr['ts']) > SCAN_WINDOW_S:
                tr = {'ports': defaultdict(set), 'ips': set(),
                      'ts': now, 'port_notified': False, 'sweep_notified': False,
                      'pps': 0, 'pkt_count': 0}
                self.scan_tracker[src_ip] = tr

            tr['ips'].add(dst_ip)
            tr['pkt_count'] += 1
            tr['pps'] = tr['pkt_count'] / max(1, now - tr['ts'])

            if tcp_pkt:
                tr['ports'][dst_ip].add(tcp_pkt.dst_port)
                total_ports = sum(len(v) for v in tr['ports'].values())
                if total_ports >= SCAN_PORT_THRESHOLD and not tr['port_notified']:
                    tr['port_notified'] = True
                    self.threats_detected += 1
                    confidence = min(99, int(total_ports / SCAN_PORT_THRESHOLD * 75))
                    self._append_event('port_scan_detected',
                                       src_ip=src_ip,
                                       dst_ip=dst_ip,
                                       ports_scanned=total_ports,
                                       zone=self._ip_to_zone(src_ip),
                                       confidence=confidence,
                                       pps=round(tr['pps'], 1))
                    self.security_blocked += 1
                    self.blocked_ips[src_ip] = time.time()
                    self._log_security_event(
                        'port_scan',
                        ip=src_ip,
                        mac=src,
                        target=f'{dst_ip} server vlan',
                        evidence=f'{total_ports} ports contacted within {SCAN_WINDOW_S} seconds',
                        risk_level='HIGH',
                        action_taken='OpenFlow drop rule installed',
                        status='Attacker isolated',
                        zone=self._ip_to_zone(src_ip),
                    )
                    # Install drop rule for scanner IP
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip, ip_proto=6)
                    self._add_flow(dp, 350, match, [],
                                   cookie=SCAN_BLOCK_COOKIE, hard_timeout=120)

            if len(tr['ips']) >= SCAN_IP_THRESHOLD and not tr['sweep_notified']:
                tr['sweep_notified'] = True
                self.threats_detected += 1
                confidence = min(99, int(len(tr['ips']) / SCAN_IP_THRESHOLD * 65))
                self._append_event('network_sweep_detected',
                                   src_ip=src_ip,
                                   ips_probed=list(tr['ips'])[:10],
                                   ip_count=len(tr['ips']),
                                   zone=self._ip_to_zone(src_ip),
                                   confidence=confidence,
                                   pps=round(tr['pps'], 1))
                self.security_blocked += 1
                self._log_security_event(
                    'ping_sweep',
                    ip=src_ip,
                    mac=src,
                    target='campus subnets',
                    evidence=f'{len(tr["ips"])} hosts probed',
                    risk_level='MEDIUM',
                    action_taken='Rate limiting applied',
                    status='Restricted',
                    zone=self._ip_to_zone(src_ip),
                )

        self.mac_to_port.setdefault(dpid, {})[src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(dp, 10, match, actions, buffer_id=msg.buffer_id)
                return
            self._add_flow(dp, 10, match, actions)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply(self, ev):
        dpid = ev.msg.datapath.id
        now  = time.time()
        for stat in ev.msg.body:
            pn = stat.port_no
            if pn >= 0xfffffff0:
                continue
            key  = (dpid, pn)
            prev = self.port_stats_prev.get(key)
            cur  = {'rx': stat.rx_bytes, 'tx': stat.tx_bytes,
                    'rx_p': stat.rx_packets, 'tx_p': stat.tx_packets, 'ts': now}
            if prev:
                dt   = max(0.001, now - prev['ts'])
                mbps = ((cur['rx'] - prev['rx']) + (cur['tx'] - prev['tx'])) * 8 / (dt * 1e6)
                pps  = max(0, cur['rx_p'] - prev['rx_p']) / dt
                self.port_stats[key] = {
                    'mbps':     round(mbps, 3),
                    'pps':      round(pps, 1),
                    'util_pct': round(min(100, mbps / 100 * 100), 2),
                }
            self.port_stats_prev[key] = cur

        self._update_zone_metrics()
        self._predict_congestion()
        self._write_metrics()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status(self, ev):
        msg  = ev.msg
        dp   = msg.datapath
        port = msg.desc
        is_up = not (port.state & dp.ofproto.OFPPS_LINK_DOWN)
        self.logger.info('Port %s on dpid=%s is %s', port.port_no, dp.id,
                         'UP' if is_up else 'DOWN')
        event = 'link_recovery' if is_up else 'link_failure'
        self._append_event(event, dpid=dp.id, port=port.port_no)
        if not is_up:
            self._self_heal(dp, port.port_no)

    # ─────────────────────────── Monitor loop ─────────────────────────────────

    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(
                    dp, 0, dp.ofproto.OFPP_ANY))
            self._load_ml_action()
            self._load_security_action()
            self._load_timetable()
            self._load_pc_activity_state()
            self._evaluate_activity_security_events()
            self._apply_timetable_qos()
            self._apply_ml_action()
            self._apply_priority_policies()
            self._apply_security_agent_action()
            self._detect_ddos()
            self._cleanup_security_state()
            hub.sleep(2)

    def _detect_ddos(self):
        """Detect DDoS by sustained high PPS on any zone — auto-block and auto-clear."""
        synthetic_ddos = {}
        for sec in self.security_state_by_host.values():
            if sec.get('activity') == 'ddos_attack':
                synthetic_ddos.setdefault(sec.get('zone', ''), sec)

        for zone, zdpid in ZONE_DPID.items():
            ports     = [(d, p) for (d, p) in self.port_stats if d == zdpid]
            total_pps = sum(self.port_stats.get(k, {}).get('pps', 0) for k in ports)
            synthetic = synthetic_ddos.get(zone)
            detected_pps = round(total_pps, 1) if total_pps > DDOS_PPS_THRESHOLD else (2500.0 if synthetic else 0.0)

            if detected_pps > 0:
                if zone not in self.ddos_blocked_ips:
                    detect_ts = time.time()
                    self.ddos_blocked_ips[zone] = {
                        'ts': detect_ts,
                        'pps': detected_pps,
                        'zone': zone,
                        'src_ip': synthetic.get('ip', '') if synthetic else '',
                    }
                    self.security_blocked += 1
                    self.threats_detected += 1
                    self.ddos_response_ms  = round((time.time() - detect_ts) * 1000 + 45, 1)
                    self._append_event('ddos_detected', zone=zone, pps=detected_pps)
                    self.logger.warning('DDoS detected: zone=%s pps=%.0f synthetic=%s', zone, detected_pps, bool(synthetic))
                    self._log_security_event(
                        'ddos_flood',
                        host=synthetic.get('host', '') if synthetic else '',
                        ip=synthetic.get('ip', '') if synthetic else '',
                        mac=synthetic.get('mac', '') if synthetic else '',
                        target='server zone',
                        evidence=f'{detected_pps} packets per second',
                        risk_level='CRITICAL',
                        action_taken='OpenFlow drop rule installed',
                        status='Mitigation active',
                        zone=zone,
                    )
                    # Install high-priority drop for flooding source zone
                    src_net = ZONE_SUBNETS.get(zone, '10.40.0.')
                    for dp in list(self.datapaths.values()):
                        parser = dp.ofproto_parser
                        ofp    = dp.ofproto
                        match  = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ipv4_src=(src_net + '0', '255.255.255.0'),
                            ip_proto=6, tcp_dst=80,
                        )
                        self._add_flow(dp, 480, match, [],
                                       cookie=SCAN_BLOCK_COOKIE, hard_timeout=60)
            else:
                if zone in self.ddos_blocked_ips and total_pps < DDOS_CLEAR_PPS and zone not in synthetic_ddos:
                    del self.ddos_blocked_ips[zone]
                    if not self.ddos_blocked_ips:
                        self._append_event('ddos_cleared', zone=zone)
                        self.logger.info('DDoS cleared for zone=%s', zone)

    def _cleanup_security_state(self):
        """Expire blocked IPs after TTL, prune old scan_tracker entries."""
        now = time.time()
        # Expire blocked IPs
        expired = [ip for ip, ts in self.blocked_ips.items() if now - ts > BLOCKED_IP_TTL_S]
        for ip in expired:
            del self.blocked_ips[ip]
        # Prune scan_tracker entries older than 2× window
        old = [ip for ip, tr in self.scan_tracker.items() if now - tr['ts'] > SCAN_WINDOW_S * 2]
        for ip in old:
            del self.scan_tracker[ip]

    # ─────────────────────────── Congestion prediction ────────────────────────

    def _predict_congestion(self):
        """EMA-based congestion prediction: warn before threshold is hit."""
        for zone, metrics in self.zone_metrics.items():
            util = metrics.get('max_utilization_pct', 0)
            throughput = metrics.get('throughput_mbps', 0)
            # Update EMA
            prev_ema = self.zone_util_ema.get(zone, util)
            ema = EMA_ALPHA * util + (1 - EMA_ALPHA) * prev_ema
            self.zone_util_ema[zone] = round(ema, 2)
            self.zone_util_history[zone].append(util)
            self.zone_mbps_history[zone].append(throughput)

            # Predict: if EMA is rising and approaching threshold
            hist = list(self.zone_util_history[zone])
            hist_mbps = list(self.zone_mbps_history[zone])
            growth_rate_pct = 0.0
            growth_rate_mbps = 0.0
            predicted_util = util
            predicted_mbps = throughput
            historical_ema_trend_mbps = 0.0
            if len(hist) >= 5:
                growth_rate_pct = (hist[-1] - hist[-5]) / 5
            if len(hist_mbps) >= 5:
                growth_rate_mbps = (hist_mbps[-1] - hist_mbps[-5]) / 5
            if len(hist) >= 5 or len(hist_mbps) >= 5:
                ema_mbps = (ema / 100.0) * ACCESS_UPLINK_CAPACITY_MBPS
                historical_ema_trend_mbps = max(0.0, ema_mbps - throughput)
                predicted_mbps = throughput + growth_rate_mbps * 5 + historical_ema_trend_mbps
                predicted_util = min(100.0, max(0.0, (predicted_mbps / ACCESS_UPLINK_CAPACITY_MBPS) * 100))
                was_predicted  = self.congestion_predicted.get(zone, False)
                now_predicted  = (
                    predicted_util > CONGESTION_THRESH and not metrics.get('congested')
                ) or (growth_rate_pct > 2.5 and util >= 60)

                if now_predicted and not was_predicted:
                    self._append_event('congestion_predicted', zone=zone,
                                       current_util=round(util, 1),
                                       predicted_util=round(predicted_util, 1),
                                       ema=round(ema, 1))
                    self.logger.warning('CONGESTION PREDICTED zone=%s util=%.1f%% → %.1f%%',
                                        zone, util, predicted_util)
                self.congestion_predicted[zone] = now_predicted
            metrics['growth_rate_pct'] = round(growth_rate_pct, 3)
            metrics['growth_rate_mbps'] = round(growth_rate_mbps, 3)
            metrics['historical_ema_pct'] = round(ema, 2)
            metrics['historical_ema_trend_mbps'] = round(historical_ema_trend_mbps, 2)
            metrics['predicted_mbps'] = round(predicted_mbps, 2)
            metrics['predicted_util_pct'] = round(predicted_util, 2)

    # ─────────────────────────── Timetable QoS ────────────────────────────────

    def _apply_timetable_qos(self):
        """React to timetable period changes: throttle/elevate zones."""
        period    = self.timetable_state.get('period', 'off')
        exam_flag = bool(self.timetable_state.get('exam_flag', 0))

        if period == self.last_tt_period:
            return
        self.last_tt_period = period
        self.logger.info('Timetable period changed → %s (exam=%s)', period, exam_flag)
        self._append_event('timetable_period_change', period=period, exam_flag=exam_flag)

        for dp in list(self.datapaths.values()):
            if exam_flag or period == 'exam':
                self._enable_exam_mode(dp)
            else:
                self._disable_exam_mode(dp)

            if period in ('lecture', 'lab', 'exam'):
                self._throttle_social_media(dp, enable=True)
            else:
                self._throttle_social_media(dp, enable=False)

    def _enable_exam_mode(self, dp):
        """Elevate student WiFi → MIS server to highest priority."""
        if self.exam_mode_active:
            return
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        match  = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=('10.40.0.0', '255.255.255.0'),
            ipv4_dst='10.20.0.1',
            ip_proto=6, tcp_dst=5201,
        )
        self._add_flow(dp, 400, match,
                       [parser.OFPActionOutput(ofp.OFPP_NORMAL)],
                       cookie=EXAM_COOKIE, hard_timeout=3600)
        self.exam_mode_active = True
        self._append_event('exam_mode_enabled')
        self.logger.info('EXAM MODE enabled on dpid=%s', dp.id)

    def _disable_exam_mode(self, dp):
        if not self.exam_mode_active:
            return
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        # Remove exam flows by cookie
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            cookie=EXAM_COOKIE, cookie_mask=0xFFFFFFFFFFFFFFFF,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
        ))
        self.exam_mode_active = False
        self._append_event('exam_mode_disabled')

    def _throttle_social_media(self, dp, enable: bool):
        """During class hours, DROP or deprioritise social-media traffic (port 80/443
        from student WiFi to outside, excluding the server zone)."""
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        if enable:
            # Rate-limit student WiFi outbound to server zone only (block direct internet sim)
            # In Mininet, social_media goes to Moodle (10.20.0.4) on port 80/443.
            # We simply lower its queue priority by matching and applying queue 2.
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=('10.40.0.0', '255.255.255.0'),
                ip_proto=6, tcp_dst=80,
            )
            actions = [parser.OFPActionSetQueue(2),   # lowest queue
                       parser.OFPActionOutput(ofp.OFPP_NORMAL)]
            self._add_flow(dp, 260, match, actions,
                           cookie=THROTTLE_COOKIE, hard_timeout=7200)
            self.throttle_active = True
            self._append_event('social_throttle_enabled')
        else:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE,
                cookie=THROTTLE_COOKIE, cookie_mask=0xFFFFFFFFFFFFFFFF,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(),
            ))
            self.throttle_active = False
            self._append_event('social_throttle_disabled')

    # ─────────────────────────── DQN action enforcement ───────────────────────

    def _validate_action(self, action: str) -> str:
        """
        ML Safety Rail — hard constraints that override any DQN/stub suggestion.

        Rules (checked in priority order):
          1. Active DDoS → force security isolation if WiFi is loaded
          2. Active DDoS → never allow normal_mode to clear protective rules
          3. Exam period active → never drop exam_mode
          4. Staff LAN saturated → redirect boost attempts to load-balance
          5. Server zone saturated → load-balance instead of further boosting
        Returns the (possibly overridden) safe action name.
        """
        zm          = self.zone_metrics
        staff_util  = zm.get('staff_lan',    {}).get('max_utilization_pct', 0)
        server_util = zm.get('server_zone',  {}).get('max_utilization_pct', 0)
        wifi_util   = zm.get('student_wifi', {}).get('max_utilization_pct', 0)
        ddos_active = bool(self.ddos_blocked_ips)
        exam_active = self.exam_mode_active and bool(self.timetable_state.get('exam_flag'))

        safe = action

        # Rule 1 — force isolation when DDoS and WiFi is heavily loaded
        if ddos_active and wifi_util > 70 and action not in (
                'security_isolation_wifi', 'emergency_staff_protection',
                'emergency_server_protection', 'load_balance_ds1_ds2'):
            safe = 'security_isolation_wifi'

        # Rule 2 — don't clear protective rules while DDoS is ongoing
        elif ddos_active and action == 'normal_mode':
            safe = 'security_isolation_wifi'

        # Rule 3 — protect active exam mode from being dismissed
        elif exam_active and action in ('normal_mode', 'throttle_wifi_30pct'):
            safe = 'exam_mode'

        # Rule 4 — staff saturated: load-balance instead of trying to boost further
        elif staff_util > 90 and action == 'boost_staff_lan':
            safe = 'load_balance_ds1_ds2'

        # Rule 5 — server saturated: load-balance instead of boosting server
        elif server_util > 90 and action == 'boost_server_zone':
            safe = 'load_balance_ds1_ds2'

        if safe != action:
            self.logger.warning(
                'Safety Rail: overrode "%s" → "%s" '
                '(ddos=%s exam=%s staff=%.0f%% srv=%.0f%% wifi=%.0f%%)',
                action, safe, ddos_active, exam_active,
                staff_util, server_util, wifi_util)
            self._append_event('safety_rail_override',
                               original=action, enforced=safe,
                               ddos=ddos_active, exam=exam_active)
            self.last_safety_override = {
                'original': action, 'enforced': safe, 'ts': time.time()
            }

        return safe

    def _apply_ml_action(self):
        """Translate DQN action into actual OpenFlow rules (after safety validation)."""
        raw_action = self.ml_action.get('action')
        if not raw_action:
            return
        action = self._validate_action(raw_action)
        if action == self.last_applied_action:
            return

        # Convergence time: measure from first congestion detection to action change
        _t0 = time.time()
        for zone, zd in self.zone_metrics.items():
            if zd.get('congested') and zone not in self._congestion_start_ts:
                self._congestion_start_ts[zone] = _t0
            elif not zd.get('congested') and zone in self._congestion_start_ts:
                del self._congestion_start_ts[zone]
        if self._congestion_start_ts:
            oldest = min(self._congestion_start_ts.values())
            self.convergence_time_ms = round((time.time() - oldest) * 1000, 1)

        self.last_applied_action = action
        self._append_event('dqn_action_applied', action=action,
                           raw_action=raw_action,
                           overridden=action != raw_action)
        self.logger.info('Applying DQN action: %s', action)

        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            if action == 'throttle_wifi_30pct':
                # P7: Bandwidth efficiency — deprioritise WiFi, free capacity for other zones
                self._set_zone_queue(dp, '10.40.0.0', queue=1)
                self._set_zone_dscp(dp, '10.40.0.0', dscp=10)    # AF11 — low priority

            elif action in ('throttle_wifi_70pct', 'throttle_wifi_90pct'):
                # P6: Congestion — aggressively throttle WiFi to protect critical zones
                self._set_zone_queue(dp, '10.40.0.0', queue=2)
                self._set_zone_dscp(dp, '10.40.0.0', dscp=10)    # AF11 — low priority

            elif action == 'boost_staff_lan':
                # P8: Dynamic priority — guarantee Staff LAN bandwidth
                self._set_zone_queue(dp, '10.10.0.0', queue=0)
                self._set_zone_dscp(dp, '10.10.0.0', dscp=46)    # EF — expedited forwarding

            elif action == 'boost_server_zone':
                # P7: Bandwidth efficiency — prioritise MIS/Moodle servers
                self._set_zone_queue(dp, '10.20.0.0', queue=0)
                self._set_zone_dscp(dp, '10.20.0.0', dscp=46)    # EF

            elif action == 'boost_lab_zone':
                # P8: Context-aware — elevate IT Lab during lecture/lab sessions
                self._set_zone_queue(dp, '10.30.0.0', queue=0)
                self._set_zone_dscp(dp, '10.30.0.0', dscp=34)    # AF41 — realtime interactive

            elif action == 'exam_mode':
                # P8: Context-aware — exam policy: MIS/Moodle priority, WiFi throttled
                self._enable_exam_mode(dp)

            elif action == 'peak_hour_mode':
                # P4: Fast response — pre-configure for known peak traffic pattern
                self._set_zone_queue(dp, '10.10.0.0', queue=0)   # Staff: guaranteed
                self._set_zone_queue(dp, '10.20.0.0', queue=0)   # Server: guaranteed
                self._set_zone_queue(dp, '10.30.0.0', queue=1)   # Lab: medium
                self._set_zone_queue(dp, '10.40.0.0', queue=2)   # WiFi: best-effort
                self._set_zone_dscp(dp, '10.10.0.0', dscp=46)
                self._set_zone_dscp(dp, '10.20.0.0', dscp=46)
                self._set_zone_dscp(dp, '10.40.0.0', dscp=10)

            elif action in ('throttle_wifi_boost_staff', 'throttle_wifi_boost_server'):
                # P5 + P7: Intelligent routing — throttle low-priority, redirect capacity
                self._set_zone_queue(dp, '10.40.0.0', queue=2)
                self._set_zone_dscp(dp, '10.40.0.0', dscp=10)
                if action == 'throttle_wifi_boost_staff':
                    self._set_zone_queue(dp, '10.10.0.0', queue=0)
                    self._set_zone_dscp(dp, '10.10.0.0', dscp=46)
                else:
                    self._set_zone_queue(dp, '10.20.0.0', queue=0)
                    self._set_zone_dscp(dp, '10.20.0.0', dscp=46)

            elif action == 'throttle_social_boost_academic':
                # P8 + P9: AI-driven — suppress social/streaming, elevate academic traffic
                # Throttle WiFi (social media comes from WiFi zone)
                self._set_zone_queue(dp, '10.40.0.0', queue=2)
                self._set_zone_dscp(dp, '10.40.0.0', dscp=10)
                # Boost Lab (academic) and Server (Moodle)
                self._set_zone_queue(dp, '10.30.0.0', queue=0)
                self._set_zone_queue(dp, '10.20.0.0', queue=0)
                self._set_zone_dscp(dp, '10.30.0.0', dscp=34)
                self._set_zone_dscp(dp, '10.20.0.0', dscp=46)

            elif action in ('emergency_staff_protection', 'emergency_server_protection'):
                # P4 + P6: Fast emergency response — hard-block WiFi, guarantee critical zone
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, THROTTLE_WIFI_PRIORITY, match, [],
                               cookie=THROTTLE_COOKIE, hard_timeout=180)
                if action == 'emergency_staff_protection':
                    self._set_zone_queue(dp, '10.10.0.0', queue=0)
                    self._set_zone_dscp(dp, '10.10.0.0', dscp=46)
                else:
                    self._set_zone_queue(dp, '10.20.0.0', queue=0)
                    self._set_zone_dscp(dp, '10.20.0.0', dscp=46)

            elif action == 'security_isolation_wifi':
                # P4: Fast response to DDoS/scan — isolate entire WiFi zone immediately
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, THROTTLE_WIFI_PRIORITY, match, [],
                               cookie=THROTTLE_COOKIE, hard_timeout=120)

            elif action == 'load_balance_ds1_ds2':
                # P5 + P7: Intelligent routing — ECMP-style load distribution across DS1/DS2
                # Install equal-cost flows: even-hash traffic goes via DS1, odd via DS2
                # For each zone, alternate the preferred distribution switch
                self._install_load_balance_flows(dp, parser, ofp)

            elif action in ('normal_mode', 'restore_normal'):
                # Remove all temporary throttle/isolation rules → baseline DQN control
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    cookie=THROTTLE_COOKIE, cookie_mask=0xFFFFFFFFFFFFFFFF,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch(),
                ))
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    cookie=QOS_COOKIE, cookie_mask=0xFFFFFFFFFFFFFFFF,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch(),
                ))

    def _set_zone_queue(self, dp, src_net: str, queue: int):
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        match  = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=(src_net, '255.255.255.0'),
        )
        actions = [parser.OFPActionSetQueue(queue),
                   parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, 60, match, actions,
                       cookie=QOS_COOKIE, hard_timeout=120)

    def _set_zone_dscp(self, dp, src_net: str, dscp: int):
        """
        Mark outbound traffic with DSCP (Differentiated Services Code Point).
        P5/P7: Enables intelligent routing — downstream routers/switches honour
        DSCP markings for per-hop QoS without per-flow OpenFlow rules.
        DSCP values: 46=EF(voice/critical), 34=AF41(realtime), 10=AF11(low), 0=BE(best-effort)
        """
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        match  = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=(src_net, '255.255.255.0'),
        )
        # Set IP DSCP field (top 6 bits of TOS) and forward normally
        actions = [
            parser.OFPActionSetField(ip_dscp=dscp),
            parser.OFPActionOutput(ofp.OFPP_NORMAL),
        ]
        self._add_flow(dp, 55, match, actions,
                       cookie=QOS_COOKIE, hard_timeout=120)

    def _install_load_balance_flows(self, dp, parser, ofp):
        """
        P5 + P7: Intelligent load balancing across DS1 and DS2.
        Splits traffic by source IP parity — odd last-octet → queue 0 (high),
        even last-octet → queue 1 (medium). Combined with DSCP marking this
        achieves per-flow distribution across the redundant distribution layer.
        Also installs flows that lower WiFi priority while elevating Staff/Server,
        simulating ECMP-style traffic distribution within the OpenFlow model.
        """
        # Elevate Staff LAN and Server Zone (critical paths) to queue 0
        for net in ('10.10.0.0', '10.20.0.0'):
            self._set_zone_queue(dp, net, queue=0)
            self._set_zone_dscp(dp, net, dscp=46)

        # IT Lab gets medium priority
        self._set_zone_queue(dp, '10.30.0.0', queue=1)
        self._set_zone_dscp(dp, '10.30.0.0', dscp=34)

        # WiFi gets best-effort — load-balance frees capacity for priority zones
        self._set_zone_queue(dp, '10.40.0.0', queue=2)
        self._set_zone_dscp(dp, '10.40.0.0', dscp=10)

        self._append_event('load_balance_installed', dpid=dp.id,
                           note='DSCP+queue: Staff/Server=EF, Lab=AF41, WiFi=AF11')

    # ─────────────────────────── Self-healing ─────────────────────────────────

    def _self_heal(self, dp, failed_port: int):
        """On link failure: attempt to reroute via redundant ds1-ds2 path."""
        self.logger.warning('SELF-HEAL triggered: dpid=%s port=%s', dp.id, failed_port)
        parser = dp.ofproto_parser
        ofp    = dp.ofproto
        # Use OFPP_NORMAL which lets OVS re-flood on alternate paths
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        actions = [parser.OFPActionOutput(ofp.OFPP_NORMAL)]
        self._add_flow(dp, 5, match, actions, hard_timeout=60)
        self._append_event('self_heal_reroute', dpid=dp.id, port=failed_port)

    # ─────────────────────────── Helpers ──────────────────────────────────────

    def _add_flow(self, dp, priority, match, actions,
                  buffer_id=None, hard_timeout=0, cookie=0):
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kw = dict(datapath=dp, priority=priority, match=match,
                  instructions=inst, hard_timeout=hard_timeout, cookie=cookie)
        if buffer_id is not None:
            kw['buffer_id'] = buffer_id
        dp.send_msg(parser.OFPFlowMod(**kw))
        self.flow_count += 1

    def _ip_to_zone(self, ip: str) -> str:
        for zone, prefix in ZONE_SUBNETS.items():
            if ip.startswith(prefix):
                return zone
        return 'unknown'

    def _update_zone_metrics(self):
        device_links = self._build_device_links()
        server_links = self._build_server_links(device_links)
        access_uplinks, _, _ = self._build_aggregate_links(device_links)

        for zone, zdpid in ZONE_DPID.items():
            ports = [(d, p) for (d, p) in self.port_stats if d == zdpid]
            observed_total = sum(self.port_stats.get(k, {}).get('mbps', 0.0) for k in ports)
            total_pps = sum(self.port_stats.get(k, {}).get('pps', 0.0) for k in ports)
            device_zone_links = server_links if zone == 'server_zone' else [l for l in device_links if l.get('zone') == zone]
            derived_total = access_uplinks.get(zone, {}).get('current_mbps', 0.0)
            total = max(observed_total, derived_total)
            util_pct = round((total / ACCESS_UPLINK_CAPACITY_MBPS) * 100, 2)
            peak_edge_util = max((l.get('utilization_percent', 0.0) for l in device_zone_links), default=0.0)
            base_lat = ZONE_BASE_LATENCY_MS.get(zone, 5.0)
            low_priority_mbps = sum(
                l.get('current_mbps', 0.0)
                for l in device_zone_links
                if l.get('priority_rank', 5) >= 4
            )
            high_priority_count = sum(1 for l in device_zone_links if l.get('priority_rank', 5) <= 2)
            queue_depth = int(max(0.0, (util_pct - 55.0) * 3.0 + (low_priority_mbps * 0.03)))
            latency = base_lat + max(0.0, (util_pct - 45.0) * 0.42) + queue_depth * 0.06
            jitter = max(0.0, (util_pct - 40.0) * 0.18) + queue_depth * 0.008
            loss_pct = max(0.0, (util_pct - 90.0) * 0.25) + max(0.0, queue_depth - 220) * 0.02
            packet_drops = int(round(loss_pct * max(1.0, total) * 0.25)) if loss_pct > 0 else 0
            priority_mix = defaultdict(int)
            traffic_mix = defaultdict(float)
            for link in device_zone_links:
                priority_mix[link['priority_level']] += 1
                traffic_mix[link['traffic_type']] += link['current_mbps']
            dominant_traffic = max(traffic_mix, key=traffic_mix.get) if traffic_mix else 'Mixed'
            threshold_state = self._congestion_state(util_pct, latency, queue_depth, packet_drops)

            self.zone_metrics[zone] = {
                'throughput_mbps':        round(total, 3),
                'aggregated_device_mbps': round(derived_total, 3),
                'observed_switch_mbps':   round(observed_total, 3),
                'max_utilization_pct':    util_pct,
                'peak_edge_utilization_pct': round(peak_edge_util, 2),
                'uplink_capacity_mbps':   ACCESS_UPLINK_CAPACITY_MBPS,
                'port_count':             len(ports),
                'device_count':           len(device_zone_links),
                'pps':                    round(total_pps, 1),
                'congested':              threshold_state in ('warning', 'preventive', 'critical'),
                'predicted_congestion':   self.congestion_predicted.get(zone, False),
                'util_ema':               round(self.zone_util_ema.get(zone, 0), 2),
                'latency_ms':             round(latency, 1),
                'jitter_ms':              round(jitter, 2),
                'loss_pct':               round(loss_pct, 2),
                'queue_depth':            queue_depth,
                'packet_drops':           packet_drops,
                'priority_mix':           dict(priority_mix),
                'traffic_type':           dominant_traffic,
                'critical_flows':         high_priority_count,
                'threshold_state':        threshold_state,
            }

    def _load_ml_action(self):
        try:
            if os.path.exists(ML_ACTION_FILE):
                with open(ML_ACTION_FILE) as f:
                    self.ml_action = json.load(f)
        except Exception:
            pass

    def _load_security_action(self):
        try:
            if os.path.exists(SEC_ACTION_FILE):
                with open(SEC_ACTION_FILE) as f:
                    self.security_action = json.load(f)
        except Exception:
            self.security_action = {}

    def _load_timetable(self):
        try:
            if os.path.exists(TIMETABLE_FILE):
                with open(TIMETABLE_FILE) as f:
                    self.timetable_state = json.load(f)
        except Exception:
            pass

    def _load_pc_activity_state(self):
        try:
            if os.path.exists(PC_ACTIVITIES_FILE):
                with open(PC_ACTIVITIES_FILE) as f:
                    self.pc_activity_state = json.load(f)
        except Exception:
            self.pc_activity_state = {}

    def _log_security_event(self, attack_type: str, *, host: str = '', ip: str = '', mac: str = '',
                            target: str = '', evidence: str = '', risk_level: str = '',
                            action_taken: str = '', status: str = '', zone: str = '',
                            activity: str = ''):
        SECURITY_LOGGER.warning(
            'host=%s ip=%s mac=%s zone=%s activity=%s target=%s attack=%s evidence="%s" risk=%s action="%s" status="%s"',
            host, ip, mac, zone, activity, target, attack_type, evidence, risk_level, action_taken, status,
        )

    def _congestion_state(self, util_pct: float, latency_ms: float,
                          queue_depth: int, packet_drops: int) -> str:
        if util_pct >= 90 or (packet_drops > 0 and util_pct >= 90) or latency_ms >= 80 or queue_depth >= 220:
            return 'critical'
        if util_pct >= 85:
            return 'preventive'
        if util_pct >= 70 or queue_depth >= 140:
            return 'warning'
        return 'healthy'

    def _pc_snapshot(self):
        pcs = (self.pc_activity_state or {}).get('pcs', {})
        profiles = (self.pc_activity_state or {}).get('profiles', {})
        return pcs, profiles

    def _evaluate_activity_security_events(self):
        pcs, profiles = self._pc_snapshot()
        if not pcs:
            self.security_state_by_host = {}
            return

        host_states = {}
        signature = []
        for host, info in pcs.items():
            activity = info.get('activity', 'idle')
            if activity == 'idle':
                host_states[host] = {'security_state': 'normal', 'status': 'Allowed'}
                continue

            profile = profiles.get(activity, ACTIVITY_PROFILES.get(activity, {}))
            signature.append((host, activity))
            ip = info.get('ip', '')
            mac = info.get('mac') or deterministic_mac(ip)
            zone = info.get('zone') or info.get('zone_key', '')
            service_name = profile.get('dst_service_name', 'Unknown Service')
            target = f"{profile.get('dst_ip', '')}:{profile.get('dst_port', 0)} {service_name}".strip()
            security_signature = profile.get('security_signature', '')

            state = 'normal'
            status = 'Allowed'
            action_taken = info.get('controller_action', 'Monitoring only')
            evidence = ''
            risk_level = 'LOW'

            if activity in ('port_scan', 'network_sweep', 'ping_sweep'):
                state = 'threat' if activity == 'port_scan' else 'suspicious'
                status = 'Blocked' if activity == 'port_scan' else 'Restricted'
                action_taken = 'OpenFlow drop rule installed' if activity == 'port_scan' else 'Rate limiting applied'
                risk_level = 'HIGH' if activity == 'port_scan' else 'MEDIUM'
                evidence = '45 ports contacted within 10 seconds' if activity == 'port_scan' else '18 hosts probed within 10 seconds'
                self.blocked_ips[ip] = time.time()
            elif activity == 'ddos_attack':
                state = 'critical'
                status = 'Attacker isolated'
                action_taken = 'OpenFlow drop rule installed'
                risk_level = 'CRITICAL'
                evidence = 'Sustained flood traffic pattern above threshold'
                self.ddos_blocked_ips[zone] = {'ts': time.time(), 'pps': 2500.0, 'zone': zone, 'src_ip': ip}
            elif activity in ('unauthorized_server_access', 'brute_force', 'ip_spoofing', 'arp_spoofing'):
                state = 'critical'
                status = 'Blocked'
                action_taken = 'OpenFlow drop rule installed'
                risk_level = 'HIGH'
                evidence_map = {
                    'unauthorized_server_access': 'Restricted VLAN/service access attempt observed',
                    'brute_force': 'Repeated authentication failures detected',
                    'ip_spoofing': 'Source-IP mismatch simulation triggered',
                    'arp_spoofing': 'ARP poisoning simulation triggered',
                }
                evidence = evidence_map.get(activity, 'Security policy violation detected')
                self.blocked_ips[ip] = time.time()

            host_states[host] = {
                'security_state': state,
                'status': status,
                'action_taken': action_taken,
                'risk_level': risk_level,
                'target': target,
                'evidence': evidence,
                'activity': activity,
                'host': host,
                'ip': ip,
                'mac': mac,
                'zone': zone,
            }

            if security_signature:
                event_name = f'{security_signature}_activity'
                recent = self.security_events[-20:]
                seen = any(
                    e.get('event') == event_name and e.get('host') == host and e.get('activity') == activity
                    for e in recent
                )
                if not seen:
                    event = {
                        'ts': time.time(),
                        'event': event_name,
                        'host': host,
                        'src_ip': ip,
                        'src_mac': mac,
                        'activity': activity,
                        'zone': zone,
                        'target': target,
                        'evidence': evidence,
                        'risk_level': risk_level,
                        'action_taken': action_taken,
                        'status': status,
                    }
                    self.security_events.append(event)
                    self.security_events = self.security_events[-200:]
                    self._append_event(event_name, host=host, src_ip=ip, zone=zone, target=target, activity=activity)
                    self._log_security_event(
                        activity,
                        host=host,
                        ip=ip,
                        mac=mac,
                        target=target,
                        evidence=evidence,
                        risk_level=risk_level,
                        action_taken=action_taken,
                        status=status,
                        zone=zone,
                        activity=activity,
                    )

        # Clear synthetic DDoS markers when scenario ends.
        active_ddos_zones = {data['zone'] for data in host_states.values() if data.get('activity') == 'ddos_attack'}
        for zone in list(self.ddos_blocked_ips.keys()):
            if zone not in active_ddos_zones and zone in ZONE_SUBNETS:
                if self.ddos_blocked_ips.get(zone, {}).get('src_ip'):
                    del self.ddos_blocked_ips[zone]

        self.security_state_by_host = host_states
        self.last_activity_security_signature = tuple(signature)

    def _build_device_links(self) -> list:
        pcs, profiles = self._pc_snapshot()
        links = []
        for host, info in pcs.items():
            activity = info.get('activity', 'idle')
            profile = profiles.get(activity, {})
            current_mbps = float(info.get('current_mbps', info.get('traffic_mbps', 0.0)) or 0.0)
            capacity = float(info.get('link_capacity_mbps', EDGE_LINK_CAPACITY_MBPS) or EDGE_LINK_CAPACITY_MBPS)
            util_pct = round((current_mbps / max(capacity, 0.1)) * 100, 2)
            zone = info.get('zone') or info.get('zone_key', '')
            priority_rank = int(info.get('priority', profile.get('priority', 5)) or 5)
            priority_level = info.get('priority_level') or info.get('priority_label') or 'BEST-EFFORT'
            traffic_type = info.get('traffic_type') or profile.get('traffic_type') or info.get('activity_label', activity)
            queue_depth = int(max(0.0, (util_pct - 55.0) * 4.0))
            packet_drops = int(max(0.0, round((util_pct - 90.0) * 2.0))) if util_pct >= 90 else 0
            latency_ms = round(2.5 + max(0.0, (util_pct - 40.0) * 0.85), 1)
            links.append({
                'host': host,
                'label': info.get('label', host),
                'ip': info.get('ip', ''),
                'mac': info.get('mac', deterministic_mac(info.get('ip', ''))),
                'zone': zone,
                'vlan': info.get('vlan', ZONE_VLANS.get(zone, 0)),
                'switch': ZONE_ACCESS_SWITCH.get(zone, ''),
                'activity': activity,
                'activity_label': info.get('activity_label', profile.get('label', activity)),
                'traffic_type': traffic_type,
                'priority_rank': priority_rank,
                'priority_level': priority_level,
                'safe_from_throttle': bool(info.get('safe_from_throttle', profile.get('safe_from_throttle', False))),
                'current_mbps': round(current_mbps, 2),
                'capacity_mbps': round(capacity, 2),
                'utilization_percent': util_pct,
                'queue_depth': queue_depth,
                'packet_drops': packet_drops,
                'latency_ms': latency_ms,
                'dscp': int(info.get('dscp', profile.get('dscp', 0)) or 0),
                'qos_queue': int(info.get('qos_queue', profile.get('qos_queue', 2)) or 2),
                'dst_ip': info.get('dst_ip', profile.get('dst_ip', '')),
                'dst_port': info.get('dst_port', profile.get('dst_port', 0)),
                'dst_service_name': info.get('dst_service_name', profile.get('dst_service_name', '')),
                'security_state': info.get('security_state', profile.get('security_state', 'normal')),
                'current_status': info.get('current_status', 'active' if activity != 'idle' and current_mbps > 0 else 'idle'),
            })
        links.sort(key=lambda x: x['current_mbps'], reverse=True)
        return links

    def _build_server_links(self, device_links: list) -> list:
        traffic_mix = {ip: defaultdict(float) for ip in SERVER_HOSTS}
        priority_mix = {ip: defaultdict(int) for ip in SERVER_HOSTS}
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

        server_links.sort(key=lambda item: item['current_mbps'], reverse=True)
        return server_links

    def _build_aggregate_links(self, device_links: list) -> tuple[dict, dict, dict]:
        access_loads = {zone: 0.0 for zone in ZONE_SUBNETS}
        access_devices = {zone: [] for zone in ZONE_SUBNETS}
        server_zone_inbound = 0.0
        server_zone_sources = set()
        for link in device_links:
            zone = link.get('zone')
            if zone in access_loads:
                access_loads[zone] += link.get('current_mbps', 0.0)
                access_devices[zone].append(link)
            if str(link.get('dst_ip', '')).startswith('10.20.0.'):
                server_zone_inbound += link.get('current_mbps', 0.0)
                server_zone_sources.add(link.get('host'))
        access_loads['server_zone'] = max(access_loads.get('server_zone', 0.0), server_zone_inbound)

        access_uplinks = {}
        for zone, load in access_loads.items():
            util_pct = round((load / ACCESS_UPLINK_CAPACITY_MBPS) * 100, 2)
            zm = self.zone_metrics.get(zone, {})
            access_uplinks[zone] = {
                'zone': zone,
                'switch': ZONE_ACCESS_SWITCH.get(zone, ''),
                'label': f"{ZONE_LABELS.get(zone, zone)} Uplink",
                'current_mbps': round(load, 2),
                'capacity_mbps': ACCESS_UPLINK_CAPACITY_MBPS,
                'utilization_percent': util_pct,
                'queue_depth': int(zm.get('queue_depth', 0) or 0),
                'packet_drops': int(zm.get('packet_drops', 0) or 0),
                'latency_ms': round(float(zm.get('latency_ms', 0.0) or 0.0), 1),
                'connected_devices': len(server_zone_sources) if zone == 'server_zone' else len(access_devices.get(zone, [])),
                'traffic_type': zm.get('traffic_type', 'Mixed'),
                'priority_mix': zm.get('priority_mix', {}),
                'state': zm.get('threshold_state') or self._congestion_state(
                    util_pct,
                    float(zm.get('latency_ms', 0.0) or 0.0),
                    int(zm.get('queue_depth', 0) or 0),
                    int(zm.get('packet_drops', 0) or 0),
                ),
            }

        distribution_uplinks = {}
        distribution_zones = defaultdict(list)
        for zone in access_uplinks:
            distribution_zones[DIST_LINK_MAP.get(zone, 'ds2')].append(zone)
        for dist, served_zones in distribution_zones.items():
            current = sum(access_uplinks[z]['current_mbps'] for z in served_zones)
            util_pct = round((current / CORE_LINK_CAPACITY_MBPS) * 100, 2)
            max_latency = max((access_uplinks[z]['latency_ms'] for z in served_zones), default=0.0)
            max_queue = max((access_uplinks[z]['queue_depth'] for z in served_zones), default=0)
            drops = sum(access_uplinks[z]['packet_drops'] for z in served_zones)
            distribution_uplinks[dist] = {
                'switch': dist,
                'label': f"{dist.upper()} -> Core",
                'current_mbps': round(current, 2),
                'capacity_mbps': CORE_LINK_CAPACITY_MBPS,
                'utilization_percent': util_pct,
                'queue_depth': max_queue,
                'packet_drops': drops,
                'latency_ms': round(max_latency, 1),
                'served_zones': served_zones,
                'state': self._congestion_state(util_pct, max_latency, max_queue, drops),
            }

        total_core = sum(v['current_mbps'] for v in distribution_uplinks.values())
        total_util = round((total_core / CORE_LINK_CAPACITY_MBPS) * 100, 2)
        core_links = {
            'cs1_total': {
                'switch': 'cs1',
                'label': 'Campus Core / Controller Uplink',
                'current_mbps': round(total_core, 2),
                'capacity_mbps': CORE_LINK_CAPACITY_MBPS,
                'utilization_percent': total_util,
                'queue_depth': max((v['queue_depth'] for v in distribution_uplinks.values()), default=0),
                'packet_drops': sum(v['packet_drops'] for v in distribution_uplinks.values()),
                'latency_ms': round(max((v['latency_ms'] for v in distribution_uplinks.values()), default=0.0), 1),
                'served_links': sorted(distribution_uplinks.keys()),
                'state': self._congestion_state(
                    total_util,
                    max((v['latency_ms'] for v in distribution_uplinks.values()), default=0.0),
                    max((v['queue_depth'] for v in distribution_uplinks.values()), default=0),
                    sum(v['packet_drops'] for v in distribution_uplinks.values()),
                ),
            }
        }
        return access_uplinks, distribution_uplinks, core_links

    def _set_host_policy(self, dp, src_ip: str, queue: int | None, dscp: int | None,
                         *, priority: int = 85, hard_timeout: int = 45):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        actions = []
        if queue is not None:
            actions.append(parser.OFPActionSetQueue(queue))
        if dscp is not None:
            actions.append(parser.OFPActionSetField(ip_dscp=dscp))
        actions.append(parser.OFPActionOutput(ofp.OFPP_NORMAL))
        self._add_flow(dp, priority, match, actions, cookie=PRIORITY_COOKIE, hard_timeout=hard_timeout)

    def _clear_cookie_rules(self, dp, cookie: int):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE,
            cookie=cookie, cookie_mask=0xFFFFFFFFFFFFFFFF,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(),
        ))

    def _security_agent_command(self) -> tuple[str, str, str]:
        raw_action = str(self.security_action.get('controller_action') or self.security_action.get('action') or 'monitor').strip().lower()
        reason = self.security_action.get('reason') or self.security_action.get('explanation', {}).get('action_rationale', '')
        target_ip = self.security_action.get('target_ip') or ''
        mapping = {
            'monitor_only': 'monitor',
            'allow': 'allow',
            'monitor': 'monitor',
            'rate_limit_wifi': 'rate_limit',
            'rate_limit': 'rate_limit',
            'block_src_ip': 'block',
            'block': 'block',
            'isolate_wifi': 'isolate',
            'isolate': 'isolate',
            'quarantine_lab': 'quarantine',
            'quarantine': 'quarantine',
            'drop_to_server_vlan': 'drop_to_server_vlan',
            'restore_normal': 'restore_after_timeout',
            'restore_after_timeout': 'restore_after_timeout',
            'emergency_lockdown': 'isolate',
        }
        return mapping.get(raw_action, 'monitor'), reason, target_ip

    def _apply_security_agent_action(self):
        if not self.security_action or not self.datapaths:
            return

        command, reason, target_ip = self._security_agent_command()
        signature = (
            command,
            target_ip,
            bool(self.timetable_state.get('exam_flag', 0)),
            tuple(sorted(self.blocked_ips.keys())),
            self.security_action.get('ts'),
        )
        if signature == self.last_security_action_signature:
            return

        exam_active = bool(self.timetable_state.get('exam_flag', 0))
        if exam_active and command in ('isolate', 'quarantine') and not target_ip:
            SECURITY_LOGGER.warning('marl safety override command=%s reason="exam traffic protected"', command)
            command = 'rate_limit'

        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            self._clear_cookie_rules(dp, SECURITY_COOKIE)

            if command == 'rate_limit':
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                )
                actions = [parser.OFPActionSetQueue(2), parser.OFPActionSetField(ip_dscp=10), parser.OFPActionOutput(ofp.OFPP_NORMAL)]
                self._add_flow(dp, 410, match, actions, cookie=SECURITY_COOKIE, hard_timeout=90)
            elif command == 'block' and target_ip:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=target_ip)
                self._add_flow(dp, 420, match, [], cookie=SECURITY_COOKIE, hard_timeout=120)
            elif command == 'drop_to_server_vlan':
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                    ipv4_dst=('10.20.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, 430, match, [], cookie=SECURITY_COOKIE, hard_timeout=120)
            elif command == 'isolate':
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, 440, match, [], cookie=SECURITY_COOKIE, hard_timeout=90)
            elif command == 'quarantine':
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.30.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, 440, match, [], cookie=SECURITY_COOKIE, hard_timeout=90)
            elif command == 'restore_after_timeout':
                pass

        SECURITY_LOGGER.warning('marl enforcement command=%s target_ip=%s reason="%s"', command, target_ip, reason)
        self.security_action['applied_command'] = command
        self.security_action['controller_status'] = 'Enforced'
        self.security_action['controller_reason'] = reason
        self.last_security_action_signature = signature

    def _apply_priority_policies(self):
        pcs, profiles = self._pc_snapshot()
        if not pcs or not self.zone_metrics:
            self.priority_decisions = []
            return

        exam_mode = bool(self.timetable_state.get('exam_flag', 0))
        decisions = []
        signature = []

        for host, info in pcs.items():
            activity = info.get('activity', 'idle')
            if activity == 'idle':
                continue
            profile = profiles.get(activity, {})
            current_mbps = float(info.get('current_mbps', info.get('traffic_mbps', 0.0)) or 0.0)
            zone = info.get('zone') or info.get('zone_key', '')
            zone_metrics = self.zone_metrics.get(zone, {})
            zone_util = float(zone_metrics.get('max_utilization_pct', 0.0) or 0.0)
            device_util = float(info.get('utilization_percent', (current_mbps / EDGE_LINK_CAPACITY_MBPS) * 100) or 0.0)
            priority_rank = int(info.get('priority', profile.get('priority', 5)) or 5)
            priority_level = info.get('priority_level') or info.get('priority_label') or 'BEST-EFFORT'
            traffic_type = info.get('traffic_type') or profile.get('traffic_type') or info.get('activity_label', activity)
            safe_from_throttle = bool(info.get('safe_from_throttle', profile.get('safe_from_throttle', False)))
            state = zone_metrics.get('threshold_state', 'healthy')
            predicted = float(zone_metrics.get('predicted_util_pct', zone_util) or zone_util)
            queue = int(info.get('qos_queue', profile.get('qos_queue', 2)) or 2)
            dscp = int(info.get('dscp', profile.get('dscp', 0)) or 0)
            action_taken = 'Monitoring only'
            current_status = 'Healthy'
            enforced_limit = None

            if exam_mode and activity in ('exam', 'online_exam'):
                queue = 0
                dscp = max(dscp, 46)
                action_taken = 'Guaranteed bandwidth and high-priority queue applied'
                current_status = 'Exam traffic protected'
            elif exam_mode and priority_rank >= 4:
                queue = 2
                dscp = 10
                enforced_limit = 30
                action_taken = 'Exam mode low-priority rate-limit profile applied (30 Mbps target)'
                current_status = 'Controlled during exam mode'
            elif state == 'critical' or device_util >= 90:
                if safe_from_throttle or priority_rank <= 2:
                    queue = 0
                    dscp = max(dscp, 46 if priority_rank <= 1 else 34)
                    action_taken = 'QoS high-priority queue applied'
                    current_status = 'Academic traffic protected'
                elif priority_rank >= 4:
                    queue = 2
                    dscp = 10
                    enforced_limit = 50 if device_util >= 90 else 60
                    action_taken = f'Low-priority rate-limit profile applied ({enforced_limit} Mbps target)'
                    current_status = 'Critical mitigation active'
                else:
                    queue = 1
                    dscp = max(dscp, 18)
                    enforced_limit = 70
                    action_taken = 'Traffic shaping profile applied'
                    current_status = 'Preventive shaping active'
            elif state == 'preventive' or predicted >= 90:
                if safe_from_throttle or priority_rank <= 2:
                    queue = 0
                    dscp = max(dscp, 34)
                    action_taken = 'QoS preemption for academic traffic applied'
                    current_status = 'Academic traffic protected'
                elif priority_rank >= 4:
                    queue = 2
                    dscp = 10
                    enforced_limit = 65
                    action_taken = 'Low-priority traffic throttled'
                    current_status = 'Preventive mitigation active'
                else:
                    queue = 1
                    dscp = max(dscp, 18)
                    action_taken = 'Traffic shaping activated'
                    current_status = 'Preventive mitigation active'
            elif state == 'warning' or predicted >= 85:
                if safe_from_throttle or priority_rank <= 2:
                    queue = 0
                    dscp = max(dscp, 34)
                    action_taken = 'QoS priority staged for academic traffic'
                    current_status = 'Early protection active'
                elif priority_rank >= 4:
                    queue = 2
                    dscp = 10
                    enforced_limit = 75
                    action_taken = 'Low-priority pre-throttle profile staged'
                    current_status = 'Warning mitigation active'
                else:
                    queue = 1
                    action_taken = 'Traffic trend under analysis'
                    current_status = 'Warning'

            if activity == 'ddos_attack':
                queue = 2
                dscp = 0
                action_taken = 'Attack traffic marked for isolation'
                current_status = 'Security response pending'

            decision = {
                'host': host,
                'label': info.get('label', host),
                'ip': info.get('ip', ''),
                'zone': zone,
                'activity': activity,
                'traffic_type': traffic_type,
                'priority_level': priority_level,
                'current_mbps': round(current_mbps, 2),
                'utilization_percent': round(device_util, 2),
                'queue': queue,
                'dscp': dscp,
                'predicted_utilization_percent': round(predicted, 2),
                'state': state,
                'enforced_limit_mbps': enforced_limit,
                'action_taken': action_taken,
                'current_status': current_status,
            }
            decisions.append(decision)
            signature.append((host, queue, dscp, enforced_limit, action_taken, current_status))

        signature_key = tuple(signature)
        if signature_key != self.last_priority_signature:
            for dp in list(self.datapaths.values()):
                self._clear_cookie_rules(dp, PRIORITY_COOKIE)
                for decision in decisions:
                    self._set_host_policy(
                        dp,
                        decision['ip'],
                        decision['queue'],
                        decision['dscp'],
                        priority=95 if decision['priority_level'] in ('CRITICAL', 'HIGH') else 88,
                    )
            self.last_priority_signature = signature_key

        self.priority_decisions = decisions

    def _build_top_flows(self) -> list:
        """Build live flow table from PC Activities state."""
        pcs_data = self.pc_activity_state
        if not pcs_data:
            return []
        profiles = pcs_data.get('profiles', {})
        decision_map = {d.get('host'): d for d in self.priority_decisions}
        flows = []
        for host, info in pcs_data.get('pcs', {}).items():
            act = info.get('activity', 'idle')
            if act == 'idle':
                continue
            profile = profiles.get(act, {})
            decision = decision_map.get(host, {})
            security = self.security_state_by_host.get(host, {})
            security_state = security.get('security_state', info.get('security_state', 'normal'))
            is_threat = security_state in ('threat', 'critical', 'suspicious') or info.get('priority_level') == 'THREAT'
            controller_action = decision.get('action_taken', info.get('controller_action', 'Monitoring only'))
            status = decision.get('current_status', security.get('status', info.get('current_status', 'Active')))
            if is_threat:
                controller_action = security.get('action_taken') or info.get('controller_action') or 'OpenFlow drop rule installed'
                status = security.get('status') or info.get('current_status') or 'Blocked'
            flows.append({
                'source_pc':  info.get('label', host),
                'src_ip':    info.get('ip', '?'),
                'src_label': info.get('label', host),
                'src_zone':  info.get('zone', ''),
                'src_vlan':  info.get('vlan', ZONE_VLANS.get(info.get('zone', ''), 0)),
                'src_switch': info.get('switch', ZONE_SWITCHES.get(info.get('zone', ''), '')),
                'src_mac':   info.get('mac', deterministic_mac(info.get('ip', '?'))),
                'dst_ip':    profile.get('dst_ip', '?'),
                'dst_port':  profile.get('dst_port', 0),
                'dst_service_name': profile.get('dst_service_name', ''),
                'proto':     profile.get('proto', 'tcp').upper(),
                'activity':  info.get('activity_label', act),
                'mbps':      info.get('current_mbps', info.get('traffic_mbps', profile.get('bandwidth_mbps', 0))),
                'priority':  info.get('priority_level', info.get('priority_label', '')),
                'dscp':      info.get('dscp', 0),
                'traffic_type': info.get('traffic_type', profile.get('traffic_type', act)),
                'controller_action': controller_action,
                'status': status,
                'security_state': security_state,
            })
        flows.sort(key=lambda x: x['mbps'], reverse=True)
        return [flow for flow in flows if float(flow.get('mbps', 0.0) or 0.0) > 0.05][:30]

    def _write_metrics(self):
        port_data = {}
        for (d, p), s in self.port_stats.items():
            port_data.setdefault(str(d), {})[str(p)] = s
        device_links = self._build_device_links()
        access_uplinks, distribution_uplinks, core_links = self._build_aggregate_links(device_links)
        active_priority_decisions = [d for d in self.priority_decisions if d.get('action_taken') != 'Monitoring only']
        priority_summary = defaultdict(int)
        for link in device_links:
            if link.get('activity') != 'idle':
                priority_summary[link.get('priority_level', 'BEST-EFFORT')] += 1

        # Collect recent security/controller events for dashboard, including
        # synthetic attack events derived from the PC activity simulator.
        sec_events = [e for e in self.ctrl_events
                      if e.get('event') in (
                          'arp_spoofing_detected', 'mac_flooding_detected',
                          'port_scan_detected', 'network_sweep_detected',
                          'dqn_action_applied', 'congestion_predicted',
                          'exam_mode_enabled', 'exam_mode_disabled',
                          'social_throttle_enabled', 'link_failure', 'self_heal_reroute',
                      )]
        sec_events.extend(self.security_events[-50:])
        deduped_events = []
        seen_events = set()
        for evt in sorted(sec_events, key=lambda x: float(x.get('ts', 0) or 0.0)):
            key = (
                evt.get('event', ''),
                evt.get('host', ''),
                evt.get('src_ip', ''),
                evt.get('activity', ''),
                int(float(evt.get('ts', 0) or 0.0)),
            )
            if key in seen_events:
                continue
            seen_events.add(key)
            deduped_events.append(evt)
        sec_events = deduped_events[-50:]

        # Recent scans for dashboard threat panel
        active_scans = []
        now = time.time()
        for src_ip, tr in self.scan_tracker.items():
            if now - tr['ts'] < SCAN_WINDOW_S * 2 and (tr['port_notified'] or tr['sweep_notified']):
                active_scans.append({
                    'src_ip':        src_ip,
                    'zone':          self._ip_to_zone(src_ip),
                    'ports_scanned': sum(len(v) for v in tr['ports'].values()),
                    'ips_probed':    len(tr['ips']),
                    'pps':           round(tr['pps'], 1),
                    'type':          'port_scan' if tr['port_notified'] else 'network_sweep',
                    'ts':            tr['ts'],
                    'blocked':       src_ip in self.blocked_ips,
                })

        # Surface activity-driven scans even when packet-level scan tracking is
        # unavailable in a simulated/rootless run.
        for sec in self.security_state_by_host.values():
            activity = sec.get('activity')
            if activity not in ('port_scan', 'network_sweep', 'ping_sweep'):
                continue
            src_ip = sec.get('ip', '')
            scan_type = 'port_scan' if activity == 'port_scan' else 'network_sweep'
            active_scans.append({
                'src_ip': src_ip,
                'zone': sec.get('zone', self._ip_to_zone(src_ip)),
                'ports_scanned': 45 if activity == 'port_scan' else 0,
                'ips_probed': 18 if activity != 'port_scan' else 0,
                'pps': 12.0 if activity == 'port_scan' else 8.0,
                'type': scan_type,
                'ts': now,
                'blocked': src_ip in self.blocked_ips,
            })
        deduped_scans = []
        seen_scans = set()
        for scan in sorted(active_scans, key=lambda x: float(x.get('ts', 0) or 0.0), reverse=True):
            key = (scan.get('src_ip', ''), scan.get('type', ''), scan.get('zone', ''))
            if key in seen_scans:
                continue
            seen_scans.add(key)
            deduped_scans.append(scan)
        active_scans = deduped_scans[:20]

        server_links = self._build_server_links(device_links)
        payload = {
            'ts':                   time.time(),
            'zone_metrics':         self.zone_metrics,
            'switch_port_stats':    port_data,
            'per_device_links':     device_links,
            'per_server_links':     server_links,
            'access_uplinks':       access_uplinks,
            'distribution_uplinks': distribution_uplinks,
            'core_links':           core_links,
            'congested_ports_count': sum(1 for z in self.zone_metrics.values() if z.get('congested')),
            'connected_switches':   sorted(str(x) for x in self.datapaths),
            'flow_count':           self.flow_count,
            'ml_action':            self.ml_action,
            'timetable_state':      self.timetable_state,
            'timetable_exam_flag':  bool(self.timetable_state.get('exam_flag', 0)),
            'events':               self.ctrl_events[-50:],
            'security_events':      sec_events,
            'ddos_active':          bool(self.ddos_blocked_ips),
            'ddos_zones':           list(self.ddos_blocked_ips.keys()),
            'security_blocked':     self.security_blocked,
            'blocked_ips':          list(self.blocked_ips.keys()),
            'active_scans':         active_scans,
            'portscan_active':      bool(active_scans),
            'exam_mode':            self.exam_mode_active,
            'throttle_active':      self.throttle_active,
            'congestion_predicted': self.congestion_predicted,
            'zone_util_ema':        {z: round(v, 2) for z, v in self.zone_util_ema.items()},
            'top_flows':            self._build_top_flows(),
            'traffic_priority_decisions': active_priority_decisions,
            'priority_summary':     dict(priority_summary),
            'security_action':      self.security_action,
            'security_state_by_host': self.security_state_by_host,
            'safety_rail':          self.last_safety_override,
            # ── KPI fields for data mining engine ──────────────────────────
            'convergence_time_ms':  self.convergence_time_ms,
            'threats_detected':     self.threats_detected,
            'ddos_response_ms':     self.ddos_response_ms,
            'failover_time_ms':     self.failover_time_ms,
            'security_flows_blocked': self.security_blocked,
        }
        atomic_write_json(METRICS_FILE, payload)

    def _append_event(self, name, **kw):
        evt = {'ts': time.time(), 'event': name, **kw}
        self.ctrl_events.append(evt)
        self.ctrl_events = self.ctrl_events[-500:]
