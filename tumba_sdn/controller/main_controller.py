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

METRICS_FILE   = os.environ.get('CAMPUS_METRICS_FILE',   '/tmp/campus_metrics.json')
ML_ACTION_FILE = os.environ.get('CAMPUS_ML_ACTION_FILE', '/tmp/campus_ml_action.json')
TIMETABLE_FILE = os.environ.get('CAMPUS_TIMETABLE_STATE','/tmp/campus_timetable_state.json')

ZONE_SUBNETS = {
    'staff_lan':    '10.10.0.',
    'server_zone':  '10.20.0.',
    'it_lab':       '10.30.0.',
    'student_wifi': '10.40.0.',
}

# Zone → access-switch dpid
ZONE_DPID = {'staff_lan': 4, 'server_zone': 5, 'it_lab': 6, 'student_wifi': 7}

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
}

PC_ACTIVITIES_FILE = '/tmp/campus_pc_activities.json'


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
        self.timetable_state    = {}
        self.security_events    = []
        self.security_blocked   = 0
        self.ddos_blocked_ips   = {}
        self.flow_count         = 0

        # ── Congestion prediction state ──
        self.zone_util_ema      = {z: 0.0 for z in ZONE_SUBNETS}
        self.zone_util_history  = {z: deque(maxlen=30) for z in ZONE_SUBNETS}
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

        # Allow cross-zone permitted ports
        for src, dst, ports in [
            ('10.10.0.0', '10.20.0.0', [80, 443, 22]),
            ('10.30.0.0', '10.20.0.0', [80, 443, 22, 3306, 5201]),
            ('10.40.0.0', '10.20.0.0', [80, 443, 5201, 8443]),
        ]:
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
                    # Install drop rule for scanner IP
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip, ip_proto=6)
                    self._add_flow(dp, 350, match, [],
                                   cookie=SCAN_BLOCK_COOKIE, hard_timeout=120)

            if len(tr['ips']) >= SCAN_IP_THRESHOLD and not tr['sweep_notified']:
                tr['sweep_notified'] = True
                confidence = min(99, int(len(tr['ips']) / SCAN_IP_THRESHOLD * 65))
                self._append_event('network_sweep_detected',
                                   src_ip=src_ip,
                                   ips_probed=list(tr['ips'])[:10],
                                   ip_count=len(tr['ips']),
                                   zone=self._ip_to_zone(src_ip),
                                   confidence=confidence,
                                   pps=round(tr['pps'], 1))
                self.security_blocked += 1

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
            self._load_timetable()
            self._apply_timetable_qos()
            self._apply_ml_action()
            self._detect_ddos()
            self._cleanup_security_state()
            hub.sleep(2)

    def _detect_ddos(self):
        """Detect DDoS by sustained high PPS on any zone — auto-block and auto-clear."""
        for zone, zdpid in ZONE_DPID.items():
            ports     = [(d, p) for (d, p) in self.port_stats if d == zdpid]
            total_pps = sum(self.port_stats.get(k, {}).get('pps', 0) for k in ports)
            was_ddos  = bool(self.ddos_blocked_ips)

            if total_pps > DDOS_PPS_THRESHOLD:
                if zone not in self.ddos_blocked_ips:
                    self.ddos_blocked_ips[zone] = {
                        'ts': time.time(), 'pps': round(total_pps, 1), 'zone': zone
                    }
                    self.security_blocked += 1
                    self._append_event('ddos_detected', zone=zone, pps=round(total_pps, 1))
                    self.logger.warning('DDoS detected: zone=%s pps=%.0f', zone, total_pps)
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
                if zone in self.ddos_blocked_ips and total_pps < DDOS_CLEAR_PPS:
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
            # Update EMA
            prev_ema = self.zone_util_ema.get(zone, util)
            ema = EMA_ALPHA * util + (1 - EMA_ALPHA) * prev_ema
            self.zone_util_ema[zone] = round(ema, 2)
            self.zone_util_history[zone].append(util)

            # Predict: if EMA is rising and approaching threshold
            hist = list(self.zone_util_history[zone])
            if len(hist) >= 5:
                trend = (hist[-1] - hist[-5]) / 5   # Mbps/sample slope
                predicted_util = ema + trend * 5     # project 5 samples ahead
                was_predicted  = self.congestion_predicted.get(zone, False)
                now_predicted  = predicted_util > CONGESTION_THRESH and not metrics.get('congested')

                if now_predicted and not was_predicted:
                    self._append_event('congestion_predicted', zone=zone,
                                       current_util=round(util, 1),
                                       predicted_util=round(predicted_util, 1),
                                       ema=round(ema, 1))
                    self.logger.warning('CONGESTION PREDICTED zone=%s util=%.1f%% → %.1f%%',
                                        zone, util, predicted_util)
                self.congestion_predicted[zone] = now_predicted

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

    def _apply_ml_action(self):
        """Translate DQN action into actual OpenFlow rules."""
        action = self.ml_action.get('action')
        if not action or action == self.last_applied_action:
            return
        self.last_applied_action = action
        self._append_event('dqn_action_applied', action=action)
        self.logger.info('Applying DQN action: %s', action)

        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            ofp    = dp.ofproto

            if action == 'throttle_wifi_30pct':
                # Deprioritise all WiFi outbound
                self._set_zone_queue(dp, '10.40.0.0', queue=1)
            elif action in ('throttle_wifi_70pct', 'throttle_wifi_90pct'):
                self._set_zone_queue(dp, '10.40.0.0', queue=2)
            elif action == 'boost_staff_lan':
                self._set_zone_queue(dp, '10.10.0.0', queue=0)
            elif action == 'boost_server_zone':
                self._set_zone_queue(dp, '10.20.0.0', queue=0)
            elif action == 'exam_mode':
                self._enable_exam_mode(dp)
            elif action == 'security_isolation_wifi':
                # Drop WiFi → server during active DDoS
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=('10.40.0.0', '255.255.255.0'),
                )
                self._add_flow(dp, THROTTLE_WIFI_PRIORITY, match, [],
                               cookie=THROTTLE_COOKIE, hard_timeout=120)
            elif action in ('normal_mode', 'restore_normal'):
                # Remove throttle/isolation rules
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    cookie=THROTTLE_COOKIE, cookie_mask=0xFFFFFFFFFFFFFFFF,
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
        for zone, zdpid in ZONE_DPID.items():
            ports   = [(d, p) for (d, p) in self.port_stats if d == zdpid]
            total   = sum(self.port_stats.get(k, {}).get('mbps', 0) for k in ports)
            mx      = max((self.port_stats.get(k, {}).get('util_pct', 0) for k in ports), default=0)
            total_pps = sum(self.port_stats.get(k, {}).get('pps', 0) for k in ports)

            # Latency/jitter/loss estimation from utilization (academic model)
            base_lat = ZONE_BASE_LATENCY_MS.get(zone, 5.0)
            latency  = base_lat + max(0.0, (mx - 50) * 1.2)
            jitter   = max(0.0, (mx - 40) * 0.25)
            loss_pct = max(0.0, (mx - 75) * 0.15) if mx > 75 else 0.0

            self.zone_metrics[zone] = {
                'throughput_mbps':      round(total, 3),
                'max_utilization_pct':  round(mx, 2),
                'port_count':           len(ports),
                'pps':                  round(total_pps, 1),
                'congested':            mx > CONGESTION_THRESH,
                'predicted_congestion': self.congestion_predicted.get(zone, False),
                'util_ema':             round(self.zone_util_ema.get(zone, 0), 2),
                'latency_ms':           round(latency, 1),
                'jitter_ms':            round(jitter, 2),
                'loss_pct':             round(loss_pct, 2),
            }

    def _load_ml_action(self):
        try:
            if os.path.exists(ML_ACTION_FILE):
                with open(ML_ACTION_FILE) as f:
                    self.ml_action = json.load(f)
        except Exception:
            pass

    def _load_timetable(self):
        try:
            if os.path.exists(TIMETABLE_FILE):
                with open(TIMETABLE_FILE) as f:
                    self.timetable_state = json.load(f)
        except Exception:
            pass

    def _build_top_flows(self) -> list:
        """Build live flow table from PC Activities state."""
        try:
            with open(PC_ACTIVITIES_FILE) as f:
                pcs_data = json.load(f)
        except Exception:
            return []
        profiles = pcs_data.get('profiles', {})
        flows = []
        for host, info in pcs_data.get('pcs', {}).items():
            act = info.get('activity', 'idle')
            if act == 'idle':
                continue
            profile = profiles.get(act, {})
            flows.append({
                'src_ip':    info.get('ip', '?'),
                'src_label': info.get('label', host),
                'src_zone':  info.get('zone', ''),
                'dst_ip':    profile.get('dst_ip', '?'),
                'dst_port':  profile.get('dst_port', 0),
                'proto':     profile.get('proto', 'tcp').upper(),
                'activity':  info.get('activity_label', act),
                'mbps':      info.get('traffic_mbps', profile.get('bandwidth_mbps', 0)),
                'priority':  info.get('priority_label', ''),
                'dscp':      info.get('dscp', 0),
            })
        flows.sort(key=lambda x: x['mbps'], reverse=True)
        return flows[:10]

    def _write_metrics(self):
        port_data = {}
        for (d, p), s in self.port_stats.items():
            port_data.setdefault(str(d), {})[str(p)] = s

        # Collect recent security events for dashboard
        sec_events = [e for e in self.ctrl_events
                      if e.get('event') in (
                          'arp_spoofing_detected', 'mac_flooding_detected',
                          'port_scan_detected', 'network_sweep_detected',
                          'dqn_action_applied', 'congestion_predicted',
                          'exam_mode_enabled', 'exam_mode_disabled',
                          'social_throttle_enabled', 'link_failure', 'self_heal_reroute',
                      )][-20:]

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

        payload = {
            'ts':                   time.time(),
            'zone_metrics':         self.zone_metrics,
            'switch_port_stats':    port_data,
            'congested_ports_count': sum(1 for z in self.zone_metrics.values() if z.get('congested')),
            'connected_switches':   sorted(str(x) for x in self.datapaths),
            'flow_count':           self.flow_count,
            'ml_action':            self.ml_action,
            'timetable_state':      self.timetable_state,
            'events':               self.ctrl_events[-50:],
            'security_events':      sec_events,
            'ddos_active':          bool(self.ddos_blocked_ips),
            'ddos_zones':           list(self.ddos_blocked_ips.keys()),
            'security_blocked':     self.security_blocked,
            'blocked_ips':          list(self.blocked_ips.keys()),
            'active_scans':         active_scans,
            'exam_mode':            self.exam_mode_active,
            'throttle_active':      self.throttle_active,
            'congestion_predicted': self.congestion_predicted,
            'zone_util_ema':        {z: round(v, 2) for z, v in self.zone_util_ema.items()},
            'top_flows':            self._build_top_flows(),
        }
        try:
            tmp = METRICS_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, METRICS_FILE)
        except Exception:
            pass

    def _append_event(self, name, **kw):
        evt = {'ts': time.time(), 'event': name, **kw}
        self.ctrl_events.append(evt)
        self.ctrl_events = self.ctrl_events[-500:]
