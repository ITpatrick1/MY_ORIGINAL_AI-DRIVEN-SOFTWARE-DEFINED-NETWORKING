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
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
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
            hub.sleep(2)

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

    def _update_zone_metrics(self):
        for zone, zdpid in ZONE_DPID.items():
            ports   = [(d, p) for (d, p) in self.port_stats if d == zdpid]
            total   = sum(self.port_stats.get(k, {}).get('mbps', 0) for k in ports)
            mx      = max((self.port_stats.get(k, {}).get('util_pct', 0) for k in ports), default=0)
            self.zone_metrics[zone] = {
                'throughput_mbps':      round(total, 3),
                'max_utilization_pct':  round(mx, 2),
                'port_count':           len(ports),
                'congested':            mx > CONGESTION_THRESH,
                'predicted_congestion': self.congestion_predicted.get(zone, False),
                'util_ema':             round(self.zone_util_ema.get(zone, 0), 2),
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

    def _write_metrics(self):
        port_data = {}
        for (d, p), s in self.port_stats.items():
            port_data.setdefault(str(d), {})[str(p)] = s

        # Collect recent security events for dashboard
        sec_events = [e for e in self.ctrl_events
                      if e.get('event') in (
                          'arp_spoofing_detected', 'mac_flooding_detected',
                          'dqn_action_applied', 'congestion_predicted',
                          'exam_mode_enabled', 'exam_mode_disabled',
                          'social_throttle_enabled', 'link_failure', 'self_heal_reroute',
                      )][-20:]

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
            'security_blocked':     self.security_blocked,
            'exam_mode':            self.exam_mode_active,
            'throttle_active':      self.throttle_active,
            'congestion_predicted': self.congestion_predicted,
            'zone_util_ema':        {z: round(v, 2) for z, v in self.zone_util_ema.items()},
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
