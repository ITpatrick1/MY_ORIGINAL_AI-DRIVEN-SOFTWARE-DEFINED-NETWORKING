#!/usr/bin/env python3
"""
Tumba College of Technology — Campus SDN Topology (Mininet)

Topology:
    Internet (NAT)
          |
       Core Switch (cs1) — OpenFlow 1.3
          |         |
         DS1        DS2        ← Distribution Switches
        / | \      / | \
      AS1 AS2    AS3 AS4       ← Access Switches (one per zone)

Zone mapping:
  AS1 → Staff LAN        (VLAN 10) — 6 virtual hosts
  AS2 → Server Zone      (VLAN 20) — 4 virtual hosts (MIS, DHCP, Auth, Moodle)
  AS3 → IT/Network Lab   (VLAN 30) — 4 virtual hosts
  AS4 → Student Wi-Fi    (VLAN 40) — 10 virtual hosts

All switches run OVS with OpenFlow 1.3.
DS1-DS2 inter-link = 1000 Mbps (redundant path for self-healing).
Each Access Switch uplink = 1000 Mbps.
"""

import os
import sys
import json
import time
import threading
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from tumba_sdn.common.campus_core import (
    atomic_write_json,
    deterministic_mac,
    external_zone_metadata,
    load_external_vm_hosts,
)


def build_static_topology_state():
    nodes = []
    links = []

    switch_specs = [
        ('cs1', 'Core Switch', '0000000000000001'),
        ('ds1', 'Distribution Switch 1', '0000000000000002'),
        ('ds2', 'Distribution Switch 2', '0000000000000003'),
        ('as1', 'Staff LAN Switch', '0000000000000004'),
        ('as2', 'Server Zone Switch', '0000000000000005'),
        ('as3', 'IT Lab Switch', '0000000000000006'),
        ('as4', 'Student WiFi Switch', '0000000000000007'),
    ]
    for switch_id, label, dpid in switch_specs:
        nodes.append({'id': switch_id, 'type': 'switch', 'dpid': dpid, 'label': label})

    zone_specs = {
        'staff_lan': ('h_staff', '10.10.0', 6, 'as1', lambda i: f'Staff PC {i}'),
        'server_zone': ('h_srv', '10.20.0', 4, 'as2', lambda i: {1: 'MIS Server', 2: 'DHCP Server', 3: 'Auth Server', 4: 'Moodle Server'}[i]),
        'it_lab': ('h_lab', '10.30.0', 4, 'as3', lambda i: f'Lab PC {i}'),
        'student_wifi': ('h_wifi', '10.40.0', 10, 'as4', lambda i: f'WiFi Device {i}'),
    }
    server_names = {1: 'h_mis', 2: 'h_dhcp', 3: 'h_auth', 4: 'h_moodle'}
    for zone, (prefix, subnet, count, switch, label_fn) in zone_specs.items():
        for i in range(1, count + 1):
            host_id = server_names[i] if zone == 'server_zone' else f'{prefix}{i}'
            ip = f'{subnet}.{i}'
            nodes.append({
                'id': host_id,
                'type': 'host',
                'ip': ip,
                'mac': deterministic_mac(ip),
                'zone': zone,
                'label': label_fn(i),
            })
            links.append({
                'src': host_id,
                'dst': switch,
                'src_intf': f'{host_id}-eth0',
                'dst_intf': f'{switch}-eth{i}',
                'bw_mbps': 100,
            })

    for src, dst in [('cs1', 'ds1'), ('cs1', 'ds2'), ('ds1', 'ds2'), ('ds1', 'as1'), ('ds1', 'as2'), ('ds2', 'as3'), ('ds2', 'as4')]:
        links.append({
            'src': src,
            'dst': dst,
            'src_intf': f'{src}-{dst}',
            'dst_intf': f'{dst}-{src}',
            'bw_mbps': 1000,
        })

    _append_external_vm_nodes(nodes, links)

    return {'ts': time.time(), 'nodes': nodes, 'links': links, 'mode': 'static_fallback'}


def _append_external_vm_nodes(nodes: list, links: list):
    zone = external_zone_metadata()
    hosts = load_external_vm_hosts()
    if not zone or not hosts:
        return
    switch_id = zone.get('switch', 'ovs_ext')
    dpid = int(zone.get('dpid', 8) or 8)
    distribution = zone.get('distribution', 'ds2')
    if not any(n.get('id') == switch_id for n in nodes):
        nodes.append({
            'id': switch_id,
            'type': 'switch',
            'dpid': f'{dpid:016x}',
            'label': f"{zone.get('label', 'External VMware')} OVS Bridge",
            'external': True,
        })
    if not any({link.get('src'), link.get('dst')} == {switch_id, distribution} for link in links):
        links.append({
            'src': distribution,
            'dst': switch_id,
            'src_intf': f'{distribution}-{switch_id}',
            'dst_intf': f'{switch_id}-{distribution}',
            'bw_mbps': float(zone.get('capacity_mbps', 1000) or 1000),
            'external': True,
        })
    for host_id, meta in hosts.items():
        if not any(n.get('id') == host_id for n in nodes):
            nodes.append({
                'id': host_id,
                'type': 'host',
                'ip': meta.get('ip', ''),
                'mac': meta.get('mac') or deterministic_mac(meta.get('ip', '')),
                'zone': meta.get('zone', zone.get('key', 'external_vm')),
                'label': meta.get('label', host_id),
                'external': True,
            })
        if not any({link.get('src'), link.get('dst')} == {host_id, switch_id} for link in links):
            links.append({
                'src': host_id,
                'dst': switch_id,
                'src_intf': f'{host_id}-eth0',
                'dst_intf': f"{switch_id}-{host_id}",
                'bw_mbps': float(meta.get('link_capacity_mbps', 100) or 100),
                'external': True,
            })


class StaticTopologyRuntime:
    mode = 'static_fallback'

    def __init__(self):
        self.net = None
        self.topology_state = {}
        self._update_topology_state()

    def _update_topology_state(self):
        self.topology_state = build_static_topology_state()
        state_file = os.environ.get('CAMPUS_TOPOLOGY_STATE_FILE', '/tmp/campus_topology_state.json')
        atomic_write_json(state_file, self.topology_state)

    def run_pingall(self):
        return {
            'ok': False,
            'mode': self.mode,
            'error': 'Mininet topology unavailable in static fallback mode',
        }


class TumbaCollegeTopo:
    """Reusable Python class that builds the Tumba College campus topology."""

    # Zone configuration
    ZONES = {
        'staff_lan':    {'vlan': 10, 'switch': 'as1', 'hosts': 6, 'prefix': 'h_staff', 'subnet': '10.10.0'},
        'server_zone':  {'vlan': 20, 'switch': 'as2', 'hosts': 4, 'prefix': 'h_srv',   'subnet': '10.20.0'},
        'it_lab':       {'vlan': 30, 'switch': 'as3', 'hosts': 4, 'prefix': 'h_lab',   'subnet': '10.30.0'},
        'student_wifi': {'vlan': 40, 'switch': 'as4', 'hosts': 10,'prefix': 'h_wifi',  'subnet': '10.40.0'},
    }

    # Server role names for server zone
    SERVER_ROLES = {1: 'mis', 2: 'dhcp', 3: 'auth', 4: 'moodle'}

    def __init__(self, controller_ip='127.0.0.1', controller_port=6653):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.net = None
        self.hosts = {}
        self.switches = {}
        self.topology_state = {}

    def build(self):
        """Build and return the Mininet network."""
        info('*** Building Tumba College topology\n')

        self.net = Mininet(
            controller=RemoteController,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=True,
        )

        # Add controller
        c0 = self.net.addController(
            'c0',
            controller=RemoteController,
            ip=self.controller_ip,
            port=self.controller_port,
            protocols='OpenFlow13',
        )

        # ─── Core Switch ───
        cs1 = self.net.addSwitch('cs1', dpid='0000000000000001', protocols='OpenFlow13')
        self.switches['cs1'] = cs1

        # ─── Distribution Switches ───
        ds1 = self.net.addSwitch('ds1', dpid='0000000000000002', protocols='OpenFlow13')
        ds2 = self.net.addSwitch('ds2', dpid='0000000000000003', protocols='OpenFlow13')
        self.switches['ds1'] = ds1
        self.switches['ds2'] = ds2

        # ─── Access Switches ───
        as1 = self.net.addSwitch('as1', dpid='0000000000000004', protocols='OpenFlow13')  # Staff LAN
        as2 = self.net.addSwitch('as2', dpid='0000000000000005', protocols='OpenFlow13')  # Server Zone
        as3 = self.net.addSwitch('as3', dpid='0000000000000006', protocols='OpenFlow13')  # IT Lab
        as4 = self.net.addSwitch('as4', dpid='0000000000000007', protocols='OpenFlow13')  # Student WiFi
        self.switches.update({'as1': as1, 'as2': as2, 'as3': as3, 'as4': as4})

        # ─── Core-to-Distribution links (1 Gbps) ───
        self.net.addLink(cs1, ds1, bw=1000, delay='1ms')
        self.net.addLink(cs1, ds2, bw=1000, delay='1ms')

        # ─── DS1-DS2 Redundant Inter-link (1 Gbps for self-healing) ───
        self.net.addLink(ds1, ds2, bw=1000, delay='1ms')

        # ─── Distribution-to-Access links (1 Gbps each) ───
        self.net.addLink(ds1, as1, bw=1000, delay='2ms')   # DS1 → Staff LAN
        self.net.addLink(ds1, as2, bw=1000, delay='2ms')   # DS1 → Server Zone
        self.net.addLink(ds2, as3, bw=1000, delay='2ms')   # DS2 → IT Lab
        self.net.addLink(ds2, as4, bw=1000, delay='2ms')   # DS2 → Student WiFi

        # ─── Add hosts per zone ───
        for zone_name, zone_cfg in self.ZONES.items():
            switch = self.switches[zone_cfg['switch']]
            for i in range(1, zone_cfg['hosts'] + 1):
                if zone_name == 'server_zone' and i in self.SERVER_ROLES:
                    host_name = f"h_{self.SERVER_ROLES[i]}"
                else:
                    host_name = f"{zone_cfg['prefix']}{i}"

                ip = f"{zone_cfg['subnet']}.{i}/24"
                host = self.net.addHost(
                    host_name,
                    ip=ip,
                    defaultRoute=f"via {zone_cfg['subnet']}.254",
                )
                self.hosts[host_name] = host
                # Host-to-access-switch link: 100 Mbps for all campus endpoints
                host_bw = 100
                self.net.addLink(host, switch, bw=host_bw, delay='1ms')

        return self.net

    def start(self):
        """Start the network."""
        if self.net is None:
            self.build()
        info('*** Starting network\n')
        self.net.start()

        # Set OpenFlow 1.3 on all switches
        for sw_name, sw in self.switches.items():
            sw.cmd(f'ovs-vsctl set Bridge {sw_name} protocols=OpenFlow13')

        info('*** Network started successfully\n')
        self._update_topology_state()
        return self.net

    def stop(self):
        """Stop the network."""
        if self.net:
            info('*** Stopping network\n')
            self.net.stop()

    def get_host(self, name):
        """Get a host by name."""
        return self.hosts.get(name)

    def get_switch(self, name):
        """Get a switch by name."""
        return self.switches.get(name)

    def get_zone_hosts(self, zone_name):
        """Get all hosts in a zone."""
        zone_cfg = self.ZONES.get(zone_name, {})
        prefix = zone_cfg.get('prefix', '')
        return [h for name, h in self.hosts.items() if name.startswith(prefix)]

    def get_zone_switch(self, zone_name):
        """Get the access switch for a zone."""
        zone_cfg = self.ZONES.get(zone_name, {})
        return self.switches.get(zone_cfg.get('switch'))

    def _update_topology_state(self):
        """Update topology state for dashboard consumption."""
        nodes = []
        links = []

        # Collect switch info
        for name, sw in self.switches.items():
            dpid = sw.dpid if hasattr(sw, 'dpid') else name
            nodes.append({
                'id': name,
                'type': 'switch',
                'dpid': str(dpid),
                'label': self._switch_label(name),
            })

        # Collect host info
        for name, host in self.hosts.items():
            ip = host.IP() if host.IP() else ''
            mac = ''
            try:
                mac = host.MAC()
            except Exception:
                pass
            zone = self._host_zone(name)
            nodes.append({
                'id': name,
                'type': 'host',
                'ip': ip,
                'mac': mac,
                'zone': zone,
                'label': self._host_label(name),
            })

        # Collect link info
        for link in self.net.links:
            i1 = link.intf1
            i2 = link.intf2
            bw = 0
            for attr in ('bw',):
                for intf in (i1, i2):
                    params = getattr(intf, 'params', {})
                    if isinstance(params, dict) and attr in params:
                        bw = params[attr]
                        break
            links.append({
                'src': i1.node.name,
                'dst': i2.node.name,
                'src_intf': i1.name,
                'dst_intf': i2.name,
                'bw_mbps': bw,
            })

        self.topology_state = {
            'ts': time.time(),
            'nodes': nodes,
            'links': links,
        }
        _append_external_vm_nodes(nodes, links)

        # Write state file for dashboard
        state_file = os.environ.get('CAMPUS_TOPOLOGY_STATE_FILE', '/tmp/campus_topology_state.json')
        try:
            atomic_write_json(state_file, self.topology_state)
        except Exception as e:
            error(f'Failed to write topology state: {e}\n')

    @staticmethod
    def _switch_label(name):
        labels = {
            'cs1': 'Core Switch',
            'ds1': 'Distribution Switch 1',
            'ds2': 'Distribution Switch 2',
            'as1': 'Staff LAN Switch',
            'as2': 'Server Zone Switch',
            'as3': 'IT Lab Switch',
            'as4': 'Student WiFi Switch',
        }
        return labels.get(name, name)

    @staticmethod
    def _host_label(name):
        labels = {
            'h_mis': 'MIS Server',
            'h_dhcp': 'DHCP Server',
            'h_auth': 'Auth Server',
            'h_moodle': 'Moodle Server',
        }
        if name in labels:
            return labels[name]
        if name.startswith('h_staff'):
            return f"Staff PC {name.split('h_staff')[1]}"
        if name.startswith('h_lab'):
            return f"Lab PC {name.split('h_lab')[1]}"
        if name.startswith('h_wifi'):
            return f"WiFi Device {name.split('h_wifi')[1]}"
        return name

    @staticmethod
    def _host_zone(name):
        if name.startswith('h_staff'):
            return 'staff_lan'
        if name.startswith('h_srv') or name.startswith('h_mis') or name.startswith('h_dhcp') or name.startswith('h_auth') or name.startswith('h_moodle'):
            return 'server_zone'
        if name.startswith('h_lab'):
            return 'it_lab'
        if name.startswith('h_wifi'):
            return 'student_wifi'
        return 'unknown'

    def run_pingall(self):
        """Run pingall and return results."""
        if not self.net:
            return {'ok': False, 'error': 'Network not started'}
        results = []
        hosts = sorted(self.net.hosts, key=lambda h: h.name)
        total_sent = 0
        total_recv = 0
        for src in hosts:
            for dst in hosts:
                if src == dst:
                    continue
                raw = src.cmd(f'ping -c1 -W1 {dst.IP()}')
                sent, recv, loss, rtt = self._parse_ping(raw)
                total_sent += sent
                total_recv += recv
                results.append({
                    'src': src.name, 'dst': dst.name,
                    'sent': sent, 'received': recv,
                    'loss_pct': loss, 'avg_rtt_ms': rtt,
                })
        overall_loss = 100.0 * (total_sent - total_recv) / max(1, total_sent)
        return {
            'ok': True,
            'ts': time.time(),
            'packet_loss_pct': round(overall_loss, 2),
            'pairs': results[:200],
        }

    @staticmethod
    def _parse_ping(raw):
        import re
        sent, recv, loss, rtt = 1, 0, 100.0, 0.0
        m = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', raw)
        if m:
            sent = int(m.group(1))
            recv = int(m.group(2))
            loss = 100.0 * (sent - recv) / max(1, sent)
        m2 = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', raw)
        if m2 and recv > 0:
            rtt = float(m2.group(1))
        return sent, recv, round(loss, 2), round(rtt, 3)


class TopologyRuntimeAPI:
    """HTTP API for dashboard to interact with live topology."""

    def __init__(self, topo, host='0.0.0.0', port=9091):
        self.topo = topo
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        handler = self._make_handler(self.topo)
        self.server = ThreadingHTTPServer((self.host, self.port), handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        info(f'*** Topology API listening on http://{self.host}:{self.port}\n')

    @staticmethod
    def _make_handler(topo):
        class Handler(BaseHTTPRequestHandler):
            _topo = topo
            def log_message(self, *args): pass

            def _send_json(self, data, code=200):
                body = json.dumps(data).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == '/health':
                    self._send_json({
                        'ok': True,
                        'service': 'topology_runtime',
                        'mode': getattr(self._topo, 'mode', 'live'),
                    })
                elif self.path in ('/topology', '/api/topology'):
                    self._topo._update_topology_state()
                    self._send_json(self._topo.topology_state)
                else:
                    self._send_json({'error': 'not found'}, 404)

            def do_POST(self):
                if self.path == '/pingall':
                    result = self._topo.run_pingall()
                    self._send_json(result)
                elif self.path == '/link_down':
                    if not getattr(self._topo, 'net', None):
                        self._send_json({'ok': False, 'error': 'Topology control unavailable in static fallback mode'}, 409)
                        return
                    body = self._read_body()
                    src = body.get('src', 'ds1')
                    dst = body.get('dst', 'cs1')
                    try:
                        link = None
                        for l in self._topo.net.links:
                            if (l.intf1.node.name == src and l.intf2.node.name == dst) or \
                               (l.intf1.node.name == dst and l.intf2.node.name == src):
                                link = l
                                break
                        if link:
                            link.intf1.ifconfig('down')
                            link.intf2.ifconfig('down')
                            self._send_json({'ok': True, 'msg': f'Link {src}-{dst} down'})
                        else:
                            self._send_json({'ok': False, 'error': f'Link {src}-{dst} not found'}, 404)
                    except Exception as e:
                        self._send_json({'ok': False, 'error': str(e)}, 500)
                elif self.path == '/link_up':
                    if not getattr(self._topo, 'net', None):
                        self._send_json({'ok': False, 'error': 'Topology control unavailable in static fallback mode'}, 409)
                        return
                    body = self._read_body()
                    src = body.get('src', 'ds1')
                    dst = body.get('dst', 'cs1')
                    try:
                        for l in self._topo.net.links:
                            if (l.intf1.node.name == src and l.intf2.node.name == dst) or \
                               (l.intf1.node.name == dst and l.intf2.node.name == src):
                                l.intf1.ifconfig('up')
                                l.intf2.ifconfig('up')
                                self._send_json({'ok': True, 'msg': f'Link {src}-{dst} up'})
                                return
                        self._send_json({'ok': False, 'error': 'Link not found'}, 404)
                    except Exception as e:
                        self._send_json({'ok': False, 'error': str(e)}, 500)
                else:
                    self._send_json({'error': 'not found'}, 404)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                self.end_headers()

            def _read_body(self):
                n = int(self.headers.get('Content-Length', 0))
                if n > 0:
                    return json.loads(self.rfile.read(n))
                return {}

        return Handler


def main():
    parser = argparse.ArgumentParser(description='Tumba College Campus SDN Topology')
    parser.add_argument('--controller-ip', default='127.0.0.1')
    parser.add_argument('--controller-port', type=int, default=6653)
    parser.add_argument('--api-port', type=int, default=9091)
    parser.add_argument('--no-cli', action='store_true')
    parser.add_argument('--api-only', action='store_true')
    args = parser.parse_args()

    setLogLevel('info')

    if args.api_only or os.geteuid() != 0:
        info('*** Starting topology API in static fallback mode (Mininet requires root)\n')
        topo = StaticTopologyRuntime()
        api = TopologyRuntimeAPI(topo, port=args.api_port)
        api.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    topo = TumbaCollegeTopo(
        controller_ip=args.controller_ip,
        controller_port=args.controller_port,
    )
    net = topo.build()
    topo.start()

    # Start runtime API
    api = TopologyRuntimeAPI(topo, port=args.api_port)
    api.start()

    if args.no_cli:
        info('*** Running in headless mode (Ctrl+C to stop)\n')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        CLI(net)

    topo.stop()


if __name__ == '__main__':
    main()
