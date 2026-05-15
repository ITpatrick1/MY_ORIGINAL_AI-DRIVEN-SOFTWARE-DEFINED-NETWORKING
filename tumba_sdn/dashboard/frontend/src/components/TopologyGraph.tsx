import type { AlertItem, Metrics, PcActivities, PcInfo, ProactiveState } from '../api/types';

type TopologyGraphProps = {
  pcActivities?: PcActivities;
  proactive?: ProactiveState;
  metrics?: Metrics;
  mlAction?: Record<string, unknown>;
  timetable?: Record<string, unknown>;
  onSelectPc?: (host: string) => void;
};

type NodeDef = {
  id: string;
  label: string;
  x: number;
  y: number;
  type: 'controller' | 'core' | 'distribution' | 'access' | 'host' | 'server';
  host?: string;
  pc?: PcInfo;
};

type LinkDef = {
  source: string;
  target: string;
};

const serverNodes: Record<string, PcInfo> = {
  h_mis: { label: 'MIS', ip: '10.20.0.1', zone_label: 'Server Zone', switch: 'as2', link_capacity_mbps: 100 },
  h_dhcp: { label: 'DHCP', ip: '10.20.0.2', zone_label: 'Server Zone', switch: 'as2', link_capacity_mbps: 100 },
  h_auth: { label: 'Auth', ip: '10.20.0.3', zone_label: 'Server Zone', switch: 'as2', link_capacity_mbps: 100 },
  h_moodle: { label: 'Moodle', ip: '10.20.0.4', zone_label: 'Server Zone', switch: 'as2', link_capacity_mbps: 100 },
};

function stateColor(state?: unknown) {
  const text = String(state || '').toLowerCase();
  if (text.includes('threat') || text.includes('block') || text.includes('isolat')) return '#c084fc';
  if (text.includes('critical') || text.includes('fail') || text.includes('down')) return '#f87171';
  if (text.includes('prevent') || text.includes('throttle') || text.includes('rate')) return '#fb923c';
  if (text.includes('warning') || text.includes('suspicious')) return '#facc15';
  if (text.includes('protect') || text.includes('high') || text.includes('exam')) return '#38bdf8';
  return '#22c55e';
}

function nodeFill(type: NodeDef['type']) {
  return {
    controller: '#0c4a6e',
    core: '#12345a',
    distribution: '#16213f',
    access: '#102f30',
    host: '#111f35',
    server: '#172554',
  }[type];
}

function nodeSize(type: NodeDef['type']) {
  if (type === 'controller') return { width: 186, height: 66 };
  if (type === 'host') return { width: 118, height: 56 };
  if (type === 'server') return { width: 116, height: 52 };
  return { width: 132, height: 58 };
}

function linkState(link?: Record<string, unknown>, pc?: PcInfo) {
  const security = String(pc?.security_state || '').toLowerCase();
  if (security && security !== 'normal') return security;
  return link?.threshold_state || link?.congestion_state || pc?.congestion_state || 'healthy';
}

function linkStats(link?: Record<string, unknown>, pc?: PcInfo, fallbackCapacity = 100) {
  const current = Number(link?.current_mbps ?? pc?.current_mbps ?? pc?.traffic_mbps ?? 0);
  const capacity = Number(link?.capacity_mbps ?? pc?.link_capacity_mbps ?? fallbackCapacity);
  const util = Number(link?.utilization_percent ?? pc?.utilization_percent ?? (capacity ? (current / capacity) * 100 : 0));
  return { current, capacity, util };
}

function linkLabel(link?: Record<string, unknown>, pc?: PcInfo, fallbackCapacity = 100) {
  const { current, capacity, util } = linkStats(link, pc, fallbackCapacity);
  return `${current.toFixed(0)} / ${capacity.toFixed(0)} Mbps (${util.toFixed(0)}%)`;
}

function truncate(text: unknown, max = 24) {
  const value = String(text || '-');
  return value.length > max ? `${value.slice(0, max - 1)}...` : value;
}

function findLink(linkIndex: Record<string, Record<string, unknown>>, a: string, b: string) {
  return linkIndex[`${a}-${b}`] || linkIndex[`${b}-${a}`];
}

function switchLinkId(id: string) {
  const accessDist: Record<string, string> = { as1: 'ds1', as2: 'ds1', as3: 'ds2', as4: 'ds2', ovs_ext: 'ds2' };
  if (accessDist[id]) return [id, accessDist[id]];
  if (id === 'ds1' || id === 'ds2') return [id, 'cs1'];
  return null;
}

function controllerLines(metrics?: Metrics, mlAction?: Record<string, unknown>, timetable?: Record<string, unknown>) {
  const decisions = (metrics?.traffic_priority_decisions as Record<string, unknown>[] | undefined) || [];
  const latestDecision = [...decisions].reverse().find((item) => String(item.action_taken || '') !== 'Monitoring only');
  const events = (metrics?.events as Record<string, unknown>[] | undefined) || [];
  const latestEvent = events.length ? events[events.length - 1] : {};
  const exam = Boolean(timetable?.exam_flag || metrics?.exam_mode);
  const securityBlocked = Number(metrics?.security_blocked || 0);
  const action = String(mlAction?.action || metrics?.ml_action || 'normal_mode');

  if (securityBlocked > 0) {
    return ['Status: Enforcing Zero-Trust', `Action: ${securityBlocked} blocked`];
  }
  if (exam) {
    return ['Status: Applying exam QoS', 'Action: DSCP 46 protected'];
  }
  if (latestDecision) {
    return ['Status: Applying QoS', `Action: ${truncate(latestDecision.action_taken, 25)}`];
  }
  if (action && action !== 'normal_mode') {
    return ['Status: ML decision active', `Action: ${truncate(action, 26)}`];
  }
  if (latestEvent.event) {
    return ['Status: Monitoring network', `Event: ${truncate(String(latestEvent.event).replaceAll('_', ' '), 26)}`];
  }
  return ['Status: Monitoring network', 'Action: baseline path'];
}

function nodeLines(
  node: NodeDef,
  linkIndex: Record<string, Record<string, unknown>>,
  proactive?: ProactiveState,
  metrics?: Metrics,
  mlAction?: Record<string, unknown>,
  timetable?: Record<string, unknown>,
) {
  if (node.type === 'controller') return controllerLines(metrics, mlAction, timetable);
  if (node.pc) {
    const activity = node.pc.activity_label || node.pc.activity || (node.type === 'server' ? 'Server service' : 'Idle');
    const priority = node.pc.priority_level || node.pc.priority_label || 'BEST-EFFORT';
    const action = node.pc.controller_action || node.pc.current_status || node.pc.security_state || 'Monitoring';
    return [truncate(activity, 22), truncate(`${priority} · ${action}`, 28)];
  }

  const pair = switchLinkId(node.id);
  const liveLink = pair
    ? findLink(linkIndex, pair[0], pair[1])
    : proactive?.core_links?.cs1_total;
  const { current, capacity, util } = linkStats(liveLink, undefined, node.id === 'cs1' ? 1000 : 1000);
  const state = liveLink?.threshold_state || liveLink?.congestion_state || (util >= 90 ? 'critical' : util >= 85 ? 'preventive' : util >= 70 ? 'warning' : 'healthy');
  return [`Traffic: ${current.toFixed(0)} / ${capacity.toFixed(0)} Mbps`, `State: ${String(state).replace('_', ' ')}`];
}

export function TopologyGraph({ pcActivities, proactive, metrics, mlAction, timetable, onSelectPc }: TopologyGraphProps) {
  const pcs = pcActivities?.pcs || {};
  const linkIndex = proactive?.link_index || {};
  const hasExternal = Object.values(pcs).some((pc) => pc.switch === 'ovs_ext');
  const nodes: NodeDef[] = [
    { id: 'controller', label: 'SDN Controller', x: 750, y: 44, type: 'controller' },
    { id: 'cs1', label: 'cs1 Core', x: 750, y: 130, type: 'core' },
    { id: 'ds1', label: 'ds1 Distribution', x: 520, y: 235, type: 'distribution' },
    { id: 'ds2', label: 'ds2 Distribution', x: 980, y: 235, type: 'distribution' },
    { id: 'as1', label: 'as1 Staff', x: 220, y: 360, type: 'access' },
    { id: 'as2', label: 'as2 Servers', x: 560, y: 360, type: 'access' },
    { id: 'as3', label: 'as3 Lab', x: 920, y: 360, type: 'access' },
    { id: 'as4', label: 'as4 WiFi', x: 1270, y: 360, type: 'access' },
  ];
  if (hasExternal) {
    nodes.push({ id: 'ovs_ext', label: 'External VM Edge', x: 1415, y: 360, type: 'access' });
  }

  const hostEntries: [string, PcInfo][] = [
    ...Object.entries(pcs),
    ...Object.entries(serverNodes),
  ];
  hostEntries.forEach(([host, pc]) => {
    const sw = pc.switch || (host.startsWith('h_mis') || host.startsWith('h_dhcp') || host.startsWith('h_auth') || host.startsWith('h_moodle') ? 'as2' : 'as4');
    const baseBySwitch: Record<string, [number, number]> = {
      as1: [95, 470],
      as2: [420, 470],
      as3: [785, 470],
      as4: [1105, 470],
      ovs_ext: [1370, 470],
    };
    const colsBySwitch: Record<string, number> = { as1: 3, as2: 4, as3: 4, as4: 4, ovs_ext: 2 };
    const base = baseBySwitch[sw] || [1100, 420];
    const siblings = hostEntries.filter(([, item]) => (item.switch || 'as4') === sw);
    const index = siblings.findIndex(([id]) => id === host);
    const columns = colsBySwitch[sw] || 4;
    const col = index % columns;
    const row = Math.floor(index / columns);
    nodes.push({
      id: host,
      host,
      pc,
      label: pc.label || host,
      x: base[0] + col * 96,
      y: base[1] + row * 68,
      type: host in serverNodes ? 'server' : 'host',
    });
  });

  const links: LinkDef[] = [
    { source: 'controller', target: 'cs1' },
    { source: 'cs1', target: 'ds1' },
    { source: 'cs1', target: 'ds2' },
    { source: 'ds1', target: 'ds2' },
    { source: 'ds1', target: 'as1' },
    { source: 'ds1', target: 'as2' },
    { source: 'ds2', target: 'as3' },
    { source: 'ds2', target: 'as4' },
    ...(hasExternal ? [{ source: 'ds2', target: 'ovs_ext' }] : []),
    ...hostEntries.map(([host, pc]) => ({ source: pc.switch || 'as4', target: host })),
  ];
  const nodeMap = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const alerts = ((proactive?.recent_alerts || proactive?.alerts || []) as AlertItem[]).slice(-4).reverse();

  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-panel">
      <svg viewBox="0 0 1500 780" role="img" className="h-[720px] w-full max-w-full">
        <style>
          {`
            @keyframes topologyFlow { to { stroke-dashoffset: -42; } }
            @keyframes topologyPulse { 0%, 100% { opacity: .64; } 50% { opacity: 1; } }
            .traffic-flow { stroke-dasharray: 9 12; animation: topologyFlow 1.2s linear infinite; }
            .threat-flow { animation: topologyPulse .85s ease-in-out infinite; }
          `}
        </style>
        <rect x="0" y="0" width="1500" height="780" rx="10" fill="#081322" />
        <path d="M0 92H1500M0 184H1500M0 276H1500M0 368H1500M0 460H1500M0 552H1500M0 644H1500M120 0V780M300 0V780M480 0V780M660 0V780M840 0V780M1020 0V780M1200 0V780M1380 0V780" stroke="#1e334f" strokeWidth="1" opacity="0.48" />
        {links.map((edge) => {
          const source = nodeMap[edge.source];
          const target = nodeMap[edge.target];
          if (!source || !target) return null;
          const link = source.id === 'controller' && target.id === 'cs1'
            ? proactive?.core_links?.cs1_total
            : findLink(linkIndex, source.id, target.id);
          const pc = target.pc || source.pc;
          const state = linkState(link, pc);
          const color = stateColor(state);
          const { current, util } = linkStats(link, pc, edge.source === 'ds1' && edge.target === 'ds2' ? 1000 : 100);
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;
          const active = current > 0.05 || String(state).toLowerCase() !== 'healthy';
          const strokeWidth = Math.max(2.5, Math.min(8, 2.5 + util / 18));
          const threat = ['threat', 'block', 'critical', 'isolat'].some((term) => String(state).toLowerCase().includes(term));
          return (
            <g key={`${edge.source}-${edge.target}`}>
              <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" opacity="0.34" />
              {active ? (
                <line
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={color}
                  strokeWidth={Math.max(2, strokeWidth - 0.5)}
                  strokeLinecap="round"
                  className={`traffic-flow ${threat ? 'threat-flow' : ''}`}
                />
              ) : null}
              <rect x={midX - 76} y={midY - 24} width="152" height="22" rx="6" fill="#0b1220" stroke="#263a56" opacity="0.94" />
              <text x={midX} y={midY - 9} textAnchor="middle" fontSize="10" fontWeight="800" fill={color}>
                {linkLabel(link, pc, edge.source === 'ds1' && edge.target === 'ds2' ? 1000 : 100)}
              </text>
            </g>
          );
        })}
        {nodes.map((node) => {
          const isHost = node.type === 'host';
          const pc = node.pc;
          const state = String(pc?.security_state || pc?.congestion_state || 'healthy');
          const switchPair = switchLinkId(node.id);
          const switchLink = switchPair ? findLink(linkIndex, switchPair[0], switchPair[1]) : undefined;
          const stroke = isHost || node.type === 'server' ? stateColor(state) : stateColor(switchLink?.threshold_state || switchLink?.congestion_state || 'healthy');
          const { width, height } = nodeSize(node.type);
          const lines = nodeLines(node, linkIndex, proactive, metrics, mlAction, timetable);
          return (
            <g key={node.id} transform={`translate(${node.x}, ${node.y})`} onClick={() => isHost && node.host ? onSelectPc?.(node.host) : undefined} className={isHost ? 'cursor-pointer' : ''}>
              <title>{`${node.label} · ${lines.join(' · ')}`}</title>
              <rect x={-width / 2} y={-height / 2} width={width} height={height} rx="8" fill={nodeFill(node.type)} stroke={stroke} strokeWidth={2.2} />
              <text y={node.type === 'controller' ? -14 : -12} textAnchor="middle" fontSize={node.type === 'controller' ? '13' : '11'} fontWeight="900" fill="#f8fafc">{truncate(node.label, node.type === 'controller' ? 24 : 18)}</text>
              <text y={node.type === 'controller' ? 4 : 4} textAnchor="middle" fontSize="9.5" fontWeight="700" fill="#cbd5e1">{truncate(lines[0], node.type === 'host' ? 22 : 30)}</text>
              <text y={node.type === 'controller' ? 20 : 19} textAnchor="middle" fontSize="8.5" fill="#9fb2ca">{truncate(lines[1] || pc?.ip || node.type, node.type === 'host' ? 25 : 32)}</text>
            </g>
          );
        })}
        {alerts.length ? (
          <g transform="translate(1075 26)">
            <rect x="0" y="0" width="400" height={22 + alerts.length * 34} rx="10" fill="#0b1220" stroke="#334155" opacity="0.96" />
            <text x="14" y="22" fontSize="12" fontWeight="900" fill="#e5edf8">Live topology alerts</text>
            {alerts.map((alert, index) => {
              const severity = alert.severity || (alert as Record<string, unknown>).risk_level || 'info';
              const color = stateColor(severity);
              return (
                <g key={`${alert.title || alert.device}-${index}`} transform={`translate(14 ${42 + index * 32})`}>
                  <circle cx="0" cy="-4" r="4" fill={color} />
                  <text x="12" y="-7" fontSize="10" fontWeight="900" fill={color}>{String(severity).toUpperCase()}</text>
                  <text x="12" y="7" fontSize="10" fill="#cbd5e1">{truncate(alert.device || alert.title || alert.detail, 54)}</text>
                </g>
              );
            })}
          </g>
        ) : null}
      </svg>
    </div>
  );
}
