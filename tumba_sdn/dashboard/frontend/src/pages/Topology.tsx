import { useState } from 'react';
import { PcControlPanel } from '../components/PcControlPanel';
import { TopologyGraph } from '../components/TopologyGraph';
import { Badge } from '../components/Badge';
import type { PageProps } from './pageTypes';

function eventTime(event: Record<string, unknown>) {
  const ts = Number(event.ts || event.timestamp || 0);
  if (!Number.isFinite(ts) || ts <= 0) return 'live';
  return new Date((ts > 1_000_000_000_000 ? ts : ts * 1000)).toLocaleTimeString();
}

function recentControllerDecisions(snapshot: PageProps['snapshot']) {
  const events = ((snapshot.metrics.events as Record<string, unknown>[] | undefined) || [])
    .slice(-8)
    .map((event) => ({
      timestamp: eventTime(event),
      device: event.host || event.dpid || event.zone || event.src_ip || 'controller',
      reason: String(event.event || 'controller event').replaceAll('_', ' '),
      action: event.action_taken || event.note || snapshot.mlAction.action || 'Monitoring network',
      status: event.status || 'Recorded',
    }));
  const priority = ((snapshot.metrics.traffic_priority_decisions as Record<string, unknown>[] | undefined) || [])
    .filter((item) => String(item.action_taken || '') !== 'Monitoring only')
    .slice(-6)
    .map((item) => ({
      timestamp: 'live',
      device: item.label || item.host || item.ip || 'flow',
      reason: `${item.activity || 'traffic'} ${item.state || ''}`.trim(),
      action: item.action_taken || 'QoS decision',
      status: item.current_status || 'Applied',
    }));
  const alerts = (snapshot.proactive.recent_alerts || [])
    .slice(-4)
    .map((alert) => ({
      timestamp: eventTime(alert as Record<string, unknown>),
      device: alert.device || alert.title || 'link',
      reason: alert.detail || alert.severity || 'proactive alert',
      action: alert.action_taken || 'Controller monitoring',
      status: alert.severity || 'Alert',
    }));
  return [...priority, ...alerts, ...events].slice(0, 10);
}

export function Topology({ snapshot, refresh }: PageProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const pcs = snapshot.pcActivities.pcs || {};
  const pc = selected ? pcs[selected] : undefined;
  const summary = snapshot.proactive.summary || {};
  const decisions = recentControllerDecisions(snapshot);
  const managedPcCount = Object.keys(pcs).length;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-black text-slate-950">Interactive Campus Topology</h2>
          <p className="text-sm text-slate-600">Core, distribution, access switches, {managedPcCount} managed PCs, server hosts, utilization labels, congestion colors, and PC control modal.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge tone="healthy">Green healthy</Badge>
          <Badge tone="warning">Yellow warning</Badge>
          <Badge tone="preventive">Orange preventive</Badge>
          <Badge tone="critical">Red critical</Badge>
          <Badge tone="isolated">Purple security</Badge>
          <Badge tone="info">{summary.warning_links || 0} warning links</Badge>
        </div>
      </div>
      <TopologyGraph
        pcActivities={snapshot.pcActivities}
        proactive={snapshot.proactive}
        metrics={snapshot.metrics}
        mlAction={snapshot.mlAction}
        timetable={snapshot.timetable}
        onSelectPc={setSelected}
      />
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-bold text-slate-900">Live Controller Decisions</h3>
          <Badge tone="ai">{decisions.length} recent actions</Badge>
        </div>
        <div className="grid gap-2 lg:grid-cols-2">
          {decisions.length ? decisions.map((decision, index) => (
            <div key={`${decision.timestamp}-${decision.device}-${index}`} className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-semibold uppercase text-slate-500">{decision.timestamp} · {String(decision.device)}</div>
                <Badge tone={String(decision.status).toLowerCase()}>{String(decision.status)}</Badge>
              </div>
              <div className="mt-1 text-sm font-semibold text-slate-900">{String(decision.action)}</div>
              <div className="mt-1 text-xs text-slate-600">{String(decision.reason)}</div>
            </div>
          )) : (
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">No controller decisions reported yet. Trigger a scenario or PC activity to populate this panel.</div>
          )}
        </div>
      </section>
      <PcControlPanel host={selected} pc={pc} onClose={() => setSelected(null)} onChanged={refresh} />
    </div>
  );
}
