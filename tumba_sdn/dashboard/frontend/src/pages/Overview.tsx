import { AlertPanel } from '../components/AlertPanel';
import { LiveFlowsTable } from '../components/LiveFlowsTable';
import { MetricCard } from '../components/MetricCard';
import { StatusCard } from '../components/StatusCard';
import { Badge, statusTone } from '../components/Badge';
import type { PageProps } from './pageTypes';

export function Overview({ snapshot }: PageProps) {
  const pcs = Object.values(snapshot.pcActivities.pcs || {});
  const activePcs = pcs.filter((pc) => pc.activity && pc.activity !== 'idle');
  const zones = snapshot.metrics.zone_metrics || {};
  const totalTraffic = Object.values(zones).reduce((sum, zone) => sum + Number(zone.throughput_mbps || 0), 0);
  const hosts = pcs.length || Number((snapshot.topology.hosts as unknown[])?.length || 0);
  const switches = snapshot.health.switches || Number((snapshot.metrics.switches as unknown[])?.length || (snapshot.metrics.connected_switches as unknown[])?.length || 0);
  const services = snapshot.health.services || {};
  const congestion = snapshot.proactive.summary || {};
  const mlAction = String(snapshot.mlAction.action || 'normal_mode');
  const marlAction = String(snapshot.marlSecurity.action || snapshot.marlSecurity.controller_action || 'monitor');
  const exam = Boolean(snapshot.timetable.exam_flag || snapshot.mlAction.exam_flag);

  return (
    <div className="space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="System Health" value={snapshot.health.ok ? 'Online' : 'Offline'} detail={`${Object.values(services).filter((s) => s.online).length}/${Object.keys(services).length} services online`} tone={snapshot.health.ok ? 'green' : 'red'} />
        <MetricCard label="Switches" value={switches} detail="OpenFlow control plane" tone="blue" />
        <MetricCard label="Hosts" value={hosts} detail={`${activePcs.length} active endpoints`} tone="slate" />
        <MetricCard label="Total Traffic" value={`${totalTraffic.toFixed(1)} Mbps`} detail="zone throughput aggregate" tone={totalTraffic > 850 ? 'red' : totalTraffic > 700 ? 'orange' : 'green'} />
        <MetricCard label="Alerts" value={snapshot.alerts.count || snapshot.alerts.alerts?.length || 0} detail="dashboard + proactive alerts" tone={(snapshot.alerts.count || 0) ? 'yellow' : 'green'} />
        <MetricCard label="Congestion" value={`${congestion.preventive_links || 0}/${congestion.critical_links || 0}`} detail="preventive / critical links" tone={(congestion.critical_links || 0) ? 'red' : (congestion.preventive_links || 0) ? 'orange' : 'green'} />
        <MetricCard label="Security" value={String(snapshot.security.security_blocked || 0)} detail="blocked or isolated flows" tone={Number(snapshot.security.security_blocked || 0) ? 'red' : 'green'} />
        <MetricCard label="Exam Mode" value={exam ? 'Active' : 'Idle'} detail="critical DSCP 46 protection" tone={exam ? 'purple' : 'slate'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900">Controller Intelligence</h2>
            <Badge tone="ai">Live state</Badge>
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-md bg-slate-50 p-3">
              <div className="text-xs font-semibold uppercase text-slate-500">ML/DQN Action</div>
              <div className="mt-1 font-bold text-slate-900">{mlAction}</div>
              <div className="mt-1 text-xs text-slate-500">reward {String(snapshot.mlAction.reward ?? '-')}</div>
            </div>
            <div className="rounded-md bg-slate-50 p-3">
              <div className="text-xs font-semibold uppercase text-slate-500">MARL Security</div>
              <div className="mt-1 font-bold text-slate-900">{marlAction}</div>
              <div className="mt-1 text-xs text-slate-500">{String(snapshot.marlSecurity.threat_level || 'normal')}</div>
            </div>
            <div className="rounded-md bg-slate-50 p-3">
              <div className="text-xs font-semibold uppercase text-slate-500">IBN Status</div>
              <div className="mt-1 font-bold text-slate-900">{((snapshot.ibn.active_intents || []) as unknown[]).length} active intents</div>
              <div className="mt-1 text-xs text-slate-500">{String(snapshot.ibn.total_submitted || 0)} submitted</div>
            </div>
          </div>
          <div className="mt-3 rounded-md border border-slate-200 p-3 text-sm">
            Latest controller action: <Badge tone={statusTone(mlAction)}>{mlAction}</Badge>
          </div>
        </section>
        <div className="space-y-2">
          {Object.entries(services).slice(0, 7).map(([name, service]) => (
            <StatusCard key={name} name={name.replaceAll('_', ' ')} status={Boolean(service.online)} detail={String(service.error || service.url || '')} />
          ))}
        </div>
      </div>

      <AlertPanel alerts={snapshot.alerts.alerts || snapshot.proactive.recent_alerts || []} />
      <LiveFlowsTable flows={snapshot.flows.flows || []} />
    </div>
  );
}
