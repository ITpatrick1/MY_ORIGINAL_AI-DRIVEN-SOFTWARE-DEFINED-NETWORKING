import { SecurityPanel } from '../components/SecurityPanel';
import { MetricCard } from '../components/MetricCard';
import { Badge, statusTone } from '../components/Badge';
import type { PageProps } from './pageTypes';

export function Security({ snapshot }: PageProps) {
  const threats = snapshot.threats.threats || [];
  const marl = snapshot.marlSecurity;
  const blocked = Number(snapshot.security.security_blocked || 0);
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Active Threats" value={threats.length} detail="port scan, DDoS, spoofing, unauthorized access" tone={threats.length ? 'red' : 'green'} />
        <MetricCard label="Blocked Flows" value={blocked} detail="controller security counter" tone={blocked ? 'red' : 'green'} />
        <MetricCard label="MARL Action" value={String(marl.action || 'monitor')} detail={String(marl.threat_level || 'normal')} tone="purple" />
        <MetricCard label="Controller Action" value={String(marl.controller_action || 'monitor')} detail="OpenFlow enforcement" tone="blue" />
      </div>
      <SecurityPanel security={snapshot.security} threats={threats} marl={marl} />
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <h2 className="mb-3 text-sm font-bold text-slate-900">Blocked / Isolated Devices</h2>
        <div className="flex flex-wrap gap-2">
          {((snapshot.security.blocked_ips || []) as unknown[]).length ? ((snapshot.security.blocked_ips || []) as unknown[]).map((ip) => (
            <Badge key={String(ip)} tone="blocked">{String(ip)}</Badge>
          )) : <Badge tone="healthy">No blocked devices</Badge>}
          <Badge tone={statusTone(snapshot.security.ddos_active ? 'critical' : 'normal')}>DDoS {snapshot.security.ddos_active ? 'active' : 'inactive'}</Badge>
          <Badge tone={statusTone(((snapshot.security.active_scans || []) as unknown[]).length ? 'warning' : 'normal')}>Scans {((snapshot.security.active_scans || []) as unknown[]).length}</Badge>
        </div>
      </section>
    </div>
  );
}
