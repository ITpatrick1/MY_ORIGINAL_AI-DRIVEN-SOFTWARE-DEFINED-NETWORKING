import { Badge, statusTone } from './Badge';

type SecurityPanelProps = {
  security?: Record<string, unknown>;
  threats?: Record<string, unknown>[];
  marl?: Record<string, unknown>;
};

export function SecurityPanel({ security = {}, threats = [], marl = {} }: SecurityPanelProps) {
  const events = (security.security_events || security.events || []) as Record<string, unknown>[];
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold text-slate-900">Security Operations</h2>
        <Badge tone={threats.length ? 'critical' : 'healthy'}>{threats.length ? `${threats.length} active` : 'Normal'}</Badge>
      </div>
      <div className="grid gap-3 p-4 md:grid-cols-3">
        <div className="rounded-md bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase text-slate-500">Blocked Flows</div>
          <div className="mt-1 text-2xl font-bold text-slate-900">{String(security.security_blocked || 0)}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase text-slate-500">MARL Decision</div>
          <div className="mt-1 font-semibold text-slate-900">{String(marl.action || marl.controller_action || 'monitor')}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase text-slate-500">Controller Action</div>
          <div className="mt-1 font-semibold text-slate-900">{String(marl.controller_action || security.action || 'monitor')}</div>
        </div>
      </div>
      <div className="overflow-x-auto border-t border-slate-200">
        <table className="table-tight min-w-full text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-600">
            <tr>
              <th>Attack Type</th>
              <th>Attacker</th>
              <th>Target</th>
              <th>Evidence</th>
              <th>Risk</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {threats.length ? threats.map((threat, index) => (
              <tr key={`${String(threat.type)}-${index}`} className="border-t border-slate-100">
                <td className="font-semibold text-slate-900">{String(threat.type || threat.title || 'threat')}</td>
                <td>{String(threat.src_ip || threat.attacker_ip || '-')}</td>
                <td>{String(threat.target_ip || threat.zone || '-')}</td>
                <td className="max-w-[24rem] truncate">{String(threat.detail || threat.evidence || '-')}</td>
                <td><Badge tone={statusTone(threat.severity)}>{String(threat.severity || 'HIGH')}</Badge></td>
                <td><Badge tone={threat.blocked ? 'blocked' : 'warning'}>{threat.blocked ? 'Blocked' : 'Detected'}</Badge></td>
              </tr>
            )) : events.slice(-6).map((event, index) => (
              <tr key={`${String(event.event)}-${index}`} className="border-t border-slate-100">
                <td className="font-semibold text-slate-900">{String(event.event || event.type || 'security_event')}</td>
                <td>{String(event.src_ip || event.ip || '-')}</td>
                <td>{String(event.target || event.target_ip || '-')}</td>
                <td className="max-w-[24rem] truncate">{String(event.evidence || event.action_taken || '-')}</td>
                <td><Badge tone={statusTone(event.risk_level)}>{String(event.risk_level || 'info')}</Badge></td>
                <td><Badge tone={statusTone(event.status)}>{String(event.status || 'Logged')}</Badge></td>
              </tr>
            ))}
            {!threats.length && !events.length ? (
              <tr><td colSpan={6} className="py-8 text-center text-slate-500">No security events reported.</td></tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </section>
  );
}
