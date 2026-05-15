import { RefreshCcw } from 'lucide-react';
import type { DashboardSnapshot } from '../api/types';
import { Badge } from './Badge';

type HeaderProps = {
  snapshot: DashboardSnapshot;
  onRefresh: () => void;
};

function epochSeconds(value: unknown) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) return 0;
  return numeric > 1_000_000_000_000 ? numeric / 1000 : numeric;
}

export function Header({ snapshot, onRefresh }: HeaderProps) {
  const services = snapshot.health.services || {};
  const online = Object.values(services).filter((service) => service.online).length;
  const total = Object.keys(services).length;
  const mlAction = String(snapshot.mlAction.action || snapshot.metrics.ml_action || 'normal_mode');
  const freshestTs = Math.max(
    epochSeconds(snapshot.health.ts),
    epochSeconds(snapshot.metrics.ts),
    epochSeconds(snapshot.pcActivities.ts),
    epochSeconds(snapshot.proactive.ts),
    epochSeconds(snapshot.mlAction.ts),
    epochSeconds(snapshot.timetable.ts),
  );
  const ageSeconds = freshestTs ? Math.max(0, Math.round(Date.now() / 1000 - freshestTs)) : 999;
  const stale = ageSeconds > 5;
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/95 px-4 py-3 backdrop-blur lg:ml-64">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase text-slate-500">Current dashboard</div>
          <h1 className="text-xl font-black text-slate-950">Professional React + TypeScript SDN Console</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={snapshot.health.ok ? 'healthy' : 'critical'}>{snapshot.health.ok ? 'Backend online' : 'Backend offline'}</Badge>
          <Badge tone={online === total ? 'healthy' : 'warning'}>{online}/{total} services</Badge>
          <Badge tone={stale ? 'warning' : 'healthy'}>{stale ? `stale ${ageSeconds}s` : 'live data'}</Badge>
          <Badge tone="ai">{mlAction}</Badge>
          <button onClick={onRefresh} className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50">
            <RefreshCcw size={15} /> Refresh
          </button>
        </div>
      </div>
    </header>
  );
}
