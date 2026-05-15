import { CongestionPanel } from '../components/CongestionPanel';
import { Badge } from '../components/Badge';
import type { PageProps } from './pageTypes';

export function ProactiveCongestion({ snapshot }: PageProps) {
  const thresholds = [
    ['0-70%', 'Healthy', 'healthy'],
    ['70-85%', 'Warning', 'warning'],
    ['85-90%', 'Preventive', 'preventive'],
    ['90-100%', 'Critical', 'critical'],
    ['75.2%', 'Warning', 'warning'],
    ['86%', 'Preventive', 'preventive'],
    ['92%', 'Critical', 'critical'],
  ] as const;
  return (
    <div className="space-y-5">
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <h2 className="mb-3 text-sm font-bold text-slate-900">Threshold Model</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-7">
          {thresholds.map(([value, label, tone]) => (
            <div key={`${value}-${label}`} className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <div className="text-lg font-black text-slate-900">{value}</div>
              <Badge tone={tone}>{label}</Badge>
            </div>
          ))}
        </div>
      </section>
      <CongestionPanel proactive={snapshot.proactive} />
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <h2 className="mb-3 text-sm font-bold text-slate-900">Before / After Mitigation</h2>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {((snapshot.proactive.before_after_utilization || []) as Record<string, unknown>[]).slice(-9).map((item, index) => (
            <div key={index} className="rounded-md bg-slate-50 p-3">
              <div className="font-semibold text-slate-900">{String(item.target || item.kind || 'link')}</div>
              <div className="mt-1 text-sm text-slate-600">
                {String(item.before_utilization_percent ?? '-')}% to {String(item.after_utilization_percent ?? '-')}%
              </div>
              <div className="mt-1 text-xs text-slate-500">{String(item.action_taken || 'mitigation estimate')}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
