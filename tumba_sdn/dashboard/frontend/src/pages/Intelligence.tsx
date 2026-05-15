import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import { MetricCard } from '../components/MetricCard';
import { Badge } from '../components/Badge';
import type { PageProps } from './pageTypes';

export function Intelligence({ snapshot }: PageProps) {
  const [intel, setIntel] = useState<Record<string, unknown>>({});
  useEffect(() => {
    void getJson<Record<string, unknown>>('/api/intelligence', {}).then(setIntel);
  }, [snapshot.mlAction.ts]);
  const ml = (intel.ml_action || snapshot.mlAction) as Record<string, unknown>;
  const qValues = (ml.q_values || []) as number[];
  const topFeatures = (((ml.xai as Record<string, unknown> | undefined)?.top_features || []) as Record<string, unknown>[]);
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="DQN Action" value={String(ml.action || 'normal_mode')} detail={`index ${String(ml.action_index ?? '-')}`} tone="purple" />
        <MetricCard label="Reward" value={String(ml.reward ?? '-')} detail="latest control reward" tone="blue" />
        <MetricCard label="Exam Context" value={String(intel.exam_mode || ml.exam_flag ? 'Active' : 'Idle')} detail="safety rail input" tone={intel.exam_mode || ml.exam_flag ? 'purple' : 'slate'} />
        <MetricCard label="Final Action" value={String(intel.final_controller_action || ml.action || 'normal_mode')} detail={String(intel.safety_rail_decision || '')} tone="green" />
      </div>
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-900">Q-values and Explainability</h2>
          <Badge tone="ai">DQN / MARL</Badge>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            {qValues.length ? qValues.map((value, index) => (
              <div key={index}>
                <div className="mb-1 flex justify-between text-xs text-slate-600">
                  <span>Action {index}</span><span>{Number(value).toFixed(3)}</span>
                </div>
                <div className="h-2 rounded bg-slate-100">
                  <div className="h-2 rounded bg-sky-600" style={{ width: `${Math.max(4, Math.min(100, (Number(value) + 1) * 50))}%` }} />
                </div>
              </div>
            )) : <div className="text-sm text-slate-500">No q-values reported yet.</div>}
          </div>
          <div className="rounded-md bg-slate-50 p-3">
            <div className="mb-2 text-xs font-semibold uppercase text-slate-500">Top input features</div>
            {topFeatures.length ? topFeatures.map((feature, index) => (
              <div key={index} className="mb-2 rounded-md border border-slate-200 bg-white p-2 text-sm">
                <div className="font-semibold text-slate-900">{String(feature.feature)}</div>
                <div className="text-xs text-slate-500">value {String(feature.value)} · impact {String(feature.impact)}</div>
              </div>
            )) : <div className="text-sm text-slate-500">Explainability values are not available yet.</div>}
          </div>
        </div>
      </section>
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <h2 className="mb-3 text-sm font-bold text-slate-900">MARL Security Summary</h2>
        <pre className="max-h-72 overflow-auto rounded-md bg-slate-950 p-3 text-xs text-slate-100">{JSON.stringify(snapshot.marlSecurity, null, 2)}</pre>
      </section>
    </div>
  );
}
