import { useState } from 'react';
import { Play, RotateCcw } from 'lucide-react';
import { postJson, runScenario } from '../api/client';
import { LiveFlowsTable } from '../components/LiveFlowsTable';
import { Badge } from '../components/Badge';
import type { PageProps } from './pageTypes';

const scenarios = [
  ['normal_traffic', 'Normal Traffic'],
  ['elearning_priority', 'E-learning Priority'],
  ['streaming_throttle', 'Streaming Throttle'],
  ['warning_wifi', 'WiFi Warning'],
  ['preventive_wifi', 'WiFi Preventive'],
  ['critical_port', 'Critical Port'],
  ['security_test', 'Security Test'],
  ['exam_mode', 'Exam Mode'],
];

export function ControlCenter({ snapshot, refresh }: PageProps) {
  const [message, setMessage] = useState('');

  async function trigger(name: string) {
    const result = await runScenario(name);
    setMessage(String(result.message || result.error || (result.ok ? 'Scenario applied' : 'Scenario failed')));
    refresh();
  }

  async function reset() {
    const result = await postJson<Record<string, unknown>>('/api/reset_activities', {}, { ok: false });
    setMessage(String(result.ok ? 'Activities reset' : result.error || 'Reset failed'));
    refresh();
  }

  return (
    <div className="space-y-5">
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-900">Scenario Control</h2>
          {message ? <Badge tone="info">{message}</Badge> : null}
        </div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {scenarios.map(([id, label]) => (
            <button key={id} onClick={() => void trigger(id)} className="inline-flex items-center justify-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-3 text-sm font-semibold text-slate-800 hover:border-sky-300 hover:bg-sky-50">
              <Play size={15} /> {label}
            </button>
          ))}
          <button onClick={() => void reset()} className="inline-flex items-center justify-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-3 text-sm font-semibold text-red-700 hover:bg-red-100">
            <RotateCcw size={15} /> Stop / Reset
          </button>
        </div>
      </section>
      <LiveFlowsTable flows={snapshot.flows.flows || []} />
    </div>
  );
}
