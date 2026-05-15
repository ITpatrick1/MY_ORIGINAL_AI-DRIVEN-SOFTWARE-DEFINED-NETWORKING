import { useState } from 'react';
import { Send } from 'lucide-react';
import { submitIntent } from '../api/client';
import { Badge, statusTone } from './Badge';

const intents = [
  'prioritize E-learning',
  'protect exam traffic',
  'block WiFi to Staff',
  'reduce streaming during congestion',
  'prioritize Google Meet',
  'protect MIS/SIAD/Admin',
  'throttle social media',
  'throttle gaming',
  'allow Lab to E-learning',
  'reset/clear intent',
];

type IntentFormProps = {
  ibn?: Record<string, unknown>;
  onChanged?: () => void;
};

export function IntentForm({ ibn = {}, onChanged }: IntentFormProps) {
  const [text, setText] = useState(intents[0]);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const active = (ibn.active_intents || []) as Record<string, unknown>[];

  async function submit(value = text) {
    const response = await submitIntent(value, value.includes('reset') ? 5 : 300);
    setResult(response);
    onChanged?.();
  }

  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold text-slate-900">IBN Intent Control</h2>
      </div>
      <div className="grid gap-4 p-4 lg:grid-cols-[1fr_1fr]">
        <div>
          <div className="grid grid-cols-2 gap-2">
            {intents.map((intent) => (
              <button key={intent} onClick={() => void submit(intent)} className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-left text-xs font-semibold text-slate-800 hover:border-sky-300 hover:bg-sky-50">
                {intent}
              </button>
            ))}
          </div>
          <div className="mt-3 flex gap-2">
            <input value={text} onChange={(event) => setText(event.target.value)} className="min-w-0 flex-1 rounded-md border border-slate-200 px-3 py-2 text-sm outline-none focus:border-sky-400" />
            <button onClick={() => void submit()} className="inline-flex items-center gap-2 rounded-md bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-700">
              <Send size={16} /> Submit
            </button>
          </div>
          {result ? <div className="mt-3 text-sm"><Badge tone={result.ok ? 'healthy' : 'critical'}>{result.ok ? 'Intent accepted' : 'Intent failed'}</Badge> <span className="text-slate-600">{String(result.error || result.message || '')}</span></div> : null}
        </div>
        <div className="rounded-md bg-slate-50 p-3">
          <div className="mb-2 text-xs font-semibold uppercase text-slate-500">Active intents</div>
          <div className="space-y-2">
            {active.length ? active.map((intent, index) => (
              <div key={`${String(intent.id)}-${index}`} className="rounded-md border border-slate-200 bg-white p-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="font-semibold text-slate-900">{String(intent.text || intent.intent || intent.action || 'intent')}</div>
                  <Badge tone={statusTone(intent.status)}>{String(intent.status || 'active')}</Badge>
                </div>
                <div className="mt-1 text-xs text-slate-500">{String(intent.action || intent.action_applied || '')}</div>
              </div>
            )) : <div className="text-sm text-slate-500">No active intents.</div>}
          </div>
        </div>
      </div>
    </section>
  );
}
