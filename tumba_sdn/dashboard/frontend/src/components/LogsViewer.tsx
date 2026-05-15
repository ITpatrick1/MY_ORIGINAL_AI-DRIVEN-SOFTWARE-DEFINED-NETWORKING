import { useEffect, useState } from 'react';
import { Copy, Download } from 'lucide-react';
import { getJson } from '../api/client';
import { Badge } from './Badge';

const services = [
  'all',
  'ryu',
  'dashboard',
  'proactive_congestion',
  'security',
  'pc_activity_manager',
  'auto_traffic',
  'ibn_engine',
  'timetable',
  'ml_stub',
  'marl_security',
  'dataset_collector',
];

type LogsResponse = {
  logs?: Record<string, { path?: string; exists?: boolean; lines?: string[] }>;
};

export function LogsViewer() {
  const [service, setService] = useState('all');
  const [search, setSearch] = useState('');
  const [auto, setAuto] = useState(true);
  const [data, setData] = useState<LogsResponse>({});

  async function load() {
    const next = await getJson<LogsResponse>(`/api/logs?service=${service}&search=${encodeURIComponent(search)}&limit=300`, {});
    setData(next);
  }

  useEffect(() => {
    void load();
    if (!auto) return undefined;
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [service, search, auto]);

  const text = Object.entries(data.logs || {})
    .flatMap(([name, item]) => [`===== ${name} =====`, ...(item.lines || [])])
    .join('\n');

  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-4 py-3">
        <select value={service} onChange={(event) => setService(event.target.value)} className="rounded-md border border-slate-200 px-3 py-2 text-sm">
          {services.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
        <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search logs" className="min-w-[14rem] flex-1 rounded-md border border-slate-200 px-3 py-2 text-sm" />
        <label className="flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" checked={auto} onChange={(event) => setAuto(event.target.checked)} />
          Auto-refresh
        </label>
        <button onClick={() => void navigator.clipboard?.writeText(text)} className="inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold">
          <Copy size={15} /> Copy
        </button>
        <a href={`/api/logs?service=${service}`} download className="inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold">
          <Download size={15} /> Refresh
        </a>
      </div>
      <div className="max-h-[620px] overflow-auto bg-slate-950 p-4 font-mono text-xs text-slate-100">
        {Object.entries(data.logs || {}).map(([name, item]) => (
          <div key={name} className="mb-5">
            <div className="mb-2 flex items-center gap-2 text-slate-300">
              <span className="font-sans text-sm font-bold">{name}</span>
              <Badge tone={item.exists ? 'healthy' : 'warning'}>{item.exists ? 'available' : 'missing'}</Badge>
              <span>{item.path}</span>
            </div>
            {(item.lines || []).length ? item.lines?.map((line, index) => {
              const danger = /error|fail|critical|permission|brokenpipe/i.test(line);
              return <div key={`${name}-${index}`} className={danger ? 'text-red-300' : 'text-slate-100'}>{line}</div>;
            }) : <div className="text-slate-500">No log lines.</div>}
          </div>
        ))}
      </div>
    </section>
  );
}
