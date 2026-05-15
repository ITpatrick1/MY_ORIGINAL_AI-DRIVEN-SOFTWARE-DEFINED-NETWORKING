import { useEffect, useState } from 'react';
import { Archive, Download, RefreshCcw, Trash2 } from 'lucide-react';
import { archiveDataset, getDatasetPreview, getDatasetStatus, resetDataset } from '../api/client';
import type { DatasetStatus } from '../api/types';
import { Badge } from '../components/Badge';
import { MetricCard } from '../components/MetricCard';
import type { PageProps } from './pageTypes';

const datasetTypes = ['traffic', 'congestion', 'security', 'qos', 'ml', 'events'];

export function Dataset(_props: PageProps) {
  const [status, setStatus] = useState<DatasetStatus>({});
  const [active, setActive] = useState('traffic');
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  const [message, setMessage] = useState('');

  async function load(type = active) {
    const [nextStatus, preview] = await Promise.all([getDatasetStatus(), getDatasetPreview(type, 50)]);
    setStatus(nextStatus);
    setRows(preview.rows || []);
  }

  useEffect(() => {
    void load(active);
    const timer = window.setInterval(() => void load(active), 4000);
    return () => window.clearInterval(timer);
  }, [active]);

  async function archive() {
    const result = await archiveDataset();
    setMessage(String(result.ok ? 'Archive created' : result.error || 'Archive failed'));
    await load(active);
  }

  async function reset() {
    const result = await resetDataset();
    setMessage(String(result.ok ? 'Realtime datasets reset' : result.error || 'Reset failed'));
    await load(active);
  }

  const columns = rows[0] ? Object.keys(rows[0]).slice(0, 12) : [];

  return (
    <div className="space-y-5">
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-black text-slate-950">Dataset / Real-Time Data</h2>
            <p className="text-sm text-slate-600">Dataset is generated from real-time captured SDN traffic and system telemetry.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Badge tone={status.running ? 'healthy' : 'warning'}>{status.running ? 'Collector running' : 'Collector offline'}</Badge>
            {message ? <Badge tone="info">{message}</Badge> : null}
          </div>
        </div>
      </section>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Traffic Rows" value={status.traffic_rows || 0} tone="blue" />
        <MetricCard label="Congestion Rows" value={status.congestion_rows || 0} tone="orange" />
        <MetricCard label="Security Rows" value={status.security_rows || 0} tone="red" />
        <MetricCard label="QoS Rows" value={status.qos_rows || 0} tone="green" />
        <MetricCard label="ML Rows" value={status.ml_rows || 0} tone="purple" />
        <MetricCard label="Events" value={status.events_rows || 0} tone="slate" />
      </div>
      <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
        <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-4 py-3">
          {datasetTypes.map((type) => (
            <button key={type} onClick={() => setActive(type)} className={`rounded-md px-3 py-2 text-sm font-semibold ${active === type ? 'bg-sky-600 text-white' : 'border border-slate-200 bg-white text-slate-700'}`}>
              {type}
            </button>
          ))}
          <button onClick={() => void load(active)} className="ml-auto inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold">
            <RefreshCcw size={15} /> Refresh
          </button>
          <a href={`/api/dataset/export?type=${active}`} className="inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold">
            <Download size={15} /> Export
          </a>
          <button onClick={() => void archive()} className="inline-flex items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold">
            <Archive size={15} /> Archive
          </button>
          <button onClick={() => void reset()} className="inline-flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm font-semibold text-red-700">
            <Trash2 size={15} /> Reset
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="table-tight min-w-full text-left text-sm">
            <thead className="bg-slate-100 text-xs uppercase text-slate-600">
              <tr>{columns.map((column) => <th key={column}>{column}</th>)}</tr>
            </thead>
            <tbody>
              {rows.length ? rows.map((row, index) => (
                <tr key={index} className="border-t border-slate-100">
                  {columns.map((column) => <td key={column} className="max-w-[18rem] truncate">{String(row[column] ?? '')}</td>)}
                </tr>
              )) : (
                <tr><td className="py-8 text-center text-slate-500" colSpan={Math.max(1, columns.length)}>No rows available yet. Trigger PC activity, congestion, or security scenarios.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
