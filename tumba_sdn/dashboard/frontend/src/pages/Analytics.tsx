import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { MetricCard } from '../components/MetricCard';
import type { PageProps } from './pageTypes';

export function Analytics({ snapshot }: PageProps) {
  const zones = Object.entries(snapshot.metrics.zone_metrics || {}).map(([zone, data]) => ({
    zone: zone.replaceAll('_', ' '),
    throughput: Number(data.throughput_mbps || 0),
    utilization: Number(data.max_utilization_pct || 0),
    latency: Number(data.latency_ms || 0),
  }));
  const total = zones.reduce((sum, item) => sum + item.throughput, 0);
  const maxUtil = Math.max(0, ...zones.map((item) => item.utilization));
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Aggregate Throughput" value={`${total.toFixed(1)} Mbps`} detail="current zone sum" tone="blue" />
        <MetricCard label="Peak Utilization" value={`${maxUtil.toFixed(1)}%`} detail="highest zone/utilized link" tone={maxUtil >= 90 ? 'red' : maxUtil >= 85 ? 'orange' : maxUtil >= 70 ? 'yellow' : 'green'} />
        <MetricCard label="Flow Count" value={snapshot.flows.count || snapshot.flows.flows?.length || 0} detail="live API table" tone="slate" />
      </div>
      <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-panel">
        <h2 className="mb-4 text-sm font-bold text-slate-900">Zone Throughput and Utilization</h2>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={zones}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="zone" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="throughput" fill="#0284c7" name="Mbps" radius={[4, 4, 0, 0]} />
              <Bar dataKey="utilization" fill="#f97316" name="Utilization %" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}
