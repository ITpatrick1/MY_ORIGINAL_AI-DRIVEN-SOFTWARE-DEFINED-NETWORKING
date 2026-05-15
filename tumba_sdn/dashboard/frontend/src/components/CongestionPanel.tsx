import type { ProactiveState } from '../api/types';
import { Badge, statusTone } from './Badge';

type CongestionPanelProps = {
  proactive?: ProactiveState;
};

export function CongestionPanel({ proactive }: CongestionPanelProps) {
  const links = Object.entries(proactive?.access_uplinks || {});
  const summary = proactive?.summary || {};
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold text-slate-900">Proactive Congestion</h2>
        <div className="flex gap-2">
          <Badge tone="warning">{summary.warning_links || 0} warning</Badge>
          <Badge tone="preventive">{summary.preventive_links || 0} preventive</Badge>
          <Badge tone="critical">{summary.critical_links || 0} critical</Badge>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="table-tight min-w-full text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-600">
            <tr>
              <th>Link</th>
              <th>Current</th>
              <th>Capacity</th>
              <th>Utilization</th>
              <th>Predicted</th>
              <th>Growth</th>
              <th>Latency</th>
              <th>Queue</th>
              <th>Drops</th>
              <th>State</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {links.length ? links.map(([zone, item]) => {
              const current = Number(item.current_mbps || 0);
              const capacity = Number(item.capacity_mbps || item.uplink_capacity_mbps || 1000);
              const util = Number(item.utilization_percent || item.utilization_pct || 0);
              return (
                <tr key={zone} className="border-t border-slate-100">
                  <td className="font-semibold text-slate-900">{String(item.label || item.display_name || zone)}</td>
                  <td>{current.toFixed(1)} Mbps</td>
                  <td>{capacity.toFixed(0)} Mbps</td>
                  <td>{util.toFixed(1)}%</td>
                  <td>{Number(item.predicted_utilization_percent || 0).toFixed(1)}%</td>
                  <td>{Number(item.growth_rate_pct || 0).toFixed(2)}%</td>
                  <td>{Number(item.latency_ms || 0).toFixed(1)} ms</td>
                  <td>{String(item.queue_depth || 0)}</td>
                  <td>{String(item.packet_drops || 0)}</td>
                  <td><Badge tone={statusTone(item.threshold_state)}>{String(item.threshold_state || 'healthy')}</Badge></td>
                  <td className="max-w-[22rem] truncate">{String(item.recommended_action || 'Monitor only')}</td>
                </tr>
              );
            }) : (
              <tr><td colSpan={11} className="py-8 text-center text-slate-500">No congestion telemetry yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
