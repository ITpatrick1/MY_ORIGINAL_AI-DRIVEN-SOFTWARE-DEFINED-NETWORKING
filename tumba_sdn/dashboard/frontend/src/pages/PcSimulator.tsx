import { useState } from 'react';
import { PcControlPanel } from '../components/PcControlPanel';
import { Badge, statusTone } from '../components/Badge';
import type { PageProps } from './pageTypes';

export function PcSimulator({ snapshot, refresh }: PageProps) {
  const [selected, setSelected] = useState<string | null>(null);
  const pcs = snapshot.pcActivities.pcs || {};
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-black text-slate-950">PC Simulator</h2>
        <p className="text-sm text-slate-600">Open any endpoint to assign academic, low-priority, congestion, or security activities.</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {Object.entries(pcs).map(([host, pc]) => (
          <button key={host} onClick={() => setSelected(host)} className="rounded-lg border border-slate-200 bg-white p-4 text-left shadow-panel hover:border-sky-300">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="font-bold text-slate-950">{pc.label || host}</div>
                <div className="text-xs text-slate-500">{pc.ip} · {pc.zone_label}</div>
              </div>
              <Badge tone={statusTone(pc.security_state || pc.congestion_state)}>{pc.security_state || pc.congestion_state || 'normal'}</Badge>
            </div>
            <div className="mt-3 text-sm text-slate-700">{pc.activity_label || pc.activity || 'Idle'}</div>
            <div className="mt-1 text-xs text-slate-500">{Number(pc.current_mbps || 0).toFixed(1)} Mbps · DSCP {pc.dscp ?? '-'}</div>
          </button>
        ))}
      </div>
      <PcControlPanel host={selected} pc={selected ? pcs[selected] : undefined} onClose={() => setSelected(null)} onChanged={refresh} />
    </div>
  );
}
