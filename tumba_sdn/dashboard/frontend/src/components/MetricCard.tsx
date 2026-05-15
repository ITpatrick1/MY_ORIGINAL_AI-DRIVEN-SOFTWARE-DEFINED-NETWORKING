import type React from 'react';

type MetricCardProps = {
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  tone?: 'green' | 'yellow' | 'orange' | 'red' | 'blue' | 'purple' | 'slate';
};

const toneClasses = {
  green: 'border-emerald-400/35 bg-emerald-500/10 text-emerald-50',
  yellow: 'border-yellow-300/40 bg-yellow-400/10 text-yellow-50',
  orange: 'border-orange-300/40 bg-orange-500/10 text-orange-50',
  red: 'border-red-300/45 bg-red-500/10 text-red-50',
  blue: 'border-sky-300/40 bg-sky-500/10 text-sky-50',
  purple: 'border-violet-300/40 bg-violet-500/10 text-violet-50',
  slate: 'border-slate-600/60 bg-white text-slate-50',
};

export function MetricCard({ label, value, detail, tone = 'slate' }: MetricCardProps) {
  return (
    <div className={`rounded-lg border p-4 shadow-panel ${toneClasses[tone]}`}>
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-bold">{value}</div>
      {detail ? <div className="mt-1 text-xs text-slate-600">{detail}</div> : null}
    </div>
  );
}
