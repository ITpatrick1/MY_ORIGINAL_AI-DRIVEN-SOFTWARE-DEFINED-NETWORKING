import { Badge, statusTone } from './Badge';

type StatusCardProps = {
  name: string;
  status?: string | boolean;
  detail?: string;
};

export function StatusCard({ name, status, detail }: StatusCardProps) {
  const label = typeof status === 'boolean' ? (status ? 'Online' : 'Offline') : status || 'Unknown';
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-panel">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-slate-900">{name}</div>
          {detail ? <div className="truncate text-xs text-slate-500">{detail}</div> : null}
        </div>
        <Badge tone={statusTone(label)}>{label}</Badge>
      </div>
    </div>
  );
}
