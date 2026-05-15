import type { AlertItem } from '../api/types';
import { Badge, statusTone } from './Badge';

type AlertPanelProps = {
  alerts?: AlertItem[];
};

export function AlertPanel({ alerts = [] }: AlertPanelProps) {
  const visible = alerts.slice(0, 8);
  return (
    <section className="rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold text-slate-900">Active Alerts</h2>
        <Badge tone={visible.length ? 'warning' : 'healthy'}>{visible.length || 'Clear'}</Badge>
      </div>
      <div className="divide-y divide-slate-100">
        {visible.length ? (
          visible.map((alert, index) => (
            <div key={`${alert.title}-${index}`} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold text-slate-900">{alert.title || alert.device || 'Alert'}</div>
                  <div className="mt-1 text-xs text-slate-600">{alert.detail || alert.action_taken || 'Controller event'}</div>
                </div>
                <Badge tone={statusTone(alert.severity)}>{alert.severity || 'info'}</Badge>
              </div>
            </div>
          ))
        ) : (
          <div className="p-4 text-sm text-slate-500">No active alerts from controller telemetry.</div>
        )}
      </div>
    </section>
  );
}
