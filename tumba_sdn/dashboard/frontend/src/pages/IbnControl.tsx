import { IntentForm } from '../components/IntentForm';
import { MetricCard } from '../components/MetricCard';
import type { PageProps } from './pageTypes';

export function IbnControl({ snapshot, refresh }: PageProps) {
  const active = ((snapshot.ibn.active_intents || []) as unknown[]).length;
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Active Intents" value={active} detail="currently enforced" tone={active ? 'purple' : 'slate'} />
        <MetricCard label="IBN Engine" value={active ? 'Active' : 'Idle'} detail="intent translator" tone={active ? 'green' : 'slate'} />
        <MetricCard label="Current Action" value={String((((snapshot.ibn.active_intents || []) as Record<string, unknown>[])[0] || {}).action || 'normal')} detail="from active intent" tone="blue" />
        <MetricCard label="Total Submitted" value={String(snapshot.ibn.total_submitted || 0)} detail="cached/live state" tone="slate" />
      </div>
      <IntentForm ibn={snapshot.ibn} onChanged={refresh} />
    </div>
  );
}
