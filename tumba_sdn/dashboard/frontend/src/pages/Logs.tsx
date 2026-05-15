import { LogsViewer } from '../components/LogsViewer';
import type { PageProps } from './pageTypes';

export function Logs(_props: PageProps) {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-black text-slate-950">Logs</h2>
        <p className="text-sm text-slate-600">Live service logs with filter, search, auto-refresh, copy, and error highlighting.</p>
      </div>
      <LogsViewer />
    </div>
  );
}
