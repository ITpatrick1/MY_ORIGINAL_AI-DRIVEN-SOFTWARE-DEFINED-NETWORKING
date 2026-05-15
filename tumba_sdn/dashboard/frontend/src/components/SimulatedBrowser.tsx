import { useState } from 'react';
import { Globe, ShieldCheck } from 'lucide-react';
import type { PcInfo } from '../api/types';
import { openBrowser } from '../api/client';
import { Badge, statusTone } from './Badge';

const serviceUrls = [
  'http://elearning.tumba.local',
  'https://mis.tumba.local',
  'https://siad.tumba.local',
  'https://auth.tumba.local',
  'http://library.tumba.local',
  'http://files.tumba.local',
  'http://streaming.tumba.local',
  'http://social.tumba.local',
  'https://admin.tumba.local',
];

type SimulatedBrowserProps = {
  host: string;
  pc?: PcInfo;
  onChanged?: () => void;
};

export function SimulatedBrowser({ host, pc, onChanged }: SimulatedBrowserProps) {
  const [url, setUrl] = useState(pc?.browser_url || serviceUrls[0]);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);

  async function openUrl(nextUrl = url) {
    setUrl(nextUrl);
    const response = await openBrowser(host, nextUrl);
    setResult(response);
    onChanged?.();
  }

  const status = String(result?.browser_status || pc?.browser_status || pc?.current_status || 'Idle');

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50">
      <div className="flex items-center gap-2 border-b border-slate-200 bg-white px-3 py-2">
        <Globe size={16} className="text-slate-500" />
        <input
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') void openUrl();
          }}
          className="min-w-0 flex-1 rounded-md border border-slate-200 px-2 py-1 text-sm outline-none focus:border-sky-400"
        />
        <button onClick={() => void openUrl()} className="rounded-md bg-sky-600 px-3 py-1 text-sm font-semibold text-white hover:bg-sky-700">
          Open
        </button>
      </div>
      <div className="grid gap-2 p-3 text-sm sm:grid-cols-2">
        <div>
          <div className="text-xs font-semibold uppercase text-slate-500">Mapped Service</div>
          <div className="mt-1 font-semibold text-slate-900">{pc?.dst_service_name || String(result?.service || '-')}</div>
          <div className="text-xs text-slate-500">{pc?.dst_ip || String(result?.dst_ip || '')}:{pc?.dst_port || String(result?.dst_port || '')}</div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase text-slate-500">Controller Result</div>
          <div className="mt-1 flex items-center gap-2">
            <ShieldCheck size={15} className="text-sky-600" />
            <Badge tone={statusTone(status)}>{status}</Badge>
          </div>
          <div className="mt-1 text-xs text-slate-500">{pc?.controller_action || String(result?.note || '')}</div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase text-slate-500">Priority</div>
          <div className="mt-1">{pc?.priority_level || String(result?.priority_level || '-')} · DSCP {pc?.dscp || String(result?.dscp || '-')}</div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase text-slate-500">Security</div>
          <div className="mt-1"><Badge tone={statusTone(pc?.security_state || result?.reason)}>{pc?.security_state || String(result?.reason || 'normal')}</Badge></div>
        </div>
      </div>
      <div className="flex flex-wrap gap-2 border-t border-slate-200 p-3">
        {serviceUrls.map((item) => (
          <button key={item} onClick={() => void openUrl(item)} className="rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-semibold text-slate-700 hover:border-sky-300">
            {item.replace(/^https?:\/\//, '')}
          </button>
        ))}
      </div>
    </div>
  );
}
