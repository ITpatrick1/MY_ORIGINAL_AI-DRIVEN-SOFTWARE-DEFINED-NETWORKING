import { useMemo, useState } from 'react';
import { X, Zap } from 'lucide-react';
import type { PcInfo } from '../api/types';
import { runTool, setActivity } from '../api/client';
import { Badge, statusTone } from './Badge';
import { SimulatedBrowser } from './SimulatedBrowser';

const groups = [
  {
    title: 'Normal / Academic',
    activities: [
      ['idle', 'Idle'],
      ['web_browsing', 'Web browsing'],
      ['research', 'Research'],
      ['elearning', 'E-learning'],
      ['google_meet', 'Google Meet'],
      ['mis', 'MIS/RP access'],
      ['siad', 'SIAD access'],
      ['online_class', 'Online class'],
      ['online_exam', 'Online exam'],
      ['study_download', 'Study material download'],
    ],
  },
  {
    title: 'Low Priority',
    activities: [
      ['video_streaming', 'Streaming'],
      ['social_media', 'Social media'],
      ['gaming', 'Gaming'],
      ['file_download', 'Large download'],
    ],
  },
  {
    title: 'Congestion',
    activities: [
      ['light_traffic', 'Light traffic'],
      ['medium_traffic', 'Medium traffic'],
      ['heavy_traffic', 'Heavy traffic'],
      ['saturate_pc_link', 'Saturate PC link'],
      ['preventive_wifi', 'Stress access uplink'],
      ['idle', 'Stop traffic'],
    ],
  },
  {
    title: 'Security / Attack',
    activities: [
      ['port_scan', 'Port scan'],
      ['network_sweep', 'Ping sweep'],
      ['ddos_attack', 'DDoS/flooding'],
      ['unauthorized_server_access', 'Unauthorized server access'],
      ['ip_spoofing', 'IP spoofing simulation'],
      ['arp_spoofing', 'ARP spoofing simulation'],
      ['brute_force', 'Brute-force simulation'],
      ['idle', 'Stop attack'],
    ],
  },
] as const;

type PcControlPanelProps = {
  host: string | null;
  pc?: PcInfo;
  onClose: () => void;
  onChanged?: () => void;
};

function row(label: string, value?: unknown) {
  return (
    <div className="rounded-md bg-slate-50 p-2">
      <div className="text-[11px] font-semibold uppercase text-slate-500">{label}</div>
      <div className="mt-1 truncate text-sm font-semibold text-slate-900">{String(value ?? '-')}</div>
    </div>
  );
}

export function PcControlPanel({ host, pc, onClose, onChanged }: PcControlPanelProps) {
  const [busy, setBusy] = useState('');
  const utilization = useMemo(() => {
    const current = Number(pc?.current_mbps || pc?.traffic_mbps || 0);
    const cap = Number(pc?.link_capacity_mbps || 100);
    return cap > 0 ? (current / cap) * 100 : 0;
  }, [pc]);

  if (!host || !pc) return null;

  async function applyActivity(activity: string) {
    setBusy(activity);
    if (activity === 'preventive_wifi') {
      await setActivity(host || '', 'file_download');
    } else {
      await setActivity(host || '', activity);
    }
    setBusy('');
    onChanged?.();
  }

  async function applyTool(activity: string) {
    const command = activity === 'network_sweep' ? 'ping sweep' : activity.replaceAll('_', ' ');
    setBusy(activity);
    await runTool(host || '', command);
    setBusy('');
    onChanged?.();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-4">
      <div className="max-h-[92vh] w-full max-w-6xl overflow-hidden rounded-lg border border-slate-200 bg-white shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <div>
            <div className="text-xs font-semibold uppercase text-slate-500">{host}</div>
            <h2 className="text-xl font-bold text-slate-950">{pc.label || host}</h2>
          </div>
          <button aria-label="Close" onClick={onClose} className="rounded-md p-2 text-slate-500 hover:bg-slate-100">
            <X size={20} />
          </button>
        </div>
        <div className="max-h-[calc(92vh-74px)] overflow-y-auto p-5">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {row('IP address', pc.ip)}
            {row('MAC address', pc.mac)}
            {row('VLAN / Zone', `${pc.vlan ?? '-'} / ${pc.zone_label || pc.zone}`)}
            {row('Connected switch', pc.switch)}
            {row('Current activity', pc.activity_label || pc.activity)}
            {row('Current Mbps', `${Number(pc.current_mbps || 0).toFixed(2)} Mbps`)}
            {row('Link capacity', `${pc.link_capacity_mbps || 100} Mbps`)}
            {row('Utilization', `${utilization.toFixed(1)}%`)}
            {row('Priority', pc.priority_level)}
            {row('DSCP', pc.dscp)}
            {row('Congestion state', pc.congestion_state)}
            {row('Security state', pc.security_state)}
          </div>
          <div className="mt-4 rounded-lg border border-slate-200 p-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone={statusTone(pc.controller_action)}>{pc.controller_action || 'Monitoring only'}</Badge>
              <Badge tone={statusTone(pc.current_status || pc.browser_status)}>{pc.current_status || pc.browser_status || 'Idle'}</Badge>
              {pc.last_alert ? <span className="text-slate-600">{pc.last_alert}</span> : null}
            </div>
          </div>
          <div className="mt-5 grid gap-4 lg:grid-cols-[1fr_1.1fr]">
            <div className="space-y-4">
              {groups.map((group) => (
                <section key={group.title} className="rounded-lg border border-slate-200 bg-white p-3">
                  <h3 className="mb-3 text-sm font-bold text-slate-900">{group.title}</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {group.activities.map(([activity, label]) => {
                      const isSecurity = group.title.startsWith('Security');
                      return (
                        <button
                          key={`${group.title}-${activity}-${label}`}
                          onClick={() => void (isSecurity && activity !== 'idle' ? applyTool(activity) : applyActivity(activity))}
                          className="flex min-h-10 items-center justify-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-2 py-2 text-xs font-semibold text-slate-800 hover:border-sky-300 hover:bg-sky-50 disabled:opacity-60"
                          disabled={busy === activity}
                        >
                          {busy === activity ? <Zap size={14} className="animate-pulse text-sky-600" /> : null}
                          {label}
                        </button>
                      );
                    })}
                  </div>
                </section>
              ))}
            </div>
            <SimulatedBrowser host={host} pc={pc} onChanged={onChanged} />
          </div>
        </div>
      </div>
    </div>
  );
}
