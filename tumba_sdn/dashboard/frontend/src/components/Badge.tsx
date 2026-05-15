import type React from 'react';

type BadgeProps = {
  children: React.ReactNode;
  tone?: string;
  className?: string;
};

const tones: Record<string, string> = {
  healthy: 'bg-emerald-500/15 text-emerald-100 border-emerald-400/40',
  online: 'bg-emerald-500/15 text-emerald-100 border-emerald-400/40',
  allowed: 'bg-emerald-500/15 text-emerald-100 border-emerald-400/40',
  warning: 'bg-yellow-400/15 text-yellow-100 border-yellow-300/45',
  suspicious: 'bg-yellow-400/15 text-yellow-100 border-yellow-300/45',
  preventive: 'bg-orange-500/15 text-orange-100 border-orange-300/45',
  controlled: 'bg-orange-500/15 text-orange-100 border-orange-300/45',
  critical: 'bg-red-500/15 text-red-100 border-red-300/50',
  blocked: 'bg-red-500/15 text-red-100 border-red-300/50',
  attack: 'bg-red-500/15 text-red-100 border-red-300/50',
  threat: 'bg-red-500/15 text-red-100 border-red-300/50',
  isolated: 'bg-purple-500/15 text-purple-100 border-purple-300/45',
  info: 'bg-sky-500/15 text-sky-100 border-sky-300/45',
  ai: 'bg-violet-500/15 text-violet-100 border-violet-300/45',
};

export function Badge({ children, tone = 'info', className = '' }: BadgeProps) {
  const key = String(tone || '').toLowerCase();
  const color = tones[key] || tones.info;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${color} ${className}`}>
      {children}
    </span>
  );
}

export function statusTone(value?: unknown) {
  const text = String(value ?? '').toLowerCase();
  if (text.includes('critical') || text.includes('block') || text.includes('attack') || text.includes('threat')) return 'critical';
  if (text.includes('isolat')) return 'isolated';
  if (text.includes('prevent') || text.includes('throttle') || text.includes('rate')) return 'preventive';
  if (text.includes('warn') || text.includes('suspicious')) return 'warning';
  if (text.includes('high') || text.includes('critical')) return 'ai';
  if (text.includes('healthy') || text.includes('normal') || text.includes('connect') || text.includes('protect')) return 'healthy';
  return 'info';
}
