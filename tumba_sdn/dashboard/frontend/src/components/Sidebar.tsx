import { NavLink } from 'react-router-dom';
import { Activity, BrainCircuit, Database, FileText, Gauge, Home, Network, RadioTower, Shield, SlidersHorizontal, Terminal, Workflow } from 'lucide-react';

const items = [
  { to: '/', label: 'Overview', icon: Home },
  { to: '/topology', label: 'Topology', icon: Network },
  { to: '/analytics', label: 'Analytics', icon: Activity },
  { to: '/control', label: 'Control Center', icon: SlidersHorizontal },
  { to: '/security', label: 'Security', icon: Shield },
  { to: '/pc-simulator', label: 'PC Simulator', icon: RadioTower },
  { to: '/intelligence', label: 'Intelligence', icon: BrainCircuit },
  { to: '/congestion', label: 'Proactive Congestion', icon: Gauge },
  { to: '/ibn', label: 'IBN Control', icon: Workflow },
  { to: '/dataset', label: 'Dataset', icon: Database },
  { to: '/logs', label: 'Logs', icon: Terminal },
  { to: '/docs', label: 'Docs', icon: FileText },
];

export function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-slate-200 bg-white lg:block">
      <div className="border-b border-slate-200 px-5 py-4">
        <div className="text-lg font-black text-slate-950">Tumba SDN</div>
        <div className="text-xs font-semibold uppercase text-slate-500">AI Network Control</div>
      </div>
      <nav className="space-y-1 p-3">
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-semibold ${
                isActive ? 'bg-sky-50 text-sky-700' : 'text-slate-700 hover:bg-slate-100'
              }`
            }
          >
            <Icon size={17} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
