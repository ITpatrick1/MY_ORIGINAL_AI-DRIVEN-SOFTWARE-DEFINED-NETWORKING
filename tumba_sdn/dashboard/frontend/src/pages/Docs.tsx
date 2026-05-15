import type { PageProps } from './pageTypes';

export function Docs(_props: PageProps) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-panel">
      <h2 className="text-xl font-black text-slate-950">Language Stack</h2>
      <div className="mt-4 grid gap-3 md:grid-cols-2">
        {[
          ['Python', 'Ryu SDN controller, OpenFlow logic, Flask APIs, Mininet topology, AI/ML engines, PC Activity Manager, congestion and security logic.'],
          ['React + TypeScript', 'Dashboard frontend, topology, PC control, live flows, security, congestion, intelligence, IBN, logs, and dataset views.'],
          ['Tailwind CSS', 'Responsive professional dashboard styling.'],
          ['Bash', 'run.sh, stop.sh, setup, verification scripts.'],
          ['JSON', 'Prototype state sharing between services.'],
        ].map(([name, detail]) => (
          <div key={name} className="rounded-md border border-slate-200 bg-slate-50 p-4">
            <div className="font-bold text-slate-950">{name}</div>
            <div className="mt-1 text-sm text-slate-600">{detail}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
