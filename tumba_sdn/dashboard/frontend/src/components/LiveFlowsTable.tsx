import type { FlowRow } from '../api/types';
import { Badge, statusTone } from './Badge';

type LiveFlowsTableProps = {
  flows?: FlowRow[];
};

function value<T>(input: T | undefined | null, fallback = '-'): T | string {
  return input === undefined || input === null || input === '' ? fallback : input;
}

export function LiveFlowsTable({ flows = [] }: LiveFlowsTableProps) {
  return (
    <section className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-panel">
      <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-bold text-slate-900">Live Flows</h2>
        <Badge tone="info">{flows.length} flows</Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="table-tight min-w-full text-left text-sm">
          <thead className="bg-slate-100 text-xs uppercase text-slate-600">
            <tr>
              <th>Source PC</th>
              <th>Source IP</th>
              <th>Zone</th>
              <th>Switch</th>
              <th>Destination</th>
              <th>Service</th>
              <th>Protocol</th>
              <th>Activity</th>
              <th>Bandwidth</th>
              <th>Priority</th>
              <th>DSCP</th>
              <th>Controller Action</th>
              <th>Status</th>
              <th>Security</th>
            </tr>
          </thead>
          <tbody>
            {flows.length ? (
              flows.map((flow, index) => (
                <tr key={`${flow.src_ip}-${flow.dst_ip}-${index}`} className="border-t border-slate-100">
                  <td className="font-semibold text-slate-900">{value(flow.source_pc || flow.src_label)}</td>
                  <td>{value(flow.src_ip)}</td>
                  <td>{value(flow.src_zone || flow.src_vlan)}</td>
                  <td>{value(flow.src_switch)}</td>
                  <td>{value(flow.dst_ip)}:{value(flow.dst_port, '')}</td>
                  <td>{value(flow.dst_service_name)}</td>
                  <td>{value(flow.proto)}</td>
                  <td>{value(flow.activity)}</td>
                  <td>{Number(flow.mbps || 0).toFixed(1)} Mbps</td>
                  <td><Badge tone={statusTone(flow.priority)}>{value(flow.priority)}</Badge></td>
                  <td>DSCP {value(flow.dscp)}</td>
                  <td className="max-w-[18rem] truncate">{value(flow.controller_action)}</td>
                  <td><Badge tone={statusTone(flow.status)}>{value(flow.status)}</Badge></td>
                  <td><Badge tone={statusTone(flow.security_state)}>{value(flow.security_state || 'normal')}</Badge></td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={14} className="py-8 text-center text-slate-500">No active flows reported yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
