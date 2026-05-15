import { useCallback, useEffect, useState } from 'react';
import { Route, Routes } from 'react-router-dom';
import { loadSnapshot } from './api/client';
import type { DashboardSnapshot } from './api/types';
import { createPollingSubscription } from './api/socket';
import { Layout } from './components/Layout';
import { Analytics } from './pages/Analytics';
import { ControlCenter } from './pages/ControlCenter';
import { Dataset } from './pages/Dataset';
import { Docs } from './pages/Docs';
import { IbnControl } from './pages/IbnControl';
import { Intelligence } from './pages/Intelligence';
import { Logs } from './pages/Logs';
import { Overview } from './pages/Overview';
import { PcSimulator } from './pages/PcSimulator';
import { ProactiveCongestion } from './pages/ProactiveCongestion';
import { Security } from './pages/Security';
import { Topology } from './pages/Topology';

const emptySnapshot: DashboardSnapshot = {
  health: {},
  metrics: {},
  topology: {},
  pcActivities: { pcs: {}, profiles: {} },
  flows: { flows: [] },
  alerts: { alerts: [] },
  proactive: {},
  security: {},
  threats: { threats: [] },
  mlAction: {},
  marlSecurity: {},
  ibn: {},
  timetable: {},
};

export default function App() {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(emptySnapshot);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const next = await loadSnapshot();
    setSnapshot(next);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
    return createPollingSubscription(() => void refresh(), 2500);
  }, [refresh]);

  const props = { snapshot, refresh };

  return (
    <Layout snapshot={snapshot} onRefresh={refresh}>
      {loading ? (
        <div className="rounded-lg border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-panel">Loading live SDN state...</div>
      ) : (
        <Routes>
          <Route path="/" element={<Overview {...props} />} />
          <Route path="/topology" element={<Topology {...props} />} />
          <Route path="/analytics" element={<Analytics {...props} />} />
          <Route path="/control" element={<ControlCenter {...props} />} />
          <Route path="/security" element={<Security {...props} />} />
          <Route path="/pc-simulator" element={<PcSimulator {...props} />} />
          <Route path="/intelligence" element={<Intelligence {...props} />} />
          <Route path="/congestion" element={<ProactiveCongestion {...props} />} />
          <Route path="/ibn" element={<IbnControl {...props} />} />
          <Route path="/dataset" element={<Dataset {...props} />} />
          <Route path="/logs" element={<Logs {...props} />} />
          <Route path="/docs" element={<Docs {...props} />} />
          <Route path="*" element={<Overview {...props} />} />
        </Routes>
      )}
    </Layout>
  );
}
