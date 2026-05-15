import type { DashboardSnapshot, DatasetStatus, HealthResponse } from './types';

export async function getJson<T>(url: string, fallback: T): Promise<T> {
  try {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) return fallback;
    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

export async function postJson<T>(url: string, body: unknown, fallback: T): Promise<T> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

export async function deleteJson<T>(url: string, fallback: T): Promise<T> {
  try {
    const response = await fetch(url, { method: 'DELETE' });
    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

export async function loadSnapshot(): Promise<DashboardSnapshot> {
  const [
    health,
    metrics,
    topology,
    pcActivities,
    flows,
    alerts,
    proactive,
    security,
    threats,
    mlAction,
    marlSecurity,
    ibn,
    timetable,
  ] = await Promise.all([
    getJson<HealthResponse>('/api/health', {}),
    getJson<Record<string, unknown>>('/api/metrics', {}),
    getJson<Record<string, unknown>>('/api/topology', {}),
    getJson<Record<string, unknown>>('/api/pc_activities', {}),
    getJson<Record<string, unknown>>('/api/flows', { flows: [] }),
    getJson<Record<string, unknown>>('/api/alerts', { alerts: [] }),
    getJson<Record<string, unknown>>('/api/proactive_congestion', {}),
    getJson<Record<string, unknown>>('/api/security', {}),
    getJson<Record<string, unknown>>('/api/threats', { threats: [] }),
    getJson<Record<string, unknown>>('/api/ml_action', {}),
    getJson<Record<string, unknown>>('/api/marl_security', {}),
    getJson<Record<string, unknown>>('/api/ibn', {}),
    getJson<Record<string, unknown>>('/api/timetable', {}),
  ]);

  return {
    health,
    metrics,
    topology,
    pcActivities,
    flows,
    alerts,
    proactive,
    security,
    threats,
    mlAction,
    marlSecurity,
    ibn,
    timetable,
  } as DashboardSnapshot;
}

export async function setActivity(host: string, activity: string) {
  return postJson<Record<string, unknown>>('/api/set_activity', { host, activity }, { ok: false });
}

export async function openBrowser(host: string, url: string) {
  return postJson<Record<string, unknown>>('/api/browser_open', { host, url }, { ok: false });
}

export async function runTool(host: string, command: string) {
  return postJson<Record<string, unknown>>('/api/run_tool', { host, command }, { ok: false });
}

export async function submitIntent(text: string, duration_s = 300) {
  return postJson<Record<string, unknown>>('/api/ibn/intent', { text, duration_s, source: 'react_dashboard' }, { ok: false });
}

export async function cancelIntent(intentId: string) {
  return deleteJson<Record<string, unknown>>(`/api/ibn/cancel/${encodeURIComponent(intentId)}`, { ok: false });
}

export async function getDatasetStatus() {
  return getJson<DatasetStatus>('/api/dataset/status', {});
}

export async function getDatasetPreview(type: string, limit = 50) {
  return getJson<{ ok?: boolean; rows?: Record<string, unknown>[]; count?: number; error?: string }>(
    `/api/dataset/preview?type=${encodeURIComponent(type)}&limit=${limit}`,
    { ok: false, rows: [] },
  );
}

export async function archiveDataset() {
  return postJson<Record<string, unknown>>('/api/dataset/archive', {}, { ok: false });
}

export async function resetDataset() {
  return postJson<Record<string, unknown>>('/api/dataset/reset', { confirm: true }, { ok: false });
}

export async function runScenario(scenario: string) {
  return postJson<Record<string, unknown>>('/api/scenario', { scenario }, { ok: false });
}
