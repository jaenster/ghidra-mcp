const BASE = '/api';

async function request(path: string, init?: RequestInit): Promise<Response> {
  const res = await fetch(path, init);
  if (res.status === 401) {
    window.location.href =
      '/dashboard/login?rt=' + encodeURIComponent(window.location.pathname);
    // Never resolve so callers don't proceed past the redirect.
    return new Promise<Response>(() => {});
  }
  return res;
}

export async function fetchHealth() {
  const res = await request('/health');
  return res.json();
}

export async function fetchSessions() {
  const res = await request(`${BASE}/sessions`);
  const data = await res.json();
  return data.sessions;
}

export async function fetchWorkers() {
  const res = await request(`${BASE}/workers`);
  const data = await res.json();
  return data.workers;
}

export async function fetchCommands(limit = 100) {
  const res = await request(`${BASE}/commands?limit=${limit}`);
  const data = await res.json();
  return data.commands;
}

export async function fetchLogs(opts: {
  level?: string;
  component?: string;
  limit?: number;
  since?: number;
} = {}) {
  const params = new URLSearchParams();
  if (opts.level) params.set('level', opts.level);
  if (opts.component) params.set('component', opts.component);
  if (opts.limit) params.set('limit', String(opts.limit));
  if (opts.since) params.set('since', String(opts.since));
  const res = await request(`${BASE}/logs?${params}`);
  return res.json();
}

export async function killWorker(workerId: string) {
  const res = await request(`${BASE}/workers/${workerId}/kill`, { method: 'POST' });
  return res.json();
}

export async function closeSession(sessionId: string) {
  const res = await request(`${BASE}/sessions/${sessionId}`, { method: 'DELETE' });
  return res.json();
}
