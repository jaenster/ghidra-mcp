const BASE = '/api';

export async function fetchHealth() {
  const res = await fetch('/health');
  return res.json();
}

export async function fetchSessions() {
  const res = await fetch(`${BASE}/sessions`);
  const data = await res.json();
  return data.sessions;
}

export async function fetchWorkers() {
  const res = await fetch(`${BASE}/workers`);
  const data = await res.json();
  return data.workers;
}

export async function fetchCommands(limit = 100) {
  const res = await fetch(`${BASE}/commands?limit=${limit}`);
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
  const res = await fetch(`${BASE}/logs?${params}`);
  return res.json();
}
