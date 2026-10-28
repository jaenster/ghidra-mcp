/**
 * What the gateway does with its daemon before it opens anything: wait until
 * the daemon answers, and, on a daemon that is private to the gateway, close
 * whatever a previous gateway process left open on it.
 */

import { UpstreamError, type Upstream } from './upstream.js';

export interface StartupOptions {
  /** Give up after this long. */
  timeoutMs: number;
  log?: (line: string) => void;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Retry until the daemon answers, backing off from 250 ms to 5 s. In a pod the
 * gateway can start before the daemon listens; that is a wait, not a failure.
 */
export async function waitForUpstream(upstream: Upstream, options: StartupOptions): Promise<void> {
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  const deadline = now() + options.timeoutMs;
  let delay = 250;
  let waited = false;
  for (;;) {
    try {
      if (upstream.health) {
        await upstream.health(5_000);
      } else {
        const res = await upstream.call('list_sessions', {}, 5_000);
        if (res.isError) throw new UpstreamError(`list_sessions failed: ${res.text}`);
      }
      if (waited) options.log?.('gateway: daemon is up');
      return;
    } catch (err) {
      if (!(err instanceof UpstreamError)) throw err;
      if (now() >= deadline) {
        throw new UpstreamError(`daemon not reachable after ${Math.round(options.timeoutMs / 1000)}s: ${err.message}`);
      }
      if (!waited) options.log?.(`gateway: waiting for the daemon (${err.message})`);
      waited = true;
      await sleep(Math.min(delay, Math.max(0, deadline - now())));
      delay = Math.min(delay * 2, 5_000);
    }
  }
}

interface Row {
  id: string;
  repoSession?: boolean;
}

async function listSessions(upstream: Upstream): Promise<Row[]> {
  const res = await upstream.call('list_sessions', {}, 30_000);
  if (res.isError) throw new UpstreamError(`list_sessions failed: ${res.text}`);
  return JSON.parse(res.text) as Row[];
}

/**
 * Close every session on the daemon, repository sessions included, and wait
 * until the daemon reports no session and no worker. Only for a daemon nobody
 * but this gateway can reach: every session on it is one a previous gateway
 * process opened and can no longer use, and each holds a worker.
 */
export async function reclaimUpstream(upstream: Upstream, options: StartupOptions): Promise<number> {
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  const stale = await listSessions(upstream);
  for (const row of stale) {
    const res = await upstream.call('close_session', { sessionId: row.id, force: true }, 60_000);
    if (res.isError && !/Session not found/.test(res.text)) {
      throw new UpstreamError(`could not close stale session: ${res.text}`);
    }
  }
  if (stale.length > 0) options.log?.(`gateway: closed ${stale.length} stale session(s) on the daemon`);
  const deadline = now() + options.timeoutMs;
  for (;;) {
    const left = (await listSessions(upstream)).length;
    const workers = upstream.health ? (await upstream.health(5_000)).workers : 0;
    if (left === 0 && workers === 0) return stale.length;
    if (now() >= deadline) {
      throw new UpstreamError(`the daemon still holds ${left} session(s) and ${workers} worker(s) after closing them all`);
    }
    await sleep(500);
  }
}
