import { describe, expect, it, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { AuditLog } from '../src/audit.js';
import { AuthError, Authenticator, type FetchLike, type Identity } from '../src/auth.js';
import { Gateway, capBytes } from '../src/gateway.js';
import { QuotaManager } from '../src/quota.js';
import { startGateway } from '../src/index.js';
import { loadConfig } from '../src/config.js';
import { PinnedSession, type Upstream, type UpstreamResult } from '../src/upstream.js';

const ALICE: Identity = { key: 'gh:1', githubId: 1, login: 'alice' };
const BOB: Identity = { key: 'gh:2', githubId: 2, login: 'bob' };

/** A daemon stand-in: one ready session, records every call it receives. */
class FakeUpstream implements Upstream {
  calls: Array<{ name: string; args: Record<string, unknown> }> = [];
  respond: (name: string, args: Record<string, unknown>) => unknown = (name) => ({ tool: name });
  sessions: Array<{ id: string; status: string; clientCount?: number }> = [];
  /** Answer create_session the way the daemon's dedup does: with an existing session. */
  dedupTo: { id: string; status: string; clientCount: number } | null = null;

  async call(name: string, args: Record<string, unknown>): Promise<UpstreamResult> {
    this.calls.push({ name, args });
    if (name === 'list_sessions') return { text: JSON.stringify(this.sessions), isError: false };
    if (name === 'create_session') {
      if (this.dedupTo) return { text: JSON.stringify(this.dedupTo), isError: false };
      const s = { id: 'sess-pinned-1', status: 'ready' };
      this.sessions.push(s);
      return { text: JSON.stringify(s), isError: false };
    }
    return { text: JSON.stringify(this.respond(name, args)), isError: false };
  }
}

function makeGateway(opts: { maxResponseBytes?: number; callsPerMinute?: number; costlyPerMinute?: number } = {}) {
  const upstream = new FakeUpstream();
  const session = new PinnedSession(upstream, {
    program: '/windows/lod/Game.exe', readyTimeoutMs: 1000, requireDedicatedUpstream: true,
  });
  let now = 0;
  const quota = new QuotaManager({
    callsPerMinute: opts.callsPerMinute ?? 60,
    costlyPerMinute: opts.costlyPerMinute ?? 6,
    maxConcurrentCostly: 2,
    now: () => now,
  });
  const lines: string[] = [];
  const gateway = new Gateway(session, quota, new AuditLog((l) => lines.push(l)), {
    maxResponseBytes: opts.maxResponseBytes ?? 256 * 1024,
    cheapTimeoutMs: 1000,
    costlyTimeoutMs: 1000,
  });
  return { upstream, gateway, lines, advance: (ms: number) => { now += ms; } };
}

describe('gateway call path', () => {
  it('pins every forwarded call to its own read-only session', async () => {
    const { upstream, gateway } = makeGateway();
    const res = await gateway.callTool(ALICE, 'list_functions', { limit: 5 });
    expect(res.isError).toBeUndefined();
    const create = upstream.calls.find((c) => c.name === 'create_session')!;
    expect(create.args).toMatchObject({ program: '/windows/lod/Game.exe', readOnly: true, autoAnalyze: false });
    const fwd = upstream.calls.filter((c) => c.name === 'list_functions');
    expect(fwd).toEqual([{ name: 'list_functions', args: { limit: 5, sessionId: 'sess-pinned-1' } }]);
  });

  it('never forwards a refused tool', async () => {
    const { upstream, gateway, lines } = makeGateway();
    for (const name of ['set_comment', 'get_logs', 'close_session', 'commit']) {
      const res = await gateway.callTool(ALICE, name, {});
      expect(res.isError).toBe(true);
    }
    const res = await gateway.callTool(ALICE, 'decompile', { name: 'main', sessionId: 'other' });
    expect(res.isError).toBe(true);
    expect(upstream.calls).toEqual([]);
    expect(lines.map((l) => JSON.parse(l).outcome)).toEqual(Array(5).fill('refused'));
  });

  it('refuses a startup on a daemon that already holds sessions', async () => {
    const upstream = new FakeUpstream();
    upstream.sessions.push({ id: 'someone-writable', status: 'ready' });
    const session = new PinnedSession(upstream, {
      program: '/windows/lod/Game.exe', readyTimeoutMs: 1000, requireDedicatedUpstream: true,
    });
    await expect(session.open()).rejects.toThrow(/daemon of its own/);
    expect(upstream.calls.map((c) => c.name)).toEqual(['list_sessions']);
  });

  it('refuses a session the daemon deduped onto an existing one', async () => {
    const upstream = new FakeUpstream();
    upstream.dedupTo = { id: 'shared-writable', status: 'ready', clientCount: 3 };
    const session = new PinnedSession(upstream, {
      program: '/windows/lod/Game.exe', readyTimeoutMs: 1000, requireDedicatedUpstream: false,
    });
    await expect(session.open()).rejects.toThrow(/existing session instead of a fresh one/);
  });

  it('stops serving when another client shows up on its daemon', async () => {
    const { upstream, gateway } = makeGateway();
    expect((await gateway.callTool(ALICE, 'get_program_info', {})).isError).toBeUndefined();
    const session = (gateway as unknown as { session: PinnedSession }).session;
    expect(await session.verifyIsolation()).toBe(true);
    upstream.sessions[0].clientCount = 2;
    expect(await session.verifyIsolation()).toBe(false);
    const before = upstream.calls.length;
    const res = await gateway.callTool(ALICE, 'get_program_info', {});
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/no longer isolated/);
    expect(upstream.calls.length).toBe(before);
  });

  it('exhausts the per-identity quota, separately for costly tools', async () => {
    const { gateway, advance } = makeGateway({ callsPerMinute: 5, costlyPerMinute: 2 });
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'a' })).isError).toBeUndefined();
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'b' })).isError).toBeUndefined();
    const costly = await gateway.callTool(ALICE, 'decompile', { name: 'c' });
    expect(costly.isError).toBe(true);
    expect(costly.content[0].text).toMatch(/costly tools/);
    // Cheap calls still have budget left: 5 total, 2 spent.
    for (let i = 0; i < 3; i++) {
      expect((await gateway.callTool(ALICE, 'get_program_info', {})).isError).toBeUndefined();
    }
    const cheap = await gateway.callTool(ALICE, 'get_program_info', {});
    expect(cheap.isError).toBe(true);
    expect(cheap.content[0].text).toMatch(/Rate limit reached; retry/);
    // Another identity is unaffected.
    expect((await gateway.callTool(BOB, 'decompile', { name: 'a' })).isError).toBeUndefined();
    // And the bucket refills.
    advance(60_000);
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'd' })).isError).toBeUndefined();
  });

  it('caps the response size with a clear marker', async () => {
    const { upstream, gateway, lines } = makeGateway({ maxResponseBytes: 2048 });
    upstream.respond = () => ({ pseudocode: 'x'.repeat(100_000) });
    const res = await gateway.callTool(ALICE, 'decompile', { name: 'big' });
    const text = res.content[0].text;
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(2048);
    expect(text).toMatch(/\[gateway: response truncated, \d+ of \d+ bytes shown/);
    const audit = JSON.parse(lines.at(-1)!);
    expect(audit).toMatchObject({ tool: 'decompile', outcome: 'ok', truncated: true, login: 'alice', githubId: 1 });
    expect(audit.argsHash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('never splits a multi-byte character when truncating', () => {
    const { text, truncated } = capBytes('é'.repeat(5000), 1000);
    expect(truncated).toBe(true);
    expect(text).not.toContain('�');
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(1000);
  });

  it('keeps the output format per caller and scrubs daemon identifiers', async () => {
    const { upstream, gateway } = makeGateway();
    upstream.respond = (_n, args) => ({ session: args.sessionId, url: 'ghidra://host:13100/Diablo2/windows/lod/Game.exe', n: 1 });
    await gateway.callTool(ALICE, 'set_output_format', { format: 'json' });
    const a = (await gateway.callTool(ALICE, 'get_program_info', {})).content[0].text;
    const b = (await gateway.callTool(BOB, 'get_program_info', {})).content[0].text;
    expect(JSON.parse(a)).toEqual({ session: '<session>', url: 'ghidra://<server>', n: 1 });
    expect(b).not.toMatch(/^\{/);
    expect(b).not.toContain('sess-pinned-1');
    expect(upstream.calls.some((c) => c.name === 'set_output_format')).toBe(false);
  });
});

describe('authentication', () => {
  const ghUser: FetchLike = vi.fn(async (_url, init) => {
    const ok = init.headers.Authorization === 'Bearer good-token';
    return { status: ok ? 200 : 401, json: async () => (ok ? { id: 42, login: 'octo' } : {}) };
  });

  it('requires a token by default', async () => {
    const auth = new Authenticator({
      allowAnonymous: false, cacheTtlMs: 60_000, negativeTtlMs: 60_000, githubApiUrl: 'https://gh', fetch: ghUser,
    });
    await expect(auth.authenticate(undefined, '1.2.3.4')).rejects.toMatchObject({ status: 401 });
    await expect(auth.authenticate('Basic abc', '1.2.3.4')).rejects.toBeInstanceOf(AuthError);
    await expect(auth.authenticate('Bearer bad-token', '1.2.3.4')).rejects.toMatchObject({ status: 401 });
  });

  it('identifies a GitHub user and caches by token hash', async () => {
    const fetch = vi.fn(ghUser);
    let now = 0;
    const auth = new Authenticator({
      allowAnonymous: false, cacheTtlMs: 1000, negativeTtlMs: 1000, githubApiUrl: 'https://gh', fetch, now: () => now,
    });
    expect(await auth.authenticate('Bearer good-token', 'x')).toEqual({ key: 'gh:42', githubId: 42, login: 'octo' });
    await auth.authenticate('Bearer good-token', 'x');
    expect(fetch).toHaveBeenCalledTimes(1);
    now = 2000;
    await auth.authenticate('Bearer good-token', 'x');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('says 503, not 401, when GitHub is unreachable', async () => {
    const auth = new Authenticator({
      allowAnonymous: false, cacheTtlMs: 1000, negativeTtlMs: 1000, githubApiUrl: 'https://gh',
      fetch: async () => { throw new Error('ECONNREFUSED'); },
    });
    await expect(auth.authenticate('Bearer t', 'x')).rejects.toMatchObject({ status: 503 });
  });

  it('allows anonymous callers only when switched on', async () => {
    const auth = new Authenticator({
      allowAnonymous: true, cacheTtlMs: 1000, negativeTtlMs: 1000, githubApiUrl: 'https://gh', fetch: ghUser,
    });
    expect(await auth.authenticate(undefined, '10.0.0.1')).toEqual({ key: 'anon:10.0.0.1', login: 'anonymous' });
  });
});

describe('HTTP surface', () => {
  async function start(env: Record<string, string>) {
    const upstream = new FakeUpstream();
    const lines: string[] = [];
    const fetch: FetchLike = async (_url, init) => {
      const ok = init.headers.Authorization === 'Bearer good-token';
      return { status: ok ? 200 : 401, json: async () => (ok ? { id: 7, login: 'carol' } : {}) };
    };
    const running = await startGateway(
      loadConfig({ GATEWAY_UPSTREAM_URL: 'http://unused', ...env }),
      { upstream, fetch, auditSink: (l) => lines.push(l) },
    );
    return { running, upstream, lines };
  }

  it('rejects an unauthenticated MCP request with 401', async () => {
    const { running, lines } = await start({ GATEWAY_PORT: '0' });
    try {
      const res = await fetch(`http://127.0.0.1:${running.port}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/^Bearer/);
      expect(JSON.parse(lines.at(-1)!).outcome).toBe('unauthenticated');
    } finally {
      await running.close();
    }
  });

  it('serves read-only tools over MCP to an authenticated caller and refuses writes', async () => {
    const { running, upstream, lines } = await start({ GATEWAY_PORT: '0' });
    const client = new Client({ name: 'test', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${running.port}/mcp`), {
      requestInit: { headers: { Authorization: 'Bearer good-token' } },
    }));
    try {
      const { tools } = await client.listTools();
      expect(tools.find((t) => t.name === 'set_comment')).toBeUndefined();
      expect(tools.every((t) => t.annotations?.readOnlyHint === true)).toBe(true);
      const ok = await client.callTool({ name: 'get_program_info', arguments: {} });
      expect(ok.isError).toBeFalsy();
      const refused = await client.callTool({ name: 'set_comment', arguments: { address: '0x1', comment: 'x' } });
      expect(refused.isError).toBe(true);
      expect(upstream.calls.some((c) => c.name === 'set_comment')).toBe(false);
      const audits = lines.map((l) => JSON.parse(l));
      expect(audits.find((a) => a.tool === 'set_comment')).toMatchObject({ outcome: 'refused', login: 'carol', githubId: 7 });
      expect(lines.join('\n')).not.toContain('good-token');
    } finally {
      await client.close();
      await running.close();
    }
  });
});
