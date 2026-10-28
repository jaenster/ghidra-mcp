import { describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, sign as rsaSign, type KeyObject } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { AuditLog } from '../src/audit.js';
import {
  AuthError, Authenticator, edgeIdentity, hasServiceToken, type FetchLike, type Identity,
} from '../src/auth.js';
import { Gateway, capBytes } from '../src/gateway.js';
import { QuotaManager } from '../src/quota.js';
import { startGateway } from '../src/index.js';
import { DEFAULT_PROGRAMS, loadConfig } from '../src/config.js';
import type { JwksFetch } from '../src/access-jwt.js';
import { PinnedSession, type Upstream, type UpstreamResult } from '../src/upstream.js';

const ALICE: Identity = { key: 'gh:1', githubId: 1, login: 'alice' };
const BOB: Identity = { key: 'gh:2', githubId: 2, login: 'bob' };

const WIN_PATH = 'Diablo2Lod/windows/lod/1.14d/Game.exe';
const MAC_PATH = 'Diablo2Lod/mac/intel/1.14d/DiabloII_macho';
/** Session ids are UUIDs on the real daemon; the fake uses the same shape. */
const SESSION_IDS: Record<string, string> = {
  [WIN_PATH]: '0b6f3c1e-1d2a-4c3b-9e8f-7a6b5c4d3e2f',
  [MAC_PATH]: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
};

/**
 * Strings that must never reach a caller: repository and program names, other
 * builds, other repositories, the server host. Session ids are checked by shape.
 */
const FORBIDDEN = [
  'Diablo2Lod', 'd2r', 'D2R', 'debug', 'A2Racer2', 'ClaudeVM', 'Factorio', 'SimTower', 'UT2004',
  'ghidra.typeguru.nl', 'typeguru', '/windows/', '/mac/', '1.14d/', 'ghidra://',
];
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function expectClean(text: string): void {
  for (const f of FORBIDDEN) expect(text, `leaked "${f}"`).not.toContain(f);
  expect(text).not.toMatch(UUID);
}

/** A daemon stand-in: one ready session per program, records every call it receives. */
class FakeUpstream implements Upstream {
  calls: Array<{ name: string; args: Record<string, unknown> }> = [];
  respond: (name: string, args: Record<string, unknown>) => unknown = (name) => ({ tool: name });
  /** When set, the next tool call fails with this daemon text. */
  failWith: string | null = null;
  sessions: Array<{ id: string; status: string; clientCount?: number; program?: string }> = [];
  versions: Record<string, number> = { [WIN_PATH]: 1757, [MAC_PATH]: 312 };
  /** Answer create_session the way the daemon's dedup does: with an existing session. */
  dedupTo: { id: string; status: string; clientCount: number } | null = null;

  async call(name: string, args: Record<string, unknown>): Promise<UpstreamResult> {
    this.calls.push({ name, args });
    if (name === 'list_sessions') return { text: JSON.stringify(this.sessions), isError: false };
    if (name === 'create_session') {
      if (this.dedupTo) return { text: JSON.stringify(this.dedupTo), isError: false };
      const program = String(args.program ?? args.binaryPath);
      const s = { id: SESSION_IDS[program] ?? `00000000-0000-4000-8000-${String(this.sessions.length).padStart(12, '0')}`, status: 'ready', program };
      this.sessions.push(s);
      return { text: JSON.stringify(s), isError: false };
    }
    if (this.failWith) return { text: this.failWith, isError: true };
    const program = this.sessions.find((s) => s.id === args.sessionId)?.program ?? '';
    if (name === 'get_program_info') {
      return {
        text: JSON.stringify({
          name: program.split('/').at(-1), path: `C:\\Users\\builder\\${program}`, format: 'PE', languageId: 'x86:LE:32:default',
          imageBase: '0x400000', pointerSize: 4, version: this.versions[program], latestVersion: this.versions[program],
          versionLoadedAt: 1_700_000_000_000,
        }),
        isError: false,
      };
    }
    return { text: JSON.stringify(this.respond(name, args)), isError: false };
  }
}

function pinned(upstream: Upstream, program: string, siblings: () => string[] = () => []) {
  return new PinnedSession(upstream, { program, readyTimeoutMs: 1000, requireDedicatedUpstream: true, siblings });
}

function makeGateway(opts: { maxResponseBytes?: number; callsPerMinute?: number; costlyPerMinute?: number } = {}) {
  const upstream = new FakeUpstream();
  const sessions: { win: PinnedSession; mac: PinnedSession } = {} as never;
  sessions.win = pinned(upstream, WIN_PATH, () => (sessions.mac.id ? [sessions.mac.id] : []));
  sessions.mac = pinned(upstream, MAC_PATH, () => (sessions.win.id ? [sessions.win.id] : []));
  let now = 0;
  const quota = new QuotaManager({
    callsPerMinute: opts.callsPerMinute ?? 60,
    costlyPerMinute: opts.costlyPerMinute ?? 6,
    maxConcurrentCostly: 2,
    now: () => now,
  });
  const lines: string[] = [];
  const gateway = new Gateway(sessions, quota, new AuditLog((l) => lines.push(l)), {
    maxResponseBytes: opts.maxResponseBytes ?? 256 * 1024,
    cheapTimeoutMs: 1000,
    costlyTimeoutMs: 1000,
  });
  return { upstream, gateway, sessions, lines, advance: (ms: number) => { now += ms; } };
}

describe('configuration', () => {
  it('pins 1.14d Windows and Mac by default', () => {
    const config = loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x' });
    expect(config.programs).toEqual({ win: { program: WIN_PATH }, mac: { program: MAC_PATH } });
    expect(DEFAULT_PROGRAMS.win.program).toBe(WIN_PATH);
  });

  it('refuses edge mode without a service token, and anonymous access in edge mode', () => {
    expect(() => loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', GATEWAY_AUTH_MODE: 'edge' })).toThrow(/ACCESS_CLIENT/);
    expect(() => loadConfig({
      GATEWAY_UPSTREAM_URL: 'http://x', GATEWAY_AUTH_MODE: 'edge', GATEWAY_ACCESS_CLIENT_ID: 'a',
      GATEWAY_ACCESS_CLIENT_SECRET: 'b', GATEWAY_ALLOW_ANONYMOUS: '1',
    })).toThrow(/ANONYMOUS/);
    expect(() => loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', GATEWAY_ACCESS_CLIENT_ID: 'a' })).toThrow(/together/);
  });
});

describe('gateway call path', () => {
  it('pins every forwarded call to the read-only session of the chosen program', async () => {
    const { upstream, gateway } = makeGateway();
    expect((await gateway.callTool(ALICE, 'list_functions', { limit: 5 })).isError).toBeUndefined();
    expect((await gateway.callTool(ALICE, 'list_functions', { limit: 5, program: 'mac' })).isError).toBeUndefined();
    const creates = upstream.calls.filter((c) => c.name === 'create_session');
    expect(creates.map((c) => c.args)).toEqual([
      { program: WIN_PATH, readOnly: true, autoAnalyze: false },
      { program: MAC_PATH, readOnly: true, autoAnalyze: false },
    ]);
    const fwd = upstream.calls.filter((c) => c.name === 'list_functions');
    expect(fwd).toEqual([
      { name: 'list_functions', args: { limit: 5, sessionId: SESSION_IDS[WIN_PATH] } },
      { name: 'list_functions', args: { limit: 5, sessionId: SESSION_IDS[MAC_PATH] } },
    ]);
  });

  it('refuses a program that is not one of the public names', async () => {
    const { upstream, gateway } = makeGateway();
    for (const program of ['/windows/d2r/Game.exe', WIN_PATH, 'WIN', 'debug_d2r', 1]) {
      const res = await gateway.callTool(ALICE, 'decompile', { name: 'main', program });
      expect(res.isError).toBe(true);
      expectClean(res.content[0].text);
    }
    expect(upstream.calls).toEqual([]);
  });

  it('never forwards a refused tool', async () => {
    const { upstream, gateway, lines } = makeGateway();
    for (const name of ['set_comment', 'get_logs', 'close_session', 'commit', 'list_programs', 'query_links']) {
      const res = await gateway.callTool(ALICE, name, {});
      expect(res.isError).toBe(true);
    }
    const res = await gateway.callTool(ALICE, 'decompile', { name: 'main', sessionId: 'other' });
    expect(res.isError).toBe(true);
    expect(upstream.calls).toEqual([]);
    expect(lines.map((l) => JSON.parse(l).outcome)).toEqual(Array(7).fill('refused'));
  });

  it('refuses a startup on a daemon that already holds sessions', async () => {
    const upstream = new FakeUpstream();
    upstream.sessions.push({ id: 'someone-writable', status: 'ready' });
    await expect(pinned(upstream, WIN_PATH).open()).rejects.toThrow(/daemon of its own/);
    expect(upstream.calls.map((c) => c.name)).toEqual(['list_sessions']);
  });

  it('accepts its own sibling session but no other', async () => {
    const { upstream, sessions } = makeGateway();
    await sessions.win.open();
    await sessions.mac.open();
    expect(await sessions.win.verifyIsolation()).toBe(true);
    expect(await sessions.mac.verifyIsolation()).toBe(true);
    upstream.sessions.push({ id: 'intruder', status: 'ready' });
    expect(await sessions.mac.verifyIsolation()).toBe(false);
  });

  it('refuses a session the daemon deduped onto an existing one', async () => {
    const upstream = new FakeUpstream();
    upstream.dedupTo = { id: 'shared-writable', status: 'ready', clientCount: 3 };
    const session = new PinnedSession(upstream, { program: WIN_PATH, readyTimeoutMs: 1000, requireDedicatedUpstream: false });
    await expect(session.open()).rejects.toThrow(/existing session instead of a fresh one/);
  });

  it('stops serving when another client shows up on its daemon, without saying why', async () => {
    const { upstream, gateway, sessions } = makeGateway();
    expect((await gateway.callTool(ALICE, 'get_program_info', {})).isError).toBeUndefined();
    expect(await sessions.win.verifyIsolation()).toBe(true);
    upstream.sessions[0].clientCount = 2;
    expect(await sessions.win.verifyIsolation()).toBe(false);
    const before = upstream.calls.length;
    const res = await gateway.callTool(ALICE, 'get_program_info', {});
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toBe('Error: This server is not serving right now.');
    expect(upstream.calls.length).toBe(before);
  });

  it('reads the served version from the worker and notices a new one', async () => {
    const { upstream, sessions } = makeGateway();
    expect((await sessions.win.refreshVersion()).version).toBe(1757);
    upstream.versions[WIN_PATH] = 1758;
    expect((await sessions.win.refreshVersion()).version).toBe(1758);
    expect(sessions.mac.servedVersion).toBeNull();
  });

  it('exhausts the per-identity quota, separately for costly tools', async () => {
    const { gateway, advance } = makeGateway({ callsPerMinute: 5, costlyPerMinute: 2 });
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'a' })).isError).toBeUndefined();
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'b' })).isError).toBeUndefined();
    const costly = await gateway.callTool(ALICE, 'decompile', { name: 'c' });
    expect(costly.isError).toBe(true);
    expect(costly.content[0].text).toMatch(/costly tools/);
    for (let i = 0; i < 3; i++) {
      expect((await gateway.callTool(ALICE, 'list_functions', {})).isError).toBeUndefined();
    }
    const cheap = await gateway.callTool(ALICE, 'list_functions', {});
    expect(cheap.isError).toBe(true);
    expect(cheap.content[0].text).toMatch(/Rate limit reached; retry/);
    expect((await gateway.callTool(BOB, 'decompile', { name: 'a' })).isError).toBeUndefined();
    advance(60_000);
    expect((await gateway.callTool(ALICE, 'decompile', { name: 'd' })).isError).toBeUndefined();
  });

  it('caps the response size with a clear marker', async () => {
    const { upstream, gateway, lines } = makeGateway({ maxResponseBytes: 2048 });
    upstream.respond = () => ({ pseudocode: 'x'.repeat(100_000) });
    const res = await gateway.callTool(ALICE, 'decompile', { name: 'big' });
    const text = res.content[0].text;
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(2048);
    expect(text).toMatch(/\[truncated: \d+ of \d+ bytes shown/);
    const audit = JSON.parse(lines.at(-1)!);
    expect(audit).toMatchObject({ tool: 'decompile', program: 'win', outcome: 'ok', truncated: true, login: 'alice', githubId: 1 });
    expect(audit.argsHash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('never splits a multi-byte character when truncating', () => {
    const { text, truncated } = capBytes('é'.repeat(5000), 1000);
    expect(truncated).toBe(true);
    expect(text).not.toContain('�');
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(1000);
  });

  it('keeps the output format per caller, and an edge-chosen format overrides it', async () => {
    const { gateway } = makeGateway();
    await gateway.callTool(ALICE, 'set_output_format', { format: 'json' });
    const a = (await gateway.callTool(ALICE, 'list_functions', {})).content[0].text;
    const b = (await gateway.callTool(BOB, 'list_functions', {})).content[0].text;
    const c = (await gateway.callTool(BOB, 'list_functions', {}, { format: 'json' })).content[0].text;
    expect(JSON.parse(a)).toEqual({ tool: 'list_functions' });
    expect(b).not.toMatch(/^\{/);
    expect(JSON.parse(c)).toEqual({ tool: 'list_functions' });
  });
});

describe('no intel about the server', () => {
  it('get_program_info answers only what is in the binary', async () => {
    const { gateway } = makeGateway();
    await gateway.callTool(ALICE, 'set_output_format', { format: 'json' });
    for (const program of ['win', 'mac']) {
      const text = (await gateway.callTool(ALICE, 'get_program_info', { program })).content[0].text;
      const info = JSON.parse(text);
      expect(Object.keys(info).sort()).toEqual(['format', 'imageBase', 'languageId', 'name', 'pointerSize']);
      expectClean(text);
    }
  });

  it('strips server keys at any depth and redacts names, hosts, paths and session ids', async () => {
    const { upstream, gateway, lines } = makeGateway();
    upstream.respond = (_n, args) => ({
      functions: [{ name: 'main', programPath: '/windows/d2r/Game.exe', sessionId: args.sessionId }],
      comment: `seen in D2R 3.0.91923 too\nsee ghidra://ghidra.typeguru.nl:13100/Diablo2Lod/windows/lod/1.14d/Game.exe`,
      note: `session ${String(args.sessionId)} on A2Racer2, debug_d2r, /Users/jaenster/notes.txt and docs/data/x.tsv`,
      plate: 'Hellfire STORM.PDB ___D2_REVERSE 01HZX3K8Q9ABCDEFGHJKMNPQRS',
      bytes: '4D5A90000300000004000000FFFF0000B8',
    });
    await gateway.callTool(ALICE, 'set_output_format', { format: 'json' });
    const text = (await gateway.callTool(ALICE, 'list_functions', {})).content[0].text;
    expectClean(text);
    for (const s of ['3.0.91923', 'Hellfire', 'STORM.PDB', '___D2_REVERSE', '/Users/', 'docs/data/', '01HZX3K8Q9ABCDEFGHJKMNPQRS']) {
      expect(text).not.toContain(s);
    }
    expect(text).toContain('4D5A90000300000004000000FFFF0000B8');
    expect(text).toContain('main');
    expect(JSON.parse(lines.at(-1)!).redactions).toBeGreaterThan(0);
  });

  it('maps daemon errors to generic messages', async () => {
    const { upstream, gateway } = makeGateway();
    const cases: Array<[string, string]> = [
      [`Error: Function not found: foo in session ${SESSION_IDS[WIN_PATH]} (/windows/d2r/Game.exe)`, 'Error: Not found in this program.'],
      ['Error: Invalid address "zz" for program Diablo2Lod/windows/lod/1.14d/Game.exe', 'Error: Invalid arguments for this tool.'],
      ['Error: Decompile timed out after 60s on worker 8c1f at ghidra.typeguru.nl', 'Error: The call took too long; narrow it and try again.'],
      ['Error: java.lang.NullPointerException at UT2004 /Users/x', 'Error: The call failed.'],
    ];
    for (const [daemon, shown] of cases) {
      upstream.failWith = daemon;
      const res = await gateway.callTool(ALICE, 'decompile', { name: 'foo' });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toBe(shown);
    }
  });

  it('the tool list names no path, repository or session', async () => {
    const { gateway } = makeGateway();
    const text = JSON.stringify(gateway.listTools());
    for (const f of ['Diablo2Lod', 'A2Racer2', 'typeguru', 'sessionId']) expect(text).not.toContain(f);
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

describe('service token', () => {
  const ID = 'abc.access';
  const SECRET = 's3cret-value';

  it('accepts only both halves, exactly', () => {
    expect(hasServiceToken({ 'cf-access-client-id': ID, 'cf-access-client-secret': SECRET }, ID, SECRET)).toBe(true);
    expect(hasServiceToken({ 'cf-access-client-id': ID }, ID, SECRET)).toBe(false);
    expect(hasServiceToken({ 'cf-access-client-secret': SECRET }, ID, SECRET)).toBe(false);
    expect(hasServiceToken({ 'cf-access-client-id': ID, 'cf-access-client-secret': 's3cret-valuE' }, ID, SECRET)).toBe(false);
    expect(hasServiceToken({ 'cf-access-client-id': 'x', 'cf-access-client-secret': SECRET }, ID, SECRET)).toBe(false);
    expect(hasServiceToken({ 'cf-access-client-id': [ID, ID], 'cf-access-client-secret': SECRET }, ID, SECRET)).toBe(false);
  });

  it('parses only a well-formed edge identity', () => {
    expect(edgeIdentity({ 'x-edge-identity': 'gh:42', 'x-edge-login': 'octo-cat' }))
      .toEqual({ key: 'gh:42', githubId: 42, login: 'octo-cat' });
    for (const [id, login] of [['gh:0', 'a'], ['anon:1.2.3.4', 'a'], ['gh:42', 'bad login'], ['gh:42x', 'a'], ['gh:42', '']]) {
      expect(edgeIdentity({ 'x-edge-identity': id, 'x-edge-login': login })).toBeNull();
    }
  });
});

describe('HTTP surface', () => {
  const ACCESS = { GATEWAY_ACCESS_CLIENT_ID: 'edge-id.access', GATEWAY_ACCESS_CLIENT_SECRET: 'edge-secret' };
  const TOKEN_HEADERS = { 'CF-Access-Client-Id': 'edge-id.access', 'CF-Access-Client-Secret': 'edge-secret' };
  const MCP_HEADERS = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };

  async function start(env: Record<string, string>, extra: { jwksFetch?: JwksFetch } = {}) {
    const upstream = new FakeUpstream();
    const lines: string[] = [];
    const fetch: FetchLike = async (_url, init) => {
      const ok = init.headers.Authorization === 'Bearer good-token';
      return { status: ok ? 200 : 401, json: async () => (ok ? { id: 7, login: 'carol' } : {}) };
    };
    const running = await startGateway(
      loadConfig({ GATEWAY_UPSTREAM_URL: 'http://unused', GATEWAY_PORT: '0', ...env }),
      { upstream, fetch, auditSink: (l) => lines.push(l), ...extra },
    );
    return { running, upstream, lines, base: `http://127.0.0.1:${running.port}` };
  }

  function rpc(method: string, params: unknown = {}) {
    return JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
  }

  it('rejects an unauthenticated MCP request with 401', async () => {
    const { running, lines, base } = await start({});
    try {
      const res = await fetch(`${base}/mcp`, { method: 'POST', headers: MCP_HEADERS, body: rpc('tools/list') });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/^Bearer/);
      expect(JSON.parse(lines.at(-1)!).outcome).toBe('unauthenticated');
    } finally {
      await running.close();
    }
  });

  it('serves read-only tools over MCP to an authenticated caller and refuses writes', async () => {
    const { running, upstream, lines, base } = await start({});
    const client = new Client({ name: 'test', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
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

  it('public /health says ok and nothing else', async () => {
    const { running, base } = await start(ACCESS);
    try {
      const res = await fetch(`${base}/health`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(JSON.parse(text)).toEqual({ status: 'ok' });
      expectClean(text + JSON.stringify([...res.headers]));
    } finally {
      await running.close();
    }
  });

  it('with a service token configured, refuses everything without it', async () => {
    const { running, upstream, base } = await start(ACCESS);
    try {
      const before = upstream.calls.length;
      for (const [path, init] of [
        ['/mcp', { method: 'POST', headers: { ...MCP_HEADERS, Authorization: 'Bearer good-token' }, body: rpc('tools/list') }],
        ['/internal/versions', {}],
        ['/internal/health', {}],
        ['/mcp', { method: 'POST', headers: { ...MCP_HEADERS, 'CF-Access-Client-Id': 'edge-id.access', 'CF-Access-Client-Secret': 'guess' }, body: rpc('tools/list') }],
      ] as const) {
        const res = await fetch(`${base}${path}`, init as RequestInit);
        expect(res.status).toBe(403);
        expectClean(await res.text());
      }
      expect(upstream.calls.length).toBe(before);
    } finally {
      await running.close();
    }
  });

  it('reports versions and their age only behind the token', async () => {
    const { running, upstream, base } = await start(ACCESS);
    try {
      const v = await fetch(`${base}/internal/versions`, { headers: TOKEN_HEADERS });
      expect(await v.json()).toEqual({ win: 1757, mac: 312 });
      const h = await fetch(`${base}/internal/health`, { headers: TOKEN_HEADERS });
      const body = await h.json() as { status: string; programs: Record<string, { version: number; ageSeconds: number }> };
      expect(body.status).toBe('ok');
      expect(body.programs.win.version).toBe(1757);
      expect(body.programs.win.ageSeconds).toBeGreaterThan(0);
      upstream.versions[WIN_PATH] = 1758;
      await running.sessions.win.refreshVersion();
      expect(await (await fetch(`${base}/internal/versions`, { headers: TOKEN_HEADERS })).json()).toEqual({ win: 1758, mac: 312 });
    } finally {
      await running.close();
    }
  });

  it('in edge mode takes the identity from the edge, only with the token', async () => {
    const { running, lines, base } = await start({ ...ACCESS, GATEWAY_AUTH_MODE: 'edge' });
    try {
      const noIdentity = await fetch(`${base}/mcp`, { method: 'POST', headers: { ...MCP_HEADERS, ...TOKEN_HEADERS }, body: rpc('tools/list') });
      expect(noIdentity.status).toBe(401);
      const forged = await fetch(`${base}/mcp`, {
        method: 'POST', headers: { ...MCP_HEADERS, 'X-Edge-Identity': 'gh:9', 'X-Edge-Login': 'mallory' }, body: rpc('tools/list'),
      });
      expect(forged.status).toBe(403);

      const client = new Client({ name: 'edge', version: '1.0.0' });
      await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { ...TOKEN_HEADERS, 'X-Edge-Identity': 'gh:99', 'X-Edge-Login': 'dave', 'X-Output-Format': 'json' } },
      }));
      try {
        const res = await client.callTool({ name: 'get_program_info', arguments: { program: 'mac' } });
        const text = (res.content as Array<{ text: string }>)[0].text;
        expect(JSON.parse(text).name).toBe('DiabloII_macho');
        expectClean(text);
      } finally {
        await client.close();
      }
      expect(lines.map((l) => JSON.parse(l)).find((a) => a.tool === 'get_program_info'))
        .toMatchObject({ identity: 'gh:99', login: 'dave', program: 'mac', outcome: 'ok' });
    } finally {
      await running.close();
    }
  });

  describe('Access JWT check', () => {
    const TEAM = 'https://example-team.cloudflareaccess.com';
    const AUD = 'a1b2c3d4e5f6';
    const TOKEN_ID = 'edge-id.access';
    const JWT_ENV = {
      GATEWAY_AUTH_MODE: 'edge', GATEWAY_ACCESS_TEAM_DOMAIN: TEAM, GATEWAY_ACCESS_AUD: AUD,
      GATEWAY_ACCESS_SERVICE_TOKEN_ID: TOKEN_ID,
    };
    const signing = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const stranger = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = { ...signing.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
    let certFetches = 0;
    const jwksFetch: JwksFetch = async (url) => {
      certFetches++;
      expect(url).toBe(`${TEAM}/cdn-cgi/access/certs`);
      return { status: 200, json: async () => ({ keys: [jwk] }) };
    };

    function jwt(claims: Record<string, unknown>, key: KeyObject = signing.privateKey, kid = 'k1'): string {
      const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
      const body = `${enc({ alg: 'RS256', kid, typ: 'JWT' })}.${enc(claims)}`;
      return `${body}.${rsaSign('RSA-SHA256', Buffer.from(body), key).toString('base64url')}`;
    }
    const now = () => Math.floor(Date.now() / 1000);
    const good = () => ({ iss: TEAM, aud: [AUD], exp: now() + 300, iat: now(), nbf: now() - 1, common_name: TOKEN_ID, type: 'app' });

    it('needs both team domain and audience, and a real team domain', () => {
      expect(() => loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', GATEWAY_ACCESS_TEAM_DOMAIN: TEAM })).toThrow(/together/);
      expect(() => loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', GATEWAY_ACCESS_TEAM_DOMAIN: 'https://evil.example', GATEWAY_ACCESS_AUD: AUD }))
        .toThrow(/cloudflareaccess/);
      expect(() => loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', ...JWT_ENV, GATEWAY_ACCESS_CLIENT_ID: 'a', GATEWAY_ACCESS_CLIENT_SECRET: 'b' }))
        .toThrow(/not both/);
      expect(loadConfig({ GATEWAY_UPSTREAM_URL: 'http://x', ...JWT_ENV }).accessJwt)
        .toEqual({ teamDomain: TEAM, audience: AUD, serviceTokenId: TOKEN_ID });
    });

    it('refuses requests without a valid token for this application', async () => {
      const { running, upstream, base } = await start(JWT_ENV, { jwksFetch });
      try {
        const before = upstream.calls.length;
        const bad = [
          undefined,
          'not.a.jwt',
          jwt({ ...good(), aud: ['other-app'] }),
          jwt({ ...good(), iss: 'https://other-team.cloudflareaccess.com' }),
          jwt({ ...good(), exp: now() - 3600 }),
          jwt({ ...good(), nbf: now() + 3600 }),
          jwt({ ...good(), common_name: 'someone-else.access' }),
          jwt({ ...good(), common_name: undefined, email: 'user@example.com' }),
          jwt(good(), stranger.privateKey),
          jwt(good(), signing.privateKey, 'unknown-kid'),
          // The plain service token headers are not enough in this mode.
          undefined,
        ];
        for (const [i, token] of bad.entries()) {
          const headers: Record<string, string> = {
            ...MCP_HEADERS, 'X-Edge-Identity': 'gh:9', 'X-Edge-Login': 'mallory',
            ...(i === bad.length - 1 ? TOKEN_HEADERS : {}),
          };
          if (token) headers['Cf-Access-Jwt-Assertion'] = token;
          const res = await fetch(`${base}/mcp`, { method: 'POST', headers, body: rpc('tools/list') });
          expect(res.status, `case ${i}`).toBe(403);
          expectClean(await res.text());
        }
        expect((await fetch(`${base}/internal/versions`)).status).toBe(403);
        expect(upstream.calls.length).toBe(before);
        expect((await fetch(`${base}/health`)).status).toBe(200);
      } finally {
        await running.close();
      }
    });

    it('takes the edge identity with a valid token, and fetches keys once', async () => {
      certFetches = 0;
      const { running, lines, base } = await start(JWT_ENV, { jwksFetch });
      try {
        const v = await fetch(`${base}/internal/versions`, { headers: { 'Cf-Access-Jwt-Assertion': jwt(good()) } });
        expect(await v.json()).toEqual({ win: 1757, mac: 312 });
        const client = new Client({ name: 'edge', version: '1.0.0' });
        await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
          requestInit: { headers: { 'Cf-Access-Jwt-Assertion': jwt(good()), 'X-Edge-Identity': 'gh:99', 'X-Edge-Login': 'dave' } },
        }));
        try {
          const res = await client.callTool({ name: 'get_program_info', arguments: {} });
          expect(res.isError).toBeFalsy();
        } finally {
          await client.close();
        }
        expect(lines.map((l) => JSON.parse(l)).find((a) => a.tool === 'get_program_info'))
          .toMatchObject({ identity: 'gh:99', login: 'dave', outcome: 'ok' });
        expect(certFetches).toBe(1);
      } finally {
        await running.close();
      }
    });
  });
});
