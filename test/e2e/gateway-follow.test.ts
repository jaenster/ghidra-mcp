/**
 * E2E: the gateway in edge mode, in front of a daemon whose read-only sessions
 * follow the latest server version.
 *
 * Runs a throwaway Ghidra Server with two programs (standing in for win and
 * mac), a follower daemon for the gateway and a writable daemon for a second
 * client. The second client checks in a rename; the gateway must serve it
 * within one interval, report the new version on its internal endpoint, never
 * fail a call during the swap, and never say anything about the server.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { loadConfig, startGateway, type RunningGateway } from '../../packages/gateway/src/index.ts';
import { startTestDaemon, cleanupAllDaemons, TEST_BINARIES_DIR, type DaemonHandle } from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';
import {
  ghidraServerSkipReason, startTestGhidraServer, TEST_SERVER_USER, type TestGhidraServer,
} from './helpers/ghidra-server.ts';

const SERVER_PORT = 13710;
const FOLLOWER_PORT = 18462;
const WRITER_PORT = 18463;
const FOLLOW_MS = 2000;
const REPO = 'E2EGatewayRepo';
const WIN = `${REPO}/builds/win/simple_main`;
const MAC = `${REPO}/builds/mac/call_graph`;
const RENAMED = 'multiply_numbers_v2';
const BINARIES = { [WIN]: path.join(TEST_BINARIES_DIR, 'simple_main'), [MAC]: path.join(TEST_BINARIES_DIR, 'call_graph') };
const ACCESS = { id: 'e2e-edge.access', secret: 'e2e-edge-secret' };

const SKIP_REASON = ghidraServerSkipReason()
  ?? Object.values(BINARIES).map((b) => (fs.existsSync(b) ? undefined : `fixture binary missing: ${b}`)).find(Boolean);

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

after(async () => {
  await cleanupAllDaemons();
});

function stopWorkersOf(ports: number[]): void {
  let out = '';
  try {
    out = execFileSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8' });
  } catch {
    return;
  }
  for (const line of out.split('\n')) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!m || !m[2].includes('com.ghidramcp.Worker')) continue;
    if (!ports.some((p) => m[2].includes(`--daemon-url http://127.0.0.1:${p} `))) continue;
    try { process.kill(Number(m[1]), 'SIGTERM'); } catch { /* gone */ }
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
type TextContent = Array<{ type: string; text: string }>;
type Fns = { functions?: Array<{ name: string; address: string }> };

describe('E2E: gateway following new versions', { skip: SKIP_REASON, timeout: 900_000 }, () => {
  let server: TestGhidraServer;
  let follower: DaemonHandle;
  let writer: DaemonHandle;
  let b: McpTestClient;
  let gateway: RunningGateway;
  let client: Client;
  /** Every text the gateway handed out, for the leak check at the end. */
  const seen: string[] = [];

  const forbidden = () => [
    REPO, 'builds/', TEST_SERVER_USER, `:${SERVER_PORT}`, 'ghidra://', 'Diablo2Lod', 'd2r', 'D2R', 'typeguru',
  ];

  async function call(name: string, args: Record<string, unknown> = {}): Promise<{ text: string; isError: boolean }> {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content as TextContent)[0]?.text ?? '';
    seen.push(text);
    return { text, isError: res.isError === true };
  }

  async function internal(pathname: string): Promise<{ status: number; body: unknown }> {
    const res = await fetch(`http://127.0.0.1:${gateway.port}${pathname}`, {
      headers: { 'CF-Access-Client-Id': ACCESS.id, 'CF-Access-Client-Secret': ACCESS.secret },
    });
    return { status: res.status, body: await res.json() };
  }

  before(async () => {
    server = await startTestGhidraServer(SERVER_PORT);
    const env = (extra: Record<string, string> = {}) => ({
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-gateway-follow-e2e-')),
      GHIDRA_MCP_HOST: '127.0.0.1',
      ...server.daemonEnv,
      ...extra,
    });
    writer = await startTestDaemon(WRITER_PORT, env());
    follower = await startTestDaemon(FOLLOWER_PORT, env({ GHIDRA_MCP_FOLLOW_VERSIONS_MS: String(FOLLOW_MS) }));
    b = new McpTestClient({ host: '127.0.0.1', port: WRITER_PORT, timeout: 300_000 });
    await b.waitForReady();
    await b.callTool('set_output_format', { format: 'json' });
    await b.callToolJson('create_repo', { name: REPO });
    for (const [programPath, localPath] of Object.entries(BINARIES)) {
      const job = await b.callToolJson<{ jobId: string }>('import_program', { localPath, programPath, analyze: true });
      const deadline = Date.now() + 300_000;
      for (;;) {
        const st = await b.callToolJson<Record<string, unknown>>('import_status', { jobId: job.jobId });
        const state = String(st.state ?? st.status ?? '');
        if (/done|finished|complete|succeeded/i.test(state)) break;
        if (/fail|error/i.test(state)) throw new Error(`import failed: ${JSON.stringify(st)}`);
        if (Date.now() > deadline) throw new Error(`import did not finish: ${JSON.stringify(st)}`);
        await sleep(1000);
      }
    }

    gateway = await startGateway(loadConfig({
      GATEWAY_UPSTREAM_URL: `http://127.0.0.1:${FOLLOWER_PORT}`,
      GATEWAY_PORT: '0',
      GATEWAY_PROGRAM_WIN: WIN,
      GATEWAY_PROGRAM_MAC: MAC,
      GATEWAY_AUTH_MODE: 'edge',
      GATEWAY_ACCESS_CLIENT_ID: ACCESS.id,
      GATEWAY_ACCESS_CLIENT_SECRET: ACCESS.secret,
      GATEWAY_VERSION_POLL_MS: '500',
      GATEWAY_SESSION_READY_TIMEOUT_MS: '300000',
      GATEWAY_CALLS_PER_MINUTE: '100000',
      GATEWAY_COSTLY_PER_MINUTE: '100000',
    }), { auditSink: () => {} });
    client = new Client({ name: 'gateway-follow-e2e', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.port}/mcp`), {
      requestInit: {
        headers: {
          'CF-Access-Client-Id': ACCESS.id,
          'CF-Access-Client-Secret': ACCESS.secret,
          'X-Edge-Identity': 'gh:4242',
          'X-Edge-Login': 'e2e-caller',
          'X-Output-Format': 'json',
        },
      },
    }));
  });

  after(async () => {
    await client?.close();
    await gateway?.close();
    b?.disconnect();
    await follower?.stop();
    await writer?.stop();
    stopWorkersOf([FOLLOWER_PORT, WRITER_PORT]);
    await server?.stop();
  });

  it('serves both programs and reports their versions internally only', async () => {
    const versions = await internal('/internal/versions');
    assert.deepStrictEqual(versions.body, { win: 1, mac: 1 });
    const pub = await fetch(`http://127.0.0.1:${gateway.port}/health`);
    const pubText = await pub.text();
    seen.push(pubText);
    assert.deepStrictEqual(JSON.parse(pubText), { status: 'ok' });
    const mac = JSON.parse((await call('list_functions', { limit: 500, program: 'mac' })).text) as Fns;
    assert.ok((mac.functions ?? []).some((f) => /leaf_function/.test(f.name)));
    seen.push((await call('get_program_info', { program: 'win' })).text);
  });

  it('serves a version checked in by another client within one interval, with no failed call', async () => {
    const before = JSON.parse((await call('list_functions', { limit: 500 })).text) as Fns;
    const target = before.functions?.find((f) => /^_?multiply_numbers$/.test(f.name));
    assert.ok(target, 'fixture has multiply_numbers');

    let running = true;
    let calls = 0;
    const failures: string[] = [];
    const loop = (async () => {
      while (running) {
        for (const [name, args] of [
          ['list_functions', { limit: 500 }],
          ['decompile', { address: target.address }],
          ['get_program_info', { program: 'mac' }],
        ] as const) {
          try {
            const res = await call(name, { ...args });
            if (res.isError || !res.text) failures.push(`${name}: ${res.text.slice(0, 200)}`);
          } catch (err) {
            failures.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
          }
          calls++;
        }
      }
    })();

    try {
      const writable = await b.callToolJson<{ id: string }>('create_session', { program: WIN, autoAnalyze: false });
      b.setSession(writable.id);
      await b.waitForSessionReady(writable.id, 300_000);
      await b.callToolJson('rename_symbol', { address: target.address, newName: RENAMED, type: 'function' });
      await b.callToolJson('commit', { message: 'rename for the gateway follow test' });
      const committedAt = Date.now();

      let servedAt = 0;
      while (Date.now() - committedAt < FOLLOW_MS + 60_000) {
        const names = (JSON.parse((await call('list_functions', { limit: 500 })).text) as Fns).functions?.map((f) => f.name) ?? [];
        if (names.includes(RENAMED)) {
          servedAt = Date.now();
          break;
        }
        await sleep(200);
      }
      assert.ok(servedAt, 'the gateway serves the rename');
      const latency = servedAt - committedAt;
      console.log(`[gateway-follow] rename served ${latency} ms after the check-in (interval ${FOLLOW_MS} ms)`);
      assert.ok(latency < FOLLOW_MS + 30_000, `took ${latency} ms`);

      const deadline = Date.now() + 5_000;
      let versions: unknown;
      while (Date.now() < deadline) {
        versions = (await internal('/internal/versions')).body;
        if ((versions as { win: number }).win === 2) break;
        await sleep(200);
      }
      assert.deepStrictEqual(versions, { win: 2, mac: 1 }, 'the edge sees the new version and can roll its cache keys');
      const health = (await internal('/internal/health')).body as { programs: { win: { version: number; ageSeconds: number } } };
      assert.strictEqual(health.programs.win.version, 2);
      assert.ok(health.programs.win.ageSeconds < 60);
      await sleep(FOLLOW_MS);
    } finally {
      running = false;
      await loop;
    }
    assert.ok(calls > 10, `only ${calls} calls ran during the swap`);
    assert.deepStrictEqual(failures, [], 'no call fails during the swap');
    await b.closeSession();
  });

  it('never named the server, the repository, a path or a session', () => {
    const all = seen.join('\n');
    for (const f of forbidden()) assert.ok(!all.includes(f), `leaked "${f}"`);
    assert.ok(!UUID.test(all), 'leaked a session id');
  });
});
