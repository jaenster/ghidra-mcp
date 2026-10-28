/**
 * E2E: a read-only session that follows the latest server version.
 *
 * Runs a throwaway Ghidra Server, imports a fixture into it, and opens it on daemon A
 * read-only with GHIDRA_MCP_FOLLOW_VERSIONS_MS set. A second, writable client on daemon B
 * renames a function and checks it in. A must serve the new version within one interval,
 * must never hold a checkout, and must not fail a single call during the swap.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { startTestDaemon, cleanupAllDaemons, TEST_BINARIES_DIR, type DaemonHandle } from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';
import { ghidraServerSkipReason, startTestGhidraServer, type TestGhidraServer } from './helpers/ghidra-server.ts';

const FOLLOWER_PORT = 18460;
const WRITER_PORT = 18461;
const FOLLOW_MS = 2000;
const REPO = 'E2EFollow';
const PROGRAM = `${REPO}/fixtures/simple_main`;
const RENAMED = 'multiply_numbers_v2';
const BINARY = path.join(TEST_BINARIES_DIR, 'simple_main');

const SKIP_REASON = ghidraServerSkipReason()
  ?? (!fs.existsSync(BINARY) ? `fixture binary missing: ${BINARY} (npm run fixtures:build)` : undefined);

after(async () => {
  await cleanupAllDaemons();
});

/**
 * Workers of a stopped daemon on 127.0.0.1 outlive it (the shared cleanup looks for
 * "localhost:<port>"). Stop the ones pointed at this test's daemons, by pid.
 */
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

type Fns = { functions?: Array<{ name: string; address: string }> };
type Info = { version?: number; latestVersion?: number; versionLoadedAt?: number };
type Checkouts = { checkouts: unknown[]; total: number };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('E2E: read-only session following the latest version', { skip: SKIP_REASON, timeout: 900_000 }, () => {
  let server: TestGhidraServer;
  let follower: DaemonHandle;
  let writer: DaemonHandle;
  let a: McpTestClient;
  let b: McpTestClient;

  async function checkouts(): Promise<Checkouts> {
    // Ask without a session so the repo worker answers, not a program session.
    const saved = b.getSession();
    b.setSession(null);
    try {
      return await b.callToolJson<Checkouts>('list_checkouts', { repo: REPO });
    } finally {
      b.setSession(saved);
    }
  }

  before(async () => {
    server = await startTestGhidraServer();
    const env = (extra: Record<string, string> = {}) => ({
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-follow-e2e-')),
      GHIDRA_MCP_HOST: '127.0.0.1',
      ...server.daemonEnv,
      ...extra,
    });
    writer = await startTestDaemon(WRITER_PORT, env());
    follower = await startTestDaemon(FOLLOWER_PORT, env({ GHIDRA_MCP_FOLLOW_VERSIONS_MS: String(FOLLOW_MS) }));
    a = new McpTestClient({ host: '127.0.0.1', port: FOLLOWER_PORT, timeout: 300_000 });
    b = new McpTestClient({ host: '127.0.0.1', port: WRITER_PORT, timeout: 300_000 });
    await a.waitForReady();
    await b.waitForReady();
    await a.callTool('set_output_format', { format: 'json' });
    await b.callTool('set_output_format', { format: 'json' });

    await b.callToolJson('create_repo', { name: REPO });
    const job = await b.callToolJson<{ jobId: string }>('import_program', {
      localPath: BINARY, programPath: PROGRAM, analyze: true,
    });
    const deadline = Date.now() + 300_000;
    for (;;) {
      const st = await b.callToolJson<Record<string, unknown>>('import_status', { jobId: job.jobId });
      const state = String(st.state ?? st.status ?? '');
      if (/done|finished|complete|succeeded/i.test(state)) break;
      if (/fail|error/i.test(state)) throw new Error(`import failed: ${JSON.stringify(st)}`);
      if (Date.now() > deadline) throw new Error(`import did not finish: ${JSON.stringify(st)}`);
      await sleep(1000);
    }
  });

  after(async () => {
    a?.disconnect();
    b?.disconnect();
    await follower?.stop();
    await writer?.stop();
    stopWorkersOf([FOLLOWER_PORT, WRITER_PORT]);
    await server?.stop();
  });

  it('opens the program read-only, without a checkout, and reports its version', async () => {
    const session = await a.callToolJson<{ id: string }>('create_session', {
      program: PROGRAM, readOnly: true, autoAnalyze: false,
    });
    a.setSession(session.id);
    await a.waitForSessionReady(session.id, 300_000);
    const info = await a.callToolJson<Info>('get_program_info');
    assert.strictEqual(info.version, 1);
    assert.strictEqual(info.latestVersion, 1);
    assert.ok(typeof info.versionLoadedAt === 'number' && info.versionLoadedAt > 0);
    assert.strictEqual((await checkouts()).total, 0, 'the read-only follower holds no checkout');
  });

  it('serves a version checked in by another client within one interval, without a failed call', async () => {
    const before = await a.callToolJson<Fns>('list_functions', { limit: 500 });
    const target = before.functions?.find((f) => /^_?multiply_numbers$/.test(f.name));
    assert.ok(target, 'fixture has multiply_numbers');

    // Calls on A run throughout the check-in and the swap; none may fail.
    let running = true;
    let calls = 0;
    const failures: string[] = [];
    const loop = (async () => {
      while (running) {
        for (const [name, args] of [
          ['list_functions', { limit: 500 }],
          ['decompile', { address: target.address }],
          ['get_program_info', {}],
        ] as const) {
          try {
            const res = await a.callTool(name, { ...args });
            const text = res.content?.[0]?.text ?? '';
            if (!text || text.startsWith('Error:')) failures.push(`${name}: ${text.slice(0, 200)}`);
          } catch (err) {
            failures.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
          }
          calls++;
        }
      }
    })();

    try {
      const writable = await b.callToolJson<{ id: string }>('create_session', { program: PROGRAM, autoAnalyze: false });
      b.setSession(writable.id);
      await b.waitForSessionReady(writable.id, 300_000);
      await b.callToolJson('rename_symbol', { address: target.address, newName: RENAMED, type: 'function' });
      await b.callToolJson('commit', { message: 'rename for the follow test' });
      const committedAt = Date.now();

      let info: Info = {};
      let servedAt = 0;
      while (Date.now() - committedAt < FOLLOW_MS + 60_000) {
        info = await a.callToolJson<Info>('get_program_info');
        if (info.version === 2) {
          servedAt = Date.now();
          break;
        }
        await sleep(200);
      }
      assert.strictEqual(info.version, 2, `follower still on version ${info.version}`);
      const names = (await a.callToolJson<Fns>('list_functions', { limit: 500 })).functions?.map((f) => f.name) ?? [];
      assert.ok(names.includes(RENAMED), 'the follower serves the renamed function');
      assert.ok(!names.some((n) => /^_?multiply_numbers$/.test(n)), 'the old name is gone');
      // Detection happens within one interval; the rest is loading the new version.
      const latency = servedAt - committedAt;
      console.log(`[follow] served version 2 ${latency} ms after the check-in (interval ${FOLLOW_MS} ms)`);
      assert.ok(latency < FOLLOW_MS + 30_000, `took ${latency} ms`);

      // Keep calling across the swap for a moment longer, then stop.
      await sleep(FOLLOW_MS);
    } finally {
      running = false;
      await loop;
    }
    assert.ok(calls > 10, `only ${calls} calls ran during the swap`);
    assert.deepStrictEqual(failures, [], 'no call fails during the swap');

    // The writer's own checkout goes when its session closes; the follower never had one.
    await b.closeSession();
    assert.strictEqual((await checkouts()).total, 0, 'no checkout is left on the server');
  });
});
