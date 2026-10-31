/**
 * E2E: sessions survive a Ghidra Server restart.
 *
 * A restarted server forgets every RMI object, so the stubs a worker holds die: reads that
 * page from the server fail with NoSuchObjectException and a check-in fails with "Not
 * connected to repository server". This opens a read-only session and a writable one with
 * an edit that is not checked in yet, restarts the server process on the same repositories,
 * and requires that reads work again, that the edit can still be checked in, and that a
 * worker left alone recovers on its own probe before anyone calls it.
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

const READER_PORT = 18470;
const WRITER_PORT = 18471;
const PROBED_PORT = 18472;
const PROBE_MS = 1500;
const REPO = 'E2ERestart';
const PROGRAM = `${REPO}/fixtures/simple_main`;
const RENAMED = 'multiply_numbers_after_restart';
const BINARY = path.join(TEST_BINARIES_DIR, 'simple_main');

const SKIP_REASON = ghidraServerSkipReason()
  ?? (!fs.existsSync(BINARY) ? `fixture binary missing: ${BINARY} (npm run fixtures:build)` : undefined);

after(async () => {
  await cleanupAllDaemons();
});

/** Workers of a stopped daemon on 127.0.0.1 outlive it; stop the ones pointed at this test's daemons. */
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
type Checkouts = { checkouts: unknown[]; total: number };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The text of a call, failing the test with the error text when the call reports one. */
async function ok(client: McpTestClient, name: string, args: Record<string, unknown> = {}): Promise<string> {
  const res = await client.callTool(name, args);
  const text = res.content?.[0]?.text ?? '';
  assert.ok(text && !text.startsWith('Error:'), `${name} failed: ${text.slice(0, 500)}`);
  return text;
}

describe('E2E: sessions survive a Ghidra Server restart', { skip: SKIP_REASON, timeout: 900_000 }, () => {
  let server: TestGhidraServer;
  let readerDaemon: DaemonHandle;
  let writerDaemon: DaemonHandle;
  let probedDaemon: DaemonHandle;
  let reader: McpTestClient;
  let writer: McpTestClient;
  let probed: McpTestClient;
  let target: { name: string; address: string };

  async function open(client: McpTestClient, readOnly: boolean): Promise<void> {
    const session = await client.callToolJson<{ id: string }>('create_session', {
      program: PROGRAM, readOnly, autoAnalyze: false,
    });
    client.setSession(session.id);
    await client.waitForSessionReady(session.id, 300_000);
  }

  before(async () => {
    server = await startTestGhidraServer();
    const env = (probeMs: number) => ({
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-restart-e2e-')),
      GHIDRA_MCP_HOST: '127.0.0.1',
      GHIDRA_MCP_SERVER_PROBE_MS: String(probeMs),
      ...server.daemonEnv,
    });
    // Probing off on two daemons, so their recovery can only come from the failed call itself.
    readerDaemon = await startTestDaemon(READER_PORT, env(0));
    writerDaemon = await startTestDaemon(WRITER_PORT, env(0));
    probedDaemon = await startTestDaemon(PROBED_PORT, env(PROBE_MS));
    reader = new McpTestClient({ host: '127.0.0.1', port: READER_PORT, timeout: 300_000 });
    writer = new McpTestClient({ host: '127.0.0.1', port: WRITER_PORT, timeout: 300_000 });
    probed = new McpTestClient({ host: '127.0.0.1', port: PROBED_PORT, timeout: 300_000 });
    for (const c of [reader, writer, probed]) {
      await c.waitForReady();
      await c.callTool('set_output_format', { format: 'json' });
    }

    await writer.callToolJson('create_repo', { name: REPO });
    const job = await writer.callToolJson<{ jobId: string }>('import_program', {
      localPath: BINARY, programPath: PROGRAM, analyze: true,
    });
    const deadline = Date.now() + 300_000;
    for (;;) {
      const st = await writer.callToolJson<Record<string, unknown>>('import_status', { jobId: job.jobId });
      const state = String(st.state ?? st.status ?? '');
      if (/done|finished|complete|succeeded/i.test(state)) break;
      if (/fail|error/i.test(state)) throw new Error(`import failed: ${JSON.stringify(st)}`);
      if (Date.now() > deadline) throw new Error(`import did not finish: ${JSON.stringify(st)}`);
      await sleep(1000);
    }

    await open(reader, true);
    await open(probed, true);
    await open(writer, false);
    const fns = await reader.callToolJson<Fns>('list_functions', { limit: 500 });
    const found = fns.functions?.find((f) => /^_?multiply_numbers$/.test(f.name));
    assert.ok(found, 'fixture has multiply_numbers');
    target = found;
    await ok(reader, 'decompile', { address: target.address });
    await ok(probed, 'decompile', { address: target.address });
    // An edit that exists only in the writer's checkout when the server goes away.
    await writer.callToolJson('rename_symbol', { address: target.address, newName: RENAMED, type: 'function' });

    await server.restart();
  });

  after(async () => {
    reader?.disconnect();
    writer?.disconnect();
    probed?.disconnect();
    await readerDaemon?.stop();
    await writerDaemon?.stop();
    await probedDaemon?.stop();
    stopWorkersOf([READER_PORT, WRITER_PORT, PROBED_PORT]);
    await server?.stop();
  });

  it('a read-only session reads again on the first call after the restart', async () => {
    await ok(reader, 'decompile', { address: target.address });
    await ok(reader, 'list_functions', { limit: 500 });
    await ok(reader, 'search', { type: 'strings', pattern: '.' });
  });

  it('a writable session checks in the edit it made before the restart', async () => {
    const committed = await ok(writer, 'commit', { message: 'rename made before the server restart' });
    assert.ok(!/nothing to commit/i.test(committed), `commit did not check anything in: ${committed}`);
    // A read-only session opened now, on a daemon that has none to reuse, reads version 2.
    const fresh = new McpTestClient({ host: '127.0.0.1', port: WRITER_PORT, timeout: 300_000 });
    await fresh.callTool('set_output_format', { format: 'json' });
    await open(fresh, true);
    const names = (await fresh.callToolJson<Fns>('list_functions', { limit: 500 })).functions?.map((f) => f.name) ?? [];
    assert.ok(names.includes(RENAMED), 'the checked-in rename is on the server');
    await fresh.closeSession();
    fresh.disconnect();
  });

  it('a worker nobody calls recovers on its own probe', async () => {
    // The probe has had several intervals since the restart; the first call must not
    // need a recovery of its own, so it answers quickly.
    await sleep(PROBE_MS * 3);
    const started = Date.now();
    await ok(probed, 'search', { type: 'strings', pattern: '.' });
    await ok(probed, 'decompile', { address: target.address });
    console.log(`[restart] first call on the probed worker took ${Date.now() - started} ms`);
  });

  it('leaves no checkout behind once the writer closes', async () => {
    await writer.closeSession();
    writer.setSession(null);
    const res = await writer.callToolJson<Checkouts>('list_checkouts', { repo: REPO });
    assert.strictEqual(res.total, 0, `checkouts left: ${JSON.stringify(res.checkouts)}`);
  });
});
