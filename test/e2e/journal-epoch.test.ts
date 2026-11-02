/**
 * E2E: the change journal's epoch and the check-in boundary.
 *
 * Sequence numbers are only meaningful within one journal. When a worker's project
 * directory goes (an emptyDir with its pod), the next journal starts again at 1, and a
 * consumer holding seq N used to drop everything up to N as "already seen". The epoch makes
 * that a detectable event. A check-in is the other boundary a consumer needs and Ghidra's
 * change records do not carry: `version.committed`.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  cleanupAllDaemons,
  TEST_BINARIES_DIR,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';
import { ghidraServerSkipReason, startTestGhidraServer, type TestGhidraServer } from './helpers/ghidra-server.ts';

interface ChangeEvent {
  epoch?: string;
  seq: number;
  kind: string;
  target: string;
  key: string;
  version?: number;
}

interface ChangesResult {
  events: ChangeEvent[];
  head: number;
  epoch: string;
}

interface SseMessage {
  event: string;
  data: Record<string, unknown>;
}

/** Read an SSE stream until `stop` says enough or the timeout passes. */
async function readSse(
  url: string,
  stop: (messages: SseMessage[]) => boolean,
  timeoutMs = 20_000
): Promise<SseMessage[]> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const messages: SseMessage[] = [];
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'text/event-stream' } });
    assert.strictEqual(res.status, 200, `GET ${url} -> ${res.status}`);
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = 'message';
        let data = '';
        for (const line of block.split('\n')) {
          if (line.startsWith('event: ')) event = line.slice(7);
          else if (line.startsWith('data: ')) data += line.slice(6);
        }
        if (data) messages.push({ event, data: JSON.parse(data) });
      }
      if (stop(messages)) break;
    }
  } catch (err) {
    if (!(err instanceof Error && err.name === 'AbortError')) throw err;
  } finally {
    clearTimeout(timer);
    ctrl.abort();
  }
  return messages;
}

after(async () => {
  await cleanupAllDaemons();
});

const LOCAL_SKIP = !process.env.GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  : !hasGhidraProjects()
    ? "No test Ghidra projects - run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

describe('E2E: journal epoch', { skip: LOCAL_SKIP, timeout: 600_000 }, () => {
  const PORT = 18442;
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let gpr: string;

  before(async () => {
    daemon = await startTestDaemon(PORT);
    client = new McpTestClient({ host: 'localhost', port: PORT, timeout: 180_000 });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    gpr = getTestProgramPath('simple_main');
    await client.createSession(gpr);
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  it('stamps every event and every read with the epoch', async () => {
    await client.callToolJson('create_label', { address: '0x100020', name: 'epoch_probe_a' });
    const res = await client.callToolJson<ChangesResult>('get_changes', { since: 0 });
    assert.match(res.epoch, /^[0-9a-f]{16}$/);
    assert.ok(res.events.length > 0);
    for (const e of res.events) assert.strictEqual(e.epoch, res.epoch);
  });

  it('a lost journal starts a new epoch, and /changes resets a subscriber from the old one', async () => {
    const old = await client.callToolJson<ChangesResult>('get_changes', { since: 0 });
    assert.ok(old.head > 0);

    // Reopen the project with its journal gone: what a respawned worker on a fresh
    // emptyDir sees.
    await client.closeSession();
    const journalDir = path.join(gpr.replace(/\.gpr$/, '.rep'), '.ghidra-mcp');
    assert.ok(fs.existsSync(journalDir), `journal dir expected at ${journalDir}`);
    fs.renameSync(journalDir, `${journalDir}.lost`);
    const session = await client.createSession(gpr);
    await client.callToolJson('create_label', { address: '0x100030', name: 'epoch_probe_b' });

    const fresh = await client.callToolJson<ChangesResult>('get_changes', { since: 0 });
    assert.notStrictEqual(fresh.epoch, old.epoch, 'a new journal must have a new epoch');
    assert.strictEqual(fresh.events[0]?.seq, 1, 'the new journal starts again at 1');

    // A subscriber resuming from the old position under the old epoch must be told, and
    // must then receive the new journal from the start rather than nothing.
    const sessionId = session.id;
    const url = `http://localhost:${PORT}/changes/${sessionId}?since=${old.head}&epoch=${old.epoch}`;
    const msgs = await readSse(url, (m) => m.filter((x) => x.event === 'change').length >= fresh.events.length);
    const reset = msgs.find((m) => m.event === 'reset');
    assert.ok(reset, `expected a reset event, got ${msgs.map((m) => m.event)}`);
    assert.strictEqual(reset.data.epoch, fresh.epoch);
    assert.strictEqual(reset.data.previousEpoch, old.epoch);
    const seqs = msgs.filter((m) => m.event === 'change').map((m) => m.data.seq);
    assert.deepStrictEqual(seqs, fresh.events.map((e) => e.seq));
  });

  it('a subscriber on the current epoch gets no reset', async () => {
    const cur = await client.callToolJson<ChangesResult>('get_changes', { since: 0 });
    const url = `http://localhost:${PORT}/changes/${client.getSession()}?since=0&epoch=${cur.epoch}`;
    const msgs = await readSse(url, (m) => m.filter((x) => x.event === 'change').length >= cur.events.length);
    assert.strictEqual(msgs.find((m) => m.event === 'reset'), undefined);
    assert.strictEqual(msgs.filter((m) => m.event === 'change').length, cur.events.length);
  });
});

const BINARY = path.join(TEST_BINARIES_DIR, 'simple_main');
const SERVER_SKIP = ghidraServerSkipReason()
  ?? (!fs.existsSync(BINARY) ? `fixture binary missing: ${BINARY} (npm run fixtures:build)` : undefined);

function stopWorkersOf(port: number): void {
  let out = '';
  try {
    out = execFileSync('ps', ['-axo', 'pid=,command='], { encoding: 'utf8' });
  } catch {
    return;
  }
  for (const line of out.split('\n')) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!m || !m[2].includes('com.ghidramcp.Worker')) continue;
    if (!m[2].includes(`--daemon-url http://127.0.0.1:${port} `)) continue;
    try { process.kill(Number(m[1]), 'SIGTERM'); } catch { /* gone */ }
  }
}

describe('E2E: version.committed', { skip: SERVER_SKIP, timeout: 900_000 }, () => {
  const PORT = 18443;
  const REPO = 'E2EEpoch';
  const PROGRAM = `${REPO}/fixtures/simple_main`;
  let server: TestGhidraServer;
  let daemon: DaemonHandle;
  let client: McpTestClient;

  before(async () => {
    server = await startTestGhidraServer();
    daemon = await startTestDaemon(PORT, {
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-epoch-e2e-')),
      GHIDRA_MCP_HOST: '127.0.0.1',
      ...server.daemonEnv,
    });
    client = new McpTestClient({ host: '127.0.0.1', port: PORT, timeout: 300_000 });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    await client.callToolJson('create_repo', { name: REPO });
    const job = await client.callToolJson<{ jobId: string }>('import_program', {
      localPath: BINARY, programPath: PROGRAM, analyze: true,
    });
    const deadline = Date.now() + 300_000;
    for (;;) {
      const st = await client.callToolJson<Record<string, unknown>>('import_status', { jobId: job.jobId });
      const state = String(st.state ?? st.status ?? '');
      if (/done|finished|complete|succeeded/i.test(state)) break;
      if (/fail|error/i.test(state)) throw new Error(`import failed: ${JSON.stringify(st)}`);
      if (Date.now() > deadline) throw new Error(`import did not finish: ${JSON.stringify(st)}`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  });

  after(async () => {
    client?.disconnect();
    await daemon?.stop();
    stopWorkersOf(PORT);
    await server?.stop();
  });

  it('emits version.committed with the new version after a check-in, and nothing for a no-op one', async () => {
    const session = await client.callToolJson<{ id: string }>('create_session', { program: PROGRAM, autoAnalyze: false });
    client.setSession(session.id);
    await client.waitForSessionReady(session.id, 300_000);

    const fns = await client.callToolJson<{ functions: Array<{ name: string; address: string }> }>(
      'list_functions', { limit: 500 });
    const target = fns.functions.find((f) => /^_?add_numbers$/.test(f.name));
    assert.ok(target, 'fixture has add_numbers');

    const before = await client.callToolJson<ChangesResult>('get_changes', { since: 0 });
    await client.callToolJson('rename_symbol', { address: target.address, newName: 'add_numbers_committed', type: 'function' });
    await client.callToolJson('commit', { message: 'epoch e2e' });
    const after = await client.callToolJson<ChangesResult>('get_changes', { since: before.head });

    const committed = after.events.filter((e) => e.kind === 'version.committed');
    assert.strictEqual(committed.length, 1, `events: ${JSON.stringify(after.events)}`);
    assert.strictEqual(committed[0]!.target, 'program');
    assert.strictEqual(committed[0]!.version, 2);
    assert.strictEqual(committed[0]!.epoch, after.epoch);
    assert.strictEqual(after.events[after.events.length - 1]!.kind, 'version.committed',
      'the commit boundary follows the edits it covers');

    // Nothing to commit: no boundary either.
    await client.callToolJson('commit', { message: 'nothing' });
    const idle = await client.callToolJson<ChangesResult>('get_changes', { since: after.head });
    assert.strictEqual(idle.events.filter((e) => e.kind === 'version.committed').length, 0);
  });
});
