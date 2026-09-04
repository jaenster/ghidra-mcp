/**
 * E2E Tests for the ordered change journal
 *
 * The journal is what a live consumer resumes from, so the properties under test are the
 * ones that make a resume trustworthy: sequences only ever increase, a write's own change
 * is readable by the time the write returns, the events a consumer needs are actually
 * emitted (struct-field and variable retypes historically appeared not to be), and a
 * consumer that asks for everything after N gets exactly that.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  cleanupAllDaemons,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';

interface ChangeEvent {
  seq: number;
  mod: number;
  ts: number;
  kind: string;
  target: string;
  key: string;
  oldName?: string;
  newName?: string;
}

interface ChangesResult {
  events: ChangeEvent[];
  head: number;
}

async function call<T = Record<string, unknown>>(
  client: McpTestClient,
  name: string,
  args: Record<string, unknown> = {}
): Promise<T> {
  const result = await client.callTool(name, args);
  const text = result.content?.[0]?.text;
  if (!text) throw new Error(`Empty response from ${name}`);
  if (text.startsWith('Error:')) throw new Error(text);
  return JSON.parse(text) as T;
}

const ANALYSIS_TIMEOUT = 180_000;
const SUITE_TIMEOUT = 600_000;

const GHIDRA_HOME = process.env.GHIDRA_HOME;
const SKIP_REASON = !GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  : !hasGhidraProjects()
    ? "No test Ghidra projects — run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: Change Journal', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let binaryPath: string;

  before(async () => {
    daemon = await startTestDaemon(18437);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    binaryPath = getTestProgramPath('simple_main');
    await client.createSession(binaryPath);
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  it('reports a head even when nothing has changed', async () => {
    const result = await call<ChangesResult>(client, 'get_changes', { since: 0 });
    assert.ok(Array.isArray(result.events), 'events must be an array');
    assert.ok(typeof result.head === 'number', 'head must be a number');
  });

  it('emits an ordered event for a function rename, carrying both names', async () => {
    const listed = await call<{ functions: Array<{ name: string; entryPoint: string }> }>(
      client,
      'list_functions',
      { limit: 5 }
    );
    const target = listed.functions[0];
    assert.ok(target, 'fixture must have at least one function');

    const before = await call<ChangesResult>(client, 'get_changes', { since: 0 });
    await call(client, 'rename_symbol', {
      address: target.entryPoint,
      newName: 'journal_probe_renamed',
    });

    const after = await call<ChangesResult>(client, 'get_changes', { since: before.head });
    assert.ok(after.events.length > 0, 'a rename must produce at least one event');

    // Ordering is the whole contract: a consumer that processes up to seq N and asks for
    // N must never be handed something older.
    for (let i = 1; i < after.events.length; i++) {
      assert.ok(
        after.events[i]!.seq > after.events[i - 1]!.seq,
        `sequences must strictly increase (${after.events[i - 1]!.seq} then ${after.events[i]!.seq})`
      );
    }
    for (const e of after.events) {
      assert.ok(e.seq > before.head, `every event must be newer than the requested since`);
    }

    const renamed = after.events.find((e) => e.kind === 'symbol.renamed');
    assert.ok(renamed, 'expected a symbol.renamed event');
    assert.strictEqual(renamed.target, 'function');
    assert.strictEqual(renamed.key, target.entryPoint);
    assert.strictEqual(renamed.newName, 'journal_probe_renamed');
    assert.strictEqual(renamed.oldName, target.name);
  });

  it('stays silent when a write changed nothing', async () => {
    // rename_symbol on a plain label reports success and leaves the label alone (read it
    // back: still the old name). The journal is the honest witness here - it emits nothing
    // because nothing moved - so this pins the tool's behaviour rather than papering over
    // it. If this test starts failing, rename_symbol was fixed and the assertion should
    // become the positive one.
    await call(client, 'create_label', { address: '0x100000', name: 'journal_label_a' });
    const before = await call<ChangesResult>(client, 'get_changes', { since: 0 });
    await call(client, 'rename_symbol', { address: '0x100000', newName: 'journal_label_b' });
    const after = await call<ChangesResult>(client, 'get_changes', { since: before.head });

    const readBack = await call<{ symbol?: { name?: string } }>(client, 'get_data_at_address', {
      address: '0x100000',
    });
    if (readBack.symbol?.name === 'journal_label_b') {
      assert.ok(
        after.events.some((e) => e.kind === 'symbol.renamed'),
        'the label really was renamed, so an event was owed'
      );
    } else {
      assert.strictEqual(
        after.events.length,
        0,
        'the label was not renamed, so the journal must report nothing'
      );
    }
  });

  it("makes a write's own change readable by the time the write returns", async () => {
    // Ghidra delivers change records on a 500 ms timer rather than at commit. Without the
    // flush on the write path this read races that timer and intermittently sees nothing,
    // which is exactly what made the old dirty tracker look like it missed retypes.
    const before = await call<ChangesResult>(client, 'get_changes', { since: 0 });
    await call(client, 'create_label', { address: '0x100010', name: 'journal_probe_flush' });
    const after = await call<ChangesResult>(client, 'get_changes', { since: before.head });
    assert.ok(after.events.length > 0, 'the change must be visible immediately after the write');
  });

  it('emits a datatype event for a struct field retype', async () => {
    const created = await call(client, 'create_structure', {
      name: 'JournalProbeStruct',
      category: '/Journal',
      fields: [
        { name: 'a', dataType: 'int', offset: 0 },
        { name: 'b', dataType: 'int', offset: 4 },
      ],
    });
    assert.strictEqual(created.success, true);

    const before = await call<ChangesResult>(client, 'get_changes', { since: 0 });
    await call(client, 'update_structure', {
      name: 'JournalProbeStruct',
      category: '/Journal',
      fields: [
        { name: 'a', dataType: 'int', offset: 0 },
        { name: 'b', dataType: 'double', offset: 8 },
      ],
    });

    const after = await call<ChangesResult>(client, 'get_changes', { since: before.head });
    const dt = after.events.find((e) => e.target === 'datatype');
    assert.ok(dt, 'a struct field retype must produce a datatype event');
    assert.ok(dt.key.includes('JournalProbeStruct'), `key should name the type, got ${dt?.key}`);
  });

  it('serves an exclusive range: asking for head returns nothing new', async () => {
    const head = (await call<ChangesResult>(client, 'get_changes', { since: 0 })).head;
    const empty = await call<ChangesResult>(client, 'get_changes', { since: head });
    assert.strictEqual(empty.events.length, 0, 'since=head must be empty');
    assert.strictEqual(empty.head, head, 'head must not move on its own');
  });

  it('honours limit without losing order', async () => {
    const all = await call<ChangesResult>(client, 'get_changes', { since: 0, limit: 10000 });
    if (all.events.length < 2) return; // nothing to slice

    const first = await call<ChangesResult>(client, 'get_changes', { since: 0, limit: 1 });
    assert.strictEqual(first.events.length, 1);
    assert.strictEqual(first.events[0]!.seq, all.events[0]!.seq, 'limit must take the oldest');

    const next = await call<ChangesResult>(client, 'get_changes', {
      since: first.events[0]!.seq,
      limit: 1,
    });
    assert.strictEqual(next.events[0]!.seq, all.events[1]!.seq, 'paging must not skip or repeat');
  });
});
