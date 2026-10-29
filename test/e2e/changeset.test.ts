/**
 * E2E: apply_changeset applies a list of edits as exactly one Ghidra transaction.
 *
 * Checked against the structures fixture (DWARF types, arm64 register storage):
 * - a three-op changeset lands as one transaction - one undo entry, every journal event
 *   stamped with the same transaction id and the changeset's description;
 * - an expect mismatch refuses the whole changeset before anything changes, and an op that
 *   fails after earlier ops were applied rolls those back too;
 * - a dry run reports what would change and changes nothing;
 * - a read-only session refuses it.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { defHash } from '../../packages/shared/src/changeset.ts';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  cleanupAllDaemons,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';

const SUITE_TIMEOUT = 600_000;
const TIMEOUT = 180_000;

const SKIP_REASON = !process.env.GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  : !hasGhidraProjects()
    ? "No test Ghidra projects — run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

// The structures fixture, as get_function_info / get_data_type report it.
const CREATE_NODE = '0x100000680';   // LinkedNode * create_node(int value)
const MAKE_POINT = '0x1000005b8';    // Point make_point(int x, int y)
const SUM_LIST = '0x10000071c';      // int sum_list(LinkedNode * head)
const POINT = '/DWARF/structures.c/Point';

interface Result {
  ok: boolean;
  dryRun: boolean;
  transactionId?: number;
  description: string;
  applied: Array<{ index: number; op: string; before: Record<string, unknown>; after: Record<string, unknown> }>;
  errors?: Array<{ index: number; op: string; errors: string[] }>;
}

interface Event { seq: number; kind: string; txId?: number; txDescription?: string }

after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: apply_changeset', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let home: string;

  async function call<T>(name: string, args: Record<string, unknown> = {}): Promise<T> {
    return client.callToolJson<T>(name, args);
  }
  const apply = (args: Record<string, unknown>) => call<Result>('apply_changeset', args);
  const undoStack = async () => (await call<{ undoStack: string[] }>('get_undo_history')).undoStack;
  const head = async () => (await call<{ head: number }>('get_changes', { since: 1e12 })).head;
  const fnName = async (address: string) => (await call<{ name: string }>('get_function_info', { address })).name;
  const params = async (address: string) =>
    (await call<{ parameters: Array<{ name: string; dataType: string; storage: string }> }>('get_function_info', { address })).parameters;
  const locals = async (address: string) =>
    (await call<{ localVariables: Array<{ name: string; dataType: string; storage: string }> }>('get_function_info', { address })).localVariables;
  const point = () => call<{ fields: Array<{ name: string; dataType: string; offset: number }> }>('get_data_type', { name: 'Point', category: '/DWARF/structures.c' });

  /** The first named global in a writable data segment, from list_data_symbols. */
  async function aGlobal(): Promise<{ address: string; name: string; type: string; size: number }> {
    const syms = await call<{ globals: Array<{ name: string; address: string }> }>('list_data_symbols', { limit: 200 });
    for (const s of syms.globals) {
      if (!/^[0-9a-f]+$/i.test(s.address)) continue; // EXTERNAL:... entries
      const d = await call<{ symbol?: { name: string; type: string }; data?: { type: string; size: number }; segment?: { writable: boolean } }>(
        'get_data_at_address', { address: `0x${s.address}` });
      if (d.symbol?.type !== 'Function' && d.segment?.writable && d.data) {
        return { address: `0x${s.address}`, name: d.symbol!.name, type: d.data.type, size: d.data.size };
      }
    }
    throw new Error('no writable global in the fixture');
  }

  before(async () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-mcp-changeset-'));
    daemon = await startTestDaemon(18437, { HOME: home });
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: TIMEOUT });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    await client.createSession(getTestProgramPath('structures'), { autoAnalyze: false });
  });

  after(async () => {
    if (client) {
      await client.closeSession().catch(() => {});
      client.disconnect();
    }
    if (daemon) await daemon.stop();
    if (home) fs.rmSync(home, { recursive: true, force: true });
  });

  it('applies a three-op changeset in exactly one transaction', { timeout: TIMEOUT }, async () => {
    const value = (await params(CREATE_NODE)).find((p) => p.name === 'value')!;
    const hash = await defHash(await point());
    const undoBefore = await undoStack();
    const seq = await head();
    const description = 'Proposal #1: name the node constructor';

    const res = await apply({
      description,
      ops: [
        { op: 'rename_function', address: CREATE_NODE, expect: { name: 'create_node' }, name: 'NODE_Create' },
        // "w0:4" as get_function_info prints it; the size may be left out.
        { op: 'rename_local', function: CREATE_NODE, storage: value.storage.replace(/:\d+$/, ''), expect: { name: 'value' }, name: 'nValue' },
        { op: 'struct_field', typePath: POINT, offset: 4, expect: { name: 'y', type: 'int', defHash: hash }, name: 'nY' },
      ],
    });

    assert.strictEqual(res.ok, true, JSON.stringify(res.errors));
    assert.strictEqual(typeof res.transactionId, 'number');
    assert.deepStrictEqual(res.applied.map((a) => [a.op, a.after.name]), [
      ['rename_function', 'NODE_Create'], ['rename_local', 'nValue'], ['struct_field', 'nY'],
    ]);
    assert.strictEqual(res.applied[2].before.defHash, hash);
    assert.notStrictEqual(res.applied[2].after.defHash, hash);

    assert.strictEqual(await fnName(CREATE_NODE), 'NODE_Create');
    assert.ok((await params(CREATE_NODE)).some((p) => p.name === 'nValue'));
    assert.strictEqual((await point()).fields.find((f) => f.offset === 4)!.name, 'nY');

    const undoAfter = await undoStack();
    assert.strictEqual(undoAfter.length, undoBefore.length + 1, 'one undo entry for the whole changeset');
    assert.strictEqual(undoAfter.filter((n) => n === description).length, 1);

    const events = (await call<{ events: Event[] }>('get_changes', { since: seq })).events;
    assert.ok(events.length > 0, 'the changes reached the journal');
    assert.deepStrictEqual([...new Set(events.map((e) => e.txId))], [res.transactionId], 'every event is the one transaction');
    assert.deepStrictEqual([...new Set(events.map((e) => e.txDescription))], [description]);
  });

  it('refuses the whole changeset when op 3\'s expect does not hold', { timeout: TIMEOUT }, async () => {
    const g = await aGlobal();
    const undoBefore = await undoStack();
    const res = await apply({
      description: 'Proposal #2: stale',
      ops: [
        { op: 'rename_function', address: MAKE_POINT, expect: { name: 'make_point' }, name: 'POINT_Make' },
        { op: 'retype_local', function: MAKE_POINT, storage: 'Stack[-0x10]', expect: { type: 'undefined4' }, type: 'int' },
        { op: 'rename_global', address: g.address, expect: { name: `${g.name}_seen_earlier` }, name: 'gpStale' },
      ],
    });

    assert.strictEqual(res.ok, false);
    assert.deepStrictEqual(res.applied, []);
    assert.deepStrictEqual(res.errors!.map((e) => e.index), [2]);
    assert.match(res.errors![0].errors[0], /expect\.name is .* but the global is named/);
    assert.strictEqual(await fnName(MAKE_POINT), 'make_point');
    assert.strictEqual((await locals(MAKE_POINT)).find((v) => v.storage.startsWith('Stack[-0x10]'))!.dataType, 'undefined4');
    assert.deepStrictEqual(await undoStack(), undoBefore);
  });

  it('rolls back ops already applied when a later op fails', { timeout: TIMEOUT }, async () => {
    const g = await aGlobal();
    const undoBefore = await undoStack();
    const res = await apply({
      description: 'Proposal #3: fails on apply',
      ops: [
        { op: 'rename_function', address: MAKE_POINT, expect: { name: 'make_point' }, name: 'POINT_Make' },
        { op: 'rename_global', address: g.address, expect: { name: g.name }, name: 'gpRolledBack' },
        { op: 'set_global_type', address: g.address, expect: { type: g.type, size: g.size }, type: 'NoSuchTypeAnywhere' },
      ],
    });

    assert.strictEqual(res.ok, false);
    assert.deepStrictEqual(res.applied, []);
    assert.deepStrictEqual(res.errors!.map((e) => e.index), [2]);
    assert.strictEqual(await fnName(MAKE_POINT), 'make_point');
    const d = await call<{ symbol: { name: string } }>('get_data_at_address', { address: g.address });
    assert.strictEqual(d.symbol.name, g.name);
    assert.deepStrictEqual(await undoStack(), undoBefore);
  });

  it('applies the remaining op kinds', { timeout: TIMEOUT }, async () => {
    const g = await aGlobal();
    const sum = await call<{ signature: string; callingConvention: string }>('get_function_info', { address: SUM_LIST });
    const newType = g.size === 8 ? (g.type === 'pointer' ? 'qword' : 'pointer') : (g.type === 'int' ? 'uint' : 'int');
    const res = await apply({
      description: 'Proposal #4: every other kind',
      ops: [
        { op: 'set_prototype', address: SUM_LIST, expect: { signature: sum.signature, callingConvention: sum.callingConvention },
          signature: 'int sum_list(LinkedNode * pHead)', callingConvention: sum.callingConvention },
        { op: 'retype_local', function: MAKE_POINT, storage: 'Stack[-0x10]:4', expect: { type: 'undefined4' }, type: 'int' },
        { op: 'rename_global', address: g.address, expect: { name: g.name }, name: 'gpChangesetGlobal' },
        { op: 'set_global_type', address: g.address, expect: { type: g.type, size: g.size }, type: newType },
      ],
    });
    assert.strictEqual(res.ok, true, JSON.stringify(res.errors));
    assert.strictEqual(res.applied[0].after.signature, 'int sum_list(LinkedNode * pHead)');
    assert.strictEqual(res.applied[1].after.type, 'int');
    assert.strictEqual(res.applied[2].after.name, 'gpChangesetGlobal');
    assert.strictEqual(res.applied[3].before.type, g.type);
    assert.strictEqual(res.applied[3].after.type, newType);
  });

  it('dryRun reports the change and changes nothing', { timeout: TIMEOUT }, async () => {
    const undoBefore = await undoStack();
    const hash = await defHash(await point());
    const res = await apply({
      description: 'Proposal #5: dry run',
      dryRun: true,
      ops: [
        { op: 'rename_function', address: MAKE_POINT, expect: { name: 'make_point' }, name: 'POINT_Make' },
        { op: 'struct_field', typePath: POINT, offset: 0, expect: { name: 'x', type: 'int', defHash: hash }, name: 'nX', type: 'uint' },
      ],
    });

    assert.strictEqual(res.ok, true, JSON.stringify(res.errors));
    assert.strictEqual(res.dryRun, true);
    assert.strictEqual(res.transactionId, undefined);
    assert.deepStrictEqual(res.applied.map((a) => [a.before.name, a.after.name]), [['make_point', 'POINT_Make'], ['x', 'nX']]);
    assert.strictEqual(res.applied[1].after.type, 'uint');

    assert.strictEqual(await fnName(MAKE_POINT), 'make_point');
    const x = (await point()).fields.find((f) => f.offset === 0)!;
    assert.deepStrictEqual([x.name, x.dataType], ['x', 'int']);
    assert.strictEqual(await defHash(await point()), hash);
    assert.deepStrictEqual(await undoStack(), undoBefore);
  });

  it('refuses malformed ops before opening a transaction', { timeout: TIMEOUT }, async () => {
    const res = await apply({
      description: 'Proposal #6: malformed',
      ops: [
        { op: 'rename_function', program: 'win', address: MAKE_POINT, expect: { name: 'make_point' }, name: 'not a name' },
        { op: 'delete_function', address: MAKE_POINT },
      ],
    });
    assert.strictEqual(res.ok, false);
    assert.deepStrictEqual(res.errors!.map((e) => e.index), [0, 1]);
    assert.ok(res.errors![0].errors.some((m) => /program: not part of a changeset op/.test(m)));
    assert.ok(res.errors![0].errors.some((m) => /a name is a C identifier/.test(m)));
  });

  it('is refused on a read-only session', { timeout: TIMEOUT }, async () => {
    const ro = await call<{ id: string; status: string }>('create_session', {
      binaryPath: getTestProgramPath('structures'), readOnly: true, autoAnalyze: false,
    });
    try {
      if (ro.status !== 'ready') await client.waitForSessionReady(ro.id);
      const res = await client.callTool('apply_changeset', {
        sessionId: ro.id,
        description: 'Proposal #7: read-only',
        ops: [{ op: 'rename_function', address: MAKE_POINT, expect: { name: 'make_point' }, name: 'POINT_Make' }],
      });
      assert.match(res.content[0].text, /^Error: .*read-only/);
      const fi = await call<{ name: string }>('get_function_info', { sessionId: ro.id, address: MAKE_POINT });
      assert.strictEqual(fi.name, 'make_point');
    } finally {
      await client.callTool('close_session', { sessionId: ro.id }).catch(() => {});
    }
  });
});
