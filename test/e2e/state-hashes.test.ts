/**
 * E2E Tests for get_state_hashes
 *
 * The hashes exist so a consumer can find what differs between two states without trusting
 * the journal. The properties that make that safe: an edit moves exactly the hash of what it
 * touched and nothing else, an undo returns every hash to its previous value byte for byte
 * (so an undo diffs to exactly the edit it reverted), and a data type's hash follows its
 * member names, not only its layout.
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

interface StateHashes {
  programVersion: number;
  modificationNumber: number;
  changeSeq?: number;
  functions: Record<string, string>;
  types: Record<string, string>;
  globals: Record<string, string>;
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

/** Keys whose value differs between two maps, including keys only one side has. */
function changedKeys(a: Record<string, string>, b: Record<string, string>): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => a[k] !== b[k]).sort();
}

const sameAddress = (a: string, b: string) =>
  a.replace(/^0x/, '').replace(/^0+/, '') === b.replace(/^0x/, '').replace(/^0+/, '');

const ANALYSIS_TIMEOUT = 180_000;
const SUITE_TIMEOUT = 600_000;

const SKIP_REASON = !process.env.GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  : !hasGhidraProjects()
    ? "No test Ghidra projects - run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: State Hashes', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;

  const hashes = () => call<StateHashes>(client, 'get_state_hashes', {});

  before(async () => {
    daemon = await startTestDaemon(18441);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    await client.createSession(getTestProgramPath('simple_main'));
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  it('is deterministic and covers functions, types and globals', async () => {
    const a = await hashes();
    const b = await hashes();
    assert.ok(Object.keys(a.functions).length > 0, 'expected function hashes');
    assert.ok(Object.keys(a.types).length > 0, 'expected type hashes');
    assert.ok(Object.keys(a.globals).length > 0, 'expected global hashes');
    assert.deepStrictEqual(b.functions, a.functions);
    assert.deepStrictEqual(b.types, a.types);
    assert.deepStrictEqual(b.globals, a.globals);
    assert.strictEqual(b.modificationNumber, a.modificationNumber, 'reading must not modify');
  });

  it('narrows to the requested kinds and addresses', async () => {
    const all = await hashes();
    const entry = Object.keys(all.functions)[0]!;
    const one = await call<StateHashes>(client, 'get_state_hashes', {
      kinds: ['functions'],
      addresses: [entry],
    });
    assert.deepStrictEqual(one.functions, { [entry]: all.functions[entry] });
    assert.strictEqual(one.types, undefined);
    assert.strictEqual(one.globals, undefined);
  });

  it("a local rename moves exactly that function's hash, and undo restores it byte for byte", async () => {
    const listed = await call<{ functions: Array<{ name: string; entryPoint: string }> }>(
      client,
      'list_functions',
      { limit: 100 }
    );
    const fn = listed.functions.find((f) => f.name === 'process_data' || f.name === '_process_data');
    assert.ok(fn, `fixture must have process_data, got ${listed.functions.map((f) => f.name)}`);

    const frame = await call<{ variables: Array<{ name: string; isParameter: boolean }> }>(
      client,
      'get_stack_frame',
      { address: fn.entryPoint }
    );
    const local = frame.variables.find((v) => !v.isParameter);
    assert.ok(local, `process_data must have a stack local, frame: ${JSON.stringify(frame.variables)}`);

    const before = await hashes();
    await call(client, 'set_function_variable_name', {
      functionAddress: fn.entryPoint,
      oldName: local.name,
      newName: 'hash_probe_local',
    });
    const renamed = await hashes();

    const key = Object.keys(before.functions).find((k) => sameAddress(k, fn.entryPoint));
    assert.ok(key, `no hash keyed by ${fn.entryPoint}`);
    assert.deepStrictEqual(changedKeys(before.functions, renamed.functions), [key]);
    assert.deepStrictEqual(changedKeys(before.types, renamed.types), []);
    assert.deepStrictEqual(changedKeys(before.globals, renamed.globals), []);
    assert.notStrictEqual(renamed.modificationNumber, before.modificationNumber);

    await call(client, 'undo', {});
    const undone = await hashes();
    assert.deepStrictEqual(undone.functions, before.functions, 'undo must restore every function hash');
    assert.deepStrictEqual(undone.types, before.types, 'undo must restore every type hash');
    assert.deepStrictEqual(undone.globals, before.globals, 'undo must restore every global hash');
  });

  it("a struct field rename moves that type's hash", async () => {
    const created = await call(client, 'create_structure', {
      name: 'HashProbeStruct',
      category: '/HashProbe',
      fields: [
        { name: 'a', dataType: 'int', offset: 0 },
        { name: 'b', dataType: 'int', offset: 4 },
      ],
    });
    assert.strictEqual(created.success, true);

    const before = await hashes();
    const path = Object.keys(before.types).find((p) => p.endsWith('/HashProbeStruct'));
    assert.ok(path, 'the new struct must have a hash');

    await call(client, 'update_structure', {
      name: 'HashProbeStruct',
      category: '/HashProbe',
      fields: [
        { name: 'a', dataType: 'int', offset: 0 },
        { name: 'renamed_b', dataType: 'int', offset: 4 },
      ],
    });
    const after = await hashes();
    assert.deepStrictEqual(changedKeys(before.types, after.types), [path]);
    assert.deepStrictEqual(changedKeys(before.functions, after.functions), []);
  });
});
