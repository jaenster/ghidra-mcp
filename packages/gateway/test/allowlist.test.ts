import { describe, expect, it } from 'vitest';
import { getAllToolDefinitions } from '@ghidra-mcp/mcp';
import {
  EXCLUDED_GROUPS,
  EXPOSED_TOOLS,
  GATEWAY_LOCAL_TOOLS,
  PINNING_ARGS,
  DENIED_RESPONSE_KEYS,
} from '../src/allowlist.js';
import { RefusedError, buildPublicTools, checkCall } from '../src/tools.js';

function refusal(fn: () => unknown): RefusedError {
  try {
    fn();
  } catch (err) {
    if (err instanceof RefusedError) return err;
    throw err;
  }
  throw new Error('expected a refusal');
}

describe('allowlist', () => {
  const daemonTools = getAllToolDefinitions().map((t) => t.name);

  it('classifies every daemon tool exactly once', () => {
    const classified = [
      ...Object.keys(EXPOSED_TOOLS),
      ...GATEWAY_LOCAL_TOOLS,
      ...Object.values(EXCLUDED_GROUPS).flatMap((g) => g.tools),
    ];
    const dupes = classified.filter((n, i) => classified.indexOf(n) !== i);
    expect(dupes).toEqual([]);
    expect(daemonTools.filter((n) => !classified.includes(n))).toEqual([]);
    expect(classified.filter((n) => !daemonTools.includes(n))).toEqual([]);
  });

  it('exposes only allowlisted tools, all annotated read-only', () => {
    const tools = buildPublicTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      [...Object.keys(EXPOSED_TOOLS), ...GATEWAY_LOCAL_TOOLS].sort());
    for (const t of tools) {
      expect(t.annotations.readOnlyHint).toBe(true);
      expect(t.annotations.destructiveHint).toBe(false);
    }
  });

  it('keeps only binary facts from get_program_info', () => {
    expect(EXPOSED_TOOLS.get_program_info.keepKeys).not.toContain('path');
    expect(DENIED_RESPONSE_KEYS).toEqual(expect.arrayContaining(['sessionId', 'programPath', 'version', 'latestVersion']));
  });

  it('strips pinning arguments from every public schema', () => {
    for (const t of buildPublicTools()) {
      for (const arg of PINNING_ARGS) expect(t.inputSchema.properties).not.toHaveProperty(arg);
      for (const r of t.inputSchema.required ?? []) expect(PINNING_ARGS).not.toContain(r);
    }
  });

  it('refuses a write tool called by name', () => {
    const err = refusal(() => checkCall('set_comment', { address: '0x401000', comment: 'x' }));
    expect(err.reason).toBe('excluded:writes');
  });

  it('refuses a leaky read called by name', () => {
    expect(refusal(() => checkCall('get_logs', {})).reason).toBe('excluded:leaky');
    expect(refusal(() => checkCall('list_programs', {})).reason).toBe('excluded:repository');
    expect(refusal(() => checkCall('list_sessions', {})).reason).toBe('excluded:sessions');
    expect(refusal(() => checkCall('execute_script', { code: 'x' })).reason).toBe('excluded:code');
  });

  it('refuses an unknown tool', () => {
    expect(refusal(() => checkCall('drop_everything', {})).reason).toBe('unknown_tool');
  });
});

describe('argument checks', () => {
  it('rejects an injected sessionId', () => {
    const err = refusal(() => checkCall('decompile', { name: 'main', sessionId: 'someone-elses' }));
    expect(err.reason).toBe('pinning_arg');
    expect(err.message).toContain('sessionId');
  });

  it('rejects an injected path, program or repo', () => {
    for (const key of ['path', 'binaryPath', 'repo', 'programPath', 'folder']) {
      expect(refusal(() => checkCall('list_functions', { [key]: '/windows/secret/Game.exe' })).reason)
        .toBe('pinning_arg');
    }
  });

  it('rejects arguments the public schema does not have', () => {
    expect(refusal(() => checkCall('detect_table', { address: '0x1', applyType: true })).reason).toBe('unknown_arg');
    expect(refusal(() => checkCall('list_functions', { bogus: 1 })).reason).toBe('unknown_arg');
  });

  it('caps batch sizes', () => {
    const addresses = Array.from({ length: 21 }, (_, i) => `0x${(0x401000 + i).toString(16)}`);
    expect(refusal(() => checkCall('batch_decompile', { addresses })).reason).toBe('batch_too_large');
    expect(refusal(() => checkCall('batch_pcode', { addresses })).reason).toBe('batch_too_large');
    expect(checkCall('batch_pcode', { addresses: addresses.slice(0, 20) }).args.addresses).toHaveLength(20);
  });

  it('clamps numeric limits and bounds unbounded defaults', () => {
    expect(checkCall('list_functions', { limit: 100000 }).args.limit).toBe(500);
    expect(checkCall('batch_decompile', { filter: 'Foo' }).args.limit).toBe(20);
    expect(checkCall('search', { type: 'decompiled', pattern: 'x' }).args.maxFunctions).toBe(200);
    expect(checkCall('read_memory', { address: '0x1', length: 1 << 30 }).args.length).toBe(65536);
  });

  it('passes a well-formed read through unchanged', () => {
    expect(checkCall('decompile', { name: 'main' })).toEqual({ name: 'decompile', program: 'win', args: { name: 'main' } });
  });

  it('takes the program only as a public name and never forwards it', () => {
    expect(checkCall('decompile', { name: 'main', program: 'mac' })).toEqual({ name: 'decompile', program: 'mac', args: { name: 'main' } });
    for (const program of ['Diablo2Lod/windows/lod/1.14d/Game.exe', '/windows/d2r/Game.exe', 'MAC', '', null, 2]) {
      expect(refusal(() => checkCall('decompile', { name: 'main', program })).reason).toBe('pinning_arg');
    }
  });

  it('offers the program choice on every forwarded tool, as an enum', () => {
    for (const t of buildPublicTools()) {
      if (t.name === 'set_output_format') continue;
      expect(t.inputSchema.properties.program).toMatchObject({ enum: ['win', 'mac'], default: 'win' });
    }
  });
});
