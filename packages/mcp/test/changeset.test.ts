import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  addrEq, CHANGESET_MAX_OPS, changesetTimeoutMs, defHash, normAddress, normConvention, normSignature, normStorage, normType,
} from '@ghidra-mcp/shared/changeset';
import type { WorkerCommand } from '@ghidra-mcp/shared/protocol';
import { GhidraToolHandler, type ToolHandlerContext, getToolByName } from '../src/index.js';

/** Produced by running the Redivivus proposal checker's own functions; ProposalNormTest reads them too. */
const vectors = JSON.parse(readFileSync(new URL('../../shared/test/changeset-vectors.json', import.meta.url), 'utf8'));

describe('changeset normalisers match the proposal checker', () => {
  it('op cap', () => {
    expect(CHANGESET_MAX_OPS).toBe(vectors.maxOps);
    expect(getToolByName('apply_changeset')!.inputSchema.properties.ops.description).toContain(`1 to ${vectors.maxOps} ops`);
  });
  it('defHash', async () => {
    for (const c of vectors.defHash) expect(await defHash(c.dataType)).toBe(c.defHash);
  });
  it('storage, types, signatures, conventions, addresses', () => {
    for (const c of vectors.normStorage) expect(normStorage(c.in)).toBe(c.out);
    for (const c of vectors.normType) expect(normType(c.in)).toBe(c.out);
    for (const c of vectors.normSignature) expect(normSignature(c.in)).toBe(c.out);
    for (const c of vectors.normConvention) expect(normConvention(c.in)).toBe(c.out);
    for (const c of vectors.normAddress) expect(normAddress(c.in)).toBe(c.out);
    for (const c of vectors.addrEq) expect(addrEq(c.a, c.b)).toBe(c.out);
  });
});

describe('apply_changeset tool', () => {
  it('is defined with description and ops required', () => {
    const t = getToolByName('apply_changeset');
    expect(t).toBeDefined();
    expect(t!.inputSchema.required).toEqual(['description', 'ops']);
    expect(Object.keys(t!.inputSchema.properties)).toEqual(expect.arrayContaining(['sessionId', 'description', 'ops', 'dryRun']));
  });

  it('sends one apply_changeset command carrying the ops untouched', async () => {
    const sent: Array<{ sessionId: string; command: WorkerCommand }> = [];
    const ctx = {
      listSessions: async () => [],
      createSession: async () => { throw new Error('unused'); },
      getDefaultSessionId: () => 's1',
      setDefaultSessionId: () => {},
      sendCommand: async (sessionId: string, command: WorkerCommand) => {
        sent.push({ sessionId, command });
        return { id: command.id, success: true, result: { ok: true, dryRun: true, description: 'd', applied: [] } };
      },
    } as unknown as ToolHandlerContext;
    const ops = [{ op: 'rename_function', address: '0x00401000', expect: { name: 'FUN_00401000' }, name: 'ITEMS_GetQuality' }];
    const handler = new GhidraToolHandler(ctx, 'json');
    const res = await handler.handleToolCall('apply_changeset', { description: 'Proposal #1: test', ops, dryRun: true });

    expect(sent).toHaveLength(1);
    expect(sent[0].sessionId).toBe('s1');
    expect(sent[0].command.command).toBe('apply_changeset');
    expect(sent[0].command.params).toEqual({ description: 'Proposal #1: test', ops, dryRun: true });
    expect(JSON.parse(res.content[0].text)).toMatchObject({ ok: true, dryRun: true });
  });
});
