/**
 * E2E: the public gateway in front of a daemon of its own.
 *
 * Starts a real daemon, starts the gateway pinned to a fixture program, and
 * talks to the gateway the way an outside MCP client would.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { loadConfig, startGateway, type RunningGateway } from '../../packages/gateway/src/index.ts';
import {
  startTestDaemon,
  getTestProgramPath,
  hasGhidraProjects,
  cleanupAllDaemons,
  cleanupScratchProjects,
  type DaemonHandle,
} from './helpers/daemon.ts';
import { McpTestClient } from './helpers/mcp-client.ts';

const DAEMON_PORT = 18452;
/** A second, shared daemon where another client edits the same program. */
const OTHER_PORT = 18453;
const EDITED = 'edited_by_other_client';
const GHIDRA_HOME = process.env.GHIDRA_HOME;
const SKIP_REASON = !GHIDRA_HOME
  ? 'GHIDRA_HOME not set'
  : !hasGhidraProjects()
    ? "No test Ghidra projects - run 'npm run fixtures:build' then 'npm run fixtures:ghidra'"
    : undefined;

after(async () => {
  await cleanupAllDaemons();
  cleanupScratchProjects();
});

type TextContent = Array<{ type: string; text: string }>;

describe('E2E: read-only gateway', { skip: SKIP_REASON, timeout: 300_000 }, () => {
  let daemon: DaemonHandle;
  let gateway: RunningGateway;
  let client: Client;
  let other: DaemonHandle | undefined;
  let program: string;
  const audit: string[] = [];

  before(async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-gateway-e2e-'));
    daemon = await startTestDaemon(DAEMON_PORT, { HOME: home, GHIDRA_MCP_HOST: '127.0.0.1' });
    program = getTestProgramPath('simple_main');
    gateway = await startGateway(loadConfig({
      GATEWAY_UPSTREAM_URL: `http://127.0.0.1:${DAEMON_PORT}`,
      GATEWAY_PORT: '0',
      GATEWAY_PROGRAM: program,
      GATEWAY_ISOLATION_CHECK_MS: '300',
      GATEWAY_ALLOW_ANONYMOUS: '1',
      GATEWAY_SESSION_READY_TIMEOUT_MS: '180000',
    }), { auditSink: (line) => audit.push(line) });
    client = new Client({ name: 'gateway-e2e', version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${gateway.port}/mcp`)));
  });

  after(async () => {
    await client?.close();
    await gateway?.close();
    await other?.stop();
    await daemon?.stop();
  });

  it('lists only read-only tools', async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('list_functions'));
    assert.ok(names.includes('decompile'));
    assert.ok(!names.includes('set_comment'));
    assert.ok(!names.includes('list_sessions'));
    assert.ok(tools.every((t) => t.annotations?.readOnlyHint === true));
    assert.ok(tools.every((t) => !('sessionId' in (t.inputSchema.properties ?? {}))));
  });

  it('runs list_functions', async () => {
    await client.callTool({ name: 'set_output_format', arguments: { format: 'json' } });
    const res = await client.callTool({ name: 'list_functions', arguments: { limit: 50 } });
    assert.ok(!res.isError, (res.content as TextContent)[0]?.text);
    const body = JSON.parse((res.content as TextContent)[0].text) as { functions?: Array<{ name: string }> };
    const names = (body.functions ?? []).map((f) => f.name);
    assert.ok(names.some((n) => /main/.test(n)), `main not in ${names.join(', ')}`);
  });

  it('runs decompile', async () => {
    const res = await client.callTool({ name: 'decompile', arguments: { name: 'main' } });
    const text = (res.content as TextContent)[0].text;
    assert.ok(!res.isError, text);
    assert.match(text, /main/);
    assert.match(text, /return/);
  });

  it('refuses set_comment and never changes the program', async () => {
    const res = await client.callTool({
      name: 'set_comment',
      arguments: { address: '0x100000000', comment: 'gateway e2e', type: 'plate' },
    });
    assert.strictEqual(res.isError, true);
    assert.match((res.content as TextContent)[0].text, /not available on this read-only gateway/);
    const comments = await client.callTool({ name: 'list_comments', arguments: {} });
    assert.ok(!(comments.content as TextContent)[0].text.includes('gateway e2e'));
  });

  it('refuses an injected sessionId', async () => {
    const res = await client.callTool({ name: 'decompile', arguments: { name: 'main', sessionId: 'x' } });
    assert.strictEqual(res.isError, true);
    assert.match((res.content as TextContent)[0].text, /sessionId/);
  });

  it('writes one audit line per call', () => {
    const lines = audit.map((l) => JSON.parse(l) as { tool: string; outcome: string; login: string });
    assert.ok(lines.some((l) => l.tool === 'decompile' && l.outcome === 'ok' && l.login === 'anonymous'));
    assert.ok(lines.some((l) => l.tool === 'set_comment' && l.outcome === 'refused'));
  });

  async function gatewayFunctionNames(): Promise<string[]> {
    const res = await client.callTool({ name: 'list_functions', arguments: { limit: 500 } });
    assert.ok(!res.isError, (res.content as TextContent)[0]?.text);
    const body = JSON.parse((res.content as TextContent)[0].text) as { functions?: Array<{ name: string }> };
    return (body.functions ?? []).map((f) => f.name);
  }

  it('does not show an edit another client makes on a shared daemon', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-gateway-e2e-other-'));
    other = await startTestDaemon(OTHER_PORT, { HOME: home, GHIDRA_MCP_HOST: '127.0.0.1' });
    const editor = new McpTestClient({ host: '127.0.0.1', port: OTHER_PORT, timeout: 180_000 });
    try {
      await editor.waitForReady();
      await editor.createSession(program, { autoAnalyze: false, waitTimeout: 180_000 });
      type Fns = { functions?: Array<{ name: string; address: string }> };
      const target = (await editor.callToolJson<Fns>('list_functions', { limit: 500 }))
        .functions?.find((f) => f.name === 'multiply_numbers');
      assert.ok(target, 'fixture has multiply_numbers');
      await editor.callToolJson('rename_symbol', { address: target.address, newName: EDITED, type: 'function' });
      const after = await editor.callToolJson<Fns>('list_functions', { limit: 500 });
      assert.ok((after.functions ?? []).some((f) => f.name === EDITED), 'the edit landed on the shared daemon');

      const names = await gatewayFunctionNames();
      assert.ok(!names.includes(EDITED), 'the gateway must not see the other client\'s edit');
      assert.ok(names.includes('multiply_numbers'));
    } finally {
      editor.disconnect();
    }
  });

  it('stops serving once another client attaches to its own daemon', async () => {
    const intruder = new McpTestClient({ host: '127.0.0.1', port: DAEMON_PORT, timeout: 180_000 });
    try {
      await intruder.waitForReady();
      // The daemon dedups this onto the gateway's pinned session.
      await intruder.createSession(program, { autoAnalyze: false, waitTimeout: 180_000 });
      const deadline = Date.now() + 10_000;
      let text = '';
      while (Date.now() < deadline) {
        const res = await client.callTool({ name: 'get_program_info', arguments: {} });
        text = (res.content as TextContent)[0].text;
        if (res.isError && /no longer isolated/.test(text)) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.match(text, /no longer isolated/);
      const health = await fetch(`http://127.0.0.1:${gateway.port}/health`);
      assert.strictEqual(health.status, 503);
    } finally {
      intruder.disconnect();
    }
  });
});
