/**
 * E2E Tests for the analyze tool
 *
 * The flow this covers is the whole point of the tool: open a session, analyze the
 * program, close it again — with the job polled through analyze_status in between.
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

interface AnalysisJob {
  jobId: string;
  state: string;
  program: string;
  finished: boolean;
  elapsedMs: number;
  functionsBefore?: number;
  functionsAfter?: number;
  saved: boolean;
  committed: boolean;
  commitSkipped?: string;
  error?: string;
}

async function call<T = Record<string, unknown>>(
  client: McpTestClient,
  name: string,
  args: Record<string, unknown> = {}
): Promise<T> {
  const result = await client.callTool(name, args);
  const text = result.content?.[0]?.text;
  if (!text) {
    throw new Error(`Empty response from ${name}`);
  }
  if (text.startsWith('Error:')) {
    throw new Error(text);
  }
  return JSON.parse(text) as T;
}

const TEST_TIMEOUT = 60_000;
const ANALYSIS_TIMEOUT = 300_000;
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

describe('E2E: Analyze', { skip: SKIP_REASON, timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let client: McpTestClient;
  let binaryPath: string;

  before(async () => {
    daemon = await startTestDaemon(18436);
    client = new McpTestClient({ host: 'localhost', port: daemon.port, timeout: ANALYSIS_TIMEOUT });
    await client.waitForReady();
    await client.callTool('set_output_format', { format: 'json' });
    binaryPath = getTestProgramPath('simple_main');
  });

  after(async () => {
    if (client) client.disconnect();
    if (daemon) await daemon.stop();
  });

  it('exposes analyze and analyze_status', { timeout: TEST_TIMEOUT }, async () => {
    const tools = await client.listTools();
    const names = tools.map((t) => t.name);
    assert.ok(names.includes('analyze'), 'Should have analyze');
    assert.ok(names.includes('analyze_status'), 'Should have analyze_status');
  });

  describe('open, analyze, close', { timeout: ANALYSIS_TIMEOUT }, () => {
    before(async () => {
      await client.createSession(binaryPath);
    });

    after(async () => {
      await client.closeSession().catch(() => {});
    });

    it('skips a program that is already analyzed', async () => {
      const job = await call<AnalysisJob>(client, 'analyze');
      assert.strictEqual(job.state, 'skipped');
      assert.ok(job.finished, 'A skipped job is finished on return');
    });

    it('analyzes when forced, and reports the finished job', async () => {
      const started = await call<AnalysisJob>(client, 'analyze', {
        force: true,
        wait: true,
        waitTimeout: 240_000,
      });
      assert.ok(started.jobId, 'Should report a jobId');
      assert.strictEqual(started.state, 'done', `Unexpected state: ${JSON.stringify(started)}`);
      assert.ok(started.finished);
      assert.ok(started.saved, 'Analysis should have saved the working copy');
      // A local .gpr session has nothing to check in to.
      assert.strictEqual(started.committed, false);
      assert.ok(started.commitSkipped, 'Should say why it did not check in');
      assert.ok((started.functionsAfter ?? 0) > 0, 'Should find functions');

      const polled = await call<AnalysisJob>(client, 'analyze_status', { jobId: started.jobId });
      assert.strictEqual(polled.jobId, started.jobId);
      assert.strictEqual(polled.state, 'done');
    });

    it('lists every job when no jobId is given', async () => {
      const result = await call<{ jobs: AnalysisJob[] }>(client, 'analyze_status');
      assert.ok(Array.isArray(result.jobs));
      assert.ok(result.jobs.length >= 1, 'Should list the jobs run so far');
    });

    it('rejects an unknown jobId', async () => {
      await assert.rejects(() => call(client, 'analyze_status', { jobId: 'nope' }));
    });

    it('leaves the program usable afterwards', async () => {
      const functions = await call<{ functions: unknown[] }>(client, 'list_functions', { limit: 5 });
      assert.ok(functions.functions.length > 0);
    });
  });
});
