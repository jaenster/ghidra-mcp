/**
 * E2E: the gateway's startup against a daemon private to it.
 *
 * The gateway starts before its daemon listens and waits for it. A second
 * gateway process on the same daemon, as after a container restart, closes what
 * the first left open and ends with one session and one worker per program. A
 * foreign client that shows up afterwards still stops it serving.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
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

const DAEMON_PORT = 18454;
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

async function daemonHealth(): Promise<{ sessions: number; workers: number }> {
  const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/health`);
  return await res.json() as { sessions: number; workers: number };
}

describe('E2E: gateway startup and restart', { skip: SKIP_REASON, timeout: 600_000 }, () => {
  let daemon: DaemonHandle | undefined;
  const running: RunningGateway[] = [];
  const config = () => loadConfig({
    GATEWAY_UPSTREAM_URL: `http://127.0.0.1:${DAEMON_PORT}`,
    GATEWAY_PORT: '0',
    GATEWAY_PROGRAM_WIN: getTestProgramPath('simple_main'),
    GATEWAY_PROGRAM_MAC: getTestProgramPath('call_graph'),
    GATEWAY_ISOLATION_CHECK_MS: '300',
    GATEWAY_ALLOW_ANONYMOUS: '1',
    GATEWAY_SESSION_READY_TIMEOUT_MS: '180000',
    GATEWAY_RECLAIM_SESSIONS: '1',
  });

  after(async () => {
    for (const g of running) await g.close();
    await daemon?.stop();
  });

  it('starts before its daemon and waits for it', async () => {
    const log: string[] = [];
    const starting = startGateway(config(), { log: (l) => log.push(l) });
    await new Promise((r) => setTimeout(r, 1500));
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-gateway-restart-'));
    daemon = await startTestDaemon(DAEMON_PORT, { HOME: home, GHIDRA_MCP_HOST: '127.0.0.1' });
    running.push(await starting);
    assert.match(log[0] ?? '', /waiting for the daemon/);
    const health = await daemonHealth();
    assert.strictEqual(health.sessions, 2);
    assert.strictEqual(health.workers, 2);
  });

  it('a restarted gateway closes the stale sessions and ends with two sessions and two workers', async () => {
    const first = running[0];
    const stale = [first.sessions.win.id, first.sessions.mac.id];
    // A process that dies does not close its sessions: stop listening, leave them open.
    await first.close();
    running.length = 0;
    const log: string[] = [];
    running.push(await startGateway(config(), { log: (l) => log.push(l) }));
    const second = running[0];
    assert.ok(log.some((l) => /closed 2 stale session/.test(l)), log.join('\n'));
    const health = await daemonHealth();
    assert.strictEqual(health.sessions, 2);
    assert.strictEqual(health.workers, 2);
    assert.ok(!stale.includes(second.sessions.win.id) && !stale.includes(second.sessions.mac.id));
    const res = await fetch(`http://127.0.0.1:${second.port}/health`);
    assert.strictEqual(res.status, 200);
  });

  it('a foreign client that shows up later still stops it serving', async () => {
    const gateway = running[0];
    const intruder = new McpTestClient({ host: '127.0.0.1', port: DAEMON_PORT, timeout: 180_000 });
    try {
      await intruder.waitForReady();
      await intruder.createSession(getTestProgramPath('structures'), { autoAnalyze: false, waitTimeout: 180_000 });
      const deadline = Date.now() + 10_000;
      let status = 0;
      while (Date.now() < deadline) {
        status = (await fetch(`http://127.0.0.1:${gateway.port}/health`)).status;
        if (status === 503) break;
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.strictEqual(status, 503);
    } finally {
      intruder.disconnect();
    }
  });
});
