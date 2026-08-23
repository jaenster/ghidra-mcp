/**
 * Test daemon management
 *
 * Starts/stops the daemon for E2E tests with proper cleanup
 */

import * as child_process from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');
const FIXTURES_DIR = path.join(PROJECT_ROOT, 'test-fixtures');

// Track all daemons we've started for cleanup
const activeDaemons = new Set<DaemonHandle>();

export interface DaemonHandle {
  port: number;
  process: child_process.ChildProcess;
  pid: number;
  workerPids: Set<number>;
  stop: () => Promise<void>;
  isRunning: () => boolean;
}

export interface TestBinary {
  name: string;
  path: string;
  ghidraProject?: string; // Path to pre-analyzed Ghidra project
}

/**
 * Start the daemon for testing.
 *
 * @param port  Listen port (defaults to 18432).
 * @param env   Extra environment overrides merged over process.env — used by
 *              the auth test to enable OAuth and isolate the app data dir.
 */
export async function startTestDaemon(
  port = 18432,
  env?: Record<string, string>
): Promise<DaemonHandle> {
  const cliPath = path.join(PROJECT_ROOT, 'packages', 'cli', 'dist', 'index.js');

  if (!fs.existsSync(cliPath)) {
    throw new Error(`CLI not built. Run 'npm run build' first. Looking for: ${cliPath}`);
  }

  // Start daemon in foreground mode with --force to allow multiple instances
  const proc = child_process.spawn(
    process.execPath,
    [cliPath, 'start', '-p', String(port), '-f', '--force'],
    {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        GHIDRA_MCP_PORT: String(port),
        ...env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
      detached: false,
    }
  );

  const workerPids = new Set<number>();

  // Parse worker PIDs from output
  proc.stdout?.on('data', (data) => {
    const text = data.toString();

    if (process.env.DEBUG) {
      console.log('[daemon]', text.trim());
    }

    // Track worker PIDs
    const pidMatch = text.match(/\[Worker [^\]]+\].*PID[:\s]+(\d+)/i);
    if (pidMatch) {
      workerPids.add(parseInt(pidMatch[1], 10));
    }
  });

  proc.stderr?.on('data', (data) => {
    if (process.env.DEBUG) {
      console.error('[daemon]', data.toString().trim());
    }
  });

  const handle: DaemonHandle = {
    port,
    process: proc,
    pid: proc.pid!,
    workerPids,
    isRunning: () => !proc.killed && proc.exitCode === null,
    stop: async () => {
      await stopDaemon(handle);
    },
  };

  activeDaemons.add(handle);

  // Wait for daemon to start
  try {
    await waitForDaemon(port, 10000);
  } catch (err) {
    await stopDaemon(handle);
    throw err;
  }

  return handle;
}

/**
 * Stop a daemon and all its workers
 */
async function stopDaemon(handle: DaemonHandle): Promise<void> {
  activeDaemons.delete(handle);

  if (!handle.isRunning()) {
    return;
  }

  const { process: proc, workerPids } = handle;

  // First, kill all tracked worker processes
  for (const workerPid of workerPids) {
    try {
      process.kill(workerPid, 'SIGTERM');
      if (process.env.DEBUG) {
        console.log(`[cleanup] Killed worker PID ${workerPid}`);
      }
    } catch {
      // Worker might already be dead
    }
  }
  workerPids.clear();

  // Now kill the daemon
  proc.kill('SIGTERM');

  // Wait for graceful shutdown with timeout
  const exitPromise = new Promise<void>((resolve) => {
    proc.on('exit', () => resolve());
  });

  const timeoutPromise = new Promise<void>((resolve) => {
    setTimeout(() => {
      if (!proc.killed) {
        console.log('[cleanup] Force killing daemon...');
        proc.kill('SIGKILL');
      }
      resolve();
    }, 3000);
  });

  await Promise.race([exitPromise, timeoutPromise]);

  // Final cleanup: find and kill any orphaned Java workers for this daemon
  await killOrphanedWorkers(handle.port);
}

/**
 * Kill any orphaned Ghidra workers that belong to our test daemon
 */
async function killOrphanedWorkers(daemonPort: number): Promise<void> {
  if (process.platform === 'win32') {
    return;
  }

  try {
    const { execSync } = await import('node:child_process');
    const pattern = `localhost:${daemonPort}`;
    const result = execSync(
      `ps aux | grep -E "java.*ghidra.*${pattern}" | grep -v grep | awk '{print $2}'`,
      { encoding: 'utf-8', timeout: 5000 }
    ).trim();

    if (result) {
      const pids = result.split('\n').filter(Boolean);
      for (const pid of pids) {
        try {
          process.kill(parseInt(pid, 10), 'SIGKILL');
          if (process.env.DEBUG) {
            console.log(`[cleanup] Killed orphaned worker PID ${pid}`);
          }
        } catch {
          // Process already dead
        }
      }
    }
  } catch {
    // ps/grep failed, that's fine
  }
}

/**
 * Wait for daemon to be ready
 */
async function waitForDaemon(port: number, timeout: number): Promise<void> {
  const start = Date.now();
  const http = await import('node:http');

  while (Date.now() - start < timeout) {
    try {
      const healthy = await new Promise<boolean>((resolve) => {
        const req = http.request(
          {
            hostname: 'localhost',
            port,
            path: '/health',
            method: 'GET',
            timeout: 1000,
          },
          (res) => {
            resolve(res.statusCode === 200);
          }
        );
        req.on('error', () => resolve(false));
        req.on('timeout', () => {
          req.destroy();
          resolve(false);
        });
        req.end();
      });

      if (healthy) {
        return;
      }
    } catch {
      // Ignore and retry
    }

    await new Promise((resolve) => setTimeout(resolve, 200));
  }

  throw new Error(`Daemon did not start within ${timeout}ms`);
}

/**
 * Cleanup all daemons - call this in global teardown
 */
export async function cleanupAllDaemons(): Promise<void> {
  const daemons = Array.from(activeDaemons);
  await Promise.all(daemons.map((d) => d.stop().catch(() => {})));
}

/**
 * Get path to a test binary
 */
export function getTestBinaryPath(name: string): string {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x86_64';
  const os = process.platform === 'darwin' ? 'macos' : 'linux';

  const binaryPath = path.join(FIXTURES_DIR, 'binaries', `${arch}-${os}-O0`, name);

  if (!fs.existsSync(binaryPath)) {
    throw new Error(
      `Test binary not found: ${binaryPath}\n` +
        `Run 'make native' in test-fixtures/ to build test binaries.`
    );
  }

  return binaryPath;
}

/**
 * Get Ghidra project path for a test binary (if pre-analyzed)
 */
export function getGhidraProjectPath(name: string): string | undefined {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x86_64';
  const os = process.platform === 'darwin' ? 'macos' : 'linux';

  const projectName = `${name}_${arch}_${os}`;
  const projectPath = path.join(FIXTURES_DIR, 'ghidra-projects', projectName);

  // Check for .rep directory (Ghidra repository)
  if (fs.existsSync(`${projectPath}.rep`)) {
    return projectPath;
  }

  return undefined;
}

/**
 * Get all available test binaries
 */
export function getTestBinaries(): TestBinary[] {
  const arch = process.arch === 'arm64' ? 'arm64' : 'x86_64';
  const os = process.platform === 'darwin' ? 'macos' : 'linux';

  const binDir = path.join(FIXTURES_DIR, 'binaries', `${arch}-${os}-O0`);

  if (!fs.existsSync(binDir)) {
    return [];
  }

  return fs
    .readdirSync(binDir)
    .filter((f) => !f.startsWith('.'))
    // A debug build drops .dSYM bundles next to the binaries; they are directories, not
    // programs, and picking one up made the multi-session test fail with EISDIR.
    .filter((f) => fs.statSync(path.join(binDir, f)).isFile())
    .map((name) => ({
      name,
      path: path.join(binDir, name),
      ghidraProject: getGhidraProjectPath(name),
    }));
}

/**
 * Check if Ghidra projects are set up
 */
export function hasGhidraProjects(): boolean {
  const projectsDir = path.join(FIXTURES_DIR, 'ghidra-projects');
  if (!fs.existsSync(projectsDir)) {
    return false;
  }

  const projects = fs.readdirSync(projectsDir).filter((f) => f.endsWith('.rep'));
  return projects.length > 0;
}

/**
 * Get setup instructions for pre-analyzed projects
 */
export function getSetupInstructions(): string {
  return `
To set up pre-analyzed Ghidra projects for faster testing:

1. Ensure GHIDRA_HOME is set:
   export GHIDRA_HOME=/path/to/ghidra

2. Build test binaries:
   cd test-fixtures && make native

3. Create Ghidra projects:
   cd test-fixtures && make ghidra-setup

This will create pre-analyzed Ghidra projects that tests can load
instantly instead of re-analyzing on every test run.
`;
}

// Register cleanup handlers for unexpected exits
process.on('SIGINT', async () => {
  console.log('\n[test] SIGINT received, cleaning up...');
  await cleanupAllDaemons();
  process.exit(130);
});

process.on('SIGTERM', async () => {
  console.log('\n[test] SIGTERM received, cleaning up...');
  await cleanupAllDaemons();
  process.exit(143);
});

process.on('uncaughtException', async (err) => {
  console.error('[test] Uncaught exception:', err);
  await cleanupAllDaemons();
  process.exit(1);
});

process.on('unhandledRejection', async (reason) => {
  console.error('[test] Unhandled rejection:', reason);
  await cleanupAllDaemons();
  process.exit(1);
});
