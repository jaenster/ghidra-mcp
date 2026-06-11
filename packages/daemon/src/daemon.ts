/**
 * Daemon lifecycle management
 */

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { getAppPaths, ensureAppDirs, getDaemonPort, getDaemonHost } from '@ghidra-mcp/shared/platform';
import { createServer } from './server.js';
import { SessionManager } from './sessions/manager.js';
import { WorkerPool } from './ghidra/pool.js';
import { StateDatabase } from './state/database.js';
import { LogStore, createLogger, type Logger } from './logging/index.js';

export interface DaemonStatus {
  running: boolean;
  pid?: number;
  port?: number;
  uptime?: number;
  sessionCount?: number;
  workerCount?: number;
}

let daemonInstance: {
  server: http.Server;
  sessionManager: SessionManager;
  workerPool: WorkerPool;
  database: StateDatabase;
  logStore: LogStore;
  logger: Logger;
  startTime: number;
} | null = null;

/**
 * Start the daemon server
 */
export async function startDaemon(options?: {
  port?: number;
  foreground?: boolean;
  force?: boolean;
}): Promise<{ pid: number; port: number }> {
  ensureAppDirs();
  const paths = getAppPaths();
  const port = options?.port ?? getDaemonPort();

  // Set the port in environment so workers know which port to connect to
  process.env.GHIDRA_MCP_PORT = String(port);

  // Secret authenticating the worker control-plane (/internal/*). Prefer an
  // explicit env value; otherwise persist a generated one so it stays stable
  // across daemon restarts (workers re-adopting after a restart must match).
  if (!process.env.GHIDRA_MCP_WORKER_SECRET) {
    const secretFile = path.join(paths.dataDir, 'worker-secret');
    let secret: string;
    try {
      secret = fs.readFileSync(secretFile, 'utf-8').trim();
      if (!secret) throw new Error('empty');
    } catch {
      secret = crypto.randomBytes(24).toString('hex');
      try { fs.writeFileSync(secretFile, secret, { mode: 0o600 }); } catch { /* best effort */ }
    }
    process.env.GHIDRA_MCP_WORKER_SECRET = secret;
  }

  // Check if already running (unless force is set)
  if (!options?.force) {
    const existingStatus = await getDaemonStatus();
    if (existingStatus.running) {
      throw new Error(`Daemon already running (PID: ${existingStatus.pid})`);
    }
  }

  // Initialize logging
  const logStore = new LogStore();
  const logger = createLogger(logStore, 'Daemon');

  // Initialize components
  const database = new StateDatabase(paths.databaseFile);
  await database.ready();
  const workerPool = new WorkerPool({ logStore });
  const sessionManager = new SessionManager(database, workerPool);
  await sessionManager.init();

  // Reopen previously-open sessions (non-blocking — failures are logged, not thrown)
  sessionManager.reopenPersistedSessions().catch((err) => {
    logger.error('Error during session reopen', { error: String(err) });
  });

  logger.info('Components initialized');

  // Create command log for dashboard
  const { CommandLog } = await import('./command-log.js');
  const commandLog = new CommandLog();

  // Create HTTP server
  const { server, app } = await createServer({
    sessionManager,
    workerPool,
    database,
    logStore,
    logger,
    commandLog,
  });

  // Bind address: loopback locally, 0.0.0.0 in a container (GHIDRA_MCP_HOST)
  const host = getDaemonHost();
  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => {
      resolve();
    });
    server.on('error', reject);
  });

  // Store instance reference
  daemonInstance = {
    server,
    sessionManager,
    workerPool,
    database,
    logStore,
    logger,
    startTime: Date.now(),
  };

  // Write PID file
  const pid = process.pid;
  fs.writeFileSync(paths.pidFile, JSON.stringify({ pid, port, startTime: Date.now() }));

  logger.info(`Daemon started on ${host}:${port}`, { pid });

  // Crash logging — write to tmp so it doesn't clutter persistent app data
  const crashLogDir = path.join(os.tmpdir(), 'ghidra-mcp');
  try { fs.mkdirSync(crashLogDir, { recursive: true }); } catch { /* best effort */ }
  const crashLogPath = path.join(crashLogDir, 'daemon-crash.log');

  // Rotate previous crash log on startup, keep only last 5
  try {
    if (fs.existsSync(crashLogPath)) {
      const stat = fs.statSync(crashLogPath);
      const ts = stat.mtime.toISOString().replace(/[:.]/g, '-');
      fs.renameSync(crashLogPath, path.join(crashLogDir, `daemon-crash-${ts}.log`));
    }
    // Prune old crash logs — keep newest 5
    const logs = fs.readdirSync(crashLogDir)
      .filter(f => f.startsWith('daemon-crash-') && f.endsWith('.log'))
      .sort()
      .reverse();
    for (const old of logs.slice(5)) {
      fs.unlinkSync(path.join(crashLogDir, old));
    }
  } catch { /* best effort */ }

  const writeCrashLog = (label: string, err: unknown) => {
    const timestamp = new Date().toISOString();
    const stack = err instanceof Error ? err.stack : String(err);
    const entry = `[${timestamp}] ${label}\n${stack}\n\n`;
    try {
      fs.appendFileSync(crashLogPath, entry);
    } catch { /* can't log the log failure */ }
    logger.error(label, { error: String(err) });
  };

  process.on('uncaughtException', (err) => {
    writeCrashLog('UNCAUGHT EXCEPTION', err);
    stopDaemon().finally(() => process.exit(1));
  });

  process.on('unhandledRejection', (reason) => {
    writeCrashLog('UNHANDLED REJECTION', reason);
  });

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down...');
    stopDaemon().catch((err) => logger.error('Shutdown error', { error: String(err) }));
  });

  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down...');
    stopDaemon().catch((err) => logger.error('Shutdown error', { error: String(err) }));
  });

  return { pid, port };
}

/**
 * Stop the daemon
 */
export async function stopDaemon(): Promise<void> {
  const paths = getAppPaths();

  if (daemonInstance) {
    // Tell workers to save but DON'T kill them — they'll reconnect when daemon restarts
    await daemonInstance.workerPool.saveAll();

    // Close database
    daemonInstance.database.close();

    // Close HTTP server
    await new Promise<void>((resolve) => {
      daemonInstance!.server.close(() => resolve());
    });

    daemonInstance.logger.info('Daemon stopped (workers preserved for reconnection)');
    daemonInstance = null;
  }

  // Remove PID file
  if (fs.existsSync(paths.pidFile)) {
    fs.unlinkSync(paths.pidFile);
  }
}

/**
 * Get daemon status
 */
export async function getDaemonStatus(): Promise<DaemonStatus> {
  const paths = getAppPaths();

  // Check if we're the running daemon
  if (daemonInstance) {
    return {
      running: true,
      pid: process.pid,
      port: getDaemonPort(),
      uptime: Date.now() - daemonInstance.startTime,
      sessionCount: daemonInstance.sessionManager.getSessionCount(),
      workerCount: daemonInstance.workerPool.getWorkerCount(),
    };
  }

  // Check PID file
  if (!fs.existsSync(paths.pidFile)) {
    return { running: false };
  }

  try {
    const pidData = JSON.parse(fs.readFileSync(paths.pidFile, 'utf-8'));
    const { pid, port, startTime } = pidData;

    // Check if process is running
    try {
      process.kill(pid, 0); // Signal 0 = check if process exists
    } catch {
      // Process not running, clean up stale PID file
      fs.unlinkSync(paths.pidFile);
      return { running: false };
    }

    // Try to connect to the daemon
    const isResponding = await checkDaemonHealth(port);
    if (!isResponding) {
      return { running: true, pid, port }; // Running but not responding
    }

    return {
      running: true,
      pid,
      port,
      uptime: Date.now() - startTime,
    };
  } catch {
    return { running: false };
  }
}

/**
 * Check if daemon is responding to health checks
 */
async function checkDaemonHealth(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path: '/health',
        method: 'GET',
        timeout: 2000,
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
}

/**
 * Get the log store from the running daemon instance
 */
export function getLogStore(): LogStore | null {
  return daemonInstance?.logStore ?? null;
}
