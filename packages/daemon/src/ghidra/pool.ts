/**
 * Ghidra worker process pool
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import {
  getGhidraPaths,
  getJavaExecutable,
  getWorkerJarPath,
  getMemoryLimit,
  getDaemonPort,
} from '@ghidra-mcp/shared/platform';
import { selectLauncher, type WorkerLauncher, type WorkerHandle } from './launcher/launcher.js';
import type {
  WorkerCommand,
  WorkerResponse,
  WorkerRegistration,
  WorkerHeartbeat,
  WORKER_STARTUP_TIMEOUT,
  DEFAULT_COMMAND_TIMEOUT,
} from '@ghidra-mcp/shared/protocol';
import { createLogger } from '../logging/logger.js';
import type { LogStore } from '../logging/store.js';
import type { Logger } from '../logging/logger.js';

interface WorkerState {
  id: string;
  sessionId: string;
  /** The launcher owns the actual process/pod; null until launched and for adopted workers. */
  handle: WorkerHandle | null;
  status: 'starting' | 'idle' | 'busy' | 'stopping' | 'stopped';
  pid?: number;
  startTime: number;
  lastHeartbeat?: number;
  activeCommands: number;
  memoryUsed?: number;
  memorySamples: number[];  // ring buffer of last 60 memory samples for sparkline
  pendingCommands: Map<string, PendingCommand>;
  commandQueue: WorkerCommand[];
  commandCallbacks: Array<(cmd: WorkerCommand) => void>;
  threads?: {
    readPoolSize: number;
    readPoolActive: number;
    activeThreads: string[];
    currentCommands: Record<string, string>;
  };
}

interface PendingCommand {
  command: WorkerCommand;
  resolve: (response: WorkerResponse) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

interface GhidraServerSpawnOptions {
  host: string;
  port: number;
  repo: string;
  programPath: string;
  serverUser: string;
  serverPassword?: string;
}

interface SpawnOptions {
  binaryPath: string;
  projectPath: string;
  programPath?: string;
  autoAnalyze?: boolean;
  analysisTimeout?: number;
  readOnly?: boolean;
  ghidraServer?: GhidraServerSpawnOptions;
}

const WORKER_STARTUP_TIMEOUT_MS = Number(process.env.GHIDRA_MCP_STARTUP_TIMEOUT_MS) || 60000;
const DEFAULT_COMMAND_TIMEOUT_MS = 120000; // 2 minutes — list commands on large binaries can be slow

export interface WorkerPoolOptions {
  maxWorkers?: number;
  logStore?: LogStore;
}

export class WorkerPool {
  private workers = new Map<string, WorkerState>();
  private maxWorkers = 10;
  private log: Logger | null = null;
  private onWorkerExitCallback?: (workerId: string, sessionId: string, code: number | null, signal: string | null) => void;
  private stalenessTimer: NodeJS.Timeout;
  private launcherPromise?: Promise<WorkerLauncher>;

  constructor(options: WorkerPoolOptions = {}) {
    // Each worker is its own Ghidra JVM at -Xmx${GHIDRA_MCP_MEMORY}. The pool MUST
    // be capped so (maxWorkers × workerHeap + nodeOverhead) fits the container's
    // memory limit, otherwise concurrent sessions OOMKill the pod. Make it
    // config-driven (GHIDRA_MCP_MAX_WORKERS) instead of a fixed 10 that can never
    // fit a small pod. Default conservative.
    const envMax = parseInt(process.env.GHIDRA_MCP_MAX_WORKERS ?? '', 10);
    this.maxWorkers = options.maxWorkers ?? (Number.isFinite(envMax) && envMax > 0 ? envMax : 4);
    if (options.logStore) {
      this.log = createLogger(options.logStore, 'WorkerPool');
    }
    // Check adopted workers for heartbeat staleness every 30s
    this.stalenessTimer = setInterval(() => this.checkHeartbeatStaleness(), 30000);
    this.stalenessTimer.unref(); // don't keep process alive just for this
  }

  /**
   * The worker launch backend (process or k8s), created lazily on first use.
   * Registers the single death handler that drives all cleanup.
   */
  private getLauncher(): Promise<WorkerLauncher> {
    if (!this.launcherPromise) {
      this.launcherPromise = selectLauncher().then((launcher) => {
        launcher.onWorkerDied((workerId, reason, code, signal) => {
          console.log(`[WorkerPool] worker ${workerId} died (${reason})`);
          this.markWorkerDead(workerId, code, signal);
        });
        console.log(`[WorkerPool] worker backend: ${launcher.backend}`);
        return launcher;
      });
    }
    return this.launcherPromise;
  }

  /**
   * Tear down a dead worker: reject in-flight commands, drop it from the pool (so it
   * stops counting against maxWorkers), and notify the session manager. Idempotent.
   */
  private markWorkerDead(workerId: string, code: number | null, signal: string | null): void {
    const state = this.workers.get(workerId);
    if (!state) return;
    state.status = 'stopped';
    for (const pending of state.pendingCommands.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Worker exited'));
    }
    state.pendingCommands.clear();
    this.workers.delete(workerId);
    this.onWorkerExitCallback?.(workerId, state.sessionId, code, signal);
  }

  /**
   * Heartbeat backstop: if a worker (process or pod) goes silent for >60s and the
   * launcher's primary death signal (child 'exit' / pod watch) didn't fire, reap it.
   */
  private checkHeartbeatStaleness(): void {
    const now = Date.now();
    // A worker that goes silent is normally dead, but during a long client-side
    // generation phase (tens of minutes with no commands sent) an idle worker can
    // stop heartbeating yet still be perfectly alive — reaping it then deadlocks
    // the client's next query. Make the threshold configurable so long runs don't
    // false-reap idle workers.
    const staleMs = Number(process.env.GHIDRA_MCP_HEARTBEAT_STALE_MS) || 60000;
    for (const [workerId, state] of this.workers) {
      if (state.status === 'stopped' || state.status === 'stopping') continue;
      if (state.lastHeartbeat && now - state.lastHeartbeat > staleMs) {
        console.log(`[WorkerPool] worker ${workerId} heartbeat stale (>${Math.round((now - state.lastHeartbeat) / 1000)}s)`);
        this.markWorkerDead(workerId, null, null);
      }
    }
  }

  /**
   * Set callback for when a worker process exits unexpectedly
   */
  setOnWorkerExit(cb: (workerId: string, sessionId: string, code: number | null, signal: string | null) => void): void {
    this.onWorkerExitCallback = cb;
  }

  /**
   * Spawn a new worker for a session
   */
  async spawnWorker(sessionId: string, options: SpawnOptions): Promise<string> {
    if (this.workers.size >= this.maxWorkers) {
      throw new Error(`Maximum worker limit reached (${this.maxWorkers})`);
    }

    const workerId = crypto.randomUUID();
    const ghidraPaths = getGhidraPaths();
    const javaPath = getJavaExecutable();
    const workerJarPath = getWorkerJarPath();
    const daemonPort = getDaemonPort();
    const memoryLimit = getMemoryLimit();

    // Build classpath from Ghidra JARs
    // We need to include ALL modules since Ghidra has complex interdependencies
    const classpathParts = [workerJarPath];

    // Add ALL Framework modules
    const frameworkDir = path.join(ghidraPaths.ghidraHome, 'Ghidra', 'Framework');
    try {
      const frameworkModules = fs.readdirSync(frameworkDir);
      for (const mod of frameworkModules) {
        const libDir = path.join(frameworkDir, mod, 'lib');
        if (fs.existsSync(libDir)) {
          classpathParts.push(path.join(libDir, '*'));
        }
      }
    } catch {
      // Fallback to hardcoded list if directory listing fails
      const modules = ['Utility', 'Generic', 'DB', 'FileSystem', 'Project', 'SoftwareModeling',
                       'Graph', 'Docking', 'Decompiler', 'Emulation', 'Help', 'Gui', 'Pty'];
      for (const mod of modules) {
        classpathParts.push(path.join(frameworkDir, mod, 'lib', '*'));
      }
    }

    // Add ALL Features modules
    const featuresDir = path.join(ghidraPaths.ghidraHome, 'Ghidra', 'Features');
    try {
      const featureModules = fs.readdirSync(featuresDir);
      for (const mod of featureModules) {
        const libDir = path.join(featuresDir, mod, 'lib');
        if (fs.existsSync(libDir)) {
          classpathParts.push(path.join(libDir, '*'));
        }
      }
    } catch {
      // Fallback
      const modules = ['Base', 'Decompiler', 'FileFormats', 'Recognizers'];
      for (const mod of modules) {
        classpathParts.push(path.join(featuresDir, mod, 'lib', '*'));
      }
    }

    // Add ALL Processors (needed for disassembly of various architectures)
    const processorsDir = path.join(ghidraPaths.ghidraHome, 'Ghidra', 'Processors');
    try {
      const processorModules = fs.readdirSync(processorsDir);
      for (const mod of processorModules) {
        const libDir = path.join(processorsDir, mod, 'lib');
        if (fs.existsSync(libDir)) {
          classpathParts.push(path.join(libDir, '*'));
        }
      }
    } catch {
      // If listing fails, add common processor pattern
      classpathParts.push(path.join(processorsDir, '*', 'lib', '*'));
    }

    // Add patches
    classpathParts.push(
      path.join(ghidraPaths.ghidraHome, 'Ghidra', 'patch', '*')
    );

    const classpath = classpathParts.join(path.delimiter);

    const launcher = await this.getLauncher();
    // The launcher decides where the worker reaches the daemon (loopback for a local
    // child process, the Service DNS for a pod) and where its local project lives.
    const daemonUrl = launcher.daemonUrl(daemonPort);
    const projectDir = launcher.projectDir(sessionId, options.projectPath);
    console.log(`[WorkerPool] Spawning worker (${launcher.backend}) with daemon URL: ${daemonUrl}`);

    const args = [
      `-Xmx${memoryLimit}`,
      '-Duser.language=en',
      '-Duser.country=US',
      `-Dghidra.mcp.decompiler.threads=${process.env.GHIDRA_MCP_DECOMPILER_THREADS ?? '8'}`,
      '-cp', classpath,
      'com.ghidramcp.Worker',
      '--worker-id', workerId,
      '--session-id', sessionId,
      '--daemon-url', daemonUrl,
    ];

    let serverPasswordEnv: string | undefined;
    if (options.ghidraServer) {
      // Ghidra Server (shared repository) mode: connect to a remote server and open a
      // checked-out (writable) shared program; pass --read-only to open read-only instead.
      // Mutually exclusive with --binary; the password is read by the worker from
      // GHIDRA_SERVER_PASSWORD (inherited env or overridden per-spawn). --project is still
      // passed: it roots the worker's LOCAL project at the per-session dir so two workers on
      // the same repo don't collide on one Ghidra project lock.
      const srv = options.ghidraServer;
      args.push(
        '--ghidra-server', `${srv.host}:${srv.port}`,
        '--repo', srv.repo,
        '--program', srv.programPath,
        '--server-user', srv.serverUser,
        '--project', projectDir,
      );
      serverPasswordEnv = srv.serverPassword;
    } else {
      args.push(
        '--binary', options.binaryPath,
        '--project', projectDir,
      );
      if (options.programPath) {
        args.push('--program-path', options.programPath);
      }
    }

    if (options.autoAnalyze) {
      args.push('--analyze');
    }
    if (options.analysisTimeout) {
      args.push('--analysis-timeout', String(options.analysisTimeout));
    }
    if (options.readOnly) {
      args.push('--read-only');
    }

    const spawnEnv: Record<string, string | undefined> = {
      ...process.env,
      GHIDRA_HOME: ghidraPaths.ghidraHome,
    };
    if (serverPasswordEnv !== undefined) {
      spawnEnv['GHIDRA_SERVER_PASSWORD'] = serverPasswordEnv;
    }

    const workerLog = this.log ? createLogger(this.log.store, `Worker:${sessionId}:${workerId.slice(0, 8)}`) : null;

    const handle = await launcher.launch({
      workerId,
      sessionId,
      javaPath,
      javaArgs: args,
      cwd: ghidraPaths.ghidraHome,
      env: spawnEnv,
      memory: memoryLimit,
      onStderr: (line) => workerLog?.error(line),
    });

    const state: WorkerState = {
      id: workerId,
      sessionId,
      handle,
      status: 'starting',
      pid: handle.pid,
      startTime: Date.now(),
      activeCommands: 0,
      memorySamples: [],
      pendingCommands: new Map(),
      commandQueue: [],
      commandCallbacks: [],
    };

    this.workers.set(workerId, state);
    return workerId;
  }

  /**
   * Wait for a worker to be ready
   */
  async waitForReady(workerId: string): Promise<void> {
    const state = this.workers.get(workerId);
    if (!state) {
      throw new Error(`Worker not found: ${workerId}`);
    }

    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const check = () => {
        if (state.status === 'idle') {
          resolve();
          return;
        }

        if (state.status === 'stopped') {
          reject(new Error('Worker stopped before becoming ready'));
          return;
        }

        if (Date.now() - startTime > WORKER_STARTUP_TIMEOUT_MS) {
          reject(new Error('Worker startup timeout'));
          return;
        }

        setTimeout(check, 100);
      };

      check();
    });
  }

  /**
   * Send a command to a worker and wait for response
   */
  /**
   * Send a command to a worker and wait for response.
   * If programPath is set, injects _programPath into params for program routing.
   */
  async sendCommand(workerId: string, command: WorkerCommand, programPath?: string): Promise<WorkerResponse> {
    const state = this.workers.get(workerId);
    if (!state) {
      throw new Error(`Worker not found: ${workerId}`);
    }

    if (state.status === 'stopped') {
      throw new Error('Worker has stopped');
    }

    // Liveness check by local PID — valid for local child processes and adopted
    // (reconnected) workers, but NOT k8s workers (their pid is in another pod).
    if (state.handle?.backend !== 'k8s' && state.pid) {
      try {
        process.kill(state.pid, 0); // signal 0 = liveness check
      } catch {
        this.markWorkerDead(workerId, null, null);
        throw new Error('Worker has stopped');
      }
    }

    // Inject _programPath for multi-program routing
    if (programPath) {
      (command as any).params = { ...command.params, _programPath: programPath };
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        state.pendingCommands.delete(command.id);
        reject(new Error('Command timeout'));
      }, command.timeout ?? DEFAULT_COMMAND_TIMEOUT_MS);

      state.pendingCommands.set(command.id, {
        command,
        resolve,
        reject,
        timeout,
      });

      // Deliver command: either directly via waiting long-poll callback, or queue it
      const queuedAt = Date.now();
      (command as any)._queuedAt = queuedAt;
      if (state.commandCallbacks.length > 0) {
        const callback = state.commandCallbacks.shift()!;
        state.activeCommands++;
        state.status = 'busy';
        this.log?.info(`${command.command} → worker (direct) [q=${state.commandQueue.length} active=${state.activeCommands}]`);
        callback(command);
      } else {
        state.commandQueue.push(command);
        this.log?.info(`${command.command} → queued [q=${state.commandQueue.length} active=${state.activeCommands} cbs=${state.commandCallbacks.length}]`);
      }
    });
  }

  /**
   * Get next command for a worker (called via HTTP by worker)
   */
  getNextCommand(workerId: string): WorkerCommand | null {
    const state = this.workers.get(workerId);
    if (!state) {
      return null;
    }

    const command = state.commandQueue.shift();
    if (command) {
      state.activeCommands++;
      state.status = 'busy';
      const waitMs = (command as any)._queuedAt ? Date.now() - (command as any)._queuedAt : -1;
      this.log?.info(`${command.command} → worker (from queue, waited ${waitMs}ms) [q=${state.commandQueue.length} active=${state.activeCommands}]`);
    }
    return command ?? null;
  }

  /**
   * Register callback for when a command is available
   */
  onCommand(workerId: string, callback: (cmd: WorkerCommand) => void): void {
    const state = this.workers.get(workerId);
    if (!state) {
      return;
    }

    // Check if there's already a command waiting
    const command = state.commandQueue.shift();
    if (command) {
      state.activeCommands++;
      state.status = state.activeCommands > 0 ? 'busy' : 'idle';
      callback(command);
      return;
    }

    // Otherwise wait for next command
    state.commandCallbacks.push(callback);
  }

  /**
   * Remove a command callback (called when long-poll times out)
   */
  removeCommandCallback(workerId: string, callback: (cmd: WorkerCommand) => void): void {
    const state = this.workers.get(workerId);
    if (!state) return;
    const idx = state.commandCallbacks.indexOf(callback);
    if (idx !== -1) {
      state.commandCallbacks.splice(idx, 1);
    }
  }

  /**
   * Handle worker registration (called via HTTP by worker)
   */
  handleWorkerRegistration(workerId: string, registration: WorkerRegistration): void {
    const state = this.workers.get(workerId);
    if (!state) {
      console.warn(`Unknown worker trying to register: ${workerId}`);
      return;
    }

    state.status = 'idle';
    state.lastHeartbeat = Date.now();
    console.log(`Worker ${workerId} registered for session ${registration.sessionId}`);
  }

  /**
   * Handle worker result (called via HTTP by worker)
   */
  async handleWorkerResult(workerId: string, result: WorkerResponse): Promise<void> {
    const state = this.workers.get(workerId);
    if (!state) {
      return;
    }

    const pending = state.pendingCommands.get(result.id);
    if (!pending) {
      this.log?.warn(`result for unknown command: ${result.id}`);
      return;
    }

    const queuedAt = (pending.command as any)._queuedAt as number | undefined;
    const totalMs = queuedAt ? Date.now() - queuedAt : -1;
    const ok = result.success ? 'ok' : 'ERR';
    this.log?.info(`${pending.command.command} ← ${ok} ${totalMs}ms [active=${state.activeCommands - 1}]`);

    clearTimeout(pending.timeout);
    state.pendingCommands.delete(result.id);
    state.activeCommands = Math.max(0, state.activeCommands - 1);
    state.status = state.activeCommands > 0 ? 'busy' : 'idle';

    pending.resolve(result);
  }

  /**
   * Handle worker heartbeat
   */
  handleHeartbeat(workerId: string, heartbeat: WorkerHeartbeat): void {
    const state = this.workers.get(workerId);
    if (!state) {
      return;
    }

    state.lastHeartbeat = Date.now();
    if (heartbeat.status === 'busy' && state.status === 'idle') {
      state.status = 'busy';
    } else if (heartbeat.status === 'idle' && state.status === 'busy' && state.activeCommands === 0) {
      state.status = 'idle';
    }

    // Store memory usage from heartbeat
    if ((heartbeat as any).memoryUsed != null) {
      state.memoryUsed = (heartbeat as any).memoryUsed;
      state.memorySamples.push(state.memoryUsed!);
      if (state.memorySamples.length > 60) {
        state.memorySamples.shift();
      }
    }

    // Store thread pool status
    if (heartbeat.threads) {
      state.threads = heartbeat.threads;
    }

    // Store dirty tracking info from worker
    if (heartbeat.hasDirty && heartbeat.dirtySummary) {
      (state as any).dirtySummary = heartbeat.dirtySummary;
    } else {
      (state as any).dirtySummary = undefined;
    }
  }

  /**
   * Shutdown a specific worker
   */
  async shutdownWorker(workerId: string): Promise<void> {
    const state = this.workers.get(workerId);
    if (!state) {
      return;
    }

    state.status = 'stopping';

    // Send shutdown command
    try {
      await this.sendCommand(workerId, {
        id: crypto.randomUUID(),
        command: 'shutdown',
        params: { save: true },
        timeout: 10000,
      });
    } catch {
      // ignore — we tear the worker down below regardless
    }

    // Tear down the underlying process/pod (idempotent; no-op if already gone).
    if (state.handle) {
      try {
        const launcher = await this.getLauncher();
        await launcher.stop(state.handle, true);
      } catch (e) {
        console.warn(`[WorkerPool] stop worker ${workerId} failed: ${(e as Error).message}`);
      }
    }

    this.workers.delete(workerId);
  }

  /**
   * Force-kill a worker by OS signal — no graceful shutdown, no save. Used by the
   * dashboard "unstick" action: kills a hung/stuck worker so a fresh one spawns on
   * next use and auto-clears any stale server project lock. Works for both managed
   * and adopted workers (the latter has no child handle, only a pid).
   */
  forceKillWorker(workerId: string): boolean {
    const state = this.workers.get(workerId);
    if (!state) return false;

    state.status = 'stopping';
    // Reject anything in flight so callers don't hang on the dead worker.
    for (const pending of state.pendingCommands.values()) {
      pending.reject(new Error('Worker force-killed'));
    }
    state.pendingCommands.clear();

    // Force-stop the underlying process/pod via the launcher (async; fire-and-forget so
    // this stays a synchronous "unstick"). Belt-and-suspenders local SIGKILL by pid too.
    const handle = state.handle;
    if (handle) {
      this.getLauncher()
        .then((l) => l.stop(handle, true))
        .catch((e) => console.warn(`[WorkerPool] force-stop ${workerId} failed: ${(e as Error).message}`));
    }
    if (handle?.backend !== 'k8s' && typeof state.pid === 'number') {
      try { process.kill(state.pid, 'SIGKILL'); } catch { /* already gone */ }
    }
    this.workers.delete(workerId);
    return true;
  }

  /**
   * Shutdown all workers
   */
  async shutdownAll(): Promise<void> {
    const shutdowns = Array.from(this.workers.keys()).map((id) =>
      this.shutdownWorker(id)
    );
    await Promise.all(shutdowns);
  }

  /**
   * Get worker count
   */
  getWorkerCount(): number {
    return this.workers.size;
  }

  /**
   * Get worker PID
   */
  getWorkerPid(workerId: string): number | undefined {
    return this.workers.get(workerId)?.pid;
  }

  /**
   * Save all workers without killing them.
   * Used during graceful daemon shutdown so workers can reconnect later.
   */
  async saveAll(): Promise<void> {
    const saves: Promise<void>[] = [];
    for (const [workerId, state] of this.workers) {
      if (state.status === 'idle' || state.status === 'busy') {
        saves.push(
          this.sendCommand(workerId, {
            id: crypto.randomUUID(),
            command: 'save',
            params: {},
            timeout: 5000,
          }).then(() => {
            console.log(`[WorkerPool] Worker ${workerId} saved`);
          }).catch((err) => {
            console.warn(`[WorkerPool] Worker ${workerId} save failed: ${(err as Error).message}`);
          })
        );
      }
    }
    await Promise.allSettled(saves);
    // Don't kill workers — they'll detect disconnect and enter reconnection mode
    clearInterval(this.stalenessTimer);
    this.workers.clear();
  }

  /**
   * Adopt a reconnecting worker that survived a daemon restart.
   * Creates a WorkerState without a child process reference.
   */
  adoptWorker(sessionId: string, pid: number): string {
    const workerId = crypto.randomUUID();
    const state: WorkerState = {
      id: workerId,
      sessionId,
      handle: null, // adopted — not launched by us this lifetime
      status: 'idle',
      pid,
      startTime: Date.now(),
      lastHeartbeat: Date.now(),
      activeCommands: 0,
      memorySamples: [],
      pendingCommands: new Map(),
      commandQueue: [],
      commandCallbacks: [],
    };
    this.workers.set(workerId, state);
    console.log(`[WorkerPool] Adopted worker ${workerId} (pid ${pid}) for session ${sessionId}`);
    return workerId;
  }

  /**
   * Get sanitized worker states for the dashboard API.
   */
  getWorkerStates(): Array<{
    id: string;
    sessionId: string;
    status: string;
    pid?: number;
    startTime: number;
    lastHeartbeat?: number;
    activeCommands: number;
    memoryUsed?: number;
    memorySamples: number[];
    dirtySummary?: { functions: number; dataTypes: number; globals: number };
    threads?: { readPoolSize: number; readPoolActive: number; activeThreads: string[]; currentCommands: Record<string, string> };
  }> {
    return Array.from(this.workers.values()).map(state => ({
      id: state.id,
      sessionId: state.sessionId,
      status: state.status,
      pid: state.pid,
      startTime: state.startTime,
      lastHeartbeat: state.lastHeartbeat,
      activeCommands: state.activeCommands,
      memoryUsed: state.memoryUsed,
      memorySamples: [...state.memorySamples],
      dirtySummary: (state as any).dirtySummary,
      threads: state.threads,
    }));
  }
}
