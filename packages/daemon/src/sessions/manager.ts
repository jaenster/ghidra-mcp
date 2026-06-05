/**
 * Session lifecycle management
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import type { Session, SessionStatus } from '@ghidra-mcp/shared';
import type { WorkerCommand, WorkerResponse, WorkerReconnectRequest } from '@ghidra-mcp/shared/protocol';
import { getProjectsDir } from '@ghidra-mcp/shared/platform';
import type { StateDatabase } from '../state/database.js';
import type { WorkerPool } from '../ghidra/pool.js';

export interface SessionCreateOptions {
  autoAnalyze?: boolean;
  analysisTimeout?: number;
  readOnly?: boolean;
  programPath?: string;
}

export class SessionManager {
  private sessions = new Map<string, SessionState>();
  private initialized = false;

  constructor(
    private database: StateDatabase,
    private workerPool: WorkerPool
  ) {
    // Don't restore in constructor - call init() after construction

    // Wire up worker death detection so session status reflects reality.
    // Multiple sessions can share a worker (e.g. .gpr with different programPaths),
    // so mark ALL sessions using this workerId as dead.
    this.workerPool.setOnWorkerExit((workerId, _sessionId, code, signal) => {
      for (const [id, state] of this.sessions) {
        if (state.workerId === workerId) {
          state.status = 'error';
          state.error = `Worker died (code=${code}, signal=${signal})`;
          state.workerId = undefined;
          console.log(`[SessionManager] Worker died for session ${id} (code=${code}, signal=${signal})`);
        }
      }
    });
  }

  /**
   * Initialize and restore sessions from database
   */
  async init(): Promise<void> {
    if (this.initialized) return;
    await this.database.ready();
    this.restoreSessions();
    this.initialized = true;
  }

  /**
   * Clear stale sessions from database on startup
   * Sessions without running workers are useless, so we start fresh
   */
  private restoreSessions(): void {
    const savedSessions = this.database.getSessions();
    for (const session of savedSessions) {
      this.database.deleteSession(session.id);
    }
  }

  /**
   * Create a new session for a binary
   */
  async createSession(
    binaryPath: string,
    options?: SessionCreateOptions
  ): Promise<Session> {
    // Ghidra Server (shared repository) session: binaryPath is a ghidra:// URL
    // rather than a local file. Skip filesystem resolution/hashing entirely.
    if (binaryPath.startsWith('ghidra://')) {
      return this.createServerSession(binaryPath, options);
    }

    // Validate binary exists
    const resolvedPath = path.resolve(binaryPath);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`Binary not found: ${resolvedPath}`);
    }

    // Compute binary hash
    const binaryHash = await this.computeFileHash(resolvedPath);

    const programPath = options?.programPath;

    // Check for existing session with same binary AND programPath
    // For .gpr projects, different programPaths should create different sessions
    const emptyHash = crypto.createHash('sha256').digest('hex');
    for (const [id, state] of this.sessions) {
      const pathMatch = state.binaryPath === resolvedPath || (binaryHash !== emptyHash && state.binaryHash === binaryHash);
      const programMatch = (state.programPath ?? null) === (programPath ?? null);

      if (pathMatch && programMatch) {
        if (state.status === 'error' && !state.workerId) {
          return this.respawnSession(id, state, options);
        }
        if (state.status !== 'error') {
          state.clientCount++;
          state.lastAccessedAt = new Date();
          this.database.updateSession(id, { lastAccessedAt: state.lastAccessedAt });
          return this.toSession(id, state);
        }
      }
    }

    // For .gpr projects with programPath, try to reuse an existing worker for the same .gpr
    let existingWorkerId: string | undefined;
    if (resolvedPath.endsWith('.gpr') && programPath) {
      for (const [, existingState] of this.sessions) {
        if (existingState.binaryPath === resolvedPath && existingState.workerId && existingState.status === 'ready') {
          existingWorkerId = existingState.workerId;
          break;
        }
      }
    }

    // Create new session
    const sessionId = crypto.randomUUID();
    const projectPath = existingWorkerId
      ? resolvedPath  // reusing worker, use the .gpr path as project path
      : path.join(getProjectsDir(), sessionId);

    const state: SessionState = {
      binaryPath: resolvedPath,
      binaryHash,
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      status: 'starting',
      clientCount: 1,
      projectPath,
      programPath,
    };

    this.sessions.set(sessionId, state);
    this.database.saveSession(sessionId, state);

    try {
      if (existingWorkerId) {
        // Reuse existing worker — send load_program command to load the new program
        console.log(`[SessionManager] Reusing worker ${existingWorkerId} for program ${programPath}`);
        state.workerId = existingWorkerId;
        state.status = 'analyzing';

        const loadCmd: WorkerCommand = {
          id: crypto.randomUUID(),
          command: 'load_program',
          params: { programPath },
          timeout: 60000,
        };
        await this.workerPool.sendCommand(existingWorkerId, loadCmd);
        state.status = 'ready';

        return this.toSession(sessionId, state);
      }

      // Spawn new worker
      const workerId = await this.workerPool.spawnWorker(sessionId, {
        binaryPath: resolvedPath,
        projectPath,
        programPath,
        autoAnalyze: options?.autoAnalyze ?? true,
        analysisTimeout: options?.analysisTimeout,
        readOnly: options?.readOnly,
      });

      state.workerId = workerId;
      state.status = 'analyzing';

      await this.workerPool.waitForReady(workerId);
      state.status = 'ready';

      return this.toSession(sessionId, state);
    } catch (error) {
      state.status = 'error';
      state.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Create a session backed by a Ghidra Server shared repository.
   * The binaryPath is a ghidra:// URL; the worker connects to the server and opens
   * the shared program checked-out (writable) unless readOnly is set. Dedup keys off
   * the URL string hash.
   */
  private async createServerSession(
    url: string,
    options?: SessionCreateOptions
  ): Promise<Session> {
    const parsed = parseGhidraServerUrl(url);
    const serverUser = process.env.GHIDRA_SERVER_USER || 'mcp';
    const ghidraServer: GhidraServerInfo = {
      host: parsed.host,
      port: parsed.port,
      repo: parsed.repo,
      programPath: parsed.programPath,
      serverUser,
    };

    // Dedup per-URL so repeated opens of the same shared program reuse the session.
    const binaryHash = crypto.createHash('sha256').update(url).digest('hex');
    const programPath = parsed.programPath;

    for (const [id, state] of this.sessions) {
      if (state.binaryPath === url || state.binaryHash === binaryHash) {
        if (state.status === 'error' && !state.workerId) {
          return this.respawnSession(id, state, options);
        }
        if (state.status !== 'error') {
          state.clientCount++;
          state.lastAccessedAt = new Date();
          this.database.updateSession(id, { lastAccessedAt: state.lastAccessedAt });
          return this.toSession(id, state);
        }
      }
    }

    const sessionId = crypto.randomUUID();
    // Server sessions still need a local project dir for the worker's transient project.
    const projectPath = path.join(getProjectsDir(), sessionId);

    const state: SessionState = {
      binaryPath: url,
      binaryHash,
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      status: 'starting',
      clientCount: 1,
      projectPath,
      programPath,
      ghidraServer,
    };

    this.sessions.set(sessionId, state);
    this.database.saveSession(sessionId, state);

    try {
      const workerId = await this.workerPool.spawnWorker(sessionId, {
        binaryPath: url,
        projectPath,
        programPath,
        autoAnalyze: options?.autoAnalyze ?? false,
        analysisTimeout: options?.analysisTimeout,
        readOnly: options?.readOnly,
        ghidraServer,
      });

      state.workerId = workerId;
      state.status = 'analyzing';

      await this.workerPool.waitForReady(workerId);
      state.status = 'ready';

      return this.toSession(sessionId, state);
    } catch (error) {
      state.status = 'error';
      state.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Resolve a session ID or alias to an actual session UUID.
   */
  resolveSessionId(idOrAlias: string): string {
    // Direct UUID match first
    if (this.sessions.has(idOrAlias)) {
      return idOrAlias;
    }
    // Try alias lookup
    const aliasEntry = this.database.getAliasByName(idOrAlias);
    if (aliasEntry) {
      return aliasEntry.sessionId;
    }
    return idOrAlias; // Return as-is, let downstream throw "not found"
  }

  /**
   * Get a session by ID or alias
   */
  getSession(sessionId: string): Session | null {
    const resolvedId = this.resolveSessionId(sessionId);
    const state = this.sessions.get(resolvedId);
    if (!state) {
      return null;
    }
    return this.toSession(resolvedId, state);
  }

  /**
   * List all sessions
   */
  listSessions(): Session[] {
    return Array.from(this.sessions.entries()).map(([id, state]) =>
      this.toSession(id, state)
    );
  }

  /**
   * Get session count
   */
  getSessionCount(): number {
    return this.sessions.size;
  }

  /**
   * Close a session
   */
  async closeSession(sessionId: string): Promise<void> {
    const state = this.sessions.get(sessionId);
    if (!state) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    state.clientCount--;

    if (state.clientCount <= 0) {
      state.status = 'closing';

      // Shutdown worker
      if (state.workerId) {
        await this.workerPool.shutdownWorker(state.workerId);
      }

      // Remove session and its aliases
      this.sessions.delete(sessionId);
      this.database.deleteSession(sessionId);
      this.database.removeAliasesForSession(sessionId);
    }
  }

  /**
   * Send a command to a session's worker
   */
  async sendCommand<T extends WorkerCommand>(
    sessionId: string,
    command: T
  ): Promise<WorkerResponse> {
    const resolvedId = this.resolveSessionId(sessionId);
    const state = this.sessions.get(resolvedId);
    if (!state) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    // Auto-respawn dead workers (rate-limited to prevent respawn loops)
    if (state.status === 'error' && !state.workerId) {
      const now = Date.now();
      const cooldown = 30_000; // 30s between respawn attempts
      if (state.lastRespawnAt && now - state.lastRespawnAt < cooldown) {
        const waitSec = Math.ceil((cooldown - (now - state.lastRespawnAt)) / 1000);
        throw new Error(`Worker died, respawn cooling down (${waitSec}s remaining). Last error: ${state.error}`);
      }
      if (!state.respawnPromise) {
        state.lastRespawnAt = now;
        state.respawnPromise = this.autoRespawn(resolvedId, state);
      }
      try {
        await state.respawnPromise;
      } catch (error) {
        throw error;
      } finally {
        state.respawnPromise = undefined;
      }
    }

    if (state.status !== 'ready') {
      throw new Error(`Session not ready (status: ${state.status})`);
    }

    if (!state.workerId) {
      throw new Error('Session has no worker');
    }

    // Update last accessed
    state.lastAccessedAt = new Date();

    return this.workerPool.sendCommand(state.workerId, command, state.programPath);
  }

  /**
   * Auto-respawn a dead worker inline during sendCommand.
   * Coalesced via state.respawnPromise so concurrent callers share one attempt.
   */
  private async autoRespawn(id: string, state: SessionState): Promise<void> {
    console.log(`[SessionManager] Auto-respawning worker for session ${id}`);
    state.status = 'starting';
    state.error = undefined;

    try {
      const workerId = await this.workerPool.spawnWorker(id, {
        binaryPath: state.binaryPath,
        projectPath: state.projectPath,
        programPath: state.programPath,
        autoAnalyze: false,
        ghidraServer: state.ghidraServer,
      });

      state.workerId = workerId;
      state.status = 'analyzing';

      await this.workerPool.waitForReady(workerId);
      state.status = 'ready';
    } catch (error) {
      state.status = 'error';
      state.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Respawn a worker for a crashed session, reusing the existing project directory
   */
  private async respawnSession(
    id: string,
    state: SessionState,
    options?: SessionCreateOptions
  ): Promise<Session> {
    console.log(`[SessionManager] Respawning worker for session ${id}`);
    state.status = 'starting';
    state.error = undefined;

    try {
      const workerId = await this.workerPool.spawnWorker(id, {
        binaryPath: state.binaryPath,
        projectPath: state.projectPath,
        programPath: state.programPath,
        autoAnalyze: options?.autoAnalyze ?? false, // don't re-analyze on respawn
        readOnly: options?.readOnly,
        ghidraServer: state.ghidraServer,
      });

      state.workerId = workerId;
      state.status = 'analyzing';

      await this.workerPool.waitForReady(workerId);
      state.status = 'ready';
      state.clientCount++;
      state.lastAccessedAt = new Date();
      return this.toSession(id, state);
    } catch (error) {
      state.status = 'error';
      state.error = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  /**
   * Handle a worker reconnecting after a daemon restart.
   * Either re-attaches to an existing session or reconstructs one from worker metadata.
   */
  async handleWorkerReconnect(
    reconnect: WorkerReconnectRequest
  ): Promise<{ workerId: string; sessionId: string }> {
    const existingSession = this.sessions.get(reconnect.sessionId);

    // If session exists and already has an active worker, reject
    if (existingSession?.workerId) {
      const existingPid = this.workerPool.getWorkerPid(existingSession.workerId);
      throw new Error(
        `Session ${reconnect.sessionId} already has an active worker (pid ${existingPid})`
      );
    }

    const workerId = this.workerPool.adoptWorker(reconnect.sessionId, reconnect.pid);

    if (existingSession) {
      // Re-attach to existing session state
      existingSession.workerId = workerId;
      existingSession.status = 'ready';
      existingSession.error = undefined;
      existingSession.lastAccessedAt = new Date();
      console.log(`[SessionManager] Reconnected worker for session ${reconnect.sessionId}`);
    } else {
      // Reconstruct session from worker metadata (daemon was fully restarted).
      // Server (ghidra://) sessions have no local file to hash — hash the URL.
      const binaryHash = reconnect.binaryPath.startsWith('ghidra://')
        ? crypto.createHash('sha256').update(reconnect.binaryPath).digest('hex')
        : await this.computeFileHash(reconnect.binaryPath);
      const state: SessionState = {
        binaryPath: reconnect.binaryPath,
        binaryHash,
        createdAt: new Date(),
        lastAccessedAt: new Date(),
        status: 'ready',
        clientCount: 0,
        projectPath: reconnect.projectPath,
        workerId,
      };
      this.sessions.set(reconnect.sessionId, state);
      this.database.saveSession(reconnect.sessionId, state);
      console.log(`[SessionManager] Reconstructed session ${reconnect.sessionId} from reconnecting worker`);
    }

    return { workerId, sessionId: reconnect.sessionId };
  }

  /**
   * Convert internal state to public Session interface
   */
  private toSession(id: string, state: SessionState): Session {
    const aliases = this.database.getAliasesForSession(id);
    return {
      id,
      binaryPath: state.binaryPath,
      binaryHash: state.binaryHash,
      programPath: state.programPath,
      createdAt: state.createdAt,
      lastAccessedAt: state.lastAccessedAt,
      status: state.status,
      clientCount: state.clientCount,
      workerPid: state.workerId
        ? this.workerPool.getWorkerPid(state.workerId)
        : undefined,
      aliases: aliases.length > 0 ? aliases : undefined,
    };
  }

  // =========================================================================
  // Alias Management
  // =========================================================================

  setAlias(alias: string, sessionId: string): void {
    const resolvedId = this.resolveSessionId(sessionId);
    if (!this.sessions.has(resolvedId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    this.database.setAlias(alias, resolvedId);
  }

  removeAlias(alias: string): void {
    this.database.removeAlias(alias);
  }

  listAliases(): Array<{ alias: string; sessionId: string }> {
    return this.database.listAliases();
  }

  // =========================================================================
  // Shared Structure Sync
  // =========================================================================

  async syncSharedStructure(name: string): Promise<{
    results: Array<{ alias: string; sessionId: string; success: boolean; error?: string }>;
  }> {
    const struct = this.database.getSharedStructure(name);
    if (!struct) {
      throw new Error(`Shared structure not found: ${name}`);
    }

    const results: Array<{ alias: string; sessionId: string; success: boolean; error?: string }> = [];

    for (const target of struct.targets) {
      const aliasEntry = this.database.getAliasByName(target.alias);
      if (!aliasEntry) {
        results.push({ alias: target.alias, sessionId: '', success: false, error: `Alias "${target.alias}" not found` });
        continue;
      }

      const state = this.sessions.get(aliasEntry.sessionId);
      if (!state || state.status !== 'ready' || !state.workerId) {
        results.push({ alias: target.alias, sessionId: aliasEntry.sessionId, success: false, error: 'Session not ready' });
        continue;
      }

      // Expand type parameters if this is a generic struct
      let expandedFields = struct.fields;
      if (struct.typeParams && struct.typeParams.length > 0 && target.bindings) {
        expandedFields = struct.fields.map(f => {
          let dataType = f.dataType;
          for (const param of struct.typeParams!) {
            if (target.bindings![param]) {
              dataType = dataType.replaceAll(param, target.bindings![param]);
            }
          }
          return { ...f, dataType };
        });
      }

      try {
        const command: WorkerCommand = {
          id: crypto.randomUUID(),
          command: 'update_structure',
          params: {
            name: struct.name,
            operation: 'replaceAll' as const,
            category: struct.category ?? undefined,
            fields: expandedFields.map(f => ({
              name: f.name,
              dataType: f.dataType,
              offset: f.offset,
              comment: f.comment,
            })),
            force: true,
          },
          timeout: 30000,
        };
        const response = await this.workerPool.sendCommand(state.workerId, command, state.programPath);
        if (response.success) {
          results.push({ alias: target.alias, sessionId: aliasEntry.sessionId, success: true });
        } else {
          results.push({ alias: target.alias, sessionId: aliasEntry.sessionId, success: false, error: response.error?.message });
        }
      } catch (err) {
        results.push({ alias: target.alias, sessionId: aliasEntry.sessionId, success: false, error: (err as Error).message });
      }
    }

    return { results };
  }

  async syncAllSharedStructures(): Promise<{
    results: Array<{ name: string; syncResults: Array<{ alias: string; sessionId: string; success: boolean; error?: string }> }>;
  }> {
    const structs = this.database.listSharedStructures();
    const results: Array<{ name: string; syncResults: Array<{ alias: string; sessionId: string; success: boolean; error?: string }> }> = [];

    for (const struct of structs) {
      const syncResult = await this.syncSharedStructure(struct.name);
      results.push({ name: struct.name, syncResults: syncResult.results });
    }

    return { results };
  }

  /**
   * Compute SHA-256 hash of a file
   */
  private async computeFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }
}

interface GhidraServerInfo {
  host: string;
  port: number;
  repo: string;
  programPath: string;
  serverUser: string;
}

interface SessionState {
  binaryPath: string;
  binaryHash: string;
  createdAt: Date;
  lastAccessedAt: Date;
  status: SessionStatus;
  clientCount: number;
  projectPath: string;
  programPath?: string;
  workerId?: string;
  workerPid?: number;
  error?: string;
  respawnPromise?: Promise<void>;
  lastRespawnAt?: number;
  ghidraServer?: GhidraServerInfo;
}

/**
 * Parse a `ghidra://HOST[:PORT]/REPO/PROGRAM/PATH` URL into its components.
 * The first path segment is the repository name; the remainder (with a leading
 * slash) is the program path within that repository. Port defaults to 13100.
 */
export function parseGhidraServerUrl(url: string): {
  host: string;
  port: number;
  repo: string;
  programPath: string;
} {
  const rest = url.slice('ghidra://'.length);
  const slash = rest.indexOf('/');
  if (slash < 0) {
    throw new Error(`Invalid ghidra:// URL (missing repo/program): ${url}`);
  }
  const authority = rest.slice(0, slash);
  const pathPart = rest.slice(slash + 1); // "REPO/PROGRAM/PATH"

  const colon = authority.indexOf(':');
  const host = colon >= 0 ? authority.slice(0, colon) : authority;
  const port = colon >= 0 ? parseInt(authority.slice(colon + 1), 10) : 13100;
  if (!host || Number.isNaN(port)) {
    throw new Error(`Invalid ghidra:// host:port: ${url}`);
  }

  const repoSlash = pathPart.indexOf('/');
  if (repoSlash < 0) {
    throw new Error(`Invalid ghidra:// URL (missing program path): ${url}`);
  }
  const repo = pathPart.slice(0, repoSlash);
  const programPath = pathPart.slice(repoSlash); // includes leading '/'
  if (!repo) {
    throw new Error(`Invalid ghidra:// URL (empty repo): ${url}`);
  }

  return { host, port, repo, programPath };
}
