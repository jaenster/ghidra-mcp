/**
 * Session lifecycle management
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import type { Session, SessionStatus } from '@ghidra-mcp/shared';

function shortId(): string {
  return crypto.randomBytes(4).toString('hex'); // 8 hex chars, 4B entropy
}
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
    this.clearStaleSessions();
    this.initialized = true;
  }

  /**
   * Clear stale sessions from database on startup
   * Sessions without running workers are useless, so we start fresh
   */
  private clearStaleSessions(): void {
    const savedSessions = this.database.getSessions();
    for (const session of savedSessions) {
      this.database.deleteSession(session.id);
    }
  }

  /**
   * Reopen all persisted sessions after a daemon restart.
   * Called after init() in daemon.ts — non-fatal per session.
   * For ghidra-server sessions, retries with exponential backoff (up to ~2 min)
   * so a pod restart where the Ghidra server is also starting doesn't lose the session.
   */
  async reopenPersistedSessions(): Promise<void> {
    const descriptors = this.database.getPersistedSessions();
    if (descriptors.length === 0) return;

    console.log(`[SessionManager] Reopening ${descriptors.length} persisted session(s)`);

    for (const desc of descriptors) {
      // Skip if already adopted via worker reconnect (worker survived the restart)
      if (this.sessions.has(desc.sessionId)) {
        console.log(`[SessionManager] Session ${desc.sessionId} already exists (worker reconnected), skipping`);
        continue;
      }

      console.log(`[SessionManager] Reopening persisted session ${desc.sessionId} (${desc.kind}: ${desc.binaryPath})`);

      const maxAttempts = desc.kind === 'server' ? 8 : 3;
      let lastError: unknown;

      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          if (attempt > 1) {
            const delayMs = Math.min(1000 * 2 ** (attempt - 2), 30_000); // 1s, 2s, 4s, 8s … 30s cap
            console.log(`[SessionManager] Retry ${attempt}/${maxAttempts} for ${desc.sessionId} in ${delayMs}ms`);
            await new Promise((r) => setTimeout(r, delayMs));
          }

          // Skip if adopted while we were waiting
          if (this.sessions.has(desc.sessionId)) {
            console.log(`[SessionManager] Session ${desc.sessionId} adopted by worker during retry, skipping`);
            break;
          }

          await this.reopenOne(desc);
          console.log(`[SessionManager] Session ${desc.sessionId} reopened successfully`);
          lastError = undefined;
          break;
        } catch (err) {
          lastError = err;
          console.warn(`[SessionManager] Failed to reopen session ${desc.sessionId} (attempt ${attempt}/${maxAttempts}): ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      if (lastError !== undefined) {
        console.error(`[SessionManager] Giving up on session ${desc.sessionId}: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
        // Remove the persisted entry so it doesn't keep failing on every restart
        this.database.deletePersistedSession(desc.sessionId);
      }
    }
  }

  private async reopenOne(desc: ReturnType<StateDatabase['getPersistedSessions']>[number]): Promise<void> {
    if (desc.kind === 'server') {
      const serverPassword = process.env.GHIDRA_SERVER_PASSWORD;
      const projectPath = path.join(getProjectsDir(), desc.sessionId);
      const ghidraServer = {
        host: desc.serverHost!,
        port: desc.serverPort!,
        repo: desc.serverRepo!,
        programPath: desc.programPath ?? '/',
        serverUser: desc.serverUser ?? process.env.GHIDRA_SERVER_USER ?? 'mcp',
        serverPassword,
      };

      const state: SessionState = {
        binaryPath: desc.binaryPath,
        binaryHash: crypto.createHash('sha256').update(desc.binaryPath).digest('hex'),
        createdAt: new Date(),
        lastAccessedAt: new Date(),
        status: 'starting',
        clientCount: 0,
        projectPath,
        programPath: desc.programPath,
        ghidraServer,
      };
      this.sessions.set(desc.sessionId, state);
      // Re-register in the sessions table so alias resolution still works
      this.database.saveSession(desc.sessionId, state);

      try {
        const workerId = await this.workerPool.spawnWorker(desc.sessionId, {
          binaryPath: desc.binaryPath,
          projectPath,
          programPath: desc.programPath,
          autoAnalyze: false,
          readOnly: desc.readOnly,
          ghidraServer,
        });
        state.workerId = workerId;
        state.status = 'analyzing';
        await this.workerPool.waitForReady(workerId);
        state.status = 'ready';
      } catch (err) {
        state.status = 'error';
        state.error = err instanceof Error ? err.message : String(err);
        this.sessions.delete(desc.sessionId);
        this.database.deleteSession(desc.sessionId);
        throw err;
      }
    } else {
      // Binary session
      if (!fs.existsSync(desc.binaryPath)) {
        throw new Error(`Binary no longer exists: ${desc.binaryPath}`);
      }
      const binaryHash = await this.computeFileHash(desc.binaryPath);
      const projectPath = path.join(getProjectsDir(), desc.sessionId);

      const state: SessionState = {
        binaryPath: desc.binaryPath,
        binaryHash,
        createdAt: new Date(),
        lastAccessedAt: new Date(),
        status: 'starting',
        clientCount: 0,
        projectPath,
        programPath: desc.programPath,
      };
      this.sessions.set(desc.sessionId, state);
      this.database.saveSession(desc.sessionId, state);

      try {
        const workerId = await this.workerPool.spawnWorker(desc.sessionId, {
          binaryPath: desc.binaryPath,
          projectPath,
          programPath: desc.programPath,
          autoAnalyze: false, // don't re-analyze on reopen
          readOnly: desc.readOnly,
        });
        state.workerId = workerId;
        state.status = 'analyzing';
        await this.workerPool.waitForReady(workerId);
        state.status = 'ready';
      } catch (err) {
        state.status = 'error';
        state.error = err instanceof Error ? err.message : String(err);
        this.sessions.delete(desc.sessionId);
        this.database.deleteSession(desc.sessionId);
        throw err;
      }
    }
  }

  /**
   * Create a new session for a binary
   */
  async createSession(
    binaryPath: string,
    options?: SessionCreateOptions
  ): Promise<Session> {
    // Ghidra Server (shared repository) session. binaryPath may be:
    //   1. host-qualified URL:  ghidra://HOST[:PORT]/REPO/program/path
    //   2. scheme + repo path:  ghidra://REPO/program/path            (no host)
    //   3. bare repo path:      REPO/program/path                     (no scheme)
    // Forms 2 & 3 are resolved against GHIDRA_SERVER_HOST/PORT so clients never need
    // to type the server host — the daemon owns the server identity via env vars
    // (GHIDRA_SERVER_HOST/PORT/USER/PASSWORD). Credentials always come from env, never the URL.
    const defaultHost = process.env.GHIDRA_SERVER_HOST;
    const port = process.env.GHIDRA_SERVER_PORT ?? '13100';
    const looksLocal = binaryPath.startsWith('/') || /^[A-Za-z]:[/\\]/.test(binaryPath)
      || binaryPath.endsWith('.gpr') || binaryPath.startsWith('.');

    if (binaryPath.startsWith('ghidra://')) {
      const afterScheme = binaryPath.slice('ghidra://'.length);
      const firstSeg = afterScheme.split('/')[0];
      // A real host segment carries a port (':'), a dotted FQDN/IP ('.'), credentials
      // ('@'), or is 'localhost'. Otherwise the first segment is a REPO name and the
      // URL is host-less → resolve against the configured default server.
      const hostQualified = firstSeg.includes(':') || firstSeg.includes('.')
        || firstSeg.includes('@') || firstSeg === 'localhost';
      if (hostQualified) {
        return this.createServerSession(binaryPath, options);
      }
      if (!defaultHost) {
        throw new Error('Host-less ghidra:// path but no GHIDRA_SERVER_HOST configured — '
          + 'set GHIDRA_SERVER_HOST or pass a full ghidra://host:port/repo/... URL.');
      }
      return this.createServerSession(`ghidra://${defaultHost}:${port}/${afterScheme}`, options);
    }

    if (defaultHost && !looksLocal) {
      return this.createServerSession(`ghidra://${defaultHost}:${port}/${binaryPath}`, options);
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
    const sessionId = shortId();
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
    this.database.savePersistedSession({
      sessionId,
      kind: 'binary',
      binaryPath: resolvedPath,
      programPath,
      readOnly: options?.readOnly,
      autoAnalyze: options?.autoAnalyze ?? true,
    });

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
    // Credentials come from the daemon's env (the server identity is owned by the
    // daemon, not the client). URL-embedded user:password is only a last-resort
    // fallback for ad-hoc connections to a different server.
    const serverUser = process.env.GHIDRA_SERVER_USER ?? parsed.user ?? 'mcp';
    const serverPassword = process.env.GHIDRA_SERVER_PASSWORD ?? parsed.password;
    const ghidraServer: GhidraServerInfo = {
      host: parsed.host,
      port: parsed.port,
      repo: parsed.repo,
      programPath: parsed.programPath,
      serverUser,
      serverPassword,
    };

    // Dedup using canonical URL (no credentials) so the same resource matches regardless of
    // how credentials were supplied.
    const canonicalUrl = parsed.canonicalUrl;
    const binaryHash = crypto.createHash('sha256').update(canonicalUrl).digest('hex');
    const programPath = parsed.programPath;

    for (const [id, state] of this.sessions) {
      if (state.binaryPath === canonicalUrl || state.binaryHash === binaryHash) {
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

    // Reuse one worker per repo (host+port+repo). The first program for a repo opens the
    // server project (which Ghidra locks exclusively on /data); a second program from the
    // SAME repo must NOT spawn a second worker (it would fail to lock the same dir). Instead
    // reuse the existing worker and load_program the repo-relative path into the open project.
    let existingWorkerId: string | undefined;
    for (const [, existingState] of this.sessions) {
      const s = existingState.ghidraServer;
      if (
        s &&
        existingState.workerId &&
        existingState.status === 'ready' &&
        s.host === ghidraServer.host &&
        s.port === ghidraServer.port &&
        s.repo === ghidraServer.repo
      ) {
        existingWorkerId = existingState.workerId;
        break;
      }
    }

    const sessionId = shortId();
    // Server sessions still need a local project dir for the worker's transient project.
    const projectPath = path.join(getProjectsDir(), sessionId);

    const state: SessionState = {
      binaryPath: canonicalUrl,
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
    this.database.savePersistedSession({
      sessionId,
      kind: 'server',
      binaryPath: canonicalUrl,
      programPath,
      readOnly: options?.readOnly,
      serverHost: ghidraServer.host,
      serverPort: ghidraServer.port,
      serverRepo: ghidraServer.repo,
      serverUser: ghidraServer.serverUser,
    });

    try {
      if (existingWorkerId) {
        // Reuse existing repo worker — load the additional program into the open project.
        // For server workers the program to load is the repo-relative program path.
        console.log(`[SessionManager] Reusing server worker ${existingWorkerId} for program ${programPath}`);
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

      const workerId = await this.workerPool.spawnWorker(sessionId, {
        binaryPath: canonicalUrl,
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
      this.database.deletePersistedSession(sessionId);
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
  serverPassword?: string;
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
 * Parse a `ghidra://[user[:password]@]HOST[:PORT]/REPO/PROGRAM/PATH` URL into its components.
 * The first path segment is the repository name; the remainder (with a leading
 * slash) is the program path within that repository. Port defaults to 13100.
 */
export function parseGhidraServerUrl(url: string): {
  host: string;
  port: number;
  repo: string;
  programPath: string;
  user?: string;
  password?: string;
  canonicalUrl: string;
} {
  const rest = url.slice('ghidra://'.length);
  const slash = rest.indexOf('/');
  if (slash < 0) {
    throw new Error(`Invalid ghidra:// URL (missing repo/program): ${url}`);
  }
  const authority = rest.slice(0, slash);
  const pathPart = rest.slice(slash + 1); // "REPO/PROGRAM/PATH"

  // Split user:password@host:port
  const atSign = authority.lastIndexOf('@');
  let user: string | undefined;
  let password: string | undefined;
  let hostPort: string;
  if (atSign >= 0) {
    const userInfo = authority.slice(0, atSign);
    hostPort = authority.slice(atSign + 1);
    const colonIdx = userInfo.indexOf(':');
    if (colonIdx >= 0) {
      user = decodeURIComponent(userInfo.slice(0, colonIdx));
      password = decodeURIComponent(userInfo.slice(colonIdx + 1));
    } else {
      user = decodeURIComponent(userInfo);
    }
  } else {
    hostPort = authority;
  }

  const colon = hostPort.lastIndexOf(':');
  const host = colon >= 0 ? hostPort.slice(0, colon) : hostPort;
  const port = colon >= 0 ? parseInt(hostPort.slice(colon + 1), 10) : 13100;
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

  // Canonical URL strips credentials so it's safe to store/log
  const canonicalUrl = `ghidra://${host}:${port}/${repo}${programPath}`;

  return { host, port, repo, programPath, user, password, canonicalUrl };
}
