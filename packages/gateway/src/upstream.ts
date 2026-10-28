/**
 * The gateway's side of the daemon: a JSON-RPC client holding the daemon
 * credential, and the one session every public call is pinned to.
 */

export interface UpstreamResult {
  text: string;
  /** The daemon reports tool failures as text starting "Error:", not as a protocol error. */
  isError: boolean;
}

/** What the daemon's /health reports: counts only. */
export interface UpstreamHealth {
  sessions: number;
  workers: number;
}

export interface Upstream {
  call(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<UpstreamResult>;
  /** The daemon's /health. Throws UpstreamError while the daemon is not answering. */
  health?(timeoutMs: number): Promise<UpstreamHealth>;
}

/**
 * A failure on the daemon side. The message is for the operator's log and may
 * carry daemon text; callers only ever see publicMessage.
 */
export class UpstreamError extends Error {
  constructor(message: string, readonly publicMessage = 'The analysis backend is unavailable; try again later.') {
    super(message);
    this.name = 'UpstreamError';
  }
}

/** Talks to a daemon's /mcp/rpc endpoint. That endpoint answers in JSON, never TOON. */
export class HttpUpstream implements Upstream {
  private nextId = 1;

  constructor(private readonly baseUrl: string, private readonly token?: string) {}

  async health(timeoutMs: number): Promise<UpstreamHealth> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl.replace(/\/+$/, '')}/health`, { signal: AbortSignal.timeout(timeoutMs) });
    } catch {
      throw new UpstreamError('daemon unreachable');
    }
    if (res.status !== 200) throw new UpstreamError(`daemon health answered HTTP ${res.status}`);
    const body = await res.json() as { sessions?: unknown; workers?: unknown };
    return {
      sessions: typeof body.sessions === 'number' ? body.sessions : 0,
      workers: typeof body.workers === 'number' ? body.workers : 0,
    };
  }

  async call(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<UpstreamResult> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl.replace(/\/+$/, '')}/mcp/rpc`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: this.nextId++,
          method: 'tools/call',
          params: { name, arguments: args },
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const timedOut = err instanceof Error && err.name === 'TimeoutError';
      throw timedOut
        ? new UpstreamError('daemon call timed out', 'The call took too long; narrow it and try again.')
        : new UpstreamError('daemon unreachable');
    }
    if (res.status !== 200) throw new UpstreamError(`daemon answered HTTP ${res.status}`);
    const body = await res.json() as {
      result?: { content?: Array<{ type: string; text?: string }> };
      error?: { message?: string };
    };
    if (body.error) throw new UpstreamError(`daemon protocol error: ${body.error.message ?? ''}`);
    const text = (body.result?.content ?? []).map((c) => c.text ?? '').join('\n');
    return { text, isError: text.startsWith('Error:') };
  }
}

export interface PinnedSessionOptions {
  /** Repository-first program path ("/windows/lod/Game.exe") or a ghidra:// URL / local .gpr. */
  program: string;
  /** Program inside a local .gpr project that holds several. */
  programPath?: string;
  readyTimeoutMs: number;
  /**
   * Refuse to start when the daemon already holds sessions the gateway did not
   * open. The gateway expects a daemon of its own; on a shared one, create_session
   * dedups onto whatever session already has the program open - writable included.
   */
  requireDedicatedUpstream: boolean;
  /**
   * Sessions the gateway itself holds for its other programs. They count as
   * the gateway's own in the isolation checks.
   */
  siblings?: () => readonly string[];
}

interface SessionRow {
  id: string;
  status: string;
  clientCount?: number;
  repoSession?: boolean;
}

const SESSION_GONE = /^Error: (Session not found|No session specified)/;

/** The server version a session serves, as its worker reports it. */
export interface ServedVersion {
  /** Server version number; null for a program that is not on a server (a local project). */
  version: number | null;
  /** When that version started being served (epoch ms). */
  since: number;
}

/**
 * Owns the one read-only session. Opened lazily, re-opened if the daemon loses
 * it, and never offered to callers: they cannot name it, list it or close it.
 */
export class PinnedSession {
  private sessionId: string | null = null;
  private opening: Promise<string> | null = null;
  /** Set when the isolation check fails; every later call is refused until restart. */
  private broken: string | null = null;
  private served: ServedVersion | null = null;

  constructor(private readonly upstream: Upstream, private readonly options: PinnedSessionOptions) {}

  /** The version last read from the worker, or null before the first read. */
  get servedVersion(): ServedVersion | null {
    return this.served;
  }

  /**
   * Ask the worker which server version it serves. A worker in version-follow
   * mode reloads by itself, so this changes without the session changing.
   */
  async refreshVersion(): Promise<ServedVersion> {
    const sid = await this.open();
    const res = await this.upstream.call('get_program_info', { sessionId: sid }, 30_000);
    if (res.isError) throw new UpstreamError(`get_program_info failed: ${res.text}`);
    const info = JSON.parse(res.text) as { version?: unknown; versionLoadedAt?: unknown };
    const version = typeof info.version === 'number' ? info.version : null;
    const loadedAt = typeof info.versionLoadedAt === 'number' ? info.versionLoadedAt : null;
    if (!this.served || this.served.version !== version) {
      this.served = { version, since: loadedAt ?? Date.now() };
    } else if (loadedAt !== null) {
      this.served = { version, since: loadedAt };
    }
    return this.served;
  }

  get id(): string | null {
    return this.sessionId;
  }

  async open(): Promise<string> {
    if (this.broken) throw new UpstreamError('not serving: the backend is no longer isolated', 'This server is not serving right now.');
    if (this.sessionId) return this.sessionId;
    if (!this.opening) {
      this.opening = this.doOpen().finally(() => {
        this.opening = null;
      });
    }
    return this.opening;
  }

  /** Forward one call on the pinned session, re-opening it once if the daemon lost it. */
  async call(name: string, args: Record<string, unknown>, timeoutMs: number): Promise<UpstreamResult> {
    const sid = await this.open();
    const first = await this.upstream.call(name, { ...args, sessionId: sid }, timeoutMs);
    if (!first.isError || !SESSION_GONE.test(first.text)) return first;
    if (this.sessionId === sid) this.sessionId = null;
    const again = await this.open();
    return this.upstream.call(name, { ...args, sessionId: again }, timeoutMs);
  }

  private async listSessions(): Promise<SessionRow[]> {
    const res = await this.upstream.call('list_sessions', {}, 30_000);
    if (res.isError) throw new UpstreamError(`list_sessions failed: ${res.text}`);
    return JSON.parse(res.text) as SessionRow[];
  }

  /**
   * Re-check that nobody else holds a session on the gateway's daemon. Another
   * client on the same daemon would share the pinned session through
   * create_session's dedup and could edit what the gateway reads. On failure the
   * gateway stops answering rather than serve possibly-edited state.
   */
  async verifyIsolation(): Promise<boolean> {
    if (!this.options.requireDedicatedUpstream || this.broken) return !this.broken;
    const siblings = new Set(this.options.siblings?.() ?? []);
    const rows = (await this.listSessions()).filter((s) => !s.repoSession && !siblings.has(s.id));
    const foreign = rows.filter((s) => s.id !== this.sessionId);
    const shared = rows.find((s) => s.id === this.sessionId && (s.clientCount ?? 1) > 1);
    if (foreign.length > 0 || shared) {
      this.broken = foreign.length > 0
        ? `${foreign.length} foreign session(s) appeared on the gateway's daemon`
        : 'another client attached to the pinned session';
      this.sessionId = null;
      return false;
    }
    return true;
  }

  get brokenReason(): string | null {
    return this.broken;
  }

  private async doOpen(): Promise<string> {
    const siblings = new Set(this.options.siblings?.() ?? []);
    const all = (await this.listSessions()).filter((s) => !s.repoSession);
    const before = all.filter((s) => !siblings.has(s.id));
    if (this.options.requireDedicatedUpstream && before.length > 0) {
      throw new UpstreamError(
        `The daemon already holds ${before.length} session(s) the gateway did not open; ` +
        'the gateway needs a daemon of its own.');
    }
    const isUrlOrProject = this.options.program.startsWith('ghidra://') || this.options.program.endsWith('.gpr');
    const res = await this.upstream.call('create_session', {
      ...(isUrlOrProject ? { binaryPath: this.options.program } : { program: this.options.program }),
      ...(this.options.programPath ? { programPath: this.options.programPath } : {}),
      readOnly: true,
      autoAnalyze: false,
    }, this.options.readyTimeoutMs);
    if (res.isError) throw new UpstreamError(`Could not open the pinned program: ${res.text}`);
    const session = JSON.parse(res.text) as SessionRow;
    // create_session hands back an existing session for the same program, writable
    // or not, and that session carries its holders' uncommitted edits. Only a
    // session this call created is acceptable.
    if (all.some((s) => s.id === session.id) || (session.clientCount ?? 1) > 1) {
      throw new UpstreamError('The daemon returned an existing session instead of a fresh one; refusing to share it.');
    }
    await this.waitReady(session.id);
    this.sessionId = session.id;
    return session.id;
  }

  private async waitReady(id: string): Promise<void> {
    const deadline = Date.now() + this.options.readyTimeoutMs;
    for (;;) {
      const row = (await this.listSessions()).find((s) => s.id === id);
      if (row?.status === 'ready') return;
      if (!row || row.status === 'error') throw new UpstreamError(`The pinned session ${row ? 'failed' : 'vanished'} while opening.`);
      if (Date.now() > deadline) throw new UpstreamError('The pinned session did not become ready in time.');
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}
