/**
 * HTTP/SSE server for the daemon
 */

import * as http from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import * as fs from 'node:fs';
import { getWorkerSecret, getUploadsDir, getDaemonPort } from '@ghidra-mcp/shared/platform';
import express, { type Express, type Request, type Response } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpServer } from '@ghidra-mcp/mcp';
import { getOAuthConfig, installOAuth } from './auth/oauth.js';
import type { RequestHandler } from 'express';
import type { SessionManager } from './sessions/manager.js';
import type { WorkerPool } from './ghidra/pool.js';
import type { StateDatabase } from './state/database.js';
import type { LogStore } from './logging/store.js';
import type { Logger } from './logging/logger.js';
import type { ToolHandlerContext } from '@ghidra-mcp/mcp';
import { UploadStore } from './uploads/store.js';
import { ChangeStore, type ChangeEvent } from './changes/store.js';
import type { WorkerCommand, WorkerResponse, WorkerReconnectRequest } from '@ghidra-mcp/shared/protocol';
import type { LogEntry, LogQueryOptions } from '@ghidra-mcp/shared';
import type { CommandLog } from './command-log.js';

export interface ServerOptions {
  sessionManager: SessionManager;
  workerPool: WorkerPool;
  database: StateDatabase;
  logStore?: LogStore;
  logger?: Logger;
  commandLog?: CommandLog;
}

// Track active SSE transports by their MCP session ID (from query param)
const activeTransports = new Map<string, SSEServerTransport>();

// Track event SSE clients for dirty tracking (sessionId → Set of Response objects)
const eventClients = new Map<string, Set<Response>>();
// Track active Streamable HTTP transports by session ID
const activeStreamableTransports = new Map<string, StreamableHTTPServerTransport>();
let defaultSessionId: string | null = null;

export async function createServer(options: ServerOptions): Promise<{
  server: http.Server;
  app: Express;
}> {
  const { sessionManager, workerPool } = options;

  const app = express();
  // Increase body size limit for large responses (data types from big binaries like Diablo 2)
  app.use(express.json({ limit: '100mb' }));

  // Upload slots: a client asks for one over MCP, PUTs a binary to the URL it gets back,
  // then names that upload in import_program. The worker fetches it from the daemon.
  const uploads = new UploadStore({ dir: getUploadsDir() });

  // Recent program changes, per session, in order. The durable copy is the worker's
  // journal file; this only spares a connected subscriber a round trip.
  const changes = new ChangeStore();

  // OAuth 2.1 authorization server (active only when GHIDRA_MCP_PUBLIC_URL +
  // GHIDRA_MCP_AUTH_SECRET are set). Gates the MCP transports below; health,
  // dashboard, and the internal worker API stay open (the latter must not be
  // exposed by the ingress — only loopback / in-pod traffic reaches it).
  const oauthConfig = getOAuthConfig();
  const passthrough: RequestHandler = (_req, _res, next) => next();
  let requireAuth: RequestHandler = passthrough;
  let requireDashboardAuth: RequestHandler = passthrough;
  if (oauthConfig.enabled) {
    const installed = installOAuth(app, options.database, oauthConfig);
    requireAuth = installed.requireAuth;
    requireDashboardAuth = installed.requireDashboardAuth;
    if (options.logger) {
      options.logger.info('OAuth enabled for MCP endpoints', { issuer: oauthConfig.publicUrl });
    }
  } else if (oauthConfig.publicUrl && process.env.GHIDRA_MCP_INSECURE !== '1') {
    // FAIL-CLOSED on a production misconfiguration: a public URL is set (so this is
    // an exposed deployment, not local dev) but OAuth isn't fully configured
    // (missing GHIDRA_MCP_AUTH_SECRET and/or OIDC issuer/client). Previously this
    // silently fell through to passthrough → every MCP + dashboard route open to the
    // internet. Refuse instead. Pure local dev (no PUBLIC_URL) stays open; set
    // GHIDRA_MCP_INSECURE=1 to force-open an exposed instance anyway.
    const denyClosed: RequestHandler = (_req: Request, res: Response) => {
      res.status(503).json({
        error: 'Auth misconfigured: GHIDRA_MCP_PUBLIC_URL is set but OAuth is incomplete ' +
          '(need GHIDRA_MCP_AUTH_SECRET + OIDC issuer/client). Refusing to serve ' +
          'unauthenticated. Fix the config, or set GHIDRA_MCP_INSECURE=1 to override.',
      });
    };
    requireAuth = denyClosed;
    requireDashboardAuth = denyClosed;
    options.logger?.error(
      'OAuth NOT fully configured but GHIDRA_MCP_PUBLIC_URL is set — failing closed ' +
      '(all MCP + dashboard routes return 503). Set GHIDRA_MCP_INSECURE=1 to override.');
  }

  // Gate the dashboard's JSON API behind the Authentik session cookie (no-op when
  // auth is disabled). Must precede the /api route handlers below.
  app.use('/api', requireDashboardAuth);

  // Health check endpoint
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      sessions: sessionManager.getSessionCount(),
      workers: workerPool.getWorkerCount(),
    });
  });

  // Status endpoint. Gated behind dashboard auth: listSessions() exposes binary +
  // program file paths and session IDs, which must not be readable unauthenticated
  // (the ingress routes `/` here, so /status is internet-reachable). /health stays
  // open for k8s probes; it only returns counts.
  app.get('/status', requireDashboardAuth, (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      sessions: sessionManager.listSessions(),
      workers: workerPool.getWorkerCount(),
      defaultSession: defaultSessionId,
    });
  });

  // Session management API
  app.get('/api/sessions', (_req: Request, res: Response) => {
    const sessions = sessionManager.listSessions();
    res.json({ sessions });
  });

  app.post('/api/sessions', async (req: Request, res: Response) => {
    try {
      const { binaryPath, programPath, autoAnalyze, analysisTimeout } = req.body;
      if (!binaryPath) {
        res.status(400).json({ error: 'binaryPath is required' });
        return;
      }

      const session = await sessionManager.createSession(binaryPath, {
        programPath,
        autoAnalyze,
        analysisTimeout,
      });

      res.json({ session });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: message });
    }
  });

  app.delete('/api/sessions/:sessionId', async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      await sessionManager.closeSession(sessionId);
      res.json({ success: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: message });
    }
  });

  // Log query endpoint
  app.get('/api/logs', (req: Request, res: Response) => {
    const { logStore } = options;
    if (!logStore) {
      res.status(503).json({ error: 'Log store not available' });
      return;
    }

    const queryOpts: LogQueryOptions = {};
    if (req.query.level) queryOpts.level = req.query.level as LogQueryOptions['level'];
    if (req.query.component) queryOpts.component = req.query.component as string;
    if (req.query.sessionId) queryOpts.sessionId = req.query.sessionId as string;
    if (req.query.limit) queryOpts.limit = parseInt(req.query.limit as string, 10);
    if (req.query.since) queryOpts.since = parseInt(req.query.since as string, 10);

    const result = logStore.query(queryOpts);
    res.json(result);
  });

  // =========================================================================
  // Dashboard API endpoints
  // =========================================================================

  // Worker states
  app.get('/api/workers', (_req: Request, res: Response) => {
    res.json({ workers: workerPool.getWorkerStates() });
  });

  // Force-kill ("unstick") a hung worker — a fresh one spawns on next use and
  // auto-clears any stale server project lock left behind.
  app.post('/api/workers/:workerId/kill', (req: Request, res: Response) => {
    const killed = workerPool.forceKillWorker(req.params.workerId);
    if (!killed) {
      res.status(404).json({ error: 'Unknown worker' });
      return;
    }
    res.json({ success: true });
  });

  // Restart a session's worker: close + recreate with the same binary/programPath.
  app.post('/api/sessions/:sessionId/restart', async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      const session = sessionManager.getSession(sessionId);
      if (!session) {
        res.status(404).json({ error: 'Session not found' });
        return;
      }
      const { binaryPath, programPath } = session;
      await sessionManager.closeSession(sessionId);
      const newSession = await sessionManager.createSession(binaryPath, { programPath });
      res.json({ session: newSession });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: message });
    }
  });

  // Save a session's program (triggers 'save' worker command).
  app.post('/api/sessions/:sessionId/save', async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      const result = await sessionManager.sendCommand(sessionId, {
        id: randomUUID(),
        command: 'save',
        params: {},
      });
      if (!result.success) {
        res.status(500).json({ error: result.error?.message ?? 'Save failed' });
        return;
      }
      res.json({ success: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: message });
    }
  });

  // Commit (check-in) a session to the Ghidra Server (triggers 'checkin' worker command).
  app.post('/api/sessions/:sessionId/commit', async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      const message = typeof req.body?.message === 'string' ? req.body.message : '';
      const result = await sessionManager.sendCommand(sessionId, {
        id: randomUUID(),
        command: 'checkin',
        params: { message },
      });
      if (!result.success) {
        res.status(500).json({ error: result.error?.message ?? 'Commit failed' });
        return;
      }
      res.json({ success: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ error: message });
    }
  });

  // Authed /api/status — same counts as /status, accessible from the dashboard.
  app.get('/api/status', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      sessions: sessionManager.listSessions(),
      workers: workerPool.getWorkerCount(),
      defaultSession: defaultSessionId,
    });
  });

  // Command history
  app.get('/api/commands', (req: Request, res: Response) => {
    const { commandLog } = options;
    if (!commandLog) {
      res.json({ commands: [] });
      return;
    }
    const limit = parseInt(req.query.limit as string, 10) || 100;
    res.json({ commands: commandLog.getRecent(limit) });
  });

  // Dashboard SSE: real-time events for commands, heartbeats, logs
  const dashboardClients = new Set<Response>();

  app.get('/api/dashboard/events', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    res.write(`event: connected\ndata: {}\n\n`);

    dashboardClients.add(res);
    _req.on('close', () => dashboardClients.delete(res));
  });

  function broadcastDashboard(event: string, data: unknown): void {
    if (dashboardClients.size === 0) return;
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of dashboardClients) {
      client.write(payload);
    }
  }

  // Hook command log events into dashboard SSE
  if (options.commandLog) {
    options.commandLog.onEvent((event, entry) => {
      broadcastDashboard(event, entry);
    });
  }

  // Serve dashboard static files (built SPA)
  try {
    const path = await import('node:path');
    const fs = await import('node:fs');
    const dashboardDist = path.resolve(
      new URL('.', import.meta.url).pathname,
      '../../dashboard/dist'
    );
    if (fs.existsSync(dashboardDist)) {
      app.use('/dashboard', requireDashboardAuth, express.static(dashboardDist));
      app.get('/dashboard/*', requireDashboardAuth, (_req: Request, res: Response) => {
        res.sendFile(path.resolve(dashboardDist, 'index.html'));
      });
    }
  } catch {
    // Dashboard not built yet, skip
  }

  // The worker control-plane is authenticated with a per-daemon shared secret
  // (sent by spawned workers). This keeps /internal/* safe even if the daemon
  // binds 0.0.0.0 and an ingress misroutes it. Applied to every /internal route
  // and the log WebSocket upgrade below.
  const workerSecret = getWorkerSecret();
  const requireWorkerSecret: RequestHandler = (req, res, next) => {
    if (!workerSecret) return next(); // not initialized (should not happen under the daemon)
    const provided = req.headers['x-worker-secret'];
    if (typeof provided === 'string' && provided.length === workerSecret.length &&
        timingSafeEqual(Buffer.from(provided), Buffer.from(workerSecret))) {
      return next();
    }
    res.status(403).json({ error: 'Forbidden' });
  };
  // Receive an upload. The unguessable, single-use, expiring id IS the authorisation —
  // the slot was handed out by an authenticated MCP call, and nothing here reads or lists
  // anything: it only fills a slot that already exists.
  // type: () => true takes the body whatever the Content-Type says — including when the
  // client sends none at all, which is what a plain `curl --upload-file` does.
  const rawBody = express.raw({ type: () => true, limit: uploads.maxBytes });
  app.put('/upload/:id', rawBody, (req: Request, res: Response) => handleUpload(req, res));
  app.post('/upload/:id', rawBody, (req: Request, res: Response) => handleUpload(req, res));

  function handleUpload(req: Request, res: Response): void {
    const slot = uploads.get(req.params.id);
    if (!slot) {
      res.status(404).json({ error: 'No such upload, or it has expired' });
      return;
    }
    if (slot.receivedAt) {
      res.status(409).json({ error: 'That upload has already been filled' });
      return;
    }
    const body = req.body as Buffer | undefined;
    if (!Buffer.isBuffer(body) || body.length === 0) {
      res.status(400).json({ error: 'Send the binary as the raw request body' });
      return;
    }
    try {
      fs.writeFileSync(slot.filePath, body);
    } catch (err) {
      res.status(500).json({ error: `Could not store the upload: ${(err as Error).message}` });
      return;
    }
    uploads.markReceived(slot.id, body.length);
    options.logger?.info('Upload received', { id: slot.id, bytes: body.length });
    res.json({
      uploadId: slot.id,
      filename: slot.filename,
      bytes: body.length,
      programPathHint: slot.filename,
    });
  }

  // Fetched by the WORKER when importing an upload; the id is the capability.
  app.get('/upload/:id/raw', (req: Request, res: Response) => {
    const slot = uploads.get(req.params.id);
    if (!slot || !slot.receivedAt) {
      res.status(404).json({ error: 'No such upload, or nothing has been uploaded to it yet' });
      return;
    }
    res.sendFile(slot.filePath);
  });

  app.use('/internal', requireWorkerSecret);

  // Internal endpoint for worker back-connect
  app.post('/internal/worker/:workerId/register', (req: Request, res: Response) => {
    const { workerId } = req.params;
    const registration = req.body;
    workerPool.handleWorkerRegistration(workerId, registration);
    res.json({ success: true });
  });

  app.get('/internal/worker/:workerId/command', (req: Request, res: Response) => {
    const { workerId } = req.params;
    const command = workerPool.getNextCommand(workerId);
    if (command) {
      res.json(command);
    } else {
      // Long-poll: wait for a command or timeout
      const callback = (cmd: any) => {
        clearTimeout(timeout);
        res.json(cmd);
      };
      const timeout = setTimeout(() => {
        workerPool.removeCommandCallback(workerId, callback);
        res.json(null);
      }, 5000);

      workerPool.onCommand(workerId, callback);
    }
  });

  app.post('/internal/worker/:workerId/result', async (req: Request, res: Response) => {
    const { workerId } = req.params;
    const result = req.body;
    await workerPool.handleWorkerResult(workerId, result);
    res.json({ success: true });
  });

  // The worker pushes each flushed batch of program changes here. Posting rather than
  // riding the heartbeat: a heartbeat is lossy and five seconds apart, and a change feed
  // that drops a batch is worse than no feed at all, because a subscriber cannot tell.
  app.post('/internal/worker/:workerId/changes', (req: Request, res: Response) => {
    const { sessionId, events } = req.body as { sessionId?: string; events?: ChangeEvent[] };
    if (!sessionId || !Array.isArray(events)) {
      res.status(400).json({ error: 'sessionId and events are required' });
      return;
    }
    const accepted = changes.append(sessionId, events);
    // The worker retries on anything but a 200, so acknowledge only what was stored.
    res.json({ success: true, accepted: accepted.length, head: changes.head(sessionId) });
  });

  app.post('/internal/worker/:workerId/heartbeat', (req: Request, res: Response) => {
    const { workerId } = req.params;
    const heartbeat = req.body;
    workerPool.handleHeartbeat(workerId, heartbeat);

    // Broadcast heartbeat to dashboard clients
    broadcastDashboard('heartbeat', {
      workerId,
      status: heartbeat.status,
      memoryUsed: heartbeat.memoryUsed,
      timestamp: Date.now(),
    });

    // Forward dirty events to connected SSE clients
    if (heartbeat.hasDirty && heartbeat.sessionId) {
      const clients = eventClients.get(heartbeat.sessionId);
      if (clients && clients.size > 0) {
        const data = JSON.stringify(heartbeat.dirtySummary ?? { functions: 0, dataTypes: 0, globals: 0 });
        for (const client of clients) {
          client.write(`event: dirty\ndata: ${data}\n\n`);
        }
      }
    }

    res.json({ success: true });
  });

  // SSE endpoint for dirty tracking events
  app.get('/api/sessions/:sessionId/events', (req: Request, res: Response) => {
    const { sessionId } = req.params;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Register this client
    if (!eventClients.has(sessionId)) {
      eventClients.set(sessionId, new Set());
    }
    eventClients.get(sessionId)!.add(res);

    // Send initial connected event
    res.write(`event: connected\ndata: {"sessionId":"${sessionId}"}\n\n`);

    // Cleanup on close
    req.on('close', () => {
      const clients = eventClients.get(sessionId);
      if (clients) {
        clients.delete(res);
        if (clients.size === 0) eventClients.delete(sessionId);
      }
    });
  });

  // Worker reconnection endpoint (after daemon restart)
  app.post('/internal/reconnect', async (req: Request, res: Response) => {
    try {
      const reconnect = req.body as WorkerReconnectRequest;
      const result = await sessionManager.handleWorkerReconnect(reconnect);
      res.json({
        success: true,
        workerId: result.workerId,
        sessionId: result.sessionId,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.status(409).json({ success: false, error: message });
    }
  });

  // Helper: create a ToolHandlerContext (shared by all MCP transports)
  function createToolContext(): ToolHandlerContext {
    const { commandLog } = options;
    return {
      listSessions: () => Promise.resolve(sessionManager.listSessions()),
      getSession: (id) => Promise.resolve(sessionManager.getSession(id)),
      createSession: (path, opts) => sessionManager.createSession(path, opts),
      closeSession: (id, force) => sessionManager.closeSession(id, force),
      getRepoSession: () => sessionManager.getRepoSession(),
      createUpload: (filename) => {
        const slot = uploads.create(filename);
        // The URL the CLIENT uses: its public address when there is one, otherwise the
        // address it already reached this daemon on.
        const base = (process.env.GHIDRA_MCP_PUBLIC_URL?.trim().replace(/\/+$/, ''))
          || `http://127.0.0.1:${getDaemonPort()}`;
        return {
          uploadId: slot.id,
          uploadUrl: `${base}/upload/${slot.id}`,
          expiresAt: slot.expiresAt,
          maxBytes: uploads.maxBytes,
        };
      },
      consumeUpload: (uploadId) => uploads.markSpent(uploadId),
      getUploadFetchUrl: (uploadId) => {
        const slot = uploads.get(uploadId);
        if (!slot || !slot.receivedAt || slot.spentAt) return null;
        // The WORKER's route to this daemon, which is not the client's.
        return `${workerPool.daemonUrlForWorkers()}/upload/${slot.id}/raw`;
      },
      sendCommand: async (sessionId: string, command: WorkerCommand) => {
        commandLog?.recordStart(command.id, sessionId, command.command, command.params ?? {});
        try {
          const result = await sessionManager.sendCommand(sessionId, command) as WorkerResponse;
          commandLog?.recordComplete(command.id, result.success, result.error?.message);
          return result;
        } catch (err) {
          commandLog?.recordComplete(command.id, false, (err as Error).message);
          throw err;
        }
      },
      getDefaultSessionId: () => defaultSessionId,
      setDefaultSessionId: (id) => {
        defaultSessionId = id;
      },
      // Session aliases
      resolveSessionId: (idOrAlias) => sessionManager.resolveSessionId(idOrAlias),
      setAlias: (alias, sid) => sessionManager.setAlias(alias, sid),
      removeAlias: (alias) => sessionManager.removeAlias(alias),
      listAliases: () => sessionManager.listAliases(),

      // Shared structures
      saveSharedStructure: (name, data) => options.database.saveSharedStructure(name, data),
      getSharedStructure: (name) => options.database.getSharedStructure(name),
      listSharedStructures: () => options.database.listSharedStructures(),
      deleteSharedStructure: (name) => options.database.deleteSharedStructure(name),
      setStructureTargets: (structName, aliases) => options.database.setStructureTargets(structName, aliases),
      syncSharedStructure: (name) => sessionManager.syncSharedStructure(name),
      syncAllSharedStructures: () => sessionManager.syncAllSharedStructures(),

      queryLogs: options.logStore
        ? (queryOpts: LogQueryOptions) => options.logStore!.query(queryOpts)
        : undefined,

      // Cross-binary links
      createLink: (sourceSession, sourceAddress, targetSession, targetAddress, linkType?, anchor?, metadata?) =>
        options.database.createLink(sourceSession, sourceAddress, targetSession, targetAddress, linkType, anchor, metadata),
      removeLink: (id) => options.database.removeLink(id),
      queryLinks: (opts) => options.database.queryLinks(opts),
      getLinksForEntity: (sessionId, address) => options.database.getLinksForEntity(sessionId, address),
      bulkCreateLinks: (links) => options.database.bulkCreateLinks(links),
      clearLinks: (opts) => options.database.clearLinks(opts),

      // Sync log
      logSync: (linkId, changeType, newValue, status?, oldValue?, error?) =>
        options.database.logSync(linkId, changeType, newValue, status, oldValue, error),
      getRecentSyncs: (limit) => options.database.getRecentSyncs(limit),
      isRecentSync: (sessionId, address, changeType) =>
        options.database.isRecentSync(sessionId, address, changeType),

      // Dependency validation
      storeDependencyRun: (violations) => options.database.storeDependencyRun(violations),
      getLatestDependencyRun: () => options.database.getLatestDependencyRun(),
    };
  }

  // MCP JSON-RPC endpoint (simpler alternative to SSE for clients/testing)
  /**
   * Ordered change feed for a session.
   *
   * A subscriber resumes with `?since=N`, or with the standard `Last-Event-ID` header
   * that browsers and SSE clients resend automatically. Everything after N is delivered
   * before any live event, so a reconnect is indistinguishable from never having
   * disconnected. When the daemon's buffer cannot cover the gap - it restarted, or the
   * subscriber was away too long - the worker's durable journal is asked instead. If even
   * that cannot answer, the stream says so with a `truncated` event rather than resuming
   * at the live edge, because a silent gap reads exactly like "nothing changed".
   */
  app.get('/changes/:sessionId', requireAuth, async (req: Request, res: Response) => {
    const sessionId = sessionManager.resolveSessionId(req.params.sessionId);
    const lastEventId = req.headers['last-event-id'];
    const sinceRaw = (req.query.since as string) ?? (typeof lastEventId === 'string' ? lastEventId : undefined);
    let since = Number.parseInt(sinceRaw ?? '0', 10);
    if (!Number.isFinite(since) || since < 0) since = 0;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const write = (event: string, data: unknown, id?: number) => {
      if (id !== undefined) res.write(`id: ${id}\n`);
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    // Backlog first, and only then the live subscription, so ordering holds across the
    // handover. Events that arrive while the backlog is being fetched are buffered here
    // and flushed after it.
    const pending: ChangeEvent[] = [];
    let live = false;
    let delivered = since;
    const unsubscribe = changes.subscribe(sessionId, (batch) => {
      if (!live) {
        pending.push(...batch);
        return;
      }
      for (const e of batch) {
        if (e.seq <= delivered) continue;
        write('change', e, e.seq);
        delivered = e.seq;
      }
    });

    req.on('close', () => {
      unsubscribe();
    });

    write('connected', { sessionId, since });

    try {
      let backlog: ChangeEvent[];
      if (changes.hasFrom(sessionId, since)) {
        backlog = changes.since(sessionId, since);
      } else {
        const response = await sessionManager.sendCommand(sessionId, {
          id: randomUUID(),
          command: 'get_changes',
          params: { since, limit: 10000 },
        } as WorkerCommand);
        const result = response.result as { events?: ChangeEvent[]; head?: number } | undefined;
        backlog = result?.events ?? [];
        if (backlog.length === 0 && (result?.head ?? 0) > since) {
          write('truncated', { since, head: result?.head ?? 0 });
        }
      }
      for (const e of backlog) {
        write('change', e, e.seq);
        delivered = Math.max(delivered, e.seq);
      }
    } catch (err) {
      write('error', { message: err instanceof Error ? err.message : String(err) });
    }

    // Anything that arrived while the backlog was being fetched may already be in it.
    // Sequence numbers make that cheap to settle without tracking identity.
    for (const e of pending) {
      if (e.seq <= delivered) continue;
      write('change', e, e.seq);
      delivered = e.seq;
    }
    pending.length = 0;
    live = true;

    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => clearInterval(ping));
  });

  app.post('/mcp/rpc', requireAuth, async (req: Request, res: Response) => {
    const { jsonrpc, id, method, params } = req.body;

    if (jsonrpc !== '2.0') {
      res.status(400).json({ jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request' } });
      return;
    }

    const context = createToolContext();

    try {
      let result: unknown;

      if (method === 'tools/list') {
        // Import tools list from mcp package
        const { getAllTools } = await import('@ghidra-mcp/mcp');
        const tools = getAllTools();
        result = { tools };
      } else if (method === 'tools/call') {
        const { name, arguments: args } = params as { name: string; arguments: Record<string, unknown> };
        const { handleToolCall } = await import('@ghidra-mcp/mcp');
        result = await handleToolCall(name, args, context);
      } else {
        res.json({ jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown method: ${method}` } });
        return;
      }

      res.json({ jsonrpc: '2.0', id, result });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      res.json({ jsonrpc: '2.0', id, error: { code: -32000, message } });
    }
  });

  // =========================================================================
  // MCP SSE transport (legacy) - at /sse and /sse/messages
  // Also available at /mcp and /mcp/messages for backward compatibility
  // =========================================================================

  const handleSseConnect = async (_req: Request, res: Response, messagesPath: string) => {
    const context = createToolContext();
    const mcpServer = createMcpServer({
      name: 'ghidra-mcp',
      version: '1.0.0',
      context,
    });

    const transport = new SSEServerTransport(messagesPath, res);
    await mcpServer.connect(transport);

    const mcpSessionId = transport.sessionId;
    activeTransports.set(mcpSessionId, transport);

    res.on('close', () => {
      activeTransports.delete(mcpSessionId);
    });
  };

  const handleSseMessage = async (req: Request, res: Response) => {
    const mcpSessionId = req.query.sessionId as string;
    if (!mcpSessionId) {
      res.status(400).json({ error: 'Missing sessionId query parameter' });
      return;
    }

    const transport = activeTransports.get(mcpSessionId);
    if (!transport) {
      res.status(400).json({ error: 'No active SSE connection for this session' });
      return;
    }

    try {
      await transport.handlePostMessage(req, res, req.body);
    } catch (error) {
      if (!res.headersSent) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: message });
      } else {
        console.error('[MCP] Error after headers sent:', error);
      }
    }
  };

  // Primary SSE paths
  app.get('/sse', requireAuth, (req, res) => handleSseConnect(req, res, '/sse/messages'));
  app.post('/sse/messages', requireAuth, handleSseMessage);

  // Backward-compatible SSE paths (Claude Code currently uses these)
  app.get('/mcp/sse', requireAuth, (req, res) => handleSseConnect(req, res, '/mcp/sse/messages'));
  app.post('/mcp/sse/messages', requireAuth, handleSseMessage);

  // =========================================================================
  // MCP Streamable HTTP transport (new) - at /mcp
  // Supports POST (requests), GET (SSE stream), DELETE (session cleanup)
  // =========================================================================

  const handleStreamableRequest = async (req: Request, res: Response) => {
    // Check for existing session
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport = sessionId ? activeStreamableTransports.get(sessionId) : undefined;

    if (!transport) {
      const body = req.body;
      const isInitialize = req.method === 'POST' && body != null &&
        (Array.isArray(body) ? body.some((m) => m?.method === 'initialize') : body.method === 'initialize');

      // A request carrying an mcp-session-id we don't recognize means the client's
      // session is gone — almost always because the daemon restarted and the in-memory
      // transport map was wiped. The MCP spec says respond 404 so the client knows to
      // re-initialize (start a fresh session). Returning 400 here left clients (incl.
      // claude.ai) stuck on the dead session forever, even after "reconnect".
      if (sessionId && !isInitialize) {
        res.status(404).json({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Session not found — reinitialize' },
          id: (body && !Array.isArray(body) ? body.id : null) ?? null,
        });
        return;
      }

      // New session - only allowed for POST with initialize request
      if (req.method !== 'POST') {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32600, message: 'No active session. Send an initialize request first.' },
        });
        return;
      }

      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      const context = createToolContext();
      const mcpServer = createMcpServer({
        name: 'ghidra-mcp',
        version: '1.0.0',
        context,
      });

      await mcpServer.connect(transport);

      // Clean up on close
      transport.onclose = () => {
        const sid = transport!.sessionId;
        if (sid) {
          activeStreamableTransports.delete(sid);
        }
      };

      // handleRequest processes the initialize and generates the session ID
      await transport.handleRequest(req, res, req.body);

      // Store AFTER handleRequest so sessionId is available
      const newSessionId = transport.sessionId;
      if (newSessionId) {
        activeStreamableTransports.set(newSessionId, transport);
      }
      return;
    }

    await transport.handleRequest(req, res, req.body);
  };

  app.post('/mcp', requireAuth, handleStreamableRequest);
  app.get('/mcp', requireAuth, handleStreamableRequest);
  app.delete('/mcp', requireAuth, handleStreamableRequest);

  // Create HTTP server
  const server = http.createServer(app);

  // Create WebSocket server for log streaming (noServer mode for path-based routing)
  const logWss = new WebSocketServer({ noServer: true });

  // Handle WebSocket connections for log streaming
  logWss.on('connection', (ws: WebSocket, workerId: string | null) => {
    const { logStore, logger } = options;

    if (logger) {
      logger.debug('Log WebSocket connected', { workerId });
    }

    ws.on('message', (data: Buffer) => {
      try {
        const entries = JSON.parse(data.toString()) as LogEntry[];
        if (Array.isArray(entries)) {
          for (const entry of entries) {
            if (logStore) logStore.append(entry);
            broadcastDashboard('log', entry);
          }
        }
      } catch (err) {
        if (logger) {
          logger.warn('Failed to parse log entries from worker', {
            error: err instanceof Error ? err.message : String(err),
            workerId,
          });
        }
      }
    });

    ws.on('close', () => {
      if (logger) {
        logger.debug('Log WebSocket disconnected', { workerId });
      }
    });

    ws.on('error', (err: Error) => {
      if (logger) {
        logger.warn('Log WebSocket error', {
          error: err.message,
          workerId,
        });
      }
    });
  });

  // Handle HTTP upgrade for WebSocket connections
  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url!, `http://${request.headers.host}`);

    if (url.pathname === '/internal/ws/logs') {
      // Authenticate the log socket with the same worker secret (passed as a
      // query param since the handshake carries workerId there already).
      const provided = url.searchParams.get('secret') ?? '';
      if (workerSecret && !(provided.length === workerSecret.length &&
          timingSafeEqual(Buffer.from(provided), Buffer.from(workerSecret)))) {
        socket.destroy();
        return;
      }
      const workerId = url.searchParams.get('workerId');

      logWss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
        logWss.emit('connection', ws, workerId);
      });
    } else {
      // Unknown upgrade path - close the connection
      socket.destroy();
    }
  });

  return { server, app };
}
