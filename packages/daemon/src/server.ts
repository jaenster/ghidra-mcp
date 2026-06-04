/**
 * HTTP/SSE server for the daemon
 */

import * as http from 'node:http';
import { randomUUID } from 'node:crypto';
import express, { type Express, type Request, type Response } from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpServer } from '@ghidra-mcp/mcp';
import type { SessionManager } from './sessions/manager.js';
import type { WorkerPool } from './ghidra/pool.js';
import type { StateDatabase } from './state/database.js';
import type { LogStore } from './logging/store.js';
import type { Logger } from './logging/logger.js';
import type { ToolHandlerContext } from '@ghidra-mcp/mcp';
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

  // Health check endpoint
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      sessions: sessionManager.getSessionCount(),
      workers: workerPool.getWorkerCount(),
    });
  });

  // Status endpoint
  app.get('/status', (_req: Request, res: Response) => {
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
      app.use('/dashboard', express.static(dashboardDist));
      app.get('/dashboard/*', (_req: Request, res: Response) => {
        res.sendFile(path.resolve(dashboardDist, 'index.html'));
      });
    }
  } catch {
    // Dashboard not built yet, skip
  }

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
      closeSession: (id) => sessionManager.closeSession(id),
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
  app.post('/mcp/rpc', async (req: Request, res: Response) => {
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
  app.get('/sse', (req, res) => handleSseConnect(req, res, '/sse/messages'));
  app.post('/sse/messages', handleSseMessage);

  // Backward-compatible SSE paths (Claude Code currently uses these)
  app.get('/mcp/sse', (req, res) => handleSseConnect(req, res, '/mcp/sse/messages'));
  app.post('/mcp/sse/messages', handleSseMessage);

  // =========================================================================
  // MCP Streamable HTTP transport (new) - at /mcp
  // Supports POST (requests), GET (SSE stream), DELETE (session cleanup)
  // =========================================================================

  const handleStreamableRequest = async (req: Request, res: Response) => {
    // Check for existing session
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport = sessionId ? activeStreamableTransports.get(sessionId) : undefined;

    if (!transport) {
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

  app.post('/mcp', handleStreamableRequest);
  app.get('/mcp', handleStreamableRequest);
  app.delete('/mcp', handleStreamableRequest);

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
