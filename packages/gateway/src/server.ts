/**
 * HTTP surface: MCP over Streamable HTTP at /mcp (stateless, one MCP server per
 * request), a bare /health, and /internal/* for the edge. Every /mcp request is
 * authenticated before the MCP layer sees it.
 *
 * Nothing here answers with daemon detail: /health says ok or not, and the
 * versions and their age are only on /internal/*, behind the service token.
 */

import * as http from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { AuditLog } from './audit.js';
import type { PublicProgram } from './allowlist.js';
import {
  AuthError, edgeIdentity, hashToken, hasServiceToken, type Authenticator, type Identity,
} from './auth.js';
import type { AuthMode } from './config.js';
import type { Format, Gateway } from './gateway.js';
import type { ServedVersion } from './upstream.js';

export interface GatewayStatus {
  serving: boolean;
  programs: Record<PublicProgram, ServedVersion | null>;
}

export interface HttpServerOptions {
  gateway: Gateway;
  auth: Authenticator;
  audit: AuditLog;
  maxBodyBytes: number;
  authMode?: AuthMode;
  /** When set, every request but /health must carry this Access service token. */
  accessToken?: { clientId: string; clientSecret: string };
  status?: () => GatewayStatus;
}

export const OUTPUT_FORMAT_HEADER = 'x-output-format';

function createMcpServer(gateway: Gateway, format: Format | undefined): Server {
  const server = new Server(
    { name: 'ghidra-mcp-gateway', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: gateway.listTools() }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const identity = extra.authInfo?.extra?.identity as Identity | undefined;
    if (!identity) throw new Error('unauthenticated');
    return gateway.callTool(identity, request.params.name, request.params.arguments, { format });
  });
  return server;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function readBody(req: http.IncomingMessage, limit: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error('Request body too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

export function createHttpServer(options: HttpServerOptions): http.Server {
  const { gateway, auth, audit, maxBodyBytes } = options;
  const authMode = options.authMode ?? 'github';
  const statusOf = options.status ?? (() => ({ serving: true, programs: { win: null, mac: null } }));

  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://gateway');

    if (url.pathname === '/health' && req.method === 'GET') {
      const healthy = statusOf().serving;
      sendJson(res, healthy ? 200 : 503, { status: healthy ? 'ok' : 'unavailable' });
      return;
    }

    if (options.accessToken
      && !hasServiceToken(req.headers, options.accessToken.clientId, options.accessToken.clientSecret)) {
      audit.record({
        identity: null, tool: '-', args: {}, durationMs: 0, bytes: 0,
        outcome: 'unauthenticated', reason: 'service_token',
      });
      sendJson(res, 403, { error: 'Forbidden' });
      return;
    }

    if (url.pathname.startsWith('/internal/')) {
      if (req.method !== 'GET' || !options.accessToken) {
        sendJson(res, 404, { error: 'Not found' });
        return;
      }
      const s = statusOf();
      if (url.pathname === '/internal/versions') {
        sendJson(res, 200, {
          win: s.programs.win?.version ?? null,
          mac: s.programs.mac?.version ?? null,
        });
        return;
      }
      if (url.pathname === '/internal/health') {
        const now = Date.now();
        const describe = (v: ServedVersion | null) =>
          v ? { version: v.version, ageSeconds: Math.round((now - v.since) / 1000) } : null;
        sendJson(res, s.serving ? 200 : 503, {
          status: s.serving ? 'ok' : 'unavailable',
          programs: { win: describe(s.programs.win), mac: describe(s.programs.mac) },
        });
        return;
      }
      sendJson(res, 404, { error: 'Not found' });
      return;
    }

    if (url.pathname !== '/mcp') {
      sendJson(res, 404, { error: 'Not found' });
      return;
    }
    if (req.method !== 'POST') {
      // Stateless: no server-initiated stream, no session to delete.
      sendJson(res, 405, { error: 'Method not allowed' }, { Allow: 'POST' });
      return;
    }

    let identity: Identity;
    const authorization = req.headers.authorization;
    try {
      if (authMode === 'edge') {
        // The service token was checked above; only now is the edge's word taken.
        const vouched = edgeIdentity(req.headers);
        if (!vouched) throw new AuthError('A signed-in caller is required.', 401);
        identity = vouched;
      } else {
        identity = await auth.authenticate(authorization, req.socket.remoteAddress ?? 'unknown');
      }
    } catch (err) {
      if (err instanceof AuthError) {
        audit.record({
          identity: null, tool: '-', args: {}, durationMs: 0, bytes: 0,
          outcome: 'unauthenticated', reason: String(err.status),
        });
        sendJson(res, err.status, { error: err.message },
          err.status === 401 ? { 'WWW-Authenticate': 'Bearer realm="ghidra-mcp-gateway"' } : {});
        return;
      }
      sendJson(res, 500, { error: 'Internal error' });
      return;
    }

    let body: unknown;
    try {
      body = await readBody(req, maxBodyBytes);
    } catch (err) {
      const status = (err as { status?: number }).status ?? 400;
      if (!res.headersSent) sendJson(res, status, { error: (err as Error).message });
      return;
    }

    const rawFormat = req.headers[OUTPUT_FORMAT_HEADER];
    const format: Format | undefined = rawFormat === 'json' || rawFormat === 'toon' ? rawFormat : undefined;

    const authInfo: AuthInfo = {
      token: authorization ? hashToken(authorization) : '',
      clientId: identity.key,
      scopes: [],
      extra: { identity },
    };
    const server = createMcpServer(gateway, format);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(Object.assign(req, { auth: authInfo }), res, body);
    } catch {
      if (!res.headersSent) sendJson(res, 500, { error: 'Internal error' });
    }
  });
}
