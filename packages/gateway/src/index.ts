/**
 * @ghidra-mcp/gateway
 * Public read-only MCP gateway in front of a dedicated daemon.
 */

import type * as http from 'node:http';
import { AuditLog, type AuditSink } from './audit.js';
import { Authenticator, type FetchLike } from './auth.js';
import type { GatewayConfig } from './config.js';
import { Gateway } from './gateway.js';
import { QuotaManager } from './quota.js';
import { createHttpServer } from './server.js';
import { HttpUpstream, PinnedSession, type Upstream } from './upstream.js';

export * from './allowlist.js';
export { checkCall, buildPublicTools, publicToolNames, RefusedError, type PublicTool } from './tools.js';
export { Authenticator, AuthError, hashToken, type Identity, type FetchLike } from './auth.js';
export { QuotaManager } from './quota.js';
export { AuditLog, hashArgs } from './audit.js';
export { Gateway, capBytes } from './gateway.js';
export { HttpUpstream, PinnedSession, UpstreamError, type Upstream } from './upstream.js';
export { loadConfig, type GatewayConfig } from './config.js';
export { createHttpServer } from './server.js';

export interface RunningGateway {
  server: http.Server;
  port: number;
  gateway: Gateway;
  session: PinnedSession;
  close(): Promise<void>;
}

/**
 * Open the pinned session, then listen. The session is opened before the port
 * is, so a gateway that cannot reach its program never accepts a call.
 */
export async function startGateway(
  config: GatewayConfig,
  deps: { upstream?: Upstream; fetch?: FetchLike; auditSink?: AuditSink } = {},
): Promise<RunningGateway> {
  const upstream = deps.upstream ?? new HttpUpstream(config.upstreamUrl, config.upstreamToken);
  const session = new PinnedSession(upstream, {
    program: config.program,
    programPath: config.programPath,
    readyTimeoutMs: config.sessionReadyTimeoutMs,
    requireDedicatedUpstream: config.requireDedicatedUpstream,
  });
  await session.open();

  const audit = new AuditLog(deps.auditSink);
  const quota = new QuotaManager({
    callsPerMinute: config.callsPerMinute,
    costlyPerMinute: config.costlyPerMinute,
    maxConcurrentCostly: config.maxConcurrentCostly,
  });
  const sweep = setInterval(() => quota.sweep(), 60_000);
  sweep.unref();
  const watchdog = setInterval(() => {
    session.verifyIsolation().then((ok) => {
      if (!ok) process.stderr.write(`gateway: stopped serving: ${session.brokenReason}\n`);
    }, () => { /* daemon unreachable: calls fail on their own */ });
  }, config.isolationCheckMs);
  watchdog.unref();
  const auth = new Authenticator({
    allowAnonymous: config.allowAnonymous,
    cacheTtlMs: config.authCacheTtlMs,
    negativeTtlMs: 60_000,
    githubApiUrl: config.githubApiUrl,
    fetch: deps.fetch,
  });
  const gateway = new Gateway(session, quota, audit, {
    maxResponseBytes: config.maxResponseBytes,
    cheapTimeoutMs: config.cheapTimeoutMs,
    costlyTimeoutMs: config.costlyTimeoutMs,
  });
  const server = createHttpServer({ gateway, auth, audit, maxBodyBytes: config.maxBodyBytes, isHealthy: () => !session.brokenReason });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : config.port;
  return {
    server,
    port,
    gateway,
    session,
    close: () => new Promise<void>((resolve) => {
      clearInterval(sweep);
      clearInterval(watchdog);
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
}
