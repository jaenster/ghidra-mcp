/**
 * @ghidra-mcp/gateway
 * Public read-only MCP gateway in front of a dedicated daemon.
 */

import type * as http from 'node:http';
import { PUBLIC_PROGRAMS, type PublicProgram } from './allowlist.js';
import { AuditLog, type AuditSink } from './audit.js';
import { Authenticator, hasServiceToken, type FetchLike } from './auth.js';
import { AccessJwtVerifier, type JwksFetch } from './access-jwt.js';
import type { GatewayConfig } from './config.js';
import { Gateway, type ProgramSessions } from './gateway.js';
import { QuotaManager } from './quota.js';
import { createHttpServer } from './server.js';
import { HttpUpstream, PinnedSession, type Upstream } from './upstream.js';

export * from './allowlist.js';
export { checkCall, buildPublicTools, publicToolNames, RefusedError, type PublicTool } from './tools.js';
export {
  Authenticator, AuthError, hashToken, hasServiceToken, edgeIdentity, type Identity, type FetchLike,
} from './auth.js';
export { QuotaManager } from './quota.js';
export { AuditLog, hashArgs } from './audit.js';
export { Gateway, capBytes, publicError } from './gateway.js';
export { HttpUpstream, PinnedSession, UpstreamError, type Upstream, type ServedVersion } from './upstream.js';
export { AccessJwtVerifier, ACCESS_JWT_HEADER, type JwksFetch } from './access-jwt.js';
export { loadConfig, DEFAULT_PROGRAMS, type GatewayConfig } from './config.js';
export { createHttpServer, type GatewayStatus } from './server.js';

export interface RunningGateway {
  server: http.Server;
  port: number;
  gateway: Gateway;
  sessions: ProgramSessions;
  close(): Promise<void>;
}

/**
 * Open the pinned session, then listen. The session is opened before the port
 * is, so a gateway that cannot reach its program never accepts a call.
 */
export async function startGateway(
  config: GatewayConfig,
  deps: { upstream?: Upstream; fetch?: FetchLike; auditSink?: AuditSink; jwksFetch?: JwksFetch; now?: () => number } = {},
): Promise<RunningGateway> {
  const upstream = deps.upstream ?? new HttpUpstream(config.upstreamUrl, config.upstreamToken);
  const built: Partial<Record<PublicProgram, PinnedSession>> = {};
  for (const name of PUBLIC_PROGRAMS) {
    const target = config.programs[name];
    built[name] = new PinnedSession(upstream, {
      program: target.program,
      programPath: target.programPath,
      readyTimeoutMs: config.sessionReadyTimeoutMs,
      requireDedicatedUpstream: config.requireDedicatedUpstream,
      siblings: () => PUBLIC_PROGRAMS
        .filter((other) => other !== name)
        .map((other) => built[other]?.id)
        .filter((id): id is string => !!id),
    });
  }
  const sessions = built as ProgramSessions;
  // One at a time: each open checks that the daemon holds nothing but the
  // sessions opened before it.
  for (const name of PUBLIC_PROGRAMS) {
    await sessions[name].open();
    await sessions[name].refreshVersion();
  }

  const audit = new AuditLog(deps.auditSink);
  const quota = new QuotaManager({
    callsPerMinute: config.callsPerMinute,
    costlyPerMinute: config.costlyPerMinute,
    maxConcurrentCostly: config.maxConcurrentCostly,
  });
  const sweep = setInterval(() => quota.sweep(), 60_000);
  sweep.unref();
  const watchdog = setInterval(() => {
    for (const name of PUBLIC_PROGRAMS) {
      const session = sessions[name];
      session.verifyIsolation().then((ok) => {
        if (!ok) process.stderr.write(`gateway: stopped serving ${name}: ${session.brokenReason}\n`);
      }, () => { /* daemon unreachable: calls fail on their own */ });
    }
  }, config.isolationCheckMs);
  watchdog.unref();
  const versionPoll = setInterval(() => {
    for (const name of PUBLIC_PROGRAMS) {
      const before = sessions[name].servedVersion?.version;
      sessions[name].refreshVersion().then((v) => {
        if (v.version !== before) process.stderr.write(`gateway: ${name} now serves version ${v.version}\n`);
      }, (err: unknown) => {
        process.stderr.write(`gateway: could not read the ${name} version: ${err instanceof Error ? err.message : String(err)}\n`);
      });
    }
  }, config.versionPollMs);
  versionPoll.unref();
  const auth = new Authenticator({
    allowAnonymous: config.allowAnonymous,
    cacheTtlMs: config.authCacheTtlMs,
    negativeTtlMs: 60_000,
    githubApiUrl: config.githubApiUrl,
    fetch: deps.fetch,
  });
  const gateway = new Gateway(sessions, quota, audit, {
    maxResponseBytes: config.maxResponseBytes,
    cheapTimeoutMs: config.cheapTimeoutMs,
    costlyTimeoutMs: config.costlyTimeoutMs,
  });
  const { accessClientId, accessClientSecret, accessJwt } = config;
  let accessCheck: ((headers: http.IncomingHttpHeaders) => boolean | Promise<boolean>) | undefined;
  if (accessClientId && accessClientSecret) {
    accessCheck = (headers) => hasServiceToken(headers, accessClientId, accessClientSecret);
  } else if (accessJwt) {
    const verifier = new AccessJwtVerifier({ ...accessJwt, fetch: deps.jwksFetch, now: deps.now });
    accessCheck = (headers) => verifier.check(headers);
  }
  const server = createHttpServer({
    gateway,
    auth,
    audit,
    maxBodyBytes: config.maxBodyBytes,
    authMode: config.authMode,
    accessCheck,
    status: () => ({
      serving: PUBLIC_PROGRAMS.every((name) => !sessions[name].brokenReason),
      programs: { win: sessions.win.servedVersion, mac: sessions.mac.servedVersion },
    }),
  });
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
    sessions,
    close: () => new Promise<void>((resolve) => {
      clearInterval(sweep);
      clearInterval(watchdog);
      clearInterval(versionPoll);
      server.closeAllConnections();
      server.close(() => resolve());
    }),
  };
}
