/**
 * Gateway configuration, from the environment.
 */

export interface GatewayConfig {
  host: string;
  port: number;
  /** The gateway's own daemon. */
  upstreamUrl: string;
  /** Bearer token for that daemon; held here and never sent to callers. */
  upstreamToken?: string;
  program: string;
  programPath?: string;
  requireDedicatedUpstream: boolean;
  allowAnonymous: boolean;
  githubApiUrl: string;
  authCacheTtlMs: number;
  callsPerMinute: number;
  costlyPerMinute: number;
  maxConcurrentCostly: number;
  maxResponseBytes: number;
  cheapTimeoutMs: number;
  costlyTimeoutMs: number;
  sessionReadyTimeoutMs: number;
  maxBodyBytes: number;
  isolationCheckMs: number;
}

function num(env: NodeJS.ProcessEnv, key: string, dflt: number, min = 1): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return dflt;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < min) throw new Error(`${key} must be a number >= ${min}, got "${raw}"`);
  return v;
}

function flag(env: NodeJS.ProcessEnv, key: string, dflt: boolean): boolean {
  const raw = env[key];
  if (raw === undefined || raw === '') return dflt;
  return raw === '1' || raw.toLowerCase() === 'true';
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const upstreamUrl = env.GATEWAY_UPSTREAM_URL?.trim();
  if (!upstreamUrl) throw new Error('GATEWAY_UPSTREAM_URL is required (the gateway\'s own daemon, e.g. http://127.0.0.1:18500)');
  return {
    host: env.GATEWAY_HOST?.trim() || '127.0.0.1',
    port: num(env, 'GATEWAY_PORT', 8090, 0),
    upstreamUrl,
    upstreamToken: env.GATEWAY_UPSTREAM_TOKEN || undefined,
    program: env.GATEWAY_PROGRAM?.trim() || '/windows/lod/Game.exe',
    programPath: env.GATEWAY_PROGRAM_PATH?.trim() || undefined,
    requireDedicatedUpstream: flag(env, 'GATEWAY_REQUIRE_DEDICATED_UPSTREAM', true),
    allowAnonymous: flag(env, 'GATEWAY_ALLOW_ANONYMOUS', false),
    githubApiUrl: env.GATEWAY_GITHUB_API_URL?.trim() || 'https://api.github.com',
    authCacheTtlMs: num(env, 'GATEWAY_AUTH_CACHE_TTL_MS', 5 * 60_000),
    callsPerMinute: num(env, 'GATEWAY_CALLS_PER_MINUTE', 60),
    costlyPerMinute: num(env, 'GATEWAY_COSTLY_PER_MINUTE', 6),
    maxConcurrentCostly: num(env, 'GATEWAY_MAX_CONCURRENT_COSTLY', 2),
    maxResponseBytes: num(env, 'GATEWAY_MAX_RESPONSE_BYTES', 256 * 1024),
    cheapTimeoutMs: num(env, 'GATEWAY_CHEAP_TIMEOUT_MS', 60_000),
    costlyTimeoutMs: num(env, 'GATEWAY_COSTLY_TIMEOUT_MS', 300_000),
    sessionReadyTimeoutMs: num(env, 'GATEWAY_SESSION_READY_TIMEOUT_MS', 300_000),
    maxBodyBytes: num(env, 'GATEWAY_MAX_BODY_BYTES', 64 * 1024),
    isolationCheckMs: num(env, 'GATEWAY_ISOLATION_CHECK_MS', 30_000),
  };
}
