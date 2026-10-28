/**
 * Gateway configuration, from the environment.
 */

import type { PublicProgram } from './allowlist.js';

/** Where one public program name points. Origin configuration only; never taken from a request. */
export interface ProgramTarget {
  /** Repository-first server path ("Diablo2Lod/windows/lod/1.14d/Game.exe"), a ghidra:// URL or a local .gpr. */
  program: string;
  /** Program inside a local .gpr project that holds several. */
  programPath?: string;
}

/**
 * github: callers send a GitHub token, checked against GitHub.
 * edge: the gateway sits behind the edge Worker, which has already signed the
 * caller in; requests must pass the Access check (the service token itself, or
 * the Access JWT for the origin's application), and only then is the identity
 * header the edge sends trusted.
 */
export type AuthMode = 'github' | 'edge';

export const DEFAULT_PROGRAMS: Readonly<Record<PublicProgram, ProgramTarget>> = {
  win: { program: 'Diablo2Lod/windows/lod/1.14d/Game.exe' },
  mac: { program: 'Diablo2Lod/mac/intel/1.14d/DiabloII_macho' },
};

export interface GatewayConfig {
  host: string;
  port: number;
  /** The gateway's own daemon. */
  upstreamUrl: string;
  /** Bearer token for that daemon; held here and never sent to callers. */
  upstreamToken?: string;
  programs: Record<PublicProgram, ProgramTarget>;
  requireDedicatedUpstream: boolean;
  authMode: AuthMode;
  /** Cloudflare Access service token the edge sends; when set, required on everything but /health. */
  accessClientId?: string;
  accessClientSecret?: string;
  /**
   * Cloudflare Access application the origin sits behind; when set, every request
   * but /health must carry a valid Cf-Access-Jwt-Assertion for it.
   */
  accessJwt?: { teamDomain: string; audience: string; serviceTokenId?: string };
  /** How often the served version of each program is re-read from its worker. */
  versionPollMs: number;
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
  const authMode = (env.GATEWAY_AUTH_MODE?.trim() || 'github') as AuthMode;
  if (authMode !== 'github' && authMode !== 'edge') {
    throw new Error(`GATEWAY_AUTH_MODE must be "github" or "edge", got "${env.GATEWAY_AUTH_MODE}"`);
  }
  const accessClientId = env.GATEWAY_ACCESS_CLIENT_ID?.trim() || undefined;
  const accessClientSecret = env.GATEWAY_ACCESS_CLIENT_SECRET?.trim() || undefined;
  if (!!accessClientId !== !!accessClientSecret) {
    throw new Error('GATEWAY_ACCESS_CLIENT_ID and GATEWAY_ACCESS_CLIENT_SECRET are set together or not at all');
  }
  const teamDomain = env.GATEWAY_ACCESS_TEAM_DOMAIN?.trim().replace(/\/+$/, '') || undefined;
  const audience = env.GATEWAY_ACCESS_AUD?.trim() || undefined;
  if (!!teamDomain !== !!audience) {
    throw new Error('GATEWAY_ACCESS_TEAM_DOMAIN and GATEWAY_ACCESS_AUD are set together or not at all');
  }
  if (teamDomain && !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(teamDomain)) {
    throw new Error(`GATEWAY_ACCESS_TEAM_DOMAIN must be https://<team>.cloudflareaccess.com, got "${teamDomain}"`);
  }
  const serviceTokenId = env.GATEWAY_ACCESS_SERVICE_TOKEN_ID?.trim() || undefined;
  if (serviceTokenId && !teamDomain) {
    throw new Error('GATEWAY_ACCESS_SERVICE_TOKEN_ID needs GATEWAY_ACCESS_TEAM_DOMAIN and GATEWAY_ACCESS_AUD');
  }
  if (accessClientId && teamDomain) {
    throw new Error('Configure the Access service token or the Access JWT check, not both');
  }
  if (authMode === 'edge' && !accessClientId && !teamDomain) {
    throw new Error('GATEWAY_AUTH_MODE=edge needs GATEWAY_ACCESS_CLIENT_ID and GATEWAY_ACCESS_CLIENT_SECRET, '
      + 'or GATEWAY_ACCESS_TEAM_DOMAIN and GATEWAY_ACCESS_AUD');
  }
  if (authMode === 'edge' && flag(env, 'GATEWAY_ALLOW_ANONYMOUS', false)) {
    throw new Error('GATEWAY_ALLOW_ANONYMOUS cannot be combined with GATEWAY_AUTH_MODE=edge');
  }
  const target = (key: 'WIN' | 'MAC', dflt: ProgramTarget): ProgramTarget => ({
    program: env[`GATEWAY_PROGRAM_${key}`]?.trim() || dflt.program,
    programPath: env[`GATEWAY_PROGRAM_PATH_${key}`]?.trim() || undefined,
  });
  return {
    host: env.GATEWAY_HOST?.trim() || '127.0.0.1',
    port: num(env, 'GATEWAY_PORT', 8090, 0),
    upstreamUrl,
    upstreamToken: env.GATEWAY_UPSTREAM_TOKEN || undefined,
    programs: { win: target('WIN', DEFAULT_PROGRAMS.win), mac: target('MAC', DEFAULT_PROGRAMS.mac) },
    requireDedicatedUpstream: flag(env, 'GATEWAY_REQUIRE_DEDICATED_UPSTREAM', true),
    authMode,
    accessClientId,
    accessClientSecret,
    accessJwt: teamDomain && audience ? { teamDomain, audience, serviceTokenId } : undefined,
    versionPollMs: num(env, 'GATEWAY_VERSION_POLL_MS', 60_000),
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
