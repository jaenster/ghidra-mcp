/**
 * Caller identity: a GitHub token checked against GitHub's /user, or an
 * anonymous identity per client address when anonymous access is switched on.
 *
 * Tokens are never stored or logged; the cache is keyed by their SHA-256.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

export interface Identity {
  /** Stable key for quotas and the audit log: "gh:<numeric id>" or "anon:<address>". */
  key: string;
  /** GitHub numeric user id; absent for anonymous callers. */
  githubId?: number;
  login: string;
}

export class AuthError extends Error {
  constructor(message: string, readonly status: 401 | 503) {
    super(message);
    this.name = 'AuthError';
  }
}

export type FetchLike = (url: string, init: { headers: Record<string, string>; signal?: AbortSignal }) =>
  Promise<{ status: number; json(): Promise<unknown> }>;

export interface AuthOptions {
  allowAnonymous: boolean;
  /** How long a verified token stays trusted without asking GitHub again. */
  cacheTtlMs: number;
  /** How long a rejected token is remembered, so a bad token cannot make us hammer GitHub. */
  negativeTtlMs: number;
  githubApiUrl: string;
  fetch?: FetchLike;
  now?: () => number;
}

interface CacheEntry {
  identity: Identity | null;
  expiresAt: number;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export class Authenticator {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly fetchImpl: FetchLike;
  private readonly now: () => number;

  constructor(private readonly options: AuthOptions) {
    this.fetchImpl = options.fetch ?? ((url, init) => fetch(url, init));
    this.now = options.now ?? Date.now;
  }

  /**
   * Resolve the caller behind an Authorization header value. Throws AuthError
   * with 401 for a missing or rejected token and 503 when GitHub cannot be reached.
   */
  async authenticate(authorization: string | undefined, remoteAddress: string): Promise<Identity> {
    const token = parseBearer(authorization);
    if (!token) {
      if (this.options.allowAnonymous) return { key: `anon:${remoteAddress}`, login: 'anonymous' };
      throw new AuthError('A GitHub token is required: send "Authorization: Bearer <token>".', 401);
    }

    const key = hashToken(token);
    const now = this.now();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) {
      if (!cached.identity) throw new AuthError('GitHub rejected this token.', 401);
      return cached.identity;
    }

    const identity = await this.askGitHub(token);
    this.prune(now);
    this.cache.set(key, {
      identity,
      expiresAt: now + (identity ? this.options.cacheTtlMs : this.options.negativeTtlMs),
    });
    if (!identity) throw new AuthError('GitHub rejected this token.', 401);
    return identity;
  }

  private async askGitHub(token: string): Promise<Identity | null> {
    let res: { status: number; json(): Promise<unknown> };
    try {
      res = await this.fetchImpl(`${this.options.githubApiUrl.replace(/\/+$/, '')}/user`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'ghidra-mcp-gateway',
        },
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new AuthError('Could not reach GitHub to verify the token.', 503);
    }
    if (res.status === 401 || res.status === 403) return null;
    if (res.status !== 200) throw new AuthError(`GitHub answered ${res.status} while verifying the token.`, 503);
    const body = await res.json() as { id?: unknown; login?: unknown };
    if (typeof body.id !== 'number' || typeof body.login !== 'string') return null;
    return { key: `gh:${body.id}`, githubId: body.id, login: body.login };
  }

  private prune(now: number): void {
    if (this.cache.size < 10_000) return;
    for (const [k, v] of this.cache) if (v.expiresAt <= now) this.cache.delete(k);
  }
}

function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return m ? m[1] : null;
}

/** The headers a Cloudflare Access service token travels in. */
export const ACCESS_CLIENT_ID_HEADER = 'cf-access-client-id';
export const ACCESS_CLIENT_SECRET_HEADER = 'cf-access-client-secret';
/** The caller the edge signed in, sent by the edge only. */
export const EDGE_IDENTITY_HEADER = 'x-edge-identity';
export const EDGE_LOGIN_HEADER = 'x-edge-login';

type HeaderBag = Record<string, string | string[] | undefined>;

function header(headers: HeaderBag, name: string): string | undefined {
  const v = headers[name];
  return Array.isArray(v) ? undefined : v;
}

/** Compare two secrets in time independent of where they differ. */
function sameSecret(a: string, b: string): boolean {
  const da = createHash('sha256').update(a).digest();
  const db = createHash('sha256').update(b).digest();
  return timingSafeEqual(da, db);
}

/**
 * Whether a request carries the configured Access service token. Both halves
 * must match; a request repeating either header is refused.
 */
export function hasServiceToken(headers: HeaderBag, clientId: string, clientSecret: string): boolean {
  const id = header(headers, ACCESS_CLIENT_ID_HEADER);
  const secret = header(headers, ACCESS_CLIENT_SECRET_HEADER);
  if (id === undefined || secret === undefined) return false;
  // Evaluate both so the time taken does not say which half was wrong.
  const idOk = sameSecret(id, clientId);
  const secretOk = sameSecret(secret, clientSecret);
  return idOk && secretOk;
}

const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

/**
 * The identity the edge vouches for. Only meaningful after hasServiceToken
 * passed: anyone can send these headers, only the edge can send them with the
 * token.
 */
export function edgeIdentity(headers: HeaderBag): Identity | null {
  const key = header(headers, EDGE_IDENTITY_HEADER);
  const login = header(headers, EDGE_LOGIN_HEADER);
  const m = key ? /^gh:([1-9][0-9]{0,15})$/.exec(key) : null;
  if (!m || !login || !LOGIN.test(login)) return null;
  const githubId = Number(m[1]);
  return { key: `gh:${githubId}`, githubId, login };
}
