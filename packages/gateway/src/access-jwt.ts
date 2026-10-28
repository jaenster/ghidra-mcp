/**
 * Cloudflare Access JWT check. Behind an Access application, every request that
 * Access let through carries `Cf-Access-Jwt-Assertion`, an RS256 token signed by
 * the team's keys (`<team domain>/cdn-cgi/access/certs`). Checking it means the
 * origin needs no copy of the service token secret: only the team domain, the
 * application's audience tag and, optionally, the service token's client id,
 * which Access puts in the `common_name` claim.
 */

import { createPublicKey, verify, type KeyObject } from 'node:crypto';

export const ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';

export type JwksFetch = (url: string) => Promise<{ status: number; json(): Promise<unknown> }>;

export interface AccessJwtOptions {
  /** https://<team>.cloudflareaccess.com; the token's `iss`. */
  teamDomain: string;
  /** The Access application's audience tag; must be in the token's `aud`. */
  audience: string;
  /** When set, the token's `common_name` must equal it (the service token's client id). */
  serviceTokenId?: string;
  fetch?: JwksFetch;
  now?: () => number;
  /** Clock skew allowed on exp/nbf, in seconds. */
  leewaySeconds?: number;
  /** Least time between two key fetches triggered by an unknown kid. */
  refetchMs?: number;
}

type HeaderBag = Record<string, string | string[] | undefined>;

function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

export class AccessJwtVerifier {
  private keys = new Map<string, KeyObject>();
  private lastFetch = 0;
  private inflight: Promise<void> | null = null;
  private readonly issuer: string;
  private readonly fetchFn: JwksFetch;
  private readonly now: () => number;
  private readonly leeway: number;
  private readonly refetchMs: number;

  constructor(private readonly options: AccessJwtOptions) {
    this.issuer = options.teamDomain.replace(/\/+$/, '');
    this.fetchFn = options.fetch ?? ((url) => fetch(url));
    this.now = options.now ?? Date.now;
    this.leeway = options.leewaySeconds ?? 60;
    this.refetchMs = options.refetchMs ?? 30_000;
  }

  private async loadKeys(): Promise<void> {
    if (this.inflight) return this.inflight;
    this.lastFetch = this.now();
    this.inflight = (async () => {
      const res = await this.fetchFn(`${this.issuer}/cdn-cgi/access/certs`);
      if (res.status !== 200) throw new Error(`access certs: HTTP ${res.status}`);
      const body = await res.json() as { keys?: Array<Record<string, unknown>> };
      const next = new Map<string, KeyObject>();
      for (const jwk of body.keys ?? []) {
        if (typeof jwk.kid !== 'string' || jwk.kty !== 'RSA') continue;
        next.set(jwk.kid, createPublicKey({ key: jwk as never, format: 'jwk' }));
      }
      this.keys = next;
    })().finally(() => { this.inflight = null; });
    return this.inflight;
  }

  private async keyFor(kid: string): Promise<KeyObject | undefined> {
    const known = this.keys.get(kid);
    if (known) return known;
    // Keys rotate; an unknown kid triggers a fetch, but not more often than refetchMs.
    if (this.keys.size === 0 || this.now() - this.lastFetch >= this.refetchMs) {
      try {
        await this.loadKeys();
      } catch {
        return undefined;
      }
    }
    return this.keys.get(kid);
  }

  /** Whether the request carries a valid Access token for this application. */
  async check(headers: HeaderBag): Promise<boolean> {
    const raw = headers[ACCESS_JWT_HEADER];
    if (typeof raw !== 'string') return false;
    const parts = raw.split('.');
    if (parts.length !== 3) return false;
    const head = b64urlJson(parts[0]);
    const claims = b64urlJson(parts[1]);
    if (!head || !claims || head.alg !== 'RS256' || typeof head.kid !== 'string') return false;

    const key = await this.keyFor(head.kid);
    if (!key) return false;
    const signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    if (!verify('RSA-SHA256', signed, key, Buffer.from(parts[2], 'base64url'))) return false;

    const nowSec = Math.floor(this.now() / 1000);
    if (claims.iss !== this.issuer) return false;
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(this.options.audience)) return false;
    if (typeof claims.exp !== 'number' || claims.exp + this.leeway < nowSec) return false;
    if (typeof claims.nbf === 'number' && claims.nbf - this.leeway > nowSec) return false;
    if (this.options.serviceTokenId !== undefined && claims.common_name !== this.options.serviceTokenId) return false;
    return true;
  }
}
