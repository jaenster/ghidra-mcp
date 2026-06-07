/**
 * OAuth 2.1 authorization server for the ghidra-mcp connector, federated to an
 * upstream OIDC provider (Authentik) for the actual human login.
 *
 * The daemon is the MCP-facing authorization + resource server: it serves
 * discovery metadata, supports Dynamic Client Registration (RFC 7591) and the
 * authorization-code + PKCE flow, and issues/validates its own opaque tokens.
 * It does NOT authenticate users itself — /authorize redirects the browser to
 * the upstream OIDC provider, and a callback validates the returned ID token,
 * enforces a username allowlist, then resumes the MCP flow by minting a code.
 *
 * Auth only activates when GHIDRA_MCP_PUBLIC_URL, GHIDRA_MCP_AUTH_SECRET and the
 * GHIDRA_MCP_OIDC_* settings are all present; otherwise the daemon stays open
 * for local development.
 *
 * Security notes:
 * - Tokens and authorization codes are persisted only as SHA-256 hashes, so a
 *   leak of the state DB does not expose usable credentials.
 * - The upstream `state` is a stateless HMAC-signed envelope carrying the
 *   pending MCP authorization params; the callback verifies it (signature +
 *   freshness) and re-validates the redirect_uri against the registered client
 *   before any code is issued.
 * - The ID token is received directly from the provider's token endpoint over
 *   TLS (OIDC Core §3.1.3.7), so iss/aud/exp are checked from the payload
 *   without a separate JWKS signature verification step.
 */

import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Express, Request, Response, RequestHandler } from 'express';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidTokenError, InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { StateDatabase } from '../state/database.js';

export interface OidcConfig {
  /** Issuer URL, exactly as it appears in the id_token `iss` claim. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Allowed logins, matched against preferred_username or email (case-insensitive). */
  allowedUsers: string[];
}

export interface OAuthConfig {
  enabled: boolean;
  publicUrl: string;
  /** Internal HMAC signing key (no longer a user-facing password). */
  secret: string;
  scopesSupported: string[];
  accessTtlSec: number;
  refreshTtlSec: number;
  oidc: OidcConfig;
}

function positiveInt(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export function getOAuthConfig(): OAuthConfig {
  const publicUrl = process.env.GHIDRA_MCP_PUBLIC_URL?.trim().replace(/\/+$/, '') ?? '';
  const secret = process.env.GHIDRA_MCP_AUTH_SECRET ?? '';
  const scopes = process.env.GHIDRA_MCP_OAUTH_SCOPES?.trim();

  const oidc: OidcConfig = {
    issuer: process.env.GHIDRA_MCP_OIDC_ISSUER?.trim().replace(/\/+$/, '') ?? '',
    clientId: process.env.GHIDRA_MCP_OIDC_CLIENT_ID?.trim() ?? '',
    clientSecret: process.env.GHIDRA_MCP_OIDC_CLIENT_SECRET ?? '',
    allowedUsers: (process.env.GHIDRA_MCP_OIDC_ALLOWED_USERS ?? '')
      .split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean),
  };
  const oidcReady = Boolean(oidc.issuer && oidc.clientId && oidc.clientSecret);

  return {
    enabled: Boolean(publicUrl && secret && oidcReady),
    publicUrl,
    secret,
    scopesSupported: scopes ? scopes.split(/[\s,]+/).filter(Boolean) : ['ghidra'],
    accessTtlSec: positiveInt(process.env.GHIDRA_MCP_ACCESS_TTL, 3600),
    refreshTtlSec: positiveInt(process.env.GHIDRA_MCP_REFRESH_TTL, 30 * 24 * 3600),
    oidc,
  };
}

const CODE_TTL_MS = 5 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;
const CALLBACK_PATH = '/oauth/authentik/callback';

function newSecret(): string {
  return randomBytes(32).toString('hex');
}

/** SHA-256 hex — used so only hashes of tokens/codes are persisted. */
function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Constant-time compare that does not leak length (both sides hashed first). */
function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(Buffer.from(hash(a), 'hex'), Buffer.from(hash(b), 'hex'));
}

function intersectScopes(requested: string, granted: string): string {
  const grantedSet = new Set(granted.split(' ').filter(Boolean));
  const kept = requested.split(' ').filter((s) => s && grantedSet.has(s));
  return kept.join(' ');
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/** Decode (not verify) a JWT payload — signature is trusted via the direct TLS exchange. */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length < 2) throw new Error('malformed id_token');
  return JSON.parse(b64urlDecode(parts[1]).toString('utf8')) as Record<string, unknown>;
}

/** The pending MCP authorization request, round-tripped through the upstream `state`. */
interface PendingAuth {
  cid: string; // client_id
  ruri: string; // redirect_uri
  cc: string; // code_challenge
  st: string; // MCP client state
  sc: string; // requested scopes
  rs: string; // resource indicator
  iat: number; // issued-at (ms)
}

interface OidcEndpoints {
  authorization_endpoint: string;
  token_endpoint: string;
}

/** Clients store backed by the persistent StateDatabase (survives restarts). */
class DbClientsStore implements OAuthRegisteredClientsStore {
  constructor(private db: StateDatabase) {}

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const json = this.db.getOAuthClient(clientId);
    return json ? (JSON.parse(json) as OAuthClientInformationFull) : undefined;
  }

  registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
    this.db.saveOAuthClient(client.client_id, JSON.stringify(client));
    return client;
  }
}

export class GhidraOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: DbClientsStore;
  /** Key for signing the stateless upstream `state` envelope. */
  private readonly stateKey: Buffer;
  private discoveryCache?: Promise<OidcEndpoints>;

  constructor(private db: StateDatabase, private config: OAuthConfig) {
    this.clientsStore = new DbClientsStore(db);
    this.stateKey = createHash('sha256').update(`${config.secret}|oidc-state`).digest();
  }

  private callbackUrl(): string {
    return `${this.config.publicUrl}${CALLBACK_PATH}`;
  }

  /** Lazily fetch + cache the upstream OIDC discovery document. */
  private discovery(): Promise<OidcEndpoints> {
    if (!this.discoveryCache) {
      const url = `${this.config.oidc.issuer}/.well-known/openid-configuration`;
      this.discoveryCache = fetch(url).then(async (r) => {
        if (!r.ok) throw new Error(`OIDC discovery failed: ${r.status}`);
        const doc = (await r.json()) as OidcEndpoints;
        if (!doc.authorization_endpoint || !doc.token_endpoint) {
          throw new Error('OIDC discovery missing endpoints');
        }
        return doc;
      }).catch((e) => {
        this.discoveryCache = undefined; // allow retry on next request
        throw e;
      });
    }
    return this.discoveryCache;
  }

  /** Sign the pending-auth envelope into an opaque, tamper-proof `state` string. */
  private signState(p: Omit<PendingAuth, 'iat'>): string {
    const payload: PendingAuth = { ...p, iat: Date.now() };
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = createHmac('sha256', this.stateKey).update(body).digest('base64url');
    return `${body}.${sig}`;
  }

  /** Verify a returned `state`, returning the pending auth or null if invalid/expired. */
  verifyState(state: string): PendingAuth | null {
    const dot = state.lastIndexOf('.');
    if (dot < 0) return null;
    const body = state.slice(0, dot);
    const sig = state.slice(dot + 1);
    const expected = createHmac('sha256', this.stateKey).update(body).digest('base64url');
    if (sig.length !== expected.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return null;
    }
    try {
      const p = JSON.parse(b64urlDecode(body).toString('utf8')) as PendingAuth;
      if (!p.iat || Date.now() - p.iat > STATE_TTL_MS) return null;
      return p;
    } catch {
      return null;
    }
  }

  isAllowed(username?: unknown, email?: unknown): boolean {
    const allow = this.config.oidc.allowedUsers;
    if (allow.length === 0) return true; // empty allowlist = any authenticated user
    const u = typeof username === 'string' ? username.toLowerCase() : '';
    const e = typeof email === 'string' ? email.toLowerCase() : '';
    return (u && allow.includes(u)) || (e && allow.includes(e)) || false;
  }

  /**
   * MCP /authorize entrypoint: instead of authenticating locally, redirect the
   * browser to the upstream OIDC provider with a signed state carrying the
   * pending MCP request so the callback can resume it.
   */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const ep = await this.discovery();
    const state = this.signState({
      cid: client.client_id,
      ruri: params.redirectUri,
      cc: params.codeChallenge,
      st: params.state ?? '',
      sc: (params.scopes ?? []).join(' '),
      rs: params.resource?.href ?? '',
    });
    const u = new URL(ep.authorization_endpoint);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', this.config.oidc.clientId);
    u.searchParams.set('redirect_uri', this.callbackUrl());
    u.searchParams.set('scope', 'openid profile email');
    u.searchParams.set('state', state);
    res.redirect(302, u.href);
  }

  /**
   * Exchange the upstream authorization code for an ID token, validate it, and
   * return its claims. Confidential-client (client_secret) + direct TLS to the
   * token endpoint is the trust anchor; iss/aud/exp are checked from the payload.
   */
  async exchangeUpstreamCode(code: string): Promise<Record<string, unknown>> {
    const ep = await this.discovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.callbackUrl(),
      client_id: this.config.oidc.clientId,
      client_secret: this.config.oidc.clientSecret,
    });
    const r = await fetch(ep.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!r.ok) throw new Error(`upstream token exchange failed: ${r.status} ${await r.text()}`);
    const tok = (await r.json()) as { id_token?: string };
    if (!tok.id_token) throw new Error('upstream response had no id_token');

    const claims = decodeJwtPayload(tok.id_token);
    const iss = String(claims.iss ?? '').replace(/\/+$/, '');
    if (iss !== this.config.oidc.issuer) throw new Error('id_token iss mismatch');
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!aud.includes(this.config.oidc.clientId)) throw new Error('id_token aud mismatch');
    if (typeof claims.exp === 'number' && Date.now() / 1000 > claims.exp) throw new Error('id_token expired');
    return claims;
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const code = this.db.getAuthCode(hash(authorizationCode));
    if (!code) throw new InvalidGrantError('Invalid authorization code');
    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const codeHash = hash(authorizationCode);
    const code = this.db.getAuthCode(codeHash);
    if (!code || code.clientId !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    this.db.deleteAuthCode(codeHash); // one-time use — delete before any further failure path
    if (Date.now() > code.expiresAt) throw new InvalidGrantError('Authorization code expired');
    if (redirectUri && redirectUri !== code.redirectUri) throw new InvalidGrantError('redirect_uri mismatch');
    if (resource && code.resource && resource.href !== code.resource) {
      throw new InvalidGrantError('resource does not match authorization request');
    }
    return this.issueTokens(client.client_id, code.scopes, code.resource);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const refreshHash = hash(refreshToken);
    const stored = this.db.getOAuthToken(refreshHash);
    if (!stored || stored.kind !== 'refresh' || stored.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid refresh token');
    }
    if (stored.expiresAt && Date.now() > stored.expiresAt) {
      this.db.deleteOAuthToken(refreshHash);
      throw new InvalidGrantError('Refresh token expired');
    }
    // Requested scopes may only narrow the originally granted set (RFC 6749 §6).
    const grantedScopes = scopes && scopes.length ? intersectScopes(scopes.join(' '), stored.scopes) : stored.scopes;
    const tokens = this.issueTokens(client.client_id, grantedScopes, stored.resource);
    this.db.deleteOAuthToken(refreshHash); // rotate after the replacement is persisted
    return tokens;
  }

  async verifyAccessToken(accessToken: string): Promise<AuthInfo> {
    const stored = this.db.getOAuthToken(hash(accessToken));
    if (!stored || stored.kind !== 'access') throw new InvalidTokenError('Invalid access token');
    const expiresAt = stored.expiresAt ?? 0;
    if (Date.now() > expiresAt) {
      this.db.deleteOAuthToken(hash(accessToken));
      throw new InvalidTokenError('Access token expired');
    }
    return {
      token: accessToken,
      clientId: stored.clientId,
      scopes: stored.scopes ? stored.scopes.split(' ').filter(Boolean) : [],
      expiresAt: Math.floor(expiresAt / 1000),
      resource: stored.resource ? new URL(stored.resource) : undefined,
    };
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    this.db.deleteOAuthToken(hash(request.token));
  }

  /** Called by the upstream callback after the ID token is validated + allowlisted. */
  issueAuthorizationCode(input: {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    scopes: string;
    resource: string;
  }): string {
    const code = newSecret();
    this.db.saveAuthCode({
      code: hash(code),
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      codeChallenge: input.codeChallenge,
      scopes: input.scopes,
      resource: input.resource || null,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    return code;
  }

  pruneExpired(): void {
    this.db.pruneExpiredOAuth(Date.now());
  }

  private issueTokens(clientId: string, scopes: string, resource: string | null): OAuthTokens {
    const accessToken = newSecret();
    const refreshToken = newSecret();
    this.db.saveOAuthToken({
      token: hash(accessToken),
      kind: 'access',
      clientId,
      scopes,
      resource,
      expiresAt: Date.now() + this.config.accessTtlSec * 1000,
    });
    this.db.saveOAuthToken({
      token: hash(refreshToken),
      kind: 'refresh',
      clientId,
      scopes,
      resource,
      expiresAt: Date.now() + this.config.refreshTtlSec * 1000,
    });
    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.config.accessTtlSec,
      refresh_token: refreshToken,
      scope: scopes || undefined,
    };
  }
}

/**
 * Wire the OAuth authorization server into the Express app: discovery metadata,
 * /authorize, /token, /register, /revoke, the upstream OIDC callback, and returns
 * the bearer-auth middleware to gate the MCP endpoints.
 */
export function installOAuth(app: Express, db: StateDatabase, config: OAuthConfig): {
  requireAuth: RequestHandler;
  provider: GhidraOAuthProvider;
} {
  const issuerUrl = new URL(config.publicUrl);
  const provider = new GhidraOAuthProvider(db, config);

  // Upstream OIDC callback — validate the ID token, enforce the allowlist, then
  // resume the MCP flow by minting our own authorization code.
  app.get(CALLBACK_PATH, async (req: Request, res: Response) => {
    const { code, state, error, error_description } = req.query as Record<string, string>;
    if (error) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderError('Login failed', `${error}${error_description ? `: ${error_description}` : ''}`));
      return;
    }

    const pending = state ? provider.verifyState(state) : null;
    if (!pending || !code) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderError('Invalid login', 'The login request was missing, tampered with, or expired. Please try again.'));
      return;
    }

    let claims: Record<string, unknown>;
    try {
      claims = await provider.exchangeUpstreamCode(code);
    } catch {
      res.status(502).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderError('Login failed', 'Could not verify your identity with the upstream provider.'));
      return;
    }

    if (!provider.isAllowed(claims.preferred_username, claims.email)) {
      res.status(403).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderError('Access denied', 'Your account is not authorized to use this ghidra-mcp server.'));
      return;
    }

    // Defense in depth: redirect_uri must still belong to the registered client.
    const client = provider.clientsStore.getClient(pending.cid);
    if (!client || !(client.redirect_uris ?? []).includes(pending.ruri)) {
      res.status(400).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderError('Invalid client', 'Unknown client or unregistered redirect_uri.'));
      return;
    }

    const authCode = provider.issueAuthorizationCode({
      clientId: pending.cid,
      redirectUri: pending.ruri,
      codeChallenge: pending.cc,
      scopes: pending.sc,
      resource: pending.rs,
    });
    const redirect = new URL(pending.ruri);
    redirect.searchParams.set('code', authCode);
    if (pending.st) redirect.searchParams.set('state', pending.st);
    res.redirect(302, redirect.href);
  });

  // Standard AS endpoints + discovery metadata (also advertises protected-resource metadata).
  app.use(mcpAuthRouter({
    provider,
    issuerUrl,
    scopesSupported: config.scopesSupported,
    resourceName: 'ghidra-mcp',
  }));

  // Periodic sweep of expired codes/tokens (unref so it never holds the process open).
  const sweep = setInterval(() => {
    try { provider.pruneExpired(); } catch { /* best effort */ }
  }, 15 * 60 * 1000);
  sweep.unref?.();

  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(issuerUrl);
  const requireAuth = requireBearerAuth({ verifier: provider, resourceMetadataUrl });

  return { requireAuth, provider };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function renderError(title: string, detail: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ghidra-mcp — ${escapeHtml(title)}</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; background: #0d1117; color: #e6edf3; display: grid; place-items: center; min-height: 100vh; margin: 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px 32px; width: min(380px, 90vw); }
  h1 { font-size: 18px; margin: 0 0 8px; }
  p { color: #8b949e; margin: 0; }
</style></head>
<body><div class="card"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(detail)}</p></div></body></html>`;
}
