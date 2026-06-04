/**
 * Self-contained OAuth 2.1 authorization server for the ghidra-mcp connector.
 *
 * The daemon acts as both authorization server and resource server: it serves
 * discovery metadata, supports Dynamic Client Registration (RFC 7591) and the
 * authorization-code + PKCE flow, and issues/validates its own opaque tokens.
 * A single shared login secret (GHIDRA_MCP_AUTH_SECRET) gates the consent step,
 * which is appropriate for a personal/single-user deployment.
 *
 * Auth only activates when both GHIDRA_MCP_PUBLIC_URL and GHIDRA_MCP_AUTH_SECRET
 * are set; otherwise the daemon stays open for local development.
 *
 * Security notes:
 * - Tokens and authorization codes are persisted only as SHA-256 hashes, so a
 *   leak of the state DB does not expose usable credentials.
 * - The consent POST is bound to a legitimate /authorize render via an HMAC over
 *   the authorization parameters, and the redirect_uri is re-validated against
 *   the registered client before any code is issued.
 */

import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Express, Request, Response, RequestHandler } from 'express';
import express from 'express';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidTokenError, InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { StateDatabase } from '../state/database.js';

export interface OAuthConfig {
  enabled: boolean;
  publicUrl: string;
  secret: string;
  scopesSupported: string[];
  accessTtlSec: number;
  refreshTtlSec: number;
}

function positiveInt(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export function getOAuthConfig(): OAuthConfig {
  const publicUrl = process.env.GHIDRA_MCP_PUBLIC_URL?.trim().replace(/\/+$/, '') ?? '';
  const secret = process.env.GHIDRA_MCP_AUTH_SECRET ?? '';
  const scopes = process.env.GHIDRA_MCP_OAUTH_SCOPES?.trim();
  return {
    enabled: Boolean(publicUrl && secret),
    publicUrl,
    secret,
    scopesSupported: scopes ? scopes.split(/[\s,]+/).filter(Boolean) : ['ghidra'],
    accessTtlSec: positiveInt(process.env.GHIDRA_MCP_ACCESS_TTL, 3600),
    refreshTtlSec: positiveInt(process.env.GHIDRA_MCP_REFRESH_TTL, 30 * 24 * 3600),
  };
}

const CODE_TTL_MS = 5 * 60 * 1000;
const CONSENT_PATH = '/oauth/consent';

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
  /** Key for binding the consent POST to a legitimate /authorize render. */
  private readonly consentKey: Buffer;

  constructor(private db: StateDatabase, private config: OAuthConfig) {
    this.clientsStore = new DbClientsStore(db);
    this.consentKey = createHash('sha256').update(`${config.secret}|consent-binding`).digest();
  }

  /** HMAC over the authorization params so consent cannot be forged/tampered. */
  signParams(p: { clientId: string; redirectUri: string; codeChallenge: string; state: string; scope: string; resource: string }): string {
    return createHmac('sha256', this.consentKey)
      .update([p.clientId, p.redirectUri, p.codeChallenge, p.state, p.scope, p.resource].join('\n'))
      .digest('hex');
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const view = {
      clientId: client.client_id,
      clientName: client.client_name ?? client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state ?? '',
      scope: (params.scopes ?? []).join(' '),
      resource: params.resource?.href ?? '',
    };
    const sig = this.signParams(view);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderConsentPage({ ...view, sig }));
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

  /** Called by the consent route after the shared secret is verified. */
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
 * /authorize, /token, /register, /revoke, the consent route, and returns the
 * bearer-auth middleware to gate the MCP endpoints.
 */
export function installOAuth(app: Express, db: StateDatabase, config: OAuthConfig): {
  requireAuth: RequestHandler;
  provider: GhidraOAuthProvider;
} {
  const issuerUrl = new URL(config.publicUrl);
  const provider = new GhidraOAuthProvider(db, config);

  // Consent form submission — verify the shared secret + param binding, re-check
  // the redirect_uri against the registered client, then mint the code.
  app.post(CONSENT_PATH, express.urlencoded({ extended: false }), (req: Request, res: Response) => {
    const { password, client_id, redirect_uri, code_challenge, state, scope, resource, sig } =
      req.body as Record<string, string>;

    if (!client_id || !redirect_uri || !code_challenge || !sig) {
      res.status(400).send('Invalid consent request');
      return;
    }

    // 1. Parameters must be unchanged since /authorize rendered them.
    const expectedSig = provider.signParams({
      clientId: client_id, redirectUri: redirect_uri, codeChallenge: code_challenge,
      state: state ?? '', scope: scope ?? '', resource: resource ?? '',
    });
    if (!safeEqual(sig, expectedSig)) {
      res.status(400).send('Invalid or tampered authorization request');
      return;
    }

    // 2. redirect_uri must belong to the registered client (defense in depth).
    const client = provider.clientsStore.getClient(client_id);
    if (!client || !(client.redirect_uris ?? []).includes(redirect_uri)) {
      res.status(400).send('Unknown client or unregistered redirect_uri');
      return;
    }

    // 3. Human gate: the shared connector password.
    if (!password || !safeEqual(password, config.secret)) {
      res.status(401).setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(renderConsentPage({
        clientId: client_id, clientName: client.client_name ?? client_id, redirectUri: redirect_uri,
        codeChallenge: code_challenge, state: state ?? '', scope: scope ?? '', resource: resource ?? '',
        sig, error: 'Incorrect password',
      }));
      return;
    }

    const code = provider.issueAuthorizationCode({
      clientId: client_id, redirectUri: redirect_uri, codeChallenge: code_challenge,
      scopes: scope ?? '', resource: resource ?? '',
    });
    const redirect = new URL(redirect_uri);
    redirect.searchParams.set('code', code);
    if (state) redirect.searchParams.set('state', state);
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

interface ConsentView {
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scope: string;
  resource: string;
  sig: string;
  error?: string;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function renderConsentPage(v: ConsentView): string {
  const hidden = (name: string, value: string) =>
    `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ghidra-mcp — authorize</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; background: #0d1117; color: #e6edf3; display: grid; place-items: center; min-height: 100vh; margin: 0; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px 32px; width: min(380px, 90vw); }
  h1 { font-size: 18px; margin: 0 0 4px; }
  p { color: #8b949e; margin: 0 0 18px; }
  .client { color: #58a6ff; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #30363d; background: #0d1117; color: #e6edf3; font-size: 15px; }
  button { width: 100%; margin-top: 14px; padding: 10px; border: 0; border-radius: 8px; background: #238636; color: #fff; font-size: 15px; cursor: pointer; }
  button:hover { background: #2ea043; }
  .err { color: #f85149; margin: 0 0 12px; }
</style></head>
<body><form class="card" method="POST" action="${CONSENT_PATH}">
  <h1>Authorize access</h1>
  <p><span class="client">${escapeHtml(v.clientName)}</span> wants to connect to your ghidra-mcp server.</p>
  ${v.error ? `<p class="err">${escapeHtml(v.error)}</p>` : ''}
  <input type="password" name="password" placeholder="Connector password" autofocus required>
  <button type="submit">Authorize</button>
  ${hidden('client_id', v.clientId)}
  ${hidden('redirect_uri', v.redirectUri)}
  ${hidden('code_challenge', v.codeChallenge)}
  ${hidden('state', v.state)}
  ${hidden('scope', v.scope)}
  ${hidden('resource', v.resource)}
  ${hidden('sig', v.sig)}
</form></body></html>`;
}
