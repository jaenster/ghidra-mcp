/**
 * E2E tests for the OAuth 2.1 connector auth layer.
 *
 * These do NOT require Ghidra — they exercise only the daemon's authorization
 * server and the bearer gate on the MCP transports, so they run in CI
 * unconditionally and guard against regressions in the auth flow.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { startTestDaemon, cleanupAllDaemons, type DaemonHandle } from './helpers/daemon.ts';

const SUITE_TIMEOUT = 60_000;

const AUTH_PORT = 18496;
const OPEN_PORT = 18497;
const SECRET = 'test-connector-password';
const WORKER_SECRET = 'test-worker-secret-abc';
const REDIRECT_URI = 'http://127.0.0.1:9999/callback';

/** Fresh HOME so the daemon's state DB / app dir is isolated per run. */
function isolatedHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ghidra-auth-test-'));
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

const enc = (o: Record<string, string>) => new URLSearchParams(o);

after(async () => {
  await cleanupAllDaemons();
});

describe('E2E: OAuth connector (auth enabled)', { timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let home: string;
  const base = `http://127.0.0.1:${AUTH_PORT}`;

  before(async () => {
    home = isolatedHome();
    daemon = await startTestDaemon(AUTH_PORT, {
      HOME: home,
      GHIDRA_MCP_HOST: '127.0.0.1',
      GHIDRA_MCP_PUBLIC_URL: base,
      GHIDRA_MCP_AUTH_SECRET: SECRET,
      GHIDRA_MCP_WORKER_SECRET: WORKER_SECRET,
    });
  });

  after(async () => {
    if (daemon) await daemon.stop();
    if (home) fs.rmSync(home, { recursive: true, force: true });
  });

  it('keeps /health open', async () => {
    const r = await fetch(`${base}/health`);
    assert.equal(r.status, 200);
  });

  it('serves OAuth discovery metadata', async () => {
    const as = await fetch(`${base}/.well-known/oauth-authorization-server`).then((r) => r.json());
    assert.ok(as.authorization_endpoint && as.token_endpoint && as.registration_endpoint,
      'AS metadata advertises authorize/token/register');
    const pr = await fetch(`${base}/.well-known/oauth-protected-resource`);
    assert.equal(pr.status, 200, 'protected-resource metadata present');
  });

  it('rejects unauthenticated /mcp with a resource_metadata challenge', async () => {
    const r = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    });
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate') || '', /resource_metadata/);
  });

  it('completes DCR + PKCE authorize→consent→token and authenticates /mcp', async () => {
    // Dynamic client registration
    const client = await fetch(`${base}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'E2E Test', redirect_uris: [REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'], token_endpoint_auth_method: 'none',
      }),
    }).then((r) => r.json());
    assert.ok(client.client_id, 'DCR returns client_id');

    const { verifier, challenge } = pkcePair();

    // /authorize renders the consent page carrying an HMAC param binding
    const authUrl = `${base}/authorize?` + enc({
      response_type: 'code', client_id: client.client_id, redirect_uri: REDIRECT_URI,
      code_challenge: challenge, code_challenge_method: 'S256', state: 'st', scope: 'ghidra',
    });
    const html = await fetch(authUrl).then((r) => r.text());
    const sig = html.match(/name="sig" value="([^"]+)"/)?.[1];
    assert.ok(sig, 'consent page includes signed param binding');

    const fields = {
      client_id: client.client_id, redirect_uri: REDIRECT_URI, code_challenge: challenge,
      state: 'st', scope: 'ghidra', resource: '', sig: sig!,
    };

    // Tampered redirect_uri breaks the HMAC → 400
    const tampered = await fetch(`${base}/oauth/consent`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ ...fields, password: SECRET, redirect_uri: 'http://evil.example/steal' }),
    });
    assert.equal(tampered.status, 400, 'tampered redirect_uri rejected');

    // Wrong password → 401
    const badPw = await fetch(`${base}/oauth/consent`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ ...fields, password: 'nope' }),
    });
    assert.equal(badPw.status, 401, 'wrong password rejected');

    // Correct consent → 302 with code + echoed state
    const consent = await fetch(`${base}/oauth/consent`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ ...fields, password: SECRET }),
    });
    assert.equal(consent.status, 302);
    const loc = new URL(consent.headers.get('location')!);
    assert.equal(loc.searchParams.get('state'), 'st', 'state echoed');
    const code = loc.searchParams.get('code')!;
    assert.ok(code, 'authorization code issued');

    // Token exchange (PKCE)
    const tok = await fetch(`${base}/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: client.client_id, code_verifier: verifier }),
    }).then((r) => r.json());
    assert.ok(tok.access_token && tok.refresh_token, 'access + refresh tokens issued');

    // Stored hashed, not raw
    const dbFiles = fs.readdirSync(home, { recursive: true }).map(String).filter((f) => f.endsWith('.db'));
    const tokHash = crypto.createHash('sha256').update(tok.access_token).digest('hex');
    let rawSeen = false, hashSeen = false;
    for (const f of dbFiles) {
      const buf = fs.readFileSync(path.join(home, f));
      if (buf.includes(Buffer.from(tok.access_token))) rawSeen = true;
      if (buf.includes(Buffer.from(tokHash))) hashSeen = true;
    }
    assert.ok(!rawSeen, 'raw token must NOT be persisted');
    assert.ok(hashSeen, 'token hash IS persisted');

    // Authenticated /mcp initialize succeeds
    const mcp = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tok.access_token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
    });
    assert.equal(mcp.status, 200, 'authenticated /mcp initialize');

    // Replayed code rejected (one-time use)
    const replay = await fetch(`${base}/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: client.client_id, code_verifier: verifier }),
    });
    assert.ok(replay.status >= 400, 'replayed authorization code rejected');

    // Refresh grant — requesting broader scope must not escalate
    const refreshed = await fetch(`${base}/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: enc({ grant_type: 'refresh_token', refresh_token: tok.refresh_token, client_id: client.client_id, scope: 'ghidra admin' }),
    }).then((r) => r.json());
    assert.ok(refreshed.access_token, 'refresh issues a new access token');
    assert.equal(refreshed.scope, 'ghidra', 'refresh scope clamped to granted');
  });

  it('gates the /internal worker control-plane on the worker secret', async () => {
    const noSecret = await fetch(`${base}/internal/worker/x/command`);
    assert.equal(noSecret.status, 403, 'no secret → 403');
    const wrong = await fetch(`${base}/internal/worker/x/command`, { headers: { 'x-worker-secret': 'wrong' } });
    assert.equal(wrong.status, 403, 'wrong secret → 403');
    // Use heartbeat (returns immediately) rather than the 5s long-poll /command.
    const right = await fetch(`${base}/internal/worker/x/heartbeat`, {
      method: 'POST',
      headers: { 'x-worker-secret': WORKER_SECRET, 'content-type': 'application/json' },
      body: JSON.stringify({ status: 'idle' }),
    });
    assert.equal(right.status, 200, 'correct secret → 200');
  });
});

describe('E2E: OAuth disabled (local dev default)', { timeout: SUITE_TIMEOUT }, () => {
  let daemon: DaemonHandle;
  let home: string;
  const base = `http://127.0.0.1:${OPEN_PORT}`;

  before(async () => {
    home = isolatedHome();
    // No GHIDRA_MCP_PUBLIC_URL / AUTH_SECRET → auth stays off.
    daemon = await startTestDaemon(OPEN_PORT, { HOME: home, GHIDRA_MCP_HOST: '127.0.0.1' });
  });

  after(async () => {
    if (daemon) await daemon.stop();
    if (home) fs.rmSync(home, { recursive: true, force: true });
  });

  it('leaves /mcp open and exposes no authorization server', async () => {
    const mcp = await fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
    });
    assert.equal(mcp.status, 200, '/mcp open without a token');

    const wellKnown = await fetch(`${base}/.well-known/oauth-authorization-server`);
    assert.equal(wellKnown.status, 404, 'no AS metadata when auth disabled');
  });
});
