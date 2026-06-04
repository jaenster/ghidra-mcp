#!/usr/bin/env node
/**
 * `ghidra` CLI command - Ghidra MCP server.
 *
 * Usage:
 *   ghidra                    Start HTTP daemon (SSE + Streamable HTTP) on port 8432
 *   ghidra --port 9000        Start on custom port
 *   ghidra --stdio            Stdio proxy to running daemon (for MCP client configs)
 *   ghidra --stdio --port 9000  Stdio proxy to daemon on custom port
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { getDaemonPort } from '@ghidra-mcp/shared/platform';

const { values: flags } = parseArgs({
  options: {
    stdio: { type: 'boolean', default: false },
    port: { type: 'string', default: undefined },
    help: { type: 'boolean', short: 'h', default: false },
  },
  strict: true,
});

if (flags.help) {
  console.log(`Usage: ghidra [options]

Options:
  --stdio        Run as stdio MCP proxy to the running daemon
  --port <port>  Daemon port (default: 8432)
  -h, --help     Show this help message

Modes:
  Default:       Start HTTP daemon with SSE + Streamable HTTP transports
  --stdio:       Proxy stdio MCP <-> daemon's Streamable HTTP endpoint

The daemon must be running for --stdio mode. Start it first with:
  ghidra          (or: node packages/cli/dist/index.js start -p 8432 -f)
`);
  process.exit(0);
}

const port = flags.port ? parseInt(flags.port, 10) : getDaemonPort();

if (flags.stdio) {
  runStdioProxy(port);
} else {
  runDaemon(port);
}

/**
 * HTTP daemon mode - start the full daemon server.
 */
async function runDaemon(port: number) {
  const { startDaemon } = await import('@ghidra-mcp/daemon');
  const { getGhidraHome } = await import('@ghidra-mcp/shared/platform');

  try {
    getGhidraHome();
  } catch {
    process.stderr.write(
      'Ghidra not found. Set GHIDRA_HOME to your Ghidra installation directory.\n',
    );
    process.exit(1);
  }

  process.stderr.write(`Starting Ghidra MCP daemon on port ${port}...\n`);
  process.stderr.write(`  SSE:              http://127.0.0.1:${port}/sse\n`);
  process.stderr.write(`  Streamable HTTP:  http://127.0.0.1:${port}/mcp\n`);

  try {
    const { pid, port: actualPort } = await startDaemon({ port, force: false });
    process.stderr.write(`Daemon started (PID: ${pid}, port: ${actualPort})\n`);
    await new Promise(() => {}); // block forever
  } catch (error) {
    process.stderr.write(`Failed: ${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}

/**
 * Stdio proxy mode - bridges stdio MCP <-> daemon Streamable HTTP.
 *
 * Reads JSON-RPC from stdin, POSTs to http://localhost:{port}/mcp,
 * writes responses to stdout. Also opens an SSE stream for server
 * notifications (if the daemon sends any).
 *
 * Auto-reconnects when the daemon restarts (stale session detection).
 */
async function runStdioProxy(port: number) {
  const baseUrl = `http://127.0.0.1:${port}`;

  // Health check with retry — daemon might still be starting
  for (let attempt = 0; ; attempt++) {
    try {
      const health = await fetch(`${baseUrl}/health`);
      if (health.ok) break;
      throw new Error(`HTTP ${health.status}`);
    } catch {
      if (attempt >= 5) {
        process.stderr.write(
          `Cannot connect to daemon at ${baseUrl} after ${attempt + 1} attempts. Is it running?\n` +
            `Start it with: ghidra --port ${port}\n`,
        );
        process.exit(1);
      }
      const delay = Math.min(1000 * 2 ** attempt, 5000);
      process.stderr.write(
        `Waiting for daemon at ${baseUrl} (attempt ${attempt + 1}/6)...\n`,
      );
      await sleep(delay);
    }
  }

  process.stderr.write(`Proxying stdio MCP <-> ${baseUrl}/mcp\n`);

  let sessionId: string | null = null;
  let stdinClosed = false;
  let initializeMessage: unknown = null;
  let sseAbortController: AbortController | null = null;

  // Serialize requests to ensure session ID propagates correctly
  let requestChain: Promise<void> = Promise.resolve();
  let pendingRequests = 0;

  const maybeExit = () => {
    if (stdinClosed && pendingRequests === 0) {
      process.exit(0);
    }
  };

  async function reinitialize(): Promise<boolean> {
    sessionId = null;
    if (!initializeMessage) return false;

    // Abort old SSE stream so it reconnects with new session
    sseAbortController?.abort();

    process.stderr.write('Session lost, re-initializing...\n');

    try {
      const resp = await fetch(`${baseUrl}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify(initializeMessage),
      });

      const newSid = resp.headers.get('mcp-session-id');
      if (newSid) sessionId = newSid;

      const contentType = resp.headers.get('content-type') ?? '';
      if (contentType.includes('text/event-stream')) {
        await handleSseResponse(resp);
      } else {
        const body = await resp.text();
        if (body.trim()) {
          process.stdout.write(body + '\n');
        }
      }

      process.stderr.write(`Re-initialized with session ${sessionId}\n`);
      return true;
    } catch (err) {
      process.stderr.write(
        `Re-initialize failed: ${err instanceof Error ? err.message : err}\n`,
      );
      return false;
    }
  }

  function isSessionLostResponse(resp: Response): boolean {
    return resp.status === 400 || resp.status === 404;
  }

  const enqueueRequest = (parsed: unknown) => {
    const isNotification = parsed && typeof parsed === 'object' && !('id' in parsed);
    pendingRequests++;

    // Capture initialize message for replay on reconnect
    if (
      !initializeMessage &&
      parsed &&
      typeof parsed === 'object' &&
      'method' in parsed &&
      (parsed as { method: string }).method === 'initialize'
    ) {
      initializeMessage = parsed;
    }

    requestChain = requestChain.then(async () => {
      try {
        const doRequest = async (): Promise<void> => {
          const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            Accept: 'application/json, text/event-stream',
          };
          if (sessionId) {
            headers['mcp-session-id'] = sessionId;
          }

          const resp = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers,
            body: JSON.stringify(parsed),
          });

          // Detect stale session
          if (isSessionLostResponse(resp)) {
            const body = await resp.text();
            if (body.includes('session') || body.includes('Session') || resp.status === 404) {
              const ok = await reinitialize();
              if (ok) {
                // Retry with new session (skip if this IS the initialize message)
                if (parsed !== initializeMessage) {
                  const retryHeaders: Record<string, string> = {
                    'Content-Type': 'application/json',
                    Accept: 'application/json, text/event-stream',
                  };
                  if (sessionId) retryHeaders['mcp-session-id'] = sessionId;

                  const retryResp = await fetch(`${baseUrl}/mcp`, {
                    method: 'POST',
                    headers: retryHeaders,
                    body: JSON.stringify(parsed),
                  });

                  const retrySid = retryResp.headers.get('mcp-session-id');
                  if (retrySid) sessionId = retrySid;

                  const retryContentType = retryResp.headers.get('content-type') ?? '';
                  if (retryContentType.includes('text/event-stream')) {
                    await handleSseResponse(retryResp);
                  } else {
                    const retryBody = await retryResp.text();
                    if (retryBody.trim()) process.stdout.write(retryBody + '\n');
                  }
                }
                return;
              }
              // reinitialize failed — fall through to error response
              if (!isNotification && parsed && typeof parsed === 'object' && 'id' in parsed) {
                const errorResp = {
                  jsonrpc: '2.0',
                  id: (parsed as { id: unknown }).id,
                  error: { code: -32603, message: 'Session lost and reconnect failed' },
                };
                process.stdout.write(JSON.stringify(errorResp) + '\n');
              }
              return;
            }
          }

          const respSessionId = resp.headers.get('mcp-session-id');
          if (respSessionId) {
            sessionId = respSessionId;
          }

          const contentType = resp.headers.get('content-type') ?? '';

          if (contentType.includes('text/event-stream')) {
            await handleSseResponse(resp);
          } else {
            const body = await resp.text();
            if (body.trim()) {
              process.stdout.write(body + '\n');
            }
          }
        };

        await doRequest();
      } catch (err) {
        // Connection error — daemon might have restarted
        const reconnected = await reinitialize();
        if (reconnected && parsed !== initializeMessage) {
          try {
            const headers: Record<string, string> = {
              'Content-Type': 'application/json',
              Accept: 'application/json, text/event-stream',
            };
            if (sessionId) headers['mcp-session-id'] = sessionId;

            const resp = await fetch(`${baseUrl}/mcp`, {
              method: 'POST',
              headers,
              body: JSON.stringify(parsed),
            });

            const respSessionId = resp.headers.get('mcp-session-id');
            if (respSessionId) sessionId = respSessionId;

            const contentType = resp.headers.get('content-type') ?? '';
            if (contentType.includes('text/event-stream')) {
              await handleSseResponse(resp);
            } else {
              const body = await resp.text();
              if (body.trim()) process.stdout.write(body + '\n');
            }
          } catch (retryErr) {
            process.stderr.write(
              `Retry failed: ${retryErr instanceof Error ? retryErr.message : retryErr}\n`,
            );
            if (!isNotification && parsed && typeof parsed === 'object' && 'id' in parsed) {
              const errorResp = {
                jsonrpc: '2.0',
                id: (parsed as { id: unknown }).id,
                error: { code: -32603, message: 'Proxy connection error after reconnect' },
              };
              process.stdout.write(JSON.stringify(errorResp) + '\n');
            }
          }
        } else {
          process.stderr.write(
            `Proxy error: ${err instanceof Error ? err.message : err}\n`,
          );
          if (!isNotification && parsed && typeof parsed === 'object' && 'id' in parsed) {
            const errorResp = {
              jsonrpc: '2.0',
              id: (parsed as { id: unknown }).id,
              error: { code: -32603, message: 'Proxy connection error' },
            };
            process.stdout.write(JSON.stringify(errorResp) + '\n');
          }
        }
      } finally {
        pendingRequests--;
        maybeExit();
      }
    });
  };

  // Open SSE stream for server-initiated notifications (auto-reconnects)
  openSseStream(baseUrl, () => sessionId, () => stdinClosed, (ac) => { sseAbortController = ac; });

  // Read JSON-RPC messages from stdin, one per line
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      process.stderr.write(`Invalid JSON from stdin: ${trimmed.slice(0, 100)}\n`);
      return;
    }

    enqueueRequest(parsed);
  });

  rl.on('close', () => {
    stdinClosed = true;
    sseAbortController?.abort();
    maybeExit();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Parse SSE response body and write JSON-RPC messages to stdout.
 */
async function handleSseResponse(resp: Response) {
  const body = resp.body;
  if (!body) return;

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';

    let currentData = '';
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        currentData += line.slice(6);
      } else if (line === '' && currentData) {
        // Empty line = end of event
        process.stdout.write(currentData + '\n');
        currentData = '';
      }
    }
  }
}

/**
 * Open persistent SSE stream for server-initiated notifications.
 * Auto-reconnects on disconnect with backoff.
 */
async function openSseStream(
  baseUrl: string,
  getSessionId: () => string | null,
  isClosed: () => boolean,
  setAbortController: (ac: AbortController) => void,
) {
  while (!isClosed()) {
    // Wait for session to be established
    while (!getSessionId() && !isClosed()) {
      await sleep(100);
    }
    if (isClosed()) break;

    const ac = new AbortController();
    setAbortController(ac);

    try {
      const resp = await fetch(`${baseUrl}/mcp`, {
        method: 'GET',
        headers: {
          Accept: 'text/event-stream',
          'mcp-session-id': getSessionId()!,
        },
        signal: ac.signal,
      });
      if (resp.ok) {
        await handleSseResponse(resp);
      }
    } catch (err) {
      if (ac.signal.aborted) continue; // intentional abort for reconnect
      process.stderr.write(`SSE stream error: ${err instanceof Error ? err.message : err}\n`);
    }

    if (!isClosed()) {
      await sleep(1000);
    }
  }
}
