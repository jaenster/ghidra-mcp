/**
 * Stdio command - runs as a stdio proxy for MCP clients
 *
 * This mode:
 * 1. Starts the daemon if not running
 * 2. Proxies stdin/stdout to the daemon's MCP endpoint
 *
 * This allows MCP clients that only support stdio transport to use
 * the Ghidra MCP daemon.
 */

import * as http from 'node:http';
import * as readline from 'node:readline';
import { startDaemon, getDaemonStatus } from '@ghidra-mcp/daemon';
import { getDaemonPort } from '@ghidra-mcp/shared/platform';

export async function stdioCommand(): Promise<void> {
  // Ensure daemon is running
  let status = await getDaemonStatus();

  if (!status.running) {
    // Start daemon in background
    process.stderr.write('Starting Ghidra MCP daemon...\n');
    try {
      await startDaemon({ foreground: false });
      // Wait for it to be ready
      await new Promise((resolve) => setTimeout(resolve, 2000));
      status = await getDaemonStatus();
    } catch (error) {
      process.stderr.write(`Failed to start daemon: ${error}\n`);
      process.exit(1);
    }
  }

  const port = status.port ?? getDaemonPort();
  process.stderr.write(`Connected to daemon on port ${port}\n`);

  // Set up stdin/stdout proxy
  const rl = readline.createInterface({
    input: process.stdin,
    terminal: false,
  });

  // Accumulate incoming JSON-RPC messages
  let buffer = '';

  rl.on('line', async (line) => {
    buffer += line;

    // Try to parse as JSON
    try {
      const message = JSON.parse(buffer);
      buffer = '';

      // Forward to daemon and relay response
      const response = await proxyRequest(port, message);
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    } catch {
      // Incomplete JSON, wait for more lines
    }
  });

  rl.on('close', () => {
    process.exit(0);
  });

  // Handle process signals
  process.on('SIGINT', () => {
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    process.exit(0);
  });
}

/**
 * Proxy a JSON-RPC request to the daemon, with retry on transient errors
 */
async function proxyRequest(port: number, message: unknown): Promise<unknown> {
  const maxRetries = 3;
  let lastErr: unknown;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await proxyRequestOnce(port, message);
    } catch (err) {
      lastErr = err;
      if (attempt < maxRetries - 1 && isTransientError(err)) {
        process.stderr.write(`Daemon connection error, retrying (${attempt + 1}/${maxRetries})...\n`);
        await new Promise(r => setTimeout(r, 1000));
        continue;
      }
      return {
        jsonrpc: '2.0',
        id: (message as { id?: unknown })?.id ?? null,
        error: { code: -32603, message: `Internal error: ${err}` },
      };
    }
  }
  return {
    jsonrpc: '2.0',
    id: (message as { id?: unknown })?.id ?? null,
    error: { code: -32603, message: `Internal error: ${lastErr}` },
  };
}

function isTransientError(err: unknown): boolean {
  const msg = String(err);
  return msg.includes('ECONNREFUSED') || msg.includes('ECONNRESET') || msg.includes('EPIPE');
}

/**
 * Single attempt to proxy a JSON-RPC request to the daemon
 */
function proxyRequestOnce(port: number, message: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(message);

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/mcp/rpc',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 60000,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(data ? JSON.parse(data) : null);
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on('error', (error) => {
      reject(error);
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        jsonrpc: '2.0',
        id: (message as { id?: unknown })?.id ?? null,
        error: {
          code: -32603,
          message: 'Request timeout',
        },
      });
    });

    req.write(body);
    req.end();
  });
}
