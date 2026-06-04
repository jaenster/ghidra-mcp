/**
 * Sessions command - manage analysis sessions
 */

import * as http from 'node:http';
import * as path from 'node:path';
import { getDaemonStatus } from '@ghidra-mcp/daemon';

interface SessionsOptions {
  binary?: string;
  sessionId?: string;
  analyze?: boolean;
}

export async function sessionsCommand(
  action: 'list' | 'create' | 'close',
  options?: SessionsOptions
): Promise<void> {
  // Ensure daemon is running
  const status = await getDaemonStatus();
  if (!status.running || !status.port) {
    console.error('Daemon is not running. Start it with: ghidra-mcp start');
    process.exit(1);
  }

  const port = status.port;

  switch (action) {
    case 'list':
      await listSessions(port);
      break;
    case 'create':
      if (!options?.binary) {
        console.error('Binary path is required');
        process.exit(1);
      }
      await createSession(port, options.binary, options.analyze !== false);
      break;
    case 'close':
      if (!options?.sessionId) {
        console.error('Session ID is required');
        process.exit(1);
      }
      await closeSession(port, options.sessionId);
      break;
  }
}

async function listSessions(port: number): Promise<void> {
  const response = await httpRequest<{ sessions: SessionInfo[] }>(
    port,
    'GET',
    '/api/sessions'
  );

  if (!response || !response.sessions) {
    console.log('No sessions found');
    return;
  }

  if (response.sessions.length === 0) {
    console.log('No active sessions');
    return;
  }

  console.log('Active Sessions:\n');
  for (const session of response.sessions) {
    console.log(`Session: ${session.id}`);
    console.log(`  Binary: ${session.binaryPath}`);
    console.log(`  Status: ${session.status}`);
    console.log(`  Clients: ${session.clientCount}`);
    console.log(`  Created: ${new Date(session.createdAt).toLocaleString()}`);
    console.log(`  Last Access: ${new Date(session.lastAccessedAt).toLocaleString()}`);
    console.log();
  }
}

async function createSession(
  port: number,
  binaryPath: string,
  autoAnalyze: boolean
): Promise<void> {
  const resolvedPath = path.resolve(binaryPath);
  console.log(`Creating session for: ${resolvedPath}`);
  console.log(`Auto-analyze: ${autoAnalyze}`);
  console.log();

  try {
    const response = await httpRequest<{ session: SessionInfo }>(
      port,
      'POST',
      '/api/sessions',
      { binaryPath: resolvedPath, autoAnalyze }
    );

    if (response?.session) {
      console.log('Session created successfully!');
      console.log(`  Session ID: ${response.session.id}`);
      console.log(`  Status: ${response.session.status}`);
    }
  } catch (error) {
    console.error('Failed to create session:', error);
    process.exit(1);
  }
}

async function closeSession(port: number, sessionId: string): Promise<void> {
  console.log(`Closing session: ${sessionId}`);

  try {
    await httpRequest(port, 'DELETE', `/api/sessions/${sessionId}`);
    console.log('Session closed successfully');
  } catch (error) {
    console.error('Failed to close session:', error);
    process.exit(1);
  }
}

interface SessionInfo {
  id: string;
  binaryPath: string;
  binaryHash: string;
  status: string;
  clientCount: number;
  createdAt: string;
  lastAccessedAt: string;
}

async function httpRequest<T>(
  port: number,
  method: string,
  path: string,
  body?: unknown
): Promise<T | null> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path,
        method,
        timeout: 30000,
        headers: body ? { 'Content-Type': 'application/json' } : {},
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            try {
              const error = JSON.parse(data);
              reject(new Error(error.error || `HTTP ${res.statusCode}`));
            } catch {
              reject(new Error(`HTTP ${res.statusCode}: ${data}`));
            }
            return;
          }

          try {
            resolve(data ? JSON.parse(data) : null);
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}
