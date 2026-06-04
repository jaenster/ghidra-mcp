/**
 * Status command - shows daemon status
 */

import * as http from 'node:http';
import { getDaemonStatus } from '@ghidra-mcp/daemon';

export async function statusCommand(): Promise<void> {
  const status = await getDaemonStatus();

  if (!status.running) {
    console.log('Daemon: not running');
    return;
  }

  console.log('Daemon Status:');
  console.log(`  Running: yes`);
  console.log(`  PID: ${status.pid}`);
  console.log(`  Port: ${status.port}`);

  if (status.uptime) {
    const uptimeSeconds = Math.floor(status.uptime / 1000);
    const hours = Math.floor(uptimeSeconds / 3600);
    const minutes = Math.floor((uptimeSeconds % 3600) / 60);
    const seconds = uptimeSeconds % 60;
    console.log(`  Uptime: ${hours}h ${minutes}m ${seconds}s`);
  }

  // Try to get more detailed status from the daemon
  if (status.port) {
    try {
      const detailedStatus = await fetchDaemonStatus(status.port);
      if (detailedStatus) {
        console.log(`  Sessions: ${detailedStatus.sessions?.length ?? 0}`);
        console.log(`  Workers: ${detailedStatus.workers ?? 0}`);

        if (detailedStatus.sessions && detailedStatus.sessions.length > 0) {
          console.log('\nActive Sessions:');
          for (const session of detailedStatus.sessions) {
            console.log(`  - ${session.id}`);
            console.log(`    Binary: ${session.binaryPath}`);
            console.log(`    Status: ${session.status}`);
            console.log(`    Clients: ${session.clientCount}`);
          }
        }
      }
    } catch {
      // Ignore errors fetching detailed status
    }
  }
}

interface DaemonStatusResponse {
  status: string;
  sessions?: Array<{
    id: string;
    binaryPath: string;
    status: string;
    clientCount: number;
  }>;
  workers?: number;
  defaultSession?: string | null;
}

async function fetchDaemonStatus(port: number): Promise<DaemonStatusResponse | null> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path: '/status',
        method: 'GET',
        timeout: 5000,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        });
      }
    );

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.end();
  });
}
