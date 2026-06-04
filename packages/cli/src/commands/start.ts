/**
 * Start command - starts the daemon
 */

import * as child_process from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDaemon, getDaemonStatus } from '@ghidra-mcp/daemon';
import { getGhidraHome } from '@ghidra-mcp/shared/platform';

interface StartOptions {
  port: string;
  foreground: boolean;
  force: boolean;
}

export async function startCommand(options: StartOptions): Promise<void> {
  const port = parseInt(options.port, 10);

  // Check if daemon is already running (unless --force is used)
  if (!options.force) {
    const status = await getDaemonStatus();
    if (status.running) {
      console.error(`Daemon already running (PID: ${status.pid}, port: ${status.port})`);
      process.exit(1);
    }
  }

  // Validate Ghidra is available
  try {
    const ghidraHome = getGhidraHome();
    console.log(`Using Ghidra from: ${ghidraHome}`);
  } catch (error) {
    console.error('Ghidra not found.');
    console.error('Please set GHIDRA_HOME environment variable to your Ghidra installation directory.');
    console.error('\nExample:');
    console.error('  export GHIDRA_HOME=/path/to/ghidra_12.x_PUBLIC');
    process.exit(1);
  }

  if (options.foreground) {
    // Run in foreground
    console.log(`Starting Ghidra MCP daemon on port ${port}...`);
    try {
      const { pid, port: actualPort } = await startDaemon({ port, force: options.force });
      console.log(`Daemon started (PID: ${pid}, port: ${actualPort})`);
      console.log('Press Ctrl+C to stop');

      // Keep process running
      await new Promise(() => {});
    } catch (error) {
      console.error('Failed to start daemon:', error);
      process.exit(1);
    }
  } else {
    // Daemonize
    console.log(`Starting Ghidra MCP daemon on port ${port}...`);

    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const scriptPath = path.join(__dirname, '..', 'index.js');

    const args = [scriptPath, 'start', '-p', String(port), '-f'];
    if (options.force) {
      args.push('--force');
    }

    const child = child_process.spawn(
      process.execPath,
      args,
      {
        detached: true,
        stdio: 'ignore',
        env: process.env,
      }
    );

    child.unref();

    // Wait a moment for the daemon to start
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Check if it started
    const newStatus = await getDaemonStatus();
    if (newStatus.running) {
      console.log(`Daemon started (PID: ${newStatus.pid}, port: ${newStatus.port})`);
    } else {
      console.error('Failed to start daemon. Check logs for details.');
      process.exit(1);
    }
  }
}
