/**
 * Stop command - stops the daemon
 */

import * as fs from 'node:fs';
import { getDaemonStatus } from '@ghidra-mcp/daemon';
import { getAppPaths } from '@ghidra-mcp/shared/platform';

export async function stopCommand(): Promise<void> {
  const status = await getDaemonStatus();

  if (!status.running) {
    console.log('Daemon is not running');
    return;
  }

  console.log(`Stopping daemon (PID: ${status.pid})...`);

  try {
    // Send SIGTERM to the daemon
    if (status.pid) {
      process.kill(status.pid, 'SIGTERM');
    }

    // Wait for it to stop
    const maxWait = 10000;
    const startTime = Date.now();

    while (Date.now() - startTime < maxWait) {
      await new Promise((resolve) => setTimeout(resolve, 500));

      const newStatus = await getDaemonStatus();
      if (!newStatus.running) {
        console.log('Daemon stopped');
        return;
      }
    }

    // Force kill if still running
    if (status.pid) {
      console.log('Daemon not responding, sending SIGKILL...');
      process.kill(status.pid, 'SIGKILL');
    }

    // Clean up PID file
    const paths = getAppPaths();
    if (fs.existsSync(paths.pidFile)) {
      fs.unlinkSync(paths.pidFile);
    }

    console.log('Daemon stopped');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') {
      // Process doesn't exist
      console.log('Daemon was not running (stale PID file cleaned up)');

      const paths = getAppPaths();
      if (fs.existsSync(paths.pidFile)) {
        fs.unlinkSync(paths.pidFile);
      }
    } else {
      console.error('Error stopping daemon:', error);
      process.exit(1);
    }
  }
}
