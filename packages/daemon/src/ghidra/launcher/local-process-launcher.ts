/**
 * Local child-process worker backend (the default; used for dev and single-host runs).
 *
 * This is the original WorkerPool.spawnWorker process handling, lifted verbatim behind
 * the WorkerLauncher seam: spawn the JVM, stream stdout/stderr, and translate the
 * child's 'exit' into onWorkerDied.
 */
import * as child_process from 'node:child_process';
import { getDaemonUrl } from '@ghidra-mcp/shared/platform';
import type {
  WorkerLauncher,
  WorkerHandle,
  LaunchSpec,
  WorkerDiedHandler,
} from './launcher.js';

export class LocalProcessLauncher implements WorkerLauncher {
  readonly backend = 'process' as const;
  private diedHandler?: WorkerDiedHandler;
  private procs = new Map<string, child_process.ChildProcess>();

  /** Workers are co-located; loopback unless GHIDRA_MCP_DAEMON_URL overrides. */
  daemonUrl(loopbackPort: number): string {
    return getDaemonUrl(loopbackPort);
  }

  /** Local working copy lives at the per-session dir the manager computed. */
  projectDir(_sessionId: string, defaultLocalDir: string): string {
    return defaultLocalDir;
  }

  onWorkerDied(cb: WorkerDiedHandler): void {
    this.diedHandler = cb;
  }

  async launch(spec: LaunchSpec): Promise<WorkerHandle> {
    const proc = child_process.spawn(spec.javaPath, spec.javaArgs, {
      cwd: spec.cwd,
      env: spec.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.procs.set(spec.workerId, proc);

    proc.stdout?.on('data', (data) => {
      const line = data.toString().trim();
      console.log(`[Worker ${spec.workerId}] ${line}`);
      spec.onStdout?.(line);
    });
    proc.stderr?.on('data', (data) => {
      const line = data.toString().trim();
      console.error(`[Worker ${spec.workerId}] ERROR: ${line}`);
      spec.onStderr?.(line);
    });

    proc.on('exit', (code, signal) => {
      console.log(`[Worker ${spec.workerId}] Exited with code ${code}, signal ${signal}`);
      this.procs.delete(spec.workerId);
      this.diedHandler?.(spec.workerId, `exit:${code}/${signal}`, code, signal);
    });
    proc.on('error', (error) => {
      console.error(`[Worker ${spec.workerId}] Error:`, error);
    });

    return { backend: this.backend, pid: proc.pid };
  }

  async stop(handle: WorkerHandle, force: boolean): Promise<void> {
    // Prefer the tracked child handle; fall back to the pid for already-detached procs.
    const proc = [...this.procs.values()].find((p) => p.pid === handle.pid);
    if (proc) {
      proc.kill(force ? 'SIGKILL' : 'SIGTERM');
      return;
    }
    if (typeof handle.pid === 'number') {
      try { process.kill(handle.pid, force ? 'SIGKILL' : 'SIGTERM'); } catch { /* already gone */ }
    }
  }
}
