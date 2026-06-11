/**
 * Worker launch backend.
 *
 * The daemon talks to every worker the same way — over HTTP, the worker connects
 * BACK to the daemon's /internal/worker endpoints and long-polls for commands. So
 * "how a worker process comes into existence" is the only thing that differs between
 * running locally and running in Kubernetes. That difference lives behind this seam:
 *
 *  - LocalProcessLauncher: spawn a child-process JVM next to the daemon (dev default).
 *  - K8sPodLauncher:       create one pod per worker that connects back over the
 *                          cluster network (each pod gets its own memory limit and
 *                          its own scratch volume — no shared lock, no shared heap).
 *
 * Everything else (command routing, ready/heartbeat tracking, result handling) is
 * backend-agnostic and stays in WorkerPool.
 */
import { getWorkerBackend, type WorkerBackend } from '@ghidra-mcp/shared/platform';
import { LocalProcessLauncher } from './local-process-launcher.js';

export type { WorkerBackend };

export interface WorkerHandle {
  backend: WorkerBackend;
  pid?: number;       // process backend
  podName?: string;   // k8s backend
}

export interface LaunchSpec {
  workerId: string;
  sessionId: string;
  /** Java executable (process backend); pods use `java` from the image PATH. */
  javaPath: string;
  /** Full java argument vector: -Xmx, -cp, com.ghidramcp.Worker, then --flags. */
  javaArgs: string[];
  /** Working directory / GHIDRA_HOME. */
  cwd: string;
  /** Spawn env (process backend). The k8s backend sources secrets in-cluster. */
  env: Record<string, string | undefined>;
  /** JVM heap string (e.g. "1536m"); the k8s backend derives the pod memory limit. */
  memory: string;
  /** Optional per-line log sinks (process backend wires stdout/stderr to these). */
  onStdout?: (line: string) => void;
  onStderr?: (line: string) => void;
}

export type WorkerDiedHandler = (
  workerId: string,
  reason: string,
  code: number | null,
  signal: string | null,
) => void;

export interface WorkerLauncher {
  readonly backend: WorkerBackend;

  /** Base URL a launched worker uses to reach the daemon's /internal API. */
  daemonUrl(loopbackPort: number): string;

  /** The worker's local Ghidra project dir (--project). */
  projectDir(sessionId: string, defaultLocalDir: string): string;

  /** Start a worker that will connect back to the daemon. */
  launch(spec: LaunchSpec): Promise<WorkerHandle>;

  /** Stop a worker (graceful unless force). Safe to call if it already exited. */
  stop(handle: WorkerHandle, force: boolean): Promise<void>;

  /** Register the single handler invoked when a launched worker dies. */
  onWorkerDied(cb: WorkerDiedHandler): void;
}

/**
 * Pick the launcher from GHIDRA_MCP_WORKER_BACKEND. The k8s launcher module is
 * loaded lazily so @kubernetes/client-node is never imported in process mode.
 */
export async function selectLauncher(): Promise<WorkerLauncher> {
  if (getWorkerBackend() === 'k8s') {
    const { K8sPodLauncher } = await import('./k8s-pod-launcher.js');
    return new K8sPodLauncher();
  }
  return new LocalProcessLauncher();
}
