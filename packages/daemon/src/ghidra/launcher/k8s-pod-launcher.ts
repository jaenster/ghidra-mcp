/**
 * Kubernetes worker backend: one pod per worker.
 *
 * Each worker runs in its own pod (same image as the daemon — it already bundles
 * Java + Ghidra + the worker jar) with its own memory limit and its own emptyDir
 * scratch volume, then connects BACK to the daemon's in-cluster Service exactly like
 * a local worker connects to loopback. The lock/heap contention of cramming every
 * worker JVM into the daemon pod simply doesn't exist here.
 *
 * @kubernetes/client-node is imported lazily (only when this module loads) so the
 * default process backend never pulls in the SDK.
 */
import {
  getWorkerImage,
  getWorkerDaemonUrl,
} from '@ghidra-mcp/shared/platform';
import type {
  WorkerLauncher,
  WorkerHandle,
  LaunchSpec,
  WorkerDiedHandler,
} from './launcher.js';

// Lazily-resolved kube client (typed loosely to avoid a hard type dep at build).
type KubeClient = {
  core: any;
  watch: any;
  namespace: string;
  /** The daemon's own pod spec — worker pods inherit its networking/scheduling. */
  self: any | null;
};

const WORKER_LABEL = 'app=ghidra-worker';

export class K8sPodLauncher implements WorkerLauncher {
  readonly backend = 'k8s' as const;
  private diedHandler?: WorkerDiedHandler;
  private clientPromise?: Promise<KubeClient>;
  private watchStarted = false;
  /** Pods we deleted on purpose — don't report those as unexpected deaths. */
  private stopping = new Set<string>();

  /** Worker pods reach the daemon via the in-cluster Service DNS. */
  daemonUrl(_loopbackPort: number): string {
    const url = getWorkerDaemonUrl();
    if (!url) {
      throw new Error(
        'GHIDRA_MCP_WORKER_DAEMON_URL must be set for the k8s worker backend ' +
        '(the in-cluster Service URL workers call back to).',
      );
    }
    return url;
  }

  /** Each pod is isolated, so the scratch project just lives under the emptyDir. */
  projectDir(sessionId: string, _defaultLocalDir: string): string {
    return `/data/projects/${sessionId}`;
  }

  onWorkerDied(cb: WorkerDiedHandler): void {
    this.diedHandler = cb;
  }

  private async client(): Promise<KubeClient> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        const k8s = await import('@kubernetes/client-node');
        const kc = new k8s.KubeConfig();
        kc.loadFromCluster();
        const namespace = process.env.GHIDRA_MCP_NAMESPACE?.trim() || 'ghidra-mcp';
        const core = kc.makeApiClient(k8s.CoreV1Api);
        // Read our own pod so worker pods can inherit its image + networking/scheduling
        // (hostAliases for the RMI return-path, imagePullSecrets, affinity, SA).
        let self: any = null;
        const selfName = process.env.GHIDRA_MCP_POD_NAME?.trim();
        if (selfName) {
          try {
            self = await core.readNamespacedPod({ name: selfName, namespace });
            self = self?.body ?? self; // client returns the object directly in v1
          } catch (e: any) {
            console.warn(`[K8sPodLauncher] could not read own pod ${selfName}: ${e?.message ?? e}`);
          }
        }
        return { core, watch: new k8s.Watch(kc), namespace, self };
      })();
    }
    return this.clientPromise;
  }

  async launch(spec: LaunchSpec): Promise<WorkerHandle> {
    const c = await this.client();
    await this.ensureWatch(c);

    const podName = `ghidra-worker-${spec.workerId.slice(0, 8)}`;
    const pod = this.buildPodManifest(spec, podName, c);

    await c.core.createNamespacedPod({ namespace: c.namespace, body: pod });
    console.log(`[K8sPodLauncher] created pod ${podName} for worker ${spec.workerId}`);
    return { backend: this.backend, podName };
  }

  async stop(handle: WorkerHandle, force: boolean): Promise<void> {
    if (!handle.podName) return;
    const c = await this.client();
    this.stopping.add(handle.podName);
    try {
      await c.core.deleteNamespacedPod({
        namespace: c.namespace,
        name: handle.podName,
        gracePeriodSeconds: force ? 0 : 30,
      });
    } catch (e: any) {
      // 404 = already gone; anything else is best-effort cleanup.
      if (e?.code !== 404 && e?.statusCode !== 404) {
        console.warn(`[K8sPodLauncher] delete pod ${handle.podName} failed: ${e?.message ?? e}`);
      }
    } finally {
      // Keep it briefly so the watch's terminal event is suppressed, then forget.
      setTimeout(() => this.stopping.delete(handle.podName!), 10000).unref?.();
    }
  }

  /** Start the shared pod watch once; map terminal pod events to onWorkerDied. */
  private async ensureWatch(c: KubeClient): Promise<void> {
    if (this.watchStarted) return;
    this.watchStarted = true;
    const start = () => {
      c.watch
        .watch(
          `/api/v1/namespaces/${c.namespace}/pods`,
          { labelSelector: WORKER_LABEL },
          (type: string, obj: any) => this.onPodEvent(type, obj),
          (err: any) => {
            console.warn(`[K8sPodLauncher] pod watch ended (${err?.message ?? err}); restarting`);
            this.watchStarted = false;
            setTimeout(() => this.ensureWatch(c), 2000).unref?.();
          },
        )
        .catch((err: any) => {
          console.warn(`[K8sPodLauncher] pod watch failed to start: ${err?.message ?? err}`);
          this.watchStarted = false;
        });
    };
    start();
  }

  private onPodEvent(type: string, pod: any): void {
    const workerId = pod?.metadata?.labels?.['ghidra-mcp/worker'];
    const podName = pod?.metadata?.name;
    if (!workerId || !podName) return;

    const phase = pod?.status?.phase;
    const terminal =
      type === 'DELETED' ||
      pod?.metadata?.deletionTimestamp ||
      phase === 'Failed' ||
      phase === 'Succeeded';
    if (!terminal) return;

    if (this.stopping.has(podName)) return; // we deleted it on purpose

    const reason = `pod:${type}:${phase ?? 'deleted'}`;
    console.log(`[K8sPodLauncher] worker ${workerId} pod ${podName} terminal (${reason})`);
    this.diedHandler?.(workerId, reason, null, null);
  }

  private buildPodManifest(spec: LaunchSpec, podName: string, c: KubeClient): any {
    const selfSpec = c.self?.spec ?? {};
    // Worker image: explicit override, else inherit the daemon's own image so worker and
    // daemon always run the same build (CI bumps one tag).
    const image = getWorkerImage() ?? selfSpec.containers?.[0]?.image;
    if (!image) {
      throw new Error(
        'No worker image: set GHIDRA_MCP_WORKER_IMAGE or run the daemon as a pod ' +
        '(GHIDRA_MCP_POD_NAME) so it can inherit its own image.',
      );
    }
    const heapMi = heapToMib(spec.memory);
    const limitMi = heapMi + 512; // headroom for JVM non-heap + Ghidra native

    // Inherit the daemon pod's networking/scheduling so workers reach the RMI server
    // (hostAliases) and stay off the ghidra node (affinity), exactly like the daemon.
    const hostAliases = selfSpec.hostAliases;
    const imagePullSecrets = selfSpec.imagePullSecrets ?? [{ name: 'ghcr' }];
    const serviceAccountName = selfSpec.serviceAccountName ?? 'ghidra-mcp';
    const affinity = selfSpec.affinity;

    // Daemon pod identity for ownerReferences → workers are GC'd if the daemon pod dies.
    const ownerName = process.env.GHIDRA_MCP_POD_NAME?.trim() ?? c.self?.metadata?.name;
    const ownerUid = process.env.GHIDRA_MCP_POD_UID?.trim() ?? c.self?.metadata?.uid;
    const ownerReferences =
      ownerName && ownerUid
        ? [{ apiVersion: 'v1', kind: 'Pod', name: ownerName, uid: ownerUid, controller: false, blockOwnerDeletion: false }]
        : undefined;

    return {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: {
        name: podName,
        namespace: c.namespace,
        labels: {
          app: 'ghidra-worker',
          'ghidra-mcp/worker': spec.workerId,
          'ghidra-mcp/session': spec.sessionId.slice(0, 60),
        },
        ...(ownerReferences ? { ownerReferences } : {}),
      },
      spec: {
        restartPolicy: 'Never',
        serviceAccountName,
        imagePullSecrets,
        ...(hostAliases ? { hostAliases } : {}),
        ...(affinity ? { affinity } : {}),
        containers: [
          {
            name: 'worker',
            image,
            // The image bundles java on PATH; run the worker with the args the pool built
            // (which already point --daemon-url at the Service and --project under /data).
            command: ['java', ...spec.javaArgs],
            workingDir: spec.cwd,
            env: [
              { name: 'GHIDRA_HOME', value: spec.cwd },
              {
                name: 'GHIDRA_MCP_WORKER_SECRET',
                valueFrom: { secretKeyRef: { name: 'ghidra-mcp-worker', key: 'GHIDRA_MCP_WORKER_SECRET' } },
              },
              {
                name: 'GHIDRA_SERVER_USER',
                valueFrom: { secretKeyRef: { name: 'ghidra-mcp-server', key: 'GHIDRA_SERVER_USER' } },
              },
              {
                name: 'GHIDRA_SERVER_PASSWORD',
                valueFrom: { secretKeyRef: { name: 'ghidra-mcp-server', key: 'GHIDRA_SERVER_PASSWORD' } },
              },
            ],
            resources: {
              requests: { memory: `${heapMi}Mi` },
              limits: { memory: `${limitMi}Mi` },
            },
            volumeMounts: [{ name: 'data', mountPath: '/data' }],
          },
        ],
        volumes: [{ name: 'data', emptyDir: {} }],
      },
    };
  }
}

/** Parse a JVM heap string ("1536m", "4g") into MiB. */
function heapToMib(mem: string): number {
  const m = mem.trim().match(/^(\d+)\s*([mMgG])?$/);
  if (!m) return 2048;
  const n = parseInt(m[1], 10);
  return (m[2] ?? 'm').toLowerCase() === 'g' ? n * 1024 : n;
}
