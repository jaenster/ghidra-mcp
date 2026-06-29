# Kubernetes deployment (kustomize template)

A self-host template for running ghidra-mcp as a remote, OAuth-secured claude.ai
connector. It is a starting point — copy the overlay and adapt it; the real values
(host, OIDC client, storage class, affinity) are environment-specific.

```
deploy/k8s/
  base/                 env-agnostic: deployment, service, rbac, pvc
  overlays/example/     per-instance: namespace, ingress, image tag, config.env
```

## The model: one daemon, one worker pod per session

The daemon pod is just the Node process. It does **not** run Ghidra itself — when a
client opens a program, the daemon **creates a new worker pod** (same image, the JVM
entrypoint) and that pod connects **back** to the daemon over the in-cluster Service,
opens the program from the shared Ghidra Server, and serves decompilation/analysis.
When the session ends (or the daemon dies) the worker pod is deleted/garbage-collected.

```
   claude.ai --HTTPS--> Ingress --> ghidra-mcp Service --> daemon pod (Node)
                                                              |  creates pods (k8s API)
                                                              v
                              worker pod    worker pod    worker pod ...
                              (java JVM)     (java JVM)    (java JVM)
                                  |  each calls back to the daemon Service, then
                                  v  opens its program from:
                            shared Ghidra Server (RMI :13100)
```

This is why the daemon needs the RBAC in `base/rbac.yaml` (create/delete/watch pods),
the downward-API env (`GHIDRA_MCP_POD_NAME/_UID/_NAMESPACE` — for ownerReferences and
where to create pods), and `GHIDRA_MCP_WORKER_DAEMON_URL` (the callback Service URL).

## Prerequisites

- A reachable, shared **Ghidra Server** (the NSA Ghidra `server/ghidraSvr`, RMI
  :13100-13102). Its version must match the image's bundled Ghidra. Programs are
  opened by repository path.
- An Ingress controller + cert-manager (the example uses nginx + `letsencrypt-prod`).
- A storage class for the RWO data PVC.
- An OIDC provider if you want federated login (optional but recommended for a public host).

## Secrets (created out-of-band, never in git)

```bash
kubectl create namespace ghidra-mcp

# Connector password shown on the consent screen (+ OIDC client secret if using OIDC).
kubectl -n ghidra-mcp create secret generic ghidra-mcp-auth \
  --from-literal=GHIDRA_MCP_AUTH_SECRET="$(openssl rand -hex 24)" \
  --from-literal=GHIDRA_MCP_OIDC_CLIENT_SECRET='<oidc-client-secret>'

# Credentials a worker uses to authenticate to the shared Ghidra Server.
kubectl -n ghidra-mcp create secret generic ghidra-mcp-server \
  --from-literal=GHIDRA_SERVER_USER='mcp' \
  --from-literal=GHIDRA_SERVER_PASSWORD='<strong-password>'

# Shared worker control-plane secret (daemon + every worker pod read the SAME value).
kubectl -n ghidra-mcp create secret generic ghidra-mcp-worker \
  --from-literal=GHIDRA_MCP_WORKER_SECRET="$(openssl rand -hex 24)"

# Pull secret if ghcr.io access is private (skip if the image/package is public).
kubectl -n ghidra-mcp create secret docker-registry ghcr \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<token>
```

## Deploy

```bash
# Edit overlays/example/config.env and overlays/example/ingress.yaml first.
kubectl apply -k deploy/k8s/overlays/example
```

Then add `https://<your-host>/mcp` as a custom connector in claude.ai.
