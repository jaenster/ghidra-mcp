# ghidra-mcp

Headless [Ghidra](https://ghidra-sre.org/) Model Context Protocol server. A single TypeScript daemon exposes Ghidra's reverse-engineering capabilities as MCP tools over **SSE** and **Streamable HTTP**, driving one Java Ghidra worker process per session. It runs locally for a single user, or remotely as an OAuth-secured **claude.ai connector**.

## Packages

| Package | Role |
|-|-|
| `@ghidra-mcp/shared` | Types, worker↔daemon protocol, platform/path detection |
| `@ghidra-mcp/mcp` | MCP server + tool definitions + tool→daemon dispatcher |
| `@ghidra-mcp/daemon` | HTTP/SSE/Streamable server, OAuth AS, session manager, worker pool, state DB |
| `@ghidra-mcp/cli` | `ghidra` binary: starts the daemon, or a stdio bridge for MCP clients |
| `@ghidra-mcp/dashboard` | React monitoring UI (served at `/dashboard`) |

The `ghidra-worker/` directory is a Gradle-built Java fat-JAR (`com.ghidramcp.Worker`) compiled against a local Ghidra install.

## Build

```bash
npm install
npm run install:ghidra     # downloads Ghidra (scripts/install-ghidra.sh)
npm run install:worker     # gradle build → ghidra-worker.jar
npm run build              # builds all TS packages
```

## Run locally

```bash
node packages/cli/dist/bin.js --port 8432    # start daemon
node packages/cli/dist/bin.js --stdio        # stdio bridge for an MCP client
```

Locally the daemon binds `127.0.0.1` and requires **no auth**.

## Run as a remote claude.ai connector

Set these and the daemon becomes a self-contained OAuth 2.1 authorization server
(Dynamic Client Registration + PKCE) gating the MCP endpoints:

| Env var | Purpose | Default |
|-|-|-|
| `GHIDRA_MCP_HOST` | Bind address — set `0.0.0.0` in a container | `127.0.0.1` |
| `GHIDRA_MCP_PORT` | Listen port | `8432` |
| `GHIDRA_MCP_PUBLIC_URL` | Public HTTPS URL (OAuth issuer/resource id) | — |
| `GHIDRA_MCP_AUTH_SECRET` | Shared password shown on the consent screen | — |
| `GHIDRA_MCP_OAUTH_SCOPES` | Supported scopes (space/comma separated) | `ghidra` |
| `GHIDRA_MCP_ACCESS_TTL` | Access-token lifetime (sec) | `3600` |
| `GHIDRA_MCP_REFRESH_TTL` | Refresh-token lifetime (sec) | `2592000` |
| `GHIDRA_MCP_DAEMON_URL` | Worker→daemon callback URL | `http://127.0.0.1:<port>` |
| `GHIDRA_HOME` | Ghidra install directory | platform default |

OAuth activates only when both `GHIDRA_MCP_PUBLIC_URL` **and** `GHIDRA_MCP_AUTH_SECRET` are set.

Add `<GHIDRA_MCP_PUBLIC_URL>/mcp` as a custom connector in claude.ai; it discovers
the OAuth endpoints, registers via DCR, and prompts for the connector password.

### Endpoints

- MCP: `POST/GET/DELETE /mcp` (Streamable HTTP), `GET /sse` + `POST /sse/messages` (SSE) — **token-gated when OAuth is on**
- OAuth: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/authorize`, `/token`, `/register`, `/revoke`, `/oauth/consent`
- Open: `/health`, `/status`, `/dashboard`
- Internal (worker control-plane): `/internal/worker/:id/*` — **must not be exposed by the ingress**; only loopback / in-pod traffic should reach it.

## Tests

```bash
npm run test:unit
npm run test:e2e
```
