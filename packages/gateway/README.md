# @ghidra-mcp/gateway

The public, read-only MCP surface. It holds the daemon credential, forwards only
allowlisted read tools (`src/allowlist.ts`), and pins every call to one session it
opens itself, read-only, on one program.

## Isolation

The gateway needs a daemon of its own. On a shared daemon, `create_session` returns
whatever session already has the program open - writable ones included - so a
read-only caller would see other clients' uncommitted edits. The gateway guards this
three ways:

- at startup it refuses a daemon that already holds sessions;
- it refuses a `create_session` answer that is not a session it just created;
- a watchdog (`GATEWAY_ISOLATION_CHECK_MS`) re-lists the daemon's sessions, and if a
  foreign session appears or another client attaches to the pinned one, the gateway
  stops answering and `/health` returns 503 until it is restarted.

Run the daemon on loopback in the gateway's pod (`GHIDRA_MCP_HOST=127.0.0.1`), with
its own data directory and Ghidra Server account, and expose only the gateway port.

## Configuration

|Variable|Default|Meaning|
|-|-|-|
|`GATEWAY_UPSTREAM_URL`|required|the gateway's own daemon|
|`GATEWAY_UPSTREAM_TOKEN`|unset|bearer token for that daemon|
|`GATEWAY_PROGRAM`|`/windows/lod/Game.exe`|program to pin (repo path, `ghidra://` URL or `.gpr`)|
|`GATEWAY_HOST` / `GATEWAY_PORT`|`127.0.0.1` / `8090`|listen address|
|`GATEWAY_ALLOW_ANONYMOUS`|`0`|`1` skips the GitHub token check - local testing only|
|`GATEWAY_CALLS_PER_MINUTE`|`60`|per identity, all tools|
|`GATEWAY_COSTLY_PER_MINUTE`|`6`|per identity, costly tools|
|`GATEWAY_MAX_CONCURRENT_COSTLY`|`2`|gateway-wide|
|`GATEWAY_MAX_RESPONSE_BYTES`|`262144`|longer responses are cut with a marker|
|`GATEWAY_REQUIRE_DEDICATED_UPSTREAM`|`1`|the startup and watchdog checks above|

Callers send `Authorization: Bearer <GitHub token>`; the gateway checks it against
GitHub's `/user` and caches the answer by token hash for `GATEWAY_AUTH_CACHE_TTL_MS`.
Each call writes one JSON audit line to stdout: identity, tool, argument hash,
duration, bytes and outcome.
