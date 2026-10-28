# @ghidra-mcp/gateway

The public, read-only MCP surface. It holds the daemon credential, forwards only
allowlisted read tools (`src/allowlist.ts`), and pins every call to a session it opens
itself, read-only, on one of two programs. Callers choose the program by name only:
`program: "win"` (default) or `"mac"`. Which server path each name opens is
configuration here and is never taken from a request.

## What callers never learn

No repository, program path, folder, other version, session id, server host, Ghidra user
or daemon internal reaches a caller:

- answers lose `DENIED_RESPONSE_KEYS` at any depth, and `get_program_info` keeps only
  what is in the binary (`keepKeys`);
- every answer goes through the deny-pattern redactor (`src/redact.ts`);
- daemon errors are mapped to four fixed messages (not found, invalid arguments, too
  slow, failed); the daemon text only reaches the audit log's `reason`;
- `/health` answers `ok` or `unavailable` and nothing else. Versions and their age are on
  `/internal/health` and `/internal/versions`, which exist only with a service token
  configured and answer only with it.

## Behind the edge

With `GATEWAY_AUTH_MODE=edge` the gateway sits behind the Cloudflare Worker at
ghidra.redivivus.app (repo jaenster/redivivus-app), which signs callers in with GitHub.
Every request but `/health` must then carry the Access service token
(`CF-Access-Client-Id`/`CF-Access-Client-Secret`); only with it is the caller in
`X-Edge-Identity`/`X-Edge-Login` trusted, and the gateway's own GitHub check is off.
The edge reads `/internal/versions` to key its cache on the version served, and the
tool list's `_meta["ghidra-mcp/tier"]` to charge costly tools more.

## Following new versions

A read-only open serves the version that was latest when it opened. Run the gateway's
daemon with `GHIDRA_MCP_FOLLOW_VERSIONS_MS` (e.g. `60000`): its read-only server sessions
then hold no checkout and reload in place when a newer version is checked in, swapping
under the worker's command fence so calls in flight finish on the old program. The
gateway re-reads the served version every `GATEWAY_VERSION_POLL_MS`.

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
|`GATEWAY_PROGRAM_WIN`|`Diablo2Lod/windows/lod/1.14d/Game.exe`|what `program: "win"` opens (repo path, `ghidra://` URL or `.gpr`)|
|`GATEWAY_PROGRAM_MAC`|`Diablo2Lod/mac/intel/1.14d/DiabloII_macho`|what `program: "mac"` opens|
|`GATEWAY_AUTH_MODE`|`github`|`edge`: trust the edge's identity header, only with the service token|
|`GATEWAY_ACCESS_CLIENT_ID` / `_SECRET`|unset|the Access service token; when set, required on everything but `/health`|
|`GATEWAY_VERSION_POLL_MS`|`60000`|how often the served version is re-read|
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
