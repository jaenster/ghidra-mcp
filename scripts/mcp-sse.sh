#!/bin/bash
# MCP SSE wrapper for ghidra-mcp
# Ensures daemon is running and connects via mcp-proxy

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DAEMON_PORT=8432
# Resolve mcp-proxy from PATH; override with MCP_PROXY=/path/to/mcp-proxy if needed.
MCP_PROXY="${MCP_PROXY:-$(command -v mcp-proxy)}"

# Point at your local Ghidra install (scripts/install-ghidra.sh drops it under the repo).
export GHIDRA_HOME="${GHIDRA_HOME:-$(echo "$PROJECT_ROOT"/ghidra_*_PUBLIC)}"

# Check if daemon is running
if ! curl -s "http://localhost:$DAEMON_PORT/health" >/dev/null 2>&1; then
    # Start daemon in background
    cd "$PROJECT_ROOT"
    nohup node packages/cli/dist/index.js start --port $DAEMON_PORT >/dev/null 2>&1 &

    # Wait for daemon to be ready (max 30 seconds)
    for i in {1..30}; do
        if curl -s "http://localhost:$DAEMON_PORT/health" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
fi

# Connect via mcp-proxy
exec "$MCP_PROXY" "http://localhost:$DAEMON_PORT/mcp"
