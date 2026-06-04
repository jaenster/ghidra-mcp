#!/bin/bash
# MCP stdio wrapper for ghidra-mcp
# Use this in Claude Code's mcpServers config

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

export GHIDRA_HOME="$PROJECT_ROOT/ghidra_12.0.2_PUBLIC"

cd "$PROJECT_ROOT"
exec node packages/cli/dist/index.js stdio
