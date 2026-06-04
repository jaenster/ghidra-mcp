/**
 * @ghidra-mcp/mcp
 * MCP protocol implementation for Ghidra
 */

export { createMcpServer, type McpServerOptions } from './server.js';
export { GhidraToolHandler, type ToolHandlerContext } from './handler.js';
export * from './tools/index.js';
export { formatResponse, setGlobalFormat, getGlobalFormat, toToon } from './toon.js';

// Re-export for convenience
import { GhidraToolHandler, type ToolHandlerContext } from './handler.js';

/**
 * Standalone function to handle tool calls (creates handler internally)
 */
export async function handleToolCall(
  toolName: string,
  args: Record<string, unknown>,
  context: ToolHandlerContext
): Promise<{ content: Array<{ type: string; text: string }> }> {
  const handler = new GhidraToolHandler(context, 'json');
  return handler.handleToolCall(toolName, args);
}
