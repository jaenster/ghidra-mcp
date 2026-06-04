/**
 * MCP Server factory for Ghidra
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { GhidraToolHandler, type ToolHandlerContext } from './handler.js';
import { getAllToolDefinitions } from './tools/index.js';

export interface McpServerOptions {
  name?: string;
  version?: string;
  context: ToolHandlerContext;
}

export function createMcpServer(options: McpServerOptions): Server {
  const {
    name = 'ghidra-mcp',
    version = '1.0.0',
    context
  } = options;

  const server = new Server(
    {
      name,
      version,
    },
    {
      capabilities: {
        tools: {},
        resources: {},
      },
    }
  );

  const handler = new GhidraToolHandler(context);

  // Register tool list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const tools = getAllToolDefinitions();
    return { tools };
  });

  // Register tool call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name: toolName, arguments: args } = request.params;
    return handler.handleToolCall(toolName, args ?? {});
  });

  // Register resource list handler
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return { resources: await handler.listResources() };
  });

  // Register resource read handler
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    return handler.readResource(uri);
  });

  return server;
}
