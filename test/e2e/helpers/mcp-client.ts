/**
 * MCP Client for E2E testing
 *
 * Connects to the daemon via proper SSE transport (GET /sse + POST /sse/messages)
 */

import * as http from 'node:http';
import { EventEmitter } from 'node:events';

export interface McpClientOptions {
  host: string;
  port: number;
  timeout?: number;
}

export interface ToolCallResult {
  content: Array<{ type: string; text: string }>;
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface PendingRequest {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

/**
 * MCP client that connects via proper SSE transport
 */
export class McpTestClient extends EventEmitter {
  private host: string;
  private port: number;
  private timeout: number;
  private requestId = 0;
  private sessionId: string | null = null;

  // SSE connection state
  private sseRequest: http.ClientRequest | null = null;
  private connected = false;
  private messagesEndpoint: string | null = null;
  private pendingRequests = new Map<number, PendingRequest>();

  constructor(options: McpClientOptions) {
    super();
    this.host = options.host;
    this.port = options.port;
    this.timeout = options.timeout ?? 30000;
  }

  /**
   * Connect to the MCP server via SSE
   */
  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: this.host,
          port: this.port,
          path: '/sse',
          method: 'GET',
          headers: {
            Accept: 'text/event-stream',
            'Cache-Control': 'no-cache',
          },
        },
        (res) => {
          if (res.statusCode !== 200) {
            reject(new Error(`SSE connection failed: ${res.statusCode}`));
            return;
          }

          this.sseRequest = req;
          let buffer = '';

          res.on('data', (chunk: Buffer) => {
            buffer += chunk.toString();

            // Parse SSE events
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // Keep incomplete line in buffer

            let eventType = 'message';
            let eventData = '';

            for (const line of lines) {
              if (line.startsWith('event:')) {
                eventType = line.slice(6).trim();
              } else if (line.startsWith('data:')) {
                eventData = line.slice(5).trim();
              } else if (line === '' && eventData) {
                // End of event
                this.handleSseEvent(eventType, eventData);
                eventType = 'message';
                eventData = '';
              }
            }
          });

          res.on('end', () => {
            this.connected = false;
            this.emit('disconnected');
          });

          res.on('error', (err) => {
            // Ignore ECONNRESET during shutdown - it's expected
            if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
              this.emit('error', err);
            }
            this.connected = false;
          });

          // Handle socket-level errors
          res.socket?.on('error', (err) => {
            // Ignore ECONNRESET during shutdown
            if ((err as NodeJS.ErrnoException).code !== 'ECONNRESET') {
              this.emit('error', err);
            }
          });

          // Connection established - wait for endpoint event
          const endpointTimeout = setTimeout(() => {
            if (!this.messagesEndpoint) {
              reject(new Error('Timeout waiting for endpoint event'));
            }
          }, 5000);

          this.once('endpoint', () => {
            clearTimeout(endpointTimeout);
            this.connected = true;
            resolve();
          });
        }
      );

      req.on('error', (err) => {
        // Ignore ECONNRESET during shutdown
        if ((err as NodeJS.ErrnoException).code === 'ECONNRESET') {
          return;
        }
        reject(err);
      });

      // Handle socket errors
      req.socket?.on('error', () => {
        // Ignore socket errors - handled above
      });

      req.end();
    });
  }

  /**
   * Disconnect from the MCP server
   */
  disconnect(): void {
    // Mark as disconnected first to prevent new requests
    this.connected = false;
    this.messagesEndpoint = null;

    // Clean up pending requests before destroying connection
    for (const [id, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Connection closed'));
    }
    this.pendingRequests.clear();

    if (this.sseRequest) {
      // Remove error listeners before destroying to avoid uncaught exceptions
      this.sseRequest.removeAllListeners('error');
      try {
        this.sseRequest.destroy();
      } catch {
        // Ignore errors during cleanup
      }
      this.sseRequest = null;
    }
  }

  /**
   * Handle incoming SSE events
   */
  private handleSseEvent(eventType: string, data: string): void {
    if (eventType === 'endpoint') {
      // The server sends the messages endpoint URL
      this.messagesEndpoint = data;
      this.emit('endpoint', data);
      return;
    }

    if (eventType === 'message') {
      try {
        const message = JSON.parse(data) as JsonRpcResponse;

        // Check if this is a response to a pending request
        if ('id' in message && message.id != null) {
          const pending = this.pendingRequests.get(message.id);
          if (pending) {
            clearTimeout(pending.timeout);
            this.pendingRequests.delete(message.id);

            if ('error' in message && message.error) {
              pending.reject(new Error(`RPC Error: ${message.error.message}`));
            } else {
              pending.resolve(message.result);
            }
          }
        }

        this.emit('message', message);
      } catch (err) {
        this.emit('error', new Error(`Failed to parse SSE message: ${data}`));
      }
    }
  }

  /**
   * Check if daemon is healthy
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.httpGet('/health');
      return response.status === 'ok';
    } catch {
      return false;
    }
  }

  /**
   * Wait for daemon to be ready
   */
  async waitForReady(maxWait = 10000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < maxWait) {
      if (await this.healthCheck()) {
        // Ensure JSON output format for test assertions
        await this.callTool('set_output_format', { format: 'json' });
        return;
      }
      await sleep(200);
    }
    throw new Error('Daemon did not become ready');
  }

  /**
   * List available tools
   */
  async listTools(): Promise<Array<{ name: string; description: string }>> {
    const response = await this.rpcCall('tools/list', {});
    return (response as { tools: Array<{ name: string; description: string }> }).tools;
  }

  /**
   * Call a tool
   */
  async callTool(name: string, args: Record<string, unknown> = {}): Promise<ToolCallResult> {
    // If we have a default session, inject it
    if (this.sessionId && !args.sessionId) {
      args = { ...args, sessionId: this.sessionId };
    }

    const response = await this.rpcCall('tools/call', {
      name,
      arguments: args,
    });

    return response as ToolCallResult;
  }

  /**
   * Helper: Call tool and parse JSON result
   */
  async callToolJson<T = unknown>(name: string, args: Record<string, unknown> = {}): Promise<T> {
    const result = await this.callTool(name, args);
    const text = result.content[0]?.text;
    if (!text) {
      throw new Error('Empty tool result');
    }
    if (text.startsWith('Error:')) {
      throw new Error(text);
    }
    return JSON.parse(text) as T;
  }

  /**
   * Set default session for subsequent calls
   */
  setSession(sessionId: string | null): void {
    this.sessionId = sessionId;
  }

  /**
   * Get current session ID
   */
  getSession(): string | null {
    return this.sessionId;
  }

  // =========================================================================
  // Higher-level helpers for common operations
  // =========================================================================

  /**
   * Create a session and set it as default
   * Optionally waits for the session to become ready
   */
  async createSession(
    binaryPath: string,
    options?: { autoAnalyze?: boolean; waitForReady?: boolean; waitTimeout?: number }
  ): Promise<{
    id: string;
    binaryPath: string;
    status: string;
  }> {
    const result = await this.callToolJson<{
      id: string;
      binaryPath: string;
      status: string;
    }>('create_session', {
      binaryPath,
      autoAnalyze: options?.autoAnalyze ?? true,
    });

    this.sessionId = result.id;

    // Wait for session to be ready if requested (default: true)
    const shouldWait = options?.waitForReady ?? true;
    if (shouldWait && result.status !== 'ready') {
      const timeout = options?.waitTimeout ?? 90000; // 90 seconds default
      await this.waitForSessionReady(result.id, timeout);
    }

    return result;
  }

  /**
   * Wait for a session to become ready
   */
  async waitForSessionReady(sessionId: string, timeout = 90000): Promise<void> {
    const start = Date.now();

    while (Date.now() - start < timeout) {
      const sessions = await this.listSessions();
      const session = sessions.find((s) => s.id === sessionId);

      if (!session) {
        throw new Error(`Session ${sessionId} not found`);
      }

      if (session.status === 'ready') {
        return;
      }

      if (session.status === 'error') {
        throw new Error(`Session ${sessionId} failed`);
      }

      // Poll every 500ms
      await sleep(500);
    }

    throw new Error(`Session ${sessionId} did not become ready within ${timeout}ms`);
  }

  /**
   * List all sessions
   */
  async listSessions(): Promise<Array<{ id: string; binaryPath: string; status: string }>> {
    return this.callToolJson('list_sessions');
  }

  /**
   * Close current session
   */
  async closeSession(): Promise<void> {
    if (this.sessionId) {
      await this.callTool('close_session', { sessionId: this.sessionId });
      this.sessionId = null;
    }
  }

  /**
   * Get program info
   */
  async getProgramInfo(): Promise<{
    name: string;
    format: string;
    architecture: string;
    imageBase: string;
  }> {
    return this.callToolJson('get_program_info');
  }

  /**
   * List functions
   */
  async listFunctions(options?: {
    offset?: number;
    limit?: number;
    filter?: string;
  }): Promise<{ functions: Array<{ name: string; address: string }>; total: number }> {
    return this.callToolJson('list_functions', options ?? {});
  }

  /**
   * Decompile a function
   */
  async decompile(options: { address?: string; name?: string }): Promise<{
    functionName: string;
    address: string;
    signature: string;
    pseudocode: string;
  }> {
    return this.callToolJson('decompile', options);
  }

  /**
   * List strings
   */
  async listStrings(options?: {
    offset?: number;
    limit?: number;
    minLength?: number;
    filter?: string;
  }): Promise<{ strings: Array<{ address: string; value: string }>; total: number }> {
    return this.callToolJson('list_strings', options ?? {});
  }

  /**
   * Get cross-references
   */
  async getXrefs(address: string, direction: 'to' | 'from' | 'both' = 'both'): Promise<{
    xrefs: Array<{
      fromAddress: string;
      toAddress: string;
      type: string;
      fromFunction?: string;
      toFunction?: string;
    }>;
  }> {
    return this.callToolJson('get_xrefs', { address, direction });
  }

  /**
   * List imports
   */
  async listImports(options?: {
    offset?: number;
    limit?: number;
    filter?: string;
  }): Promise<{ imports: Array<{ name: string; address: string; library?: string }>; total: number }> {
    return this.callToolJson('list_imports', options ?? {});
  }

  /**
   * Search
   */
  async search(pattern: string, type: string | string[]): Promise<{
    results: Array<{ type: string; name: string; address: string }>;
    total: number;
  }> {
    return this.callToolJson('search', { pattern, type });
  }

  // =========================================================================
  // Low-level methods
  // =========================================================================

  private async rpcCall(method: string, params: unknown): Promise<unknown> {
    // Ensure we're connected
    if (!this.connected) {
      await this.connect();
    }

    if (!this.messagesEndpoint) {
      throw new Error('Not connected - no messages endpoint');
    }

    const id = ++this.requestId;
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      id,
      method,
      params,
    };

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Request timeout for ${method}`));
      }, this.timeout);

      this.pendingRequests.set(id, { resolve, reject, timeout });

      // Send request via POST to messages endpoint
      this.httpPost(this.messagesEndpoint!, request).catch((err) => {
        clearTimeout(timeout);
        this.pendingRequests.delete(id);
        reject(err);
      });
    });
  }

  private httpGet(path: string): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: this.host,
          port: this.port,
          path,
          method: 'GET',
          timeout: this.timeout,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch {
              reject(new Error(`Invalid JSON: ${data}`));
            }
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.end();
    });
  }

  private httpPost(path: string, body: unknown): Promise<void> {
    return new Promise((resolve, reject) => {
      const bodyStr = JSON.stringify(body);

      const req = http.request(
        {
          hostname: this.host,
          port: this.port,
          path,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(bodyStr),
          },
          timeout: this.timeout,
        },
        (res) => {
          // For SSE transport, the response comes via SSE, not the POST response
          // The POST just acknowledges receipt
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            if (res.statusCode === 200 || res.statusCode === 202) {
              resolve();
            } else {
              reject(new Error(`POST failed: ${res.statusCode} - ${data}`));
            }
          });
        }
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.write(bodyStr);
      req.end();
    });
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
