/**
 * Tool handler that dispatches MCP tool calls to Ghidra workers
 */

import type { Session, LogQueryOptions, LogQueryResult } from '@ghidra-mcp/shared';
import type { WorkerCommand, WorkerResponse, ImportSpecParams } from '@ghidra-mcp/shared/protocol';
import { formatResponse } from './toon.js';

/**
 * Context interface that connects MCP tools to the daemon's session/worker management
 */
export interface ToolHandlerContext {
  // Session management
  listSessions(): Promise<Session[]>;
  getSession(sessionId: string): Promise<Session | null>;
  createSession(binaryPath: string, options?: SessionCreateOptions): Promise<Session>;
  closeSession(sessionId: string, force?: boolean): Promise<CloseSessionResult | void>;

  /** A worker connected to the Ghidra Server with nothing open, for repo-scoped tools. */
  getRepoSession?(): Promise<string>;

  /** The repository the daemon is configured for, so clients need not name it. */
  getDefaultRepo?(): string | undefined;

  // Send command to a session's worker
  sendCommand(
    sessionId: string,
    command: WorkerCommand
  ): Promise<WorkerResponse>;

  // Default session (if set)
  getDefaultSessionId(): string | null;
  setDefaultSessionId(sessionId: string | null): void;

  // Session alias management
  resolveSessionId?(idOrAlias: string): string;
  setAlias?(alias: string, sessionId: string): void;
  removeAlias?(alias: string): void;
  listAliases?(): Array<{ alias: string; sessionId: string }>;

  // Shared structure management
  saveSharedStructure?(name: string, data: {
    category?: string;
    fields: Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
    packed?: boolean;
    typeParams?: string[];
  }): void;
  getSharedStructure?(name: string): {
    name: string;
    category: string | null;
    fields: Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
    packed: boolean;
    typeParams?: string[];
    updatedAt: Date;
    targets: Array<{ alias: string; bindings?: Record<string, string> }>;
  } | null;
  listSharedStructures?(): Array<{
    name: string;
    category: string | null;
    fieldCount: number;
    packed: boolean;
    typeParams?: string[];
    updatedAt: Date;
    targets: Array<{ alias: string; bindings?: Record<string, string> }>;
  }>;
  deleteSharedStructure?(name: string): void;
  setStructureTargets?(structName: string, targets: Array<{ alias: string; bindings?: Record<string, string> }>): void;
  syncSharedStructure?(name: string): Promise<{
    results: Array<{ alias: string; sessionId: string; success: boolean; error?: string }>;
  }>;
  syncAllSharedStructures?(): Promise<{
    results: Array<{ name: string; syncResults: Array<{ alias: string; sessionId: string; success: boolean; error?: string }> }>;
  }>;

  // Log querying (optional - not all contexts may support it)
  queryLogs?(options: LogQueryOptions): LogQueryResult;

  // Cross-binary link management
  createLink?(sourceSession: string, sourceAddress: string, targetSession: string, targetAddress: string, linkType?: string, anchor?: boolean, metadata?: Record<string, unknown>): string;
  removeLink?(id: string): void;
  queryLinks?(opts?: { sessionId?: string; address?: string; type?: string; anchor?: boolean }): Array<{
    id: string; sourceSession: string; sourceAddress: string;
    targetSession: string; targetAddress: string; linkType: string;
    anchor: boolean; metadata: Record<string, unknown> | null; createdAt: Date;
  }>;
  getLinksForEntity?(sessionId: string, address: string): Array<{
    id: string; sourceSession: string; sourceAddress: string;
    targetSession: string; targetAddress: string; linkType: string;
    anchor: boolean; metadata: Record<string, unknown> | null;
  }>;
  bulkCreateLinks?(links: Array<{
    sourceSession: string; sourceAddress: string;
    targetSession: string; targetAddress: string;
    linkType?: string; anchor?: boolean; metadata?: Record<string, unknown>;
  }>): number;
  clearLinks?(opts?: { sourceSession?: string; targetSession?: string }): number;

  // Sync log
  logSync?(linkId: string, changeType: string, newValue: string, status?: 'applied' | 'failed', oldValue?: string, error?: string): string;
  getRecentSyncs?(limit?: number): Array<{
    id: string; linkId: string; changeType: string; oldValue: string | null;
    newValue: string; status: string; error: string | null; createdAt: Date;
  }>;
  isRecentSync?(sessionId: string, address: string, changeType: string): boolean;

  // Dependency validation
  storeDependencyRun?(violations: Array<{ file: string; includePath: string; owningModule: string; referencedModule: string }>): string;
  getLatestDependencyRun?(): { runId: string; violations: Array<{ file: string; includePath: string; owningModule: string; referencedModule: string }>; createdAt: Date } | null;
}

export interface CloseSessionResult {
  closed: boolean;
  sessionId: string;
  clientCount: number;
  message?: string;
}

export interface SessionCreateOptions {
  autoAnalyze?: boolean;
  analysisTimeout?: number;
  readOnly?: boolean;
  programPath?: string;
}


/**
 * Handles MCP tool calls by dispatching to appropriate Ghidra workers
 */
export class GhidraToolHandler {
  private outputFormat: 'toon' | 'json';

  constructor(private context: ToolHandlerContext, defaultFormat: 'toon' | 'json' = 'toon') {
    this.outputFormat = defaultFormat;
  }

  /**
   * Handle a tool call from an MCP client
   */
  async handleToolCall(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text: string }> }> {
    try {
      // Handle format setting tool — per-connection state
      if (toolName === 'set_output_format') {
        const format = args.format as 'toon' | 'json';
        this.outputFormat = format;
        return {
          content: [{ type: 'text', text: `Output format set to: ${format}` }],
        };
      }

      let result = await this.executeToolCall(toolName, args);

      // Strip rawPseudocode in-place — nearly identical to pseudocode, wastes context tokens
      if (toolName === 'decompile' && result && typeof result === 'object' && 'rawPseudocode' in result) {
        delete (result as Record<string, unknown>).rawPseudocode;
      }
      if (toolName === 'batch_decompile' && result && typeof result === 'object' && 'results' in result) {
        const arr = (result as { results: unknown[] }).results;
        if (Array.isArray(arr)) {
          for (const r of arr) {
            if (r && typeof r === 'object' && 'rawPseudocode' in r) {
              delete (r as Record<string, unknown>).rawPseudocode;
            }
          }
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: typeof result === 'string' ? result : formatResponse(result, this.outputFormat),
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${errorMessage}`,
          },
        ],
      };
    }
  }

  /**
   * Execute the actual tool call
   */
  private async executeToolCall(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    // Extract sessionId from args, or use default, then resolve alias
    let sessionId = (args.sessionId as string) || this.context.getDefaultSessionId();
    if (sessionId && this.context.resolveSessionId) {
      sessionId = this.context.resolveSessionId(sessionId);
    }

    // Session management tools (don't require a session)
    switch (toolName) {
      case 'list_sessions':
        return this.context.listSessions();

      case 'create_session': {
        // `program` is the repo path form; `binaryPath` is kept for ghidra:// URLs and
        // local .gpr projects. Either names the same thing to the resolver.
        const binaryPath = (args.program as string) || (args.binaryPath as string);
        if (!binaryPath) {
          throw new Error('program is required (a repository path, or a ghidra:// URL)');
        }
        const session = await this.context.createSession(binaryPath, {
          autoAnalyze: args.autoAnalyze as boolean | undefined,
          analysisTimeout: args.analysisTimeout as number | undefined,
          readOnly: args.readOnly as boolean | undefined,
          programPath: args.programPath as string | undefined,
        });
        // Auto-set as default if it's the first session
        if (!this.context.getDefaultSessionId()) {
          this.context.setDefaultSessionId(session.id);
        }
        return session;
      }

      case 'close_session': {
        const rawCloseId = (args.sessionId as string) || sessionId;
        if (!rawCloseId) {
          throw new Error('sessionId is required');
        }
        const closeSessionId = this.context.resolveSessionId
          ? this.context.resolveSessionId(rawCloseId)
          : rawCloseId;
        const result = await this.context.closeSession(closeSessionId, args.force as boolean | undefined);
        // Only forget the default when the session actually went away.
        const closed = !result || result.closed;
        if (closed && this.context.getDefaultSessionId() === closeSessionId) {
          this.context.setDefaultSessionId(null);
        }
        return result ?? { closed: true, sessionId: closeSessionId, clientCount: 0 };
      }

      case 'set_default_session': {
        const newDefaultId = args.sessionId as string;
        if (!newDefaultId) {
          throw new Error('sessionId is required');
        }
        // Resolve alias before setting default
        const resolvedDefault = this.context.resolveSessionId
          ? this.context.resolveSessionId(newDefaultId)
          : newDefaultId;
        this.context.setDefaultSessionId(resolvedDefault);
        return { success: true, sessionId: resolvedDefault };
      }

      // Session alias tools
      case 'set_session_alias': {
        if (!this.context.setAlias) throw new Error('Alias management not available');
        const alias = args.alias as string;
        const targetSessionId = args.sessionId as string;
        if (!alias || !targetSessionId) throw new Error('alias and sessionId are required');
        this.context.setAlias(alias, targetSessionId);
        return { success: true, alias, sessionId: targetSessionId };
      }

      case 'remove_session_alias': {
        if (!this.context.removeAlias) throw new Error('Alias management not available');
        const aliasToRemove = args.alias as string;
        if (!aliasToRemove) throw new Error('alias is required');
        this.context.removeAlias(aliasToRemove);
        return { success: true };
      }

      case 'list_session_aliases': {
        if (!this.context.listAliases) throw new Error('Alias management not available');
        return this.context.listAliases();
      }

      // Shared structure tools
      case 'create_shared_structure': {
        if (!this.context.saveSharedStructure) throw new Error('Shared structures not available');
        const name = args.name as string;
        const fields = args.fields as Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
        if (!name || !fields) throw new Error('name and fields are required');

        this.context.saveSharedStructure(name, {
          category: args.category as string | undefined,
          fields,
          packed: args.packed as boolean | undefined,
          typeParams: args.typeParams as string[] | undefined,
        });

        const targets = args.targets as Array<{ alias: string; bindings?: Record<string, string> }> | undefined;
        if (targets && this.context.setStructureTargets) {
          this.context.setStructureTargets(name, targets);
        }

        // Auto-sync to targets
        let syncResults;
        if (targets && targets.length > 0 && this.context.syncSharedStructure) {
          syncResults = await this.context.syncSharedStructure(name);
        }

        return { success: true, name, syncResults };
      }

      case 'update_shared_structure': {
        if (!this.context.saveSharedStructure) throw new Error('Shared structures not available');
        const name = args.name as string;
        const fields = args.fields as Array<{ name: string; dataType: string; offset: number; length: number; comment?: string }>;
        if (!name || !fields) throw new Error('name and fields are required');

        this.context.saveSharedStructure(name, {
          category: args.category as string | undefined,
          fields,
          packed: args.packed as boolean | undefined,
          typeParams: args.typeParams as string[] | undefined,
        });

        if (args.targets && this.context.setStructureTargets) {
          this.context.setStructureTargets(
            name,
            args.targets as Array<{ alias: string; bindings?: Record<string, string> }>
          );
        }

        // Auto-sync to targets
        let syncResults;
        if (this.context.syncSharedStructure) {
          syncResults = await this.context.syncSharedStructure(name);
        }

        return { success: true, name, syncResults };
      }

      case 'list_shared_structures': {
        if (!this.context.listSharedStructures) throw new Error('Shared structures not available');
        return this.context.listSharedStructures();
      }

      case 'delete_shared_structure': {
        if (!this.context.deleteSharedStructure) throw new Error('Shared structures not available');
        const name = args.name as string;
        if (!name) throw new Error('name is required');
        this.context.deleteSharedStructure(name);
        return { success: true };
      }

      case 'sync_shared_structures': {
        const name = args.name as string | undefined;
        if (name) {
          if (!this.context.syncSharedStructure) throw new Error('Shared structures not available');
          return this.context.syncSharedStructure(name);
        } else {
          if (!this.context.syncAllSharedStructures) throw new Error('Shared structures not available');
          return this.context.syncAllSharedStructures();
        }
      }

      case 'get_logs': {
        if (!this.context.queryLogs) {
          throw new Error('Log querying is not available in this context');
        }
        return this.context.queryLogs({
          sessionId: args.sessionId as string | undefined,
          workerId: args.workerId as string | undefined,
          level: args.level as 'ERROR' | 'WARN' | 'INFO' | 'DEBUG' | undefined,
          component: args.component as string | undefined,
          since: args.since as number | undefined,
          limit: args.limit as number | undefined,
        });
      }

      // Cross-binary link tools
      case 'create_link': {
        if (!this.context.createLink) throw new Error('Link management not available');
        const id = this.context.createLink(
          args.sourceSession as string,
          args.sourceAddress as string,
          args.targetSession as string,
          args.targetAddress as string,
          args.linkType as string | undefined,
          args.anchor as boolean | undefined,
          args.metadata as Record<string, unknown> | undefined,
        );
        return { success: true, id };
      }

      case 'remove_link': {
        if (!this.context.removeLink) throw new Error('Link management not available');
        this.context.removeLink(args.id as string);
        return { success: true };
      }

      case 'query_links': {
        if (!this.context.queryLinks) throw new Error('Link management not available');
        return this.context.queryLinks({
          sessionId: args.sessionId as string | undefined,
          address: args.address as string | undefined,
          type: args.type as string | undefined,
          anchor: args.anchor as boolean | undefined,
        });
      }

      case 'bulk_create_links': {
        if (!this.context.bulkCreateLinks) throw new Error('Link management not available');
        const linksArg = args.links as Array<{
          sourceSession: string; sourceAddress: string;
          targetSession: string; targetAddress: string;
          linkType?: string; anchor?: boolean; metadata?: Record<string, unknown>;
        }>;
        const count = this.context.bulkCreateLinks(linksArg);
        return { success: true, count };
      }

      case 'clear_links': {
        if (!this.context.clearLinks) throw new Error('Link management not available');
        const deleted = this.context.clearLinks({
          sourceSession: args.sourceSession as string | undefined,
          targetSession: args.targetSession as string | undefined,
        });
        return { success: true, deleted };
      }

      case 'sync_status': {
        if (!this.context.getRecentSyncs) throw new Error('Sync log not available');
        return this.context.getRecentSyncs(args.limit as number | undefined);
      }

      case 'validate_dependencies': {
        if (!this.context.storeDependencyRun) throw new Error('Dependency validation not available');
        const { validateDependencies } = await import('./dependency-validator.js');
        const result = await validateDependencies(args.projectJsonPath as string | undefined);
        const runId = this.context.storeDependencyRun(result.violations);
        return { ...result, runId };
      }
    }

    // Multi-session tools (need their own session resolution)
    if (toolName === 'discover_table_anchors') {
      if (!this.context.bulkCreateLinks) throw new Error('Link management not available');
      const { discoverTableAnchors } = await import('./table-discovery.js');
      let winSession = args.winSession as string;
      let macSession = args.macSession as string;
      if (this.context.resolveSessionId) {
        winSession = this.context.resolveSessionId(winSession);
        macSession = this.context.resolveSessionId(macSession);
      }
      return discoverTableAnchors({
        winSession,
        macSession,
        dryRun: args.dryRun as boolean | undefined,
        tables: args.tables as string[] | undefined,
        sendCommand: (sid, cmd) => this.context.sendCommand(sid, cmd),
        bulkCreateLinks: (links) => this.context.bulkCreateLinks!(links),
      });
    }

    // Repository-scoped tools act on the server, not on a program, so they must work
    // before any session exists — that is the whole point of being able to discover what
    // is on the server. Fall back to the daemon's repo worker.
    const REPO_TOOLS = new Set([
      'list_repos', 'import_program', 'import_status', 'delete_program', 'move_program',
    ]);
    const repoScoped = REPO_TOOLS.has(toolName) || toolName === 'list_programs';
    if (repoScoped && !args.repo && this.context.getDefaultRepo?.()) {
      args = { ...args, repo: this.context.getDefaultRepo() };
    }
    const needsRepoWorker = REPO_TOOLS.has(toolName)
      || (toolName === 'list_programs' && typeof args.repo === 'string');
    if (!sessionId && needsRepoWorker) {
      if (!this.context.getRepoSession) {
        throw new Error('Repository access is not available in this context');
      }
      sessionId = await this.context.getRepoSession();
    }

    // All other tools require a session
    if (!sessionId) {
      throw new Error(
        'No session specified and no default session set. ' +
        'Use create_session first or specify sessionId.'
      );
    }

    // Dispatch to worker
    const result = await this.dispatchToWorker(toolName, sessionId, args);

    // Auto-sync mutations to linked sessions
    if (!args.skipSync && this.context.getLinksForEntity) {
      const syncableTools: Record<string, { changeType: string; getAddress: (a: Record<string, unknown>) => string; getNewValue: (a: Record<string, unknown>) => string }> = {
        rename_symbol: {
          changeType: 'rename',
          getAddress: (a) => a.address as string,
          getNewValue: (a) => a.newName as string,
        },
        set_prototype: {
          changeType: 'prototype',
          getAddress: (a) => a.functionAddress as string,
          getNewValue: (a) => a.prototype as string,
        },
        set_data_type: {
          changeType: 'data_type',
          getAddress: (a) => a.address as string,
          getNewValue: (a) => a.dataType as string,
        },
      };

      const syncDef = syncableTools[toolName];
      if (syncDef) {
        const address = syncDef.getAddress(args);
        const newValue = syncDef.getNewValue(args);
        // Fire-and-forget: don't block the response on sync
        this.syncToLinked(sessionId, address, toolName, syncDef.changeType, newValue, args).catch(() => {});
      }
    }

    return result;
  }

  /**
   * Sync a mutation to linked sessions
   */
  private async syncToLinked(
    sessionId: string,
    address: string,
    toolName: string,
    changeType: string,
    newValue: string,
    originalArgs: Record<string, unknown>
  ): Promise<void> {
    if (!this.context.getLinksForEntity || !this.context.logSync) return;

    // Guard against infinite loops
    if (this.context.isRecentSync?.(sessionId, address, changeType)) return;

    const links = this.context.getLinksForEntity(sessionId, address);
    if (links.length === 0) return;

    for (const link of links) {
      // Determine target session + address
      const isSource = link.sourceSession === sessionId && link.sourceAddress === address;
      const targetSession = isSource ? link.targetSession : link.sourceSession;
      const targetAddress = isSource ? link.targetAddress : link.sourceAddress;

      try {
        // Build the sync command with skipSync=true
        const syncArgs: Record<string, unknown> = { ...originalArgs, sessionId: targetSession, skipSync: true };

        // Adjust address fields for the target
        if (toolName === 'rename_symbol') {
          syncArgs.address = targetAddress;
        } else if (toolName === 'set_prototype') {
          syncArgs.functionAddress = targetAddress;
        } else if (toolName === 'set_data_type') {
          syncArgs.address = targetAddress;
        }

        const cmd = this.buildCommand(toolName, syncArgs);
        const response = await this.context.sendCommand(targetSession, cmd);

        if (response.success) {
          this.context.logSync(link.id, changeType, newValue, 'applied');
        } else {
          this.context.logSync(link.id, changeType, newValue, 'failed', undefined, response.error?.message);
        }
      } catch (err) {
        this.context.logSync(link.id, changeType, newValue, 'failed', undefined, (err as Error).message);
      }
    }
  }

  /**
   * Dispatch a tool call to the appropriate worker
   */
  private async dispatchToWorker(
    toolName: string,
    sessionId: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    const command = this.buildCommand(toolName, args);
    const response = await this.context.sendCommand(sessionId, command);

    if (!response.success) {
      throw new Error(response.error?.message || 'Command failed');
    }

    // For execute_script: try to parse JSON output so it gets formatted (TOON/JSON)
    if (toolName === 'execute_script' && response.result) {
      const result = response.result as Record<string, unknown>;
      if (typeof result.output === 'string') {
        try {
          result.output = JSON.parse(result.output.trim());
        } catch {
          // Not JSON — leave as raw text
        }
      }
    }

    return response.result;
  }

  /**
   * Build a worker command from tool name and arguments
   */
  private buildCommand(toolName: string, args: Record<string, unknown>): WorkerCommand {
    const id = crypto.randomUUID();
    const timeout = (args.timeout as number) || undefined;

    // Remove sessionId from args as it's not needed by the worker
    const { sessionId: _sessionId, ...params } = args;

    switch (toolName) {
      // Multi-program management
      case 'list_programs':
        return {
          id,
          command: 'list_programs',
          params: {
            repo: params.repo as string | undefined,
            folder: params.folder as string | undefined,
            recursive: params.recursive as boolean | undefined,
            filter: params.filter as string | undefined,
          },
          timeout,
        };

      case 'import_program':
        return {
          id,
          command: 'import_program',
          params: {
            repo: params.repo as string | undefined,
            items: params.items as ImportSpecParams[] | undefined,
            url: params.url as string | undefined,
            localPath: params.localPath as string | undefined,
            bytesBase64: params.bytesBase64 as string | undefined,
            programPath: params.programPath as string | undefined,
            processor: params.processor as string | undefined,
            compilerSpec: params.compilerSpec as string | undefined,
            analyze: params.analyze as boolean | undefined,
            overwrite: params.overwrite as boolean | undefined,
            wait: params.wait as boolean | undefined,
            waitTimeout: params.waitTimeout as number | undefined,
          },
          timeout,
        };

      case 'import_status':
        return {
          id,
          command: 'import_status',
          params: { jobId: params.jobId as string | undefined },
          timeout,
        };

      case 'delete_program':
        return {
          id,
          command: 'delete_program',
          params: {
            repo: params.repo as string | undefined,
            programPath: params.programPath as string,
          },
          timeout,
        };

      case 'move_program':
        return {
          id,
          command: 'move_program',
          params: {
            repo: params.repo as string | undefined,
            from: params.from as string,
            to: params.to as string,
          },
          timeout,
        };

      case 'load_program':
        return {
          id,
          command: 'load_program',
          params: {
            programPath: params.programPath as string,
          },
          timeout,
        };

      // Version Tracking
      case 'vt_create_session':
        return {
          id,
          command: 'vt_create_session',
          params: {
            sourceProgramPath: params.sourceProgramPath as string,
            destProgramPath: params.destProgramPath as string,
          },
          timeout: 60000,
        };

      case 'vt_run_correlator':
        return {
          id,
          command: 'vt_run_correlator',
          params: {
            correlatorName: params.correlatorName as string,
          },
          timeout: 600000, // correlators can be slow
        };

      case 'vt_list_matches':
        return {
          id,
          command: 'vt_list_matches',
          params: {
            minScore: params.minScore as number | undefined,
            limit: params.limit as number | undefined,
          },
          timeout,
        };

      case 'vt_accept_matches':
        return {
          id,
          command: 'vt_accept_matches',
          params: {
            acceptAll: params.acceptAll as boolean | undefined,
            minScore: params.minScore as number | undefined,
          },
          timeout,
        };

      case 'vt_apply_markup':
        return {
          id,
          command: 'vt_apply_markup',
          params: {},
          timeout: 600000,
        };

      case 'vt_get_correlators':
        return {
          id,
          command: 'vt_get_correlators',
          params: {},
          timeout,
        };

      // Program info
      case 'get_program_info':
        return { id, command: 'get_program_info', params: {}, timeout };

      // Functions
      case 'list_functions':
        return {
          id,
          command: 'list_functions',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            namespace: params.namespace as string | undefined,
            includeChildren: params.includeChildren as boolean | undefined,
          },
          timeout,
        };

      case 'get_function_info':
        return {
          id,
          command: 'get_function_info',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
          },
          timeout,
        };

      case 'get_function_summary':
        return {
          id,
          command: 'get_function_summary',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            includeStrings: params.includeStrings as boolean | undefined,
            includeXrefs: params.includeXrefs as boolean | undefined,
            maxCalls: params.maxCalls as number | undefined,
            maxCallers: params.maxCallers as number | undefined,
          },
          timeout,
        };

      // Decompilation
      case 'decompile':
        return {
          id,
          command: 'decompile',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            timeout: params.decompileTimeout as number | undefined,
          },
          timeout,
        };

      // Batch decompilation
      case 'batch_decompile':
        return {
          id,
          command: 'batch_decompile',
          params: {
            addresses: params.addresses as string[] | undefined,
            names: params.names as string[] | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            namespace: params.namespace as string | undefined,
            startAddress: params.startAddress as string | undefined,
            endAddress: params.endAddress as string | undefined,
            limit: params.limit as number | undefined,
            decompileTimeout: params.decompileTimeout as number | undefined,
          },
          timeout: Math.max(600000, ((params.addresses as string[])?.length ?? 50) * 60 * 1000),
        };

      // Disassembly
      case 'get_disassembly':
        return {
          id,
          command: 'get_disassembly',
          params: {
            address: params.address as string,
            count: params.count as number | undefined,
            context: params.context as number | undefined,
          },
          timeout,
        };

      case 'get_basic_blocks':
        return {
          id,
          command: 'get_basic_blocks',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
          },
          timeout,
        };

      // Cross-references
      case 'get_xrefs':
        return {
          id,
          command: 'get_xrefs',
          params: {
            address: params.address as string,
            direction: (params.direction as 'to' | 'from' | 'both') || 'both',
            limit: params.limit as number | undefined,
            refType: params.refType as string | string[] | undefined,
          },
          timeout,
        };

      case 'get_xrefs_with_context':
        return {
          id,
          command: 'get_xrefs_with_context',
          params: {
            address: params.address as string,
            direction: (params.direction as 'to' | 'from' | 'both') || 'both',
            contextLines: params.contextLines as number | undefined,
            contextPattern: params.contextPattern as string | undefined,
            limit: params.limit as number | undefined,
            refType: params.refType as string | string[] | undefined,
          },
          timeout,
        };

      // Data symbols (global and namespaced)
      case 'list_data_symbols':
        return {
          id,
          command: 'get_global_variables',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            segment: params.segment as string | undefined,
            sortBy: params.sortBy as string | undefined,
            dataType: params.dataType as string | undefined,
          },
          timeout,
        };

      case 'read_data_value':
        return {
          id,
          command: 'read_data_value',
          params: {
            address: params.address as string,
          },
          timeout,
        };

      // Symbols
      case 'list_symbols':
        return {
          id,
          command: 'list_symbols',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            type: params.type as string | undefined,
          },
          timeout,
        };

      case 'list_imports':
        return {
          id,
          command: 'list_imports',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
          },
          timeout,
        };

      case 'list_exports':
        return {
          id,
          command: 'list_exports',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
          },
          timeout,
        };

      // Data types
      case 'list_data_types':
        return {
          id,
          command: 'list_data_types',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            category: params.category as string | undefined,
          },
          timeout,
        };

      case 'get_data_type':
        return {
          id,
          command: 'get_data_type',
          params: {
            name: params.name as string,
            category: params.category as string | undefined,
          },
          timeout,
        };

      // Memory
      case 'list_segments':
        return {
          id,
          command: 'list_segments',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
          },
          timeout,
        };

      case 'read_memory':
        return {
          id,
          command: 'read_memory',
          params: {
            address: params.address as string,
            length: params.length as number,
          },
          timeout,
        };

      case 'get_hexdump':
        return {
          id,
          command: 'get_hexdump',
          params: {
            address: params.address as string,
            length: params.length as number,
            bytesPerLine: params.bytesPerLine as number | undefined,
          },
          timeout,
        };

      // Strings
      case 'list_strings':
        return {
          id,
          command: 'list_strings',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            minLength: params.minLength as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
          },
          timeout,
        };

      // Search
      case 'search':
        return {
          id,
          command: 'search',
          params: {
            pattern: params.pattern as string | undefined, // backward compat
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            hexPattern: params.hexPattern as string | undefined,
            type: params.type as string | string[],
            caseSensitive: params.caseSensitive as boolean | undefined,
            limit: params.limit as number | undefined,
            offset: params.offset as number | undefined,
            countOnly: params.countOnly as boolean | undefined,
            scope: params.scope as { type: string; value?: string; startAddress?: string; endAddress?: string } | undefined,
            functionFilter: params.functionFilter as string | undefined,
            searchMode: params.searchMode as string | undefined,
            flowType: params.flowType as string | undefined,
          },
          timeout,
        };

      // Call graph
      case 'get_call_graph':
        return {
          id,
          command: 'get_call_graph',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            depth: params.depth as number | undefined,
            direction: params.direction as 'callers' | 'callees' | 'both' | undefined,
            maxNodes: params.maxNodes as number | undefined,
          },
          timeout,
        };

      case 'find_call_path':
        return {
          id,
          command: 'find_call_path',
          params: {
            from: params.from as string,
            to: params.to as string,
            maxDepth: params.maxDepth as number | undefined,
          },
          timeout,
        };

      // Namespaces/classes
      case 'list_namespaces':
        return {
          id,
          command: 'list_namespaces',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
          },
          timeout,
        };

      case 'get_class_info':
        return {
          id,
          command: 'get_class_info',
          params: {
            name: params.name as string,
          },
          timeout,
        };

      // Comments/bookmarks
      case 'list_comments':
        return {
          id,
          command: 'list_comments',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            type: params.type as string | undefined,
            inFunction: params.inFunction as string | undefined,
          },
          timeout,
        };

      case 'list_bookmarks':
        return {
          id,
          command: 'list_bookmarks',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            type: params.type as string | undefined,
            category: params.category as string | undefined,
          },
          timeout,
        };

      // PCode
      case 'get_pcode':
        return {
          id,
          command: 'get_pcode',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            highLevel: params.highLevel as boolean | undefined,
          },
          timeout,
        };

      case 'batch_pcode':
        return {
          id,
          command: 'batch_pcode',
          params: {
            addresses: params.addresses as string[],
            highLevel: params.highLevel as boolean | undefined,
          },
          timeout: Math.max(600000, ((params.addresses as string[])?.length ?? 50) * 30 * 1000),
        };

      // Modification tools
      case 'rename_symbol':
        return {
          id,
          command: 'rename_symbol',
          params: {
            address: params.address as string,
            newName: params.newName as string,
            type: params.type as 'function' | 'variable' | 'label' | 'data',
            scope: params.scope as string | undefined,
            description: params.description as string | undefined,
          },
          timeout,
        };

      case 'set_comment':
        return {
          id,
          command: 'set_comment',
          params: {
            address: params.address as string,
            comment: params.comment as string,
            type: (params.type as string) || 'EOL',
          },
          timeout,
        };

      case 'set_data_type':
        return {
          id,
          command: 'set_data_type',
          params: {
            address: params.address as string,
            dataType: params.dataType as string,
            length: params.length as number | undefined,
          },
          timeout,
        };

      case 'set_prototype':
        return {
          id,
          command: 'set_prototype',
          params: {
            functionAddress: params.functionAddress as string,
            prototype: params.prototype as string,
            description: params.description as string | undefined,
            callingConvention: params.callingConvention as string | undefined,
            force: params.force as boolean | undefined,
          },
          timeout,
        };

      case 'set_custom_signature':
        return {
          id,
          command: 'set_custom_signature',
          params: {
            functionAddress: params.functionAddress as string,
            returnType: (params.returnType as string) || 'void',
            parameters: params.parameters as Array<{
              name: string;
              dataType: string;
              storage: string;
            }>,
            description: params.description as string | undefined,
          },
          timeout,
        };

      case 'create_structure':
        return {
          id,
          command: 'create_structure',
          params: {
            name: params.name as string,
            fields: params.fields as Array<{
              name: string;
              dataType: string;
              offset?: number;
              comment?: string;
            }>,
            category: params.category as string | undefined,
            packed: params.packed as boolean | undefined,
          },
          timeout,
        };

      case 'batch_rename':
        return {
          id,
          command: 'batch_rename',
          params: {
            mappings: params.mappings as Array<{ address: string; newName: string }>,
            dryRun: params.dryRun as boolean | undefined,
            description: params.description as string | undefined,
          },
          timeout,
        };

      // Script execution
      case 'execute_script':
        return {
          id,
          command: 'execute_script',
          params: {
            code: params.code as string | undefined,
            filePath: params.filePath as string | undefined,
            language: (params.language as 'javascript' | 'python' | undefined) || 'python',
            timeout: params.scriptTimeout as number | undefined,
            sandbox: params.sandbox as boolean | undefined,
          },
          timeout,
        };

      // Analysis hints
      case 'get_analysis_hints':
        return {
          id,
          command: 'get_analysis_hints',
          params: {
            address: params.address as string | undefined,
            function: params.function as string | undefined,
          },
          timeout,
        };

      // Compound queries
      case 'find_functions_matching':
        return {
          id,
          command: 'find_functions_matching',
          params: {
            calls: params.calls as string[] | undefined,
            notCalls: params.notCalls as string[] | undefined,
            referencesString: params.referencesString as string | undefined,
            inNamespace: params.inNamespace as string | undefined,
            sizeMin: params.sizeMin as number | undefined,
            sizeMax: params.sizeMax as number | undefined,
            limit: params.limit as number | undefined,
          },
          timeout,
        };

      case 'trace_data_flow':
        return {
          id,
          command: 'trace_data_flow',
          params: {
            from: params.from as string,
            depth: params.depth as number | undefined,
            includeCalls: params.includeCalls as boolean | undefined,
          },
          timeout,
        };

      // Save session
      case 'save_session':
        return { id, command: 'save', params: {}, timeout };

      // Commit (Ghidra Server check-in)
      case 'commit':
        return {
          id,
          command: 'checkin',
          params: { message: params.message as string },
          timeout,
        };

      // Type archive
      case 'export_type_archive':
        return {
          id,
          command: 'export_type_archive',
          params: {
            archivePath: params.archivePath as string,
            categories: params.categories as string[] | undefined,
          },
          timeout: (timeout ?? 30000) * 2,
        };

      case 'import_type_archive':
        return {
          id,
          command: 'import_type_archive',
          params: {
            archivePath: params.archivePath as string,
            categories: params.categories as string[] | undefined,
          },
          timeout: (timeout ?? 30000) * 2,
        };

      // Bookmark management
      case 'add_bookmark':
        return {
          id,
          command: 'add_bookmark',
          params: {
            address: params.address as string,
            type: params.type as string | undefined,
            category: params.category as string | undefined,
            comment: params.comment as string | undefined,
          },
          timeout,
        };

      case 'delete_bookmark':
        return {
          id,
          command: 'delete_bookmark',
          params: {
            address: params.address as string,
            type: params.type as string | undefined,
          },
          timeout,
        };

      case 'delete_comment':
        return {
          id,
          command: 'delete_comment',
          params: {
            address: params.address as string,
            type: (params.type as string) || 'EOL',
          },
          timeout,
        };

      // Label management
      case 'create_label':
        return {
          id,
          command: 'create_label',
          params: {
            address: params.address as string,
            name: params.name as string,
            namespace: params.namespace as string | undefined,
            primary: params.primary as boolean | undefined,
          },
          timeout,
        };

      case 'delete_label':
        return {
          id,
          command: 'delete_label',
          params: {
            address: params.address as string,
            name: params.name as string | undefined,
          },
          timeout,
        };

      // Function management
      case 'create_function':
        return {
          id,
          command: 'create_function',
          params: {
            address: params.address as string,
            name: params.name as string | undefined,
          },
          timeout,
        };

      case 'delete_function':
        return {
          id,
          command: 'delete_function',
          params: {
            address: params.address as string,
          },
          timeout,
        };

      // Data type creation
      case 'create_enum':
        return {
          id,
          command: 'create_enum',
          params: {
            name: params.name as string,
            values: params.values as Record<string, number>,
            category: params.category as string | undefined,
            size: params.size as number | undefined,
          },
          timeout,
        };

      case 'create_union':
        return {
          id,
          command: 'create_union',
          params: {
            name: params.name as string,
            fields: params.fields as Array<{
              name: string;
              dataType: string;
              comment?: string;
            }>,
            category: params.category as string | undefined,
          },
          timeout,
        };

      case 'create_typedef':
        return {
          id,
          command: 'create_typedef',
          params: {
            name: params.name as string,
            baseType: params.baseType as string,
            category: params.category as string | undefined,
          },
          timeout,
        };

      case 'update_structure':
        return {
          id,
          command: 'update_structure',
          params: {
            name: params.name as string,
            operation: params.operation as 'replaceAll' | 'updateFields' | 'insertField' | 'deleteField' | 'replace' | 'addField' | 'removeField',
            fields: params.fields as Array<{
              name?: string;
              dataType?: string;
              offset?: number;
              comment?: string;
              fieldName?: string;
              newName?: string;
              newDataType?: string;
            }> | undefined,
            fieldName: params.fieldName as string | undefined,
            category: params.category as string | undefined,
            force: params.force as boolean | undefined,
          },
          timeout,
        };

      case 'delete_data_type':
        return {
          id,
          command: 'delete_data_type',
          params: {
            name: params.name as string,
            category: params.category as string | undefined,
          },
          timeout,
        };

      // Code manipulation
      case 'disassemble':
        return {
          id,
          command: 'disassemble',
          params: {
            address: params.address as string,
            length: params.length as number | undefined,
          },
          timeout,
        };

      case 'clear_listing':
        return {
          id,
          command: 'clear_listing',
          params: {
            startAddress: params.startAddress as string,
            endAddress: params.endAddress as string | undefined,
          },
          timeout,
        };

      // Variable management
      case 'set_function_variable_name':
        return {
          id,
          command: 'set_function_variable_name',
          params: {
            functionAddress: params.functionAddress as string,
            oldName: params.oldName as string,
            newName: params.newName as string,
            description: params.description as string | undefined,
          },
          timeout,
        };

      case 'set_function_variable_type':
        return {
          id,
          command: 'set_function_variable_type',
          params: {
            functionAddress: params.functionAddress as string,
            variableName: params.variableName as string,
            dataType: params.dataType as string,
            description: params.description as string | undefined,
            force: params.force as boolean | undefined,
          },
          timeout,
        };

      // Equate management
      case 'list_equates':
        return {
          id,
          command: 'list_equates',
          params: {
            offset: params.offset as number | undefined,
            limit: params.limit as number | undefined,
            filter: params.filter as string | undefined,
            regex: params.regex as string | undefined,
            value: params.value as number | undefined,
          },
          timeout,
        };

      case 'set_equate':
        return {
          id,
          command: 'set_equate',
          params: {
            address: params.address as string,
            operandIndex: params.operandIndex as number | undefined,
            value: params.value as number,
            name: params.name as string,
          },
          timeout,
        };

      case 'delete_equate':
        return {
          id,
          command: 'delete_equate',
          params: {
            address: params.address as string,
            operandIndex: params.operandIndex as number | undefined,
            name: params.name as string,
          },
          timeout,
        };

      // Function attributes/tags
      case 'set_function_attributes':
        return {
          id,
          command: 'set_function_attributes',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            callingConvention: params.callingConvention as string | undefined,
            noReturn: params.noReturn as boolean | undefined,
            inline: params.inline as boolean | undefined,
            varArgs: params.varArgs as boolean | undefined,
            force: params.force as boolean | undefined,
          },
          timeout,
        };

      case 'add_function_tag':
        return {
          id,
          command: 'add_function_tag',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            tag: params.tag as string,
          },
          timeout,
        };

      case 'remove_function_tag':
        return {
          id,
          command: 'remove_function_tag',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
            tag: params.tag as string,
          },
          timeout,
        };

      case 'batch_tag_symbols':
        return {
          id,
          command: 'batch_tag_symbols',
          params: {
            operations: params.operations as Array<{
              address: string;
              tag: { type: string; data?: string };
              action: 'add' | 'remove';
            }>,
          },
          timeout,
        };

      // Namespace management
      case 'create_namespace':
        return {
          id,
          command: 'create_namespace',
          params: {
            name: params.name as string,
            parent: params.parent as string | undefined,
            isClass: params.isClass as boolean | undefined,
          },
          timeout,
        };

      case 'move_symbol_to_namespace':
        return {
          id,
          command: 'move_symbol_to_namespace',
          params: {
            address: params.address as string,
            namespace: params.namespace as string,
            type: params.type as 'function' | 'label' | 'data',
          },
          timeout,
        };

      case 'rename_namespace':
        return {
          id,
          command: 'rename_namespace',
          params: {
            oldName: params.oldName as string,
            newName: params.newName as string,
          },
          timeout,
        };

      case 'delete_namespace':
        return {
          id,
          command: 'delete_namespace',
          params: {
            name: params.name as string,
            force: params.force as boolean | undefined,
          },
          timeout,
        };

      // Undo/redo
      case 'undo':
        return { id, command: 'undo', params: {}, timeout };

      case 'redo':
        return { id, command: 'redo', params: {}, timeout };

      case 'get_undo_history':
        return { id, command: 'get_undo_history', params: {}, timeout };

      // Analysis
      case 'get_stack_frame':
        return {
          id,
          command: 'get_stack_frame',
          params: {
            address: params.address as string | undefined,
            name: params.name as string | undefined,
          },
          timeout,
        };

      case 'reanalyze':
        return {
          id,
          command: 'reanalyze',
          params: {
            address: params.address as string | undefined,
          },
          timeout: 300000, // 5 min for full program re-analysis
        };

      // Switch table
      case 'get_switch_table':
        return {
          id,
          command: 'get_switch_table',
          params: {
            address: params.address as string,
          },
          timeout,
        };

      case 'set_switch_override':
        return {
          id,
          command: 'set_switch_override',
          params: {
            address: params.address as string,
            caseAddresses: params.caseAddresses as string[],
          },
          timeout,
        };

      // Symbol navigation
      case 'get_symbol_after':
        return {
          id,
          command: 'get_symbol_after',
          params: {
            address: params.address as string,
            count: params.count as number | undefined,
          },
          timeout,
        };

      // Data inspection
      case 'get_data_at_address':
        return {
          id,
          command: 'get_data_at_address',
          params: {
            address: params.address as string,
            lookAhead: params.lookAhead as number | undefined,
          },
          timeout,
        };

      case 'detect_table':
        return {
          id,
          command: 'detect_table',
          params: {
            address: params.address as string,
            maxEntries: params.maxEntries as number | undefined,
            applyType: params.applyType as boolean | undefined,
            name: params.name as string | undefined,
          },
          timeout,
        };

      default:
        throw new Error(`Unknown tool: ${toolName}`);
    }
  }

  /**
   * List available resources (binary info, session state)
   */
  async listResources(): Promise<Array<{ uri: string; name: string; mimeType?: string }>> {
    const sessions = await this.context.listSessions();
    const resources: Array<{ uri: string; name: string; mimeType?: string }> = [];

    for (const session of sessions) {
      resources.push({
        uri: `ghidra://session/${session.id}/info`,
        name: `${session.binaryPath} (Session Info)`,
        mimeType: 'application/json',
      });
    }

    return resources;
  }

  /**
   * Read a resource
   */
  async readResource(uri: string): Promise<{ contents: Array<{ uri: string; text: string; mimeType?: string }> }> {
    const url = new URL(uri);
    if (url.protocol !== 'ghidra:') {
      throw new Error(`Invalid resource URI: ${uri}`);
    }

    const pathParts = url.pathname.split('/').filter(Boolean);
    if (pathParts[0] === 'session' && pathParts[2] === 'info') {
      const sessionId = pathParts[1];
      const session = await this.context.getSession(sessionId);
      if (!session) {
        throw new Error(`Session not found: ${sessionId}`);
      }

      return {
        contents: [
          {
            uri,
            text: JSON.stringify(session, null, 2),
            mimeType: 'application/json',
          },
        ],
      };
    }

    throw new Error(`Unknown resource: ${uri}`);
  }
}
