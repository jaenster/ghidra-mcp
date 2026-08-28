/**
 * MCP Tool definitions for Ghidra
 *
 * Organized by phase:
 * - Phase 1: Core Read (MVP)
 * - Phase 2: Navigation & Discovery
 * - Phase 3: LLM Power Tools
 * - Phase 4: Modification
 * - Phase 5: Advanced
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';

// =============================================================================
// Tool Definition Helper
// =============================================================================

interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

function defineTool(
  name: string,
  description: string,
  properties: Record<string, unknown>,
  required: string[] = []
): ToolDefinition {
  return {
    name,
    description,
    inputSchema: {
      type: 'object',
      properties,
      required: required.length > 0 ? required : undefined,
    },
  };
}

// Common property definitions
const sessionIdProp = {
  sessionId: {
    type: 'string',
    description: 'Session ID (uses default if not specified)',
  },
};

const paginationProps = {
  offset: {
    type: 'number',
    description: 'Offset for pagination (default: 0)',
  },
  limit: {
    type: 'number',
    description: 'Maximum number of results (default: 100)',
  },
};

const addressOrNameProps = {
  address: {
    type: 'string',
    description: 'Address of the function (e.g., "0x00401234")',
  },
  name: {
    type: 'string',
    description: 'Name of the function',
  },
};

const filterProps = {
  filter: {
    type: 'string',
    description: 'Substring filter — case-insensitive, matches anywhere in the name',
  },
  regex: {
    type: 'string',
    description: 'Regex filter — case-insensitive regex applied with .find() (substring match)',
  },
};

// =============================================================================
// Session Management Tools
// =============================================================================

export const sessionTools: ToolDefinition[] = [
  defineTool(
    'list_sessions',
    'List all active Ghidra sessions. Shows binary path, session ID, and status for each session.',
    {}
  ),

  defineTool(
    'create_session',
    'Open a program from the Ghidra Server and start a session on it. ' +
    'A program is named repository-first, exactly as list_programs prints it: ' +
    '"Diablo2Lod/windows/1.09d/D2Game.dll". A path that names no repository is matched across all ' +
    'of them and accepted when exactly one program matches. ' +
    'Use list_repos and list_programs (neither needs a session) to see what is available. ' +
    'A full ghidra://[user:password@]host[:port]/repo/program/path URL opens a program on a different ' +
    'server; the port defaults to 13100. ' +
    'To analyse a binary that is not on the server yet, put it there with import_program first.',
    {
      program: {
        type: 'string',
        description: 'Repository-first program path, e.g. "Diablo2Lod/windows/1.09d/D2Game.dll"',
      },
      binaryPath: {
        type: 'string',
        description: 'Alternative to program: a ghidra://host[:port]/repo/program URL, or a local .gpr project path when the worker runs on this machine',
      },
      programPath: {
        type: 'string',
        description: 'Program to select within a local .gpr project that holds several',
      },
      autoAnalyze: {
        type: 'boolean',
        description: 'Automatically run analysis after loading (default: true)',
      },
      analysisTimeout: {
        type: 'number',
        description: 'Maximum time for analysis in milliseconds (default: 300000)',
      },
      readOnly: {
        type: 'boolean',
        description: 'Open without checking the program out, so nothing can be written back (default: false)',
      },
    }
  ),

  defineTool(
    'close_session',
    'Close a Ghidra session and terminate its worker process. ' +
    'Sessions are reference-counted: if other clients still hold this one, the call only ' +
    'decrements and reports closed=false with the remaining clientCount — pass force to close ' +
    'it regardless.',
    {
      ...sessionIdProp,
      force: {
        type: 'boolean',
        description: 'Close even if other clients still hold the session (default: false)',
      },
    },
    ['sessionId']
  ),

  defineTool(
    'save_session',
    'Save the current state of a Ghidra session. Persists all changes (renames, comments, type definitions) to the project.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'commit',
    'Check in (commit) a Ghidra Server session as a new server version. Saves the working copy, then performs a Ghidra check-in with the given message, keeping the checkout so editing can continue. Only valid for writable Ghidra Server sessions.',
    {
      ...sessionIdProp,
      message: {
        type: 'string',
        description: 'Commit message describing the changes (becomes the server version comment)',
      },
    },
    ['message']
  ),

  defineTool(
    'set_default_session',
    'Set the default session for subsequent tool calls.',
    {
      sessionId: {
        type: 'string',
        description: 'Session ID to set as default',
      },
    },
    ['sessionId']
  ),

  defineTool(
    'set_output_format',
    'Set the output format for this connection. TOON is more token-efficient, JSON is more verbose. Setting persists for the lifetime of the MCP connection.',
    {
      format: {
        type: 'string',
        enum: ['toon', 'json'],
        description: 'Output format: "toon" (default, compact) or "json" (verbose)',
      },
    },
    ['format']
  ),
];

// =============================================================================
// Session Alias Tools
// =============================================================================

export const aliasTools: ToolDefinition[] = [
  defineTool(
    'set_session_alias',
    'Assign a human-readable alias to a session (e.g. "windows", "mac"). Aliases can be used anywhere a sessionId is accepted.',
    {
      alias: {
        type: 'string',
        description: 'Human-readable alias name (e.g. "windows", "mac")',
      },
      sessionId: {
        type: 'string',
        description: 'Session ID to alias',
      },
    },
    ['alias', 'sessionId']
  ),

  defineTool(
    'remove_session_alias',
    'Remove a session alias.',
    {
      alias: {
        type: 'string',
        description: 'Alias to remove',
      },
    },
    ['alias']
  ),

  defineTool(
    'list_session_aliases',
    'List all session aliases and their mapped session IDs.',
    {}
  ),
];

// =============================================================================
// Shared Structure Tools
// =============================================================================

export const sharedStructureTools: ToolDefinition[] = [
  defineTool(
    'create_shared_structure',
    'Create a shared structure definition that can be synced to multiple sessions. ' +
    'Supports generic types: define typeParams (e.g. ["$TContext", "$TClient"]) and provide per-target bindings ' +
    'to expand them to concrete types. Fields use type parameter names in dataType, which get substituted per target on sync.',
    {
      name: {
        type: 'string',
        description: 'Structure name (e.g. "D2QServerStrc")',
      },
      category: {
        type: 'string',
        description: 'Category path (e.g. "/D2Structs")',
      },
      fields: {
        type: 'array',
        description: 'Structure fields. Use type parameter names (e.g. "$TContext *") in dataType for generic fields.',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Field name' },
            dataType: { type: 'string', description: 'Data type — may include type params like "$TContext *"' },
            offset: { type: 'number', description: 'Byte offset' },
            length: { type: 'number', description: 'Field size in bytes' },
            comment: { type: 'string', description: 'Optional comment' },
          },
          required: ['name', 'dataType', 'offset', 'length'],
        },
      },
      packed: {
        type: 'boolean',
        description: 'Whether the structure is packed (no padding). Default: false',
      },
      typeParams: {
        type: 'array',
        description: 'Type parameters for generic structs (e.g. ["$TContext", "$TClient"])',
        items: { type: 'string' },
      },
      targets: {
        type: 'array',
        description: 'Target sessions with optional type bindings for generics',
        items: {
          type: 'object',
          properties: {
            alias: { type: 'string', description: 'Session alias' },
            bindings: {
              type: 'object',
              description: 'Type parameter bindings (e.g. {"$TContext": "D2GameStrc", "$TClient": "D2ClientStrc"})',
              additionalProperties: { type: 'string' },
            },
          },
          required: ['alias'],
        },
      },
    },
    ['name', 'fields']
  ),

  defineTool(
    'update_shared_structure',
    'Update a shared structure definition and re-sync to all target sessions. Type parameter bindings are expanded per target.',
    {
      name: {
        type: 'string',
        description: 'Structure name',
      },
      category: {
        type: 'string',
        description: 'Category path',
      },
      fields: {
        type: 'array',
        description: 'Updated structure fields',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Field name' },
            dataType: { type: 'string', description: 'Data type — may include type params' },
            offset: { type: 'number', description: 'Byte offset' },
            length: { type: 'number', description: 'Field size in bytes' },
            comment: { type: 'string', description: 'Optional comment' },
          },
          required: ['name', 'dataType', 'offset', 'length'],
        },
      },
      packed: {
        type: 'boolean',
        description: 'Whether the structure is packed',
      },
      typeParams: {
        type: 'array',
        description: 'Type parameters (e.g. ["$TContext", "$TClient"])',
        items: { type: 'string' },
      },
      targets: {
        type: 'array',
        description: 'Update target sessions with optional type bindings (replaces existing targets)',
        items: {
          type: 'object',
          properties: {
            alias: { type: 'string', description: 'Session alias' },
            bindings: {
              type: 'object',
              description: 'Type parameter bindings',
              additionalProperties: { type: 'string' },
            },
          },
          required: ['alias'],
        },
      },
    },
    ['name', 'fields']
  ),

  defineTool(
    'list_shared_structures',
    'List all shared structure definitions with their target sessions and field counts.',
    {}
  ),

  defineTool(
    'delete_shared_structure',
    'Delete a shared structure definition. Does not remove the struct from sessions where it was already synced.',
    {
      name: {
        type: 'string',
        description: 'Structure name to delete',
      },
    },
    ['name']
  ),

  defineTool(
    'sync_shared_structures',
    'Re-sync all shared structures (or a specific one) to their target sessions. Useful after session restarts.',
    {
      name: {
        type: 'string',
        description: 'Specific structure name to sync (omit to sync all)',
      },
    }
  ),
];

// =============================================================================
// Multi-Program Tools
// =============================================================================

export const multiProgramTools: ToolDefinition[] = [
  defineTool(
    'list_repos',
    'List the repositories on the configured Ghidra Server. Needs no session — use it to see ' +
    'what is available before opening anything.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'request_upload',
    'Reserve a slot for uploading a binary, for when it is only on the client\'s machine. ' +
    'Returns a one-time URL: PUT the file to it as the raw request body, then pass the ' +
    'uploadId to import_program. The slot expires, and can only be filled once. ' +
    'Prefer a plain url on import_program when the worker can already reach the file.',
    {
      ...sessionIdProp,
      filename: {
        type: 'string',
        description: 'Original file name, used to name the stored file (optional)',
      },
    }
  ),

  defineTool(
    'create_repo',
    'Create a repository on the Ghidra Server. The connecting user owns it, so imports and ' +
    'check-ins into it work straight away. There is no delete counterpart — Ghidra Server does ' +
    'not implement deleting a repository; that is done on the server host.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Repository name',
      },
    },
    ['name']
  ),

  defineTool(
    'list_programs',
    'List programs on the Ghidra Server. Needs no session, so it works before anything is open. ' +
    'With no repo it lists every repository, each path repository-first ' +
    '("Diablo2Lod/windows/1.09d/D2Game.dll") so it can be handed straight to create_session.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Repository to list (omit to list every repository on the server)',
      },
      folder: {
        type: 'string',
        description: 'Folder within the repository to list (default: "/")',
      },
      recursive: {
        type: 'boolean',
        description: 'Descend into subfolders (default: true)',
      },
      filter: {
        type: 'string',
        description: 'Case-insensitive substring the program path must contain',
      },
    }
  ),

  defineTool(
    'import_program',
    'Import one or more binaries into a Ghidra Server repository, so they can then be opened ' +
    'with create_session. The WORKER fetches the bytes, so give it a url it can reach (or a ' +
    'localPath on the worker host, or inline bytesBase64) — the worker cannot read the client\'s disk. ' +
    'programPath names its repository first, the same form everything else uses: ' +
    '"Diablo2Lod/windows/1.09d/Game.exe". Create the repository with create_repo if it is new. ' +
    'Analysis is slow, so the import runs as a background job: it returns a jobId immediately, ' +
    'which import_status polls. Pass items to import many in one call.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Target repository, if you would rather not put it in programPath',
      },
      url: {
        type: 'string',
        description: 'URL for the worker to fetch the binary from',
      },
      uploadId: {
        type: 'string',
        description: 'A filled upload slot from request_upload — use this for a file that only exists on the client',
      },
      localPath: {
        type: 'string',
        description: 'Path to the binary ON THE WORKER HOST (only useful when the worker runs locally)',
      },
      bytesBase64: {
        type: 'string',
        description: 'The binary itself, base64-encoded. Fine for small files; prefer url for big ones.',
      },
      programPath: {
        type: 'string',
        description: 'Where it lands, repository first: "Diablo2Lod/windows/1.09d/Game.exe"',
      },
      processor: {
        type: 'string',
        description: 'Language ID to force, e.g. "x86:LE:32:default" (omit to let Ghidra detect it)',
      },
      compilerSpec: {
        type: 'string',
        description: 'Compiler spec ID to pair with processor, e.g. "windows" (default: the language default)',
      },
      items: {
        type: 'array',
        description: 'Several binaries in one job; each entry takes url/uploadId/localPath/bytesBase64, programPath, processor, compilerSpec',
        items: {
          type: 'object',
          properties: {
            url: { type: 'string' },
            uploadId: { type: 'string' },
            localPath: { type: 'string' },
            bytesBase64: { type: 'string' },
            programPath: { type: 'string' },
            processor: { type: 'string' },
            compilerSpec: { type: 'string' },
          },
        },
      },
      analyze: {
        type: 'boolean',
        description: 'Run auto-analysis on each imported program (default: true)',
      },
      overwrite: {
        type: 'boolean',
        description: 'Replace a program already at that path (default: false)',
      },
      wait: {
        type: 'boolean',
        description: 'Hold the request until the job finishes instead of returning a jobId (default: false)',
      },
      waitTimeout: {
        type: 'number',
        description: 'How long to hold the request when wait is set, in ms (default: 600000)',
      },
    }
  ),

  defineTool(
    'import_status',
    'Check an import job started by import_program. Omit jobId to list every job this worker knows about.',
    {
      ...sessionIdProp,
      jobId: {
        type: 'string',
        description: 'Job to report on (omit for all)',
      },
    }
  ),

  defineTool(
    'delete_program',
    'Delete a program from a Ghidra Server repository. Refuses to delete a program a session has open.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Repository, if you would rather not put it in programPath',
      },
      programPath: {
        type: 'string',
        description: 'Program to delete, repository first: "Diablo2Lod/windows/1.09d/Game.exe"',
      },
      force: {
        type: 'boolean',
        description: 'Break a checkout left behind by a dead worker, losing anything uncommitted in it. Refuses another user\'s checkout — the server does not allow it (default: false)',
      },
    },
    ['programPath']
  ),

  defineTool(
    'move_program',
    'Move or rename a program within a Ghidra Server repository — for fixing an import that landed ' +
    'in the wrong place. Both paths name the same repository. Refuses to move a program a session has open.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Repository, if you would rather not put it in the paths',
      },
      from: {
        type: 'string',
        description: 'Current path, repository first: "Diablo2Lod/windows/Game.exe"',
      },
      to: {
        type: 'string',
        description: 'New path, same repository (folders are created as needed)',
      },
      force: {
        type: 'boolean',
        description: 'Break a checkout left behind by a dead worker, losing anything uncommitted in it. Refuses another user\'s checkout — the server does not allow it (default: false)',
      },
    },
    ['from', 'to']
  ),

  defineTool(
    'list_checkouts',
    'List outstanding checkouts on the Ghidra Server. A checkout is what a writable session ' +
    'holds while it edits a program, and one left behind by a crashed worker is the usual ' +
    'reason move_program or delete_program refuses. With nothing named it sweeps every ' +
    'repository, which costs one server round trip per program — narrow it with repo, ' +
    'programPath or filter on a large server.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Repository to scan (omit to scan every repository)',
      },
      programPath: {
        type: 'string',
        description: 'A single program to report on, repository first: "Diablo2Lod/windows/Game.exe"',
      },
      filter: {
        type: 'string',
        description: 'Case-insensitive substring a program path must contain to be checked',
      },
    }
  ),

  defineTool(
    'terminate_checkout',
    'Give a checkout back to the server. Use it to clear a checkout stranded by a worker that ' +
    'died, so the program can be moved, deleted or opened writable again. Omit checkoutId to ' +
    'terminate every checkout on the program. This is not a check-in: anything changed under ' +
    'that checkout and never committed is lost. Take the ids from list_checkouts.',
    {
      ...sessionIdProp,
      repo: {
        type: 'string',
        description: 'Repository, if you would rather not put it in programPath',
      },
      programPath: {
        type: 'string',
        description: 'Program whose checkout to terminate, repository first: "Diablo2Lod/windows/Game.exe"',
      },
      checkoutId: {
        type: 'number',
        description: 'Which checkout to terminate (omit for all of them on this program)',
      },
    },
    ['programPath']
  ),

  defineTool(
    'load_program',
    'Load an additional program from the open .gpr project into the worker. ' +
    'Use list_programs to see available programs first.',
    {
      ...sessionIdProp,
      programPath: {
        type: 'string',
        description: 'Path of the program within the project (e.g., "/DiabloII_macho")',
      },
    },
    ['programPath']
  ),
];

// =============================================================================
// Phase 1: Core Read Tools (MVP)
// =============================================================================

export const coreReadTools: ToolDefinition[] = [
  defineTool(
    'get_program_info',
    'Get metadata about the loaded binary including architecture, image base, compiler, and analysis state.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'list_functions',
    'List functions in the program with optional filtering and pagination.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
      namespace: {
        type: 'string',
        description: 'Filter by namespace',
      },
      includeChildren: {
        type: 'boolean',
        description: 'Include child namespaces (default: false)',
      },
    }
  ),

  defineTool(
    'get_function_info',
    'Get detailed information about a specific function including parameters, local variables, and calling convention. ' +
    'A variable still typed as a raw stack slot (undefined1[N]) carries resolvedType alongside it — what decompile ' +
    'makes of that slot — so the two tools agree about the same variable. ' +
    'address may be anywhere inside the function, and name may be the fully-qualified one that list_symbols prints.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
    }
  ),

  defineTool(
    'get_function_summary',
    'Get a rich summary of a function including calls, callers, strings used, and interesting patterns. Optimized for LLM consumption.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      includeStrings: {
        type: 'boolean',
        description: 'Include strings referenced by this function (default: true)',
      },
      includeXrefs: {
        type: 'boolean',
        description: 'Include call graph info (default: true)',
      },
      maxCalls: {
        type: 'number',
        description: 'Maximum number of callees to include (default: 20)',
      },
      maxCallers: {
        type: 'number',
        description: 'Maximum number of callers to include (default: 20)',
      },
    }
  ),

  defineTool(
    'decompile',
    'Decompile a function to pseudo-C code. This is the primary tool for understanding what a function does.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      decompileTimeout: {
        type: 'number',
        description: 'Decompilation timeout in seconds (default: 30)',
      },
    }
  ),

  defineTool(
    'batch_decompile',
    'Decompile multiple functions in one call. Select functions by explicit address/name list, ' +
    'or by filter/namespace/address range. Returns results and failures separately.',
    {
      ...sessionIdProp,
      addresses: {
        type: 'array',
        items: { type: 'string' },
        description: 'Explicit list of function addresses to decompile',
      },
      names: {
        type: 'array',
        items: { type: 'string' },
        description: 'Explicit list of function names to decompile',
      },
      ...filterProps,
      namespace: {
        type: 'string',
        description: 'Filter by namespace',
      },
      startAddress: {
        type: 'string',
        description: 'Start of address range filter',
      },
      endAddress: {
        type: 'string',
        description: 'End of address range filter',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of functions to decompile (default: 50, max: 200)',
      },
      decompileTimeout: {
        type: 'number',
        description: 'Per-function decompilation timeout in seconds (default: 30)',
      },
    }
  ),

  defineTool(
    'get_disassembly',
    'Get assembly instructions at an address. Useful for understanding low-level behavior.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Start address for disassembly',
      },
      count: {
        type: 'number',
        description: 'Number of instructions (default: 20)',
      },
      context: {
        type: 'number',
        description: 'Instructions of context before the address (default: 0)',
      },
    },
    ['address']
  ),

  defineTool(
    'read_memory',
    'Read raw bytes from memory at an address. Returns hex-encoded bytes.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Start address to read from',
      },
      length: {
        type: 'number',
        description: 'Number of bytes to read',
      },
    },
    ['address', 'length']
  ),

  defineTool(
    'get_hexdump',
    'Get a formatted hexdump of memory. Useful for examining data structures and non-code regions.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Start address',
      },
      length: {
        type: 'number',
        description: 'Number of bytes',
      },
      bytesPerLine: {
        type: 'number',
        description: 'Bytes per line (default: 16)',
      },
    },
    ['address', 'length']
  ),
];

// =============================================================================
// Phase 2: Navigation & Discovery Tools
// =============================================================================

export const navigationTools: ToolDefinition[] = [
  defineTool(
    'get_xrefs',
    'Get cross-references to or from an address. Essential for understanding how code is connected.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to get xrefs for',
      },
      direction: {
        type: 'string',
        enum: ['to', 'from', 'both'],
        description: 'Direction of references (default: "both")',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of results (default: 50)',
      },
      refType: {
        oneOf: [
          { type: 'string' },
          { type: 'array', items: { type: 'string' } },
        ],
        description: 'Filter by reference type. Exact types: UNCONDITIONAL_CALL, CONDITIONAL_CALL, COMPUTED_CALL, ' +
                     'UNCONDITIONAL_JUMP, CONDITIONAL_JUMP, COMPUTED_JUMP, DATA, READ, WRITE, READ_WRITE, PARAM, INDIRECTION. ' +
                     'Shortcuts: "calls", "data", "jumps", "reads", "writes"',
      },
    },
    ['address']
  ),

  defineTool(
    'get_xrefs_with_context',
    'Get cross-references with surrounding code context. Filter by patterns in the context.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to get xrefs for',
      },
      direction: {
        type: 'string',
        enum: ['to', 'from', 'both'],
        description: 'Direction of references (default: "both")',
      },
      contextLines: {
        type: 'number',
        description: 'Lines of context to include (default: 5)',
      },
      contextPattern: {
        type: 'string',
        description: 'Only include xrefs where context matches this pattern',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of results (default: 50)',
      },
      refType: {
        oneOf: [
          { type: 'string' },
          { type: 'array', items: { type: 'string' } },
        ],
        description: 'Filter by reference type. Exact types: UNCONDITIONAL_CALL, CONDITIONAL_CALL, COMPUTED_CALL, ' +
                     'UNCONDITIONAL_JUMP, CONDITIONAL_JUMP, COMPUTED_JUMP, DATA, READ, WRITE, READ_WRITE, PARAM, INDIRECTION. ' +
                     'Shortcuts: "calls", "data", "jumps", "reads", "writes"',
      },
    },
    ['address']
  ),

  defineTool(
    'get_call_graph',
    'Get the call graph for a function showing callers and callees.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      depth: {
        type: 'number',
        description: 'Depth to traverse (default: 2)',
      },
      direction: {
        type: 'string',
        enum: ['callers', 'callees', 'both'],
        description: 'Direction to traverse (default: "both")',
      },
      maxNodes: {
        type: 'number',
        description: 'Maximum number of nodes before truncating (default: 500)',
      },
    }
  ),

  defineTool(
    'find_call_path',
    'Find a call path between two functions. Useful for understanding how execution can flow from one function to another.',
    {
      ...sessionIdProp,
      from: {
        type: 'string',
        description: 'Source function name or address',
      },
      to: {
        type: 'string',
        description: 'Target function name or address',
      },
      maxDepth: {
        type: 'number',
        description: 'Maximum depth to search (default: 10)',
      },
    },
    ['from', 'to']
  ),

  defineTool(
    'get_basic_blocks',
    'Get basic blocks for a function with control flow information.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
    }
  ),

  defineTool(
    'list_strings',
    'List string literals in the program with optional filtering.',
    {
      ...sessionIdProp,
      ...paginationProps,
      minLength: {
        type: 'number',
        description: 'Minimum string length (default: 4)',
      },
      ...filterProps,
    }
  ),

  defineTool(
    'list_imports',
    'List imported functions/symbols.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
    }
  ),

  defineTool(
    'list_exports',
    'List exported functions/symbols.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
    }
  ),

  defineTool(
    'list_symbols',
    'List all symbols with optional type filtering.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
      type: {
        type: 'string',
        enum: ['FUNCTION', 'LABEL', 'CLASS', 'NAMESPACE', 'PARAMETER', 'LOCAL_VAR', 'GLOBAL_REGISTER_VAR', 'GLOBAL', 'LIBRARY'],
        description: 'Filter by symbol type',
      },
    }
  ),

  defineTool(
    'list_data_symbols',
    'List data symbols (global and namespaced) with type, size, xref count, and referencing functions.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
      segment: {
        type: 'string',
        description: 'Filter by memory segment name (e.g., ".data", ".rdata", ".bss")',
      },
      sortBy: {
        type: 'string',
        enum: ['address', 'xrefs', 'name'],
        description: 'Sort results by field (default: "address")',
      },
      dataType: {
        type: 'string',
        description: 'Filter by data type name — case-insensitive substring, so "UnitAny" also matches "UnitAny *". Symbols with no defined data are excluded when this is set.',
      },
    }
  ),

  defineTool(
    'read_data_value',
    'Read the initialized data value at an address. Returns a structured tree for arrays, structs, pointers (resolved to symbol names), enums, strings, and scalars. Use this to inspect dispatch tables, vtables, and initialized global data.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the data to read (e.g., "0x006E0D18")',
      },
    },
    ['address']
  ),

  defineTool(
    'list_segments',
    'List memory segments/sections in the program.',
    {
      ...sessionIdProp,
      ...paginationProps,
    }
  ),

  defineTool(
    'list_namespaces',
    'List namespaces in the program.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
    }
  ),

  defineTool(
    'get_class_info',
    'Get detailed information about a class including methods, fields, and vtable.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Class name',
      },
    },
    ['name']
  ),

  defineTool(
    'get_stack_frame',
    'Get the stack frame layout for a function including all local variables and parameters with their offsets.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
    }
  ),

  defineTool(
    'get_switch_table',
    'Get the switch/jump table at an address. Returns all cases with their target addresses.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the switch/indirect jump instruction',
      },
    },
    ['address']
  ),

  defineTool(
    'set_switch_override',
    'Override a switch/jump table at an address with explicit case destination addresses. Fixes "Could not recover jumptable" warnings by telling Ghidra the exact branch targets.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the indirect jump/branch instruction',
      },
      caseAddresses: {
        type: 'array',
        items: { type: 'string' },
        description: 'Array of destination addresses for each case',
      },
    },
    ['address', 'caseAddresses']
  ),

  defineTool(
    'get_symbol_after',
    'Get the next N symbols after a given address. Returns symbol name, type, namespace, distance, function/data info, and xref count. Useful for understanding memory layout and finding nearby code/data.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to search from (e.g., "0x00401234")',
      },
      count: {
        type: 'number',
        description: 'Number of symbols to return (default: 10)',
      },
    },
    ['address']
  ),

  defineTool(
    'get_data_at_address',
    'Get detailed data information at an address including symbol, type, segment, next symbol distance, xrefs, and pointer table pattern detection.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to inspect',
      },
      lookAhead: {
        type: 'number',
        description: 'Max bytes to scan for patterns (default: 0 = auto: distance to next symbol)',
      },
    },
    ['address']
  ),

  defineTool(
    'detect_table',
    'Detect a pointer/data table at an address. Reads consecutive pointer-sized values and resolves each to function, data, string, or unknown. Stops at NULL or non-pointer value.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Start of suspected table',
      },
      maxEntries: {
        type: 'number',
        description: 'Max entries to scan (default: 256)',
      },
      applyType: {
        type: 'boolean',
        description: 'Create array type at address (default: false)',
      },
      name: {
        type: 'string',
        description: 'Rename symbol at address (optional)',
      },
    },
    ['address']
  ),
];

// =============================================================================
// Phase 3: LLM Power Tools
// =============================================================================

export const llmPowerTools: ToolDefinition[] = [
  defineTool(
    'search',
    'Unified search across the program. Supports regex patterns and multiple search types. ' +
    'This is the primary discovery tool - use it to find functions, strings, symbols, and more. ' +
    'Advanced types "disassembly", "bytes", and "decompiled" are NOT included in "all" — they require explicit opt-in. ' +
    '"bytes" uses hex patterns with ?? wildcards (e.g. "55 8B EC"), not regex.\n' +
    'Note on "decompiled": it decompiles as it goes, so an unscoped search stops after a few hundred ' +
    'functions and says so in coverageNote — zero results there means "not seen", not "not present". ' +
    'Narrow it with functionFilter or scope, or raise maxFunctions.',
    {
      ...sessionIdProp,
      pattern: {
        type: 'string',
        description: 'Regex pattern to search for (or hex byte pattern for type "bytes", e.g. "55 8B EC ?? ??")',
      },
      ...filterProps,
      hexPattern: {
        type: 'string',
        description: 'Hex byte pattern with ?? wildcards for type "bytes" (e.g. "55 8B EC ?? ??"). Only for type "bytes".',
      },
      type: {
        oneOf: [
          { type: 'string' },
          { type: 'array', items: { type: 'string' } },
        ],
        description: 'Search type(s): "functions", "strings", "symbols", "data", "imports", "exports", "namespaces", "comments", or "all". ' +
                     'Advanced (explicit only): "disassembly" (grep instructions), "bytes" (hex pattern with ?? wildcards), "decompiled" (grep pseudocode)',
      },
      caseSensitive: {
        type: 'boolean',
        description: 'Case-sensitive search (default: false)',
      },
      countOnly: {
        type: 'boolean',
        description: 'Only return the total match count, no result objects (default: false). Much faster for counting.',
      },
      ...paginationProps,
      scope: {
        type: 'object',
        description: 'Limit search scope',
        properties: {
          type: { type: 'string', enum: ['program', 'function', 'namespace', 'address_range'] },
          value: { type: 'string' },
          startAddress: { type: 'string' },
          endAddress: { type: 'string' },
        },
      },
      functionFilter: {
        type: 'string',
        description: 'Filter by function name (for disassembly/decompiled search types)',
      },
      searchMode: {
        type: 'string',
        enum: ['regex', 'mnemonic', 'operand'],
        description: 'Search mode for disassembly type only: "regex" (default, full instruction text), ' +
                     '"mnemonic" (match mnemonic only, e.g. "MOV"), "operand" (match operands only)',
      },
      flowType: {
        type: 'string',
        enum: ['call', 'jump', 'conditional_jump', 'unconditional_jump', 'terminal'],
        description: 'Pre-filter instructions by flow type (disassembly type only). ' +
                     'Can combine with any searchMode.',
      },
      maxFunctions: {
        type: 'number',
        description: 'Decompiled search only: how many functions to decompile before stopping (default: 200 unscoped, unlimited when functionFilter or scope narrows it)',
      },
    },
    ['type']
  ),

  defineTool(
    'find_functions_matching',
    'Find functions that match compound criteria. Essential for finding related code patterns. ' +
    'Results are paged: total is the real number of matches (not just what was returned), and ' +
    'hasMore says whether to ask for the next offset — a broad query no longer silently truncates.',
    {
      ...sessionIdProp,
      calls: {
        type: 'array',
        items: { type: 'string' },
        description: 'Functions that must be called',
      },
      notCalls: {
        type: 'array',
        items: { type: 'string' },
        description: 'Functions that must NOT be called',
      },
      referencesString: {
        type: 'string',
        description: 'String pattern that must be referenced',
      },
      inNamespace: {
        type: 'string',
        description: 'Must be in this namespace',
      },
      sizeMin: {
        type: 'number',
        description: 'Minimum function size in bytes',
      },
      sizeMax: {
        type: 'number',
        description: 'Maximum function size in bytes',
      },
      offset: {
        type: 'number',
        description: 'Skip this many matches, for paging (default: 0)',
      },
      limit: {
        type: 'number',
        description: 'Maximum results per page (default: 50)',
      },
    }
  ),

  defineTool(
    'trace_data_flow',
    'Trace where a value (parameter, variable) flows through the code. Useful for understanding data dependencies.',
    {
      ...sessionIdProp,
      from: {
        type: 'string',
        description: 'Starting point (e.g., "function:parseInput:param_1" or an address)',
      },
      depth: {
        type: 'number',
        description: 'Maximum depth to trace (default: 5)',
      },
      includeCalls: {
        type: 'boolean',
        description: 'Follow data flow into called functions (default: true)',
      },
    },
    ['from']
  ),

  defineTool(
    'get_analysis_hints',
    'Get analysis hints and suggestions for an address or function. Returns suspicious patterns, unanalyzed code, type mismatches, and potential vulnerabilities.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to analyze',
      },
      function: {
        type: 'string',
        description: 'Function name to analyze',
      },
    }
  ),

  defineTool(
    'execute_script',
    'Execute a Java GhidraScript for custom Ghidra analysis (recommended). ' +
    'The Java body runs as a GhidraScript.run() with access to currentProgram, ' +
    'monitor, println(...), and all GhidraScript/FlatProgramAPI methods. Wrap ' +
    'mutations in a transaction (start("msg")/end(true) or ' +
    'currentProgram.startTransaction/endTransaction). Python (Jython) was removed ' +
    'in Ghidra 12.1 and is not available on this build.',
    {
      ...sessionIdProp,
      code: {
        type: 'string',
        description: 'Inline script code to execute. Provide code or filePath.',
      },
      filePath: {
        type: 'string',
        description: 'Path to a .java, .py, or .js script file to execute.',
      },
      language: {
        type: 'string',
        enum: ['java', 'python', 'javascript'],
        description:
          'Script language. Use "java" (working GhidraScript path). Python is ' +
          'stubbed (Jython removed in 12.1). Auto-detected from file extension.',
      },
      scriptTimeout: {
        type: 'number',
        description: 'Execution timeout in seconds (default: 30)',
      },
      sandbox: {
        type: 'boolean',
        description: 'Run in sandboxed mode with restricted operations (default: true)',
      },
    }
  ),

  defineTool(
    'get_pcode',
    'Get P-Code (Ghidra intermediate representation) for a function. Useful for advanced analysis.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      highLevel: {
        type: 'boolean',
        description: 'Get high-level P-Code after optimization (default: false)',
      },
    }
  ),

  defineTool(
    'batch_pcode',
    'Get P-Code for multiple functions in one call. Much faster than individual get_pcode calls.',
    {
      ...sessionIdProp,
      addresses: {
        type: 'array',
        items: { type: 'string' },
        description: 'List of function addresses to get P-Code for',
      },
      highLevel: {
        type: 'boolean',
        description: 'Get high-level P-Code after optimization (default: false)',
      },
    }
  ),
];

// =============================================================================
// Phase 4: Modification Tools
// =============================================================================

export const modificationTools: ToolDefinition[] = [
  defineTool(
    'rename_symbol',
    'Rename a function, variable, label, or data item.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the symbol',
      },
      newName: {
        type: 'string',
        description: 'New name for the symbol',
      },
      type: {
        type: 'string',
        enum: ['function', 'variable', 'label', 'data'],
        description: 'Type of symbol to rename',
      },
      scope: {
        type: 'string',
        description: 'Scope for the rename (for local variables)',
      },
      description: {
        type: 'string',
        description: 'Optional description of what this function does. Updates @description in PLATE comment.',
      },
      skipSync: {
        type: 'boolean',
        description: 'Skip cross-binary sync (used internally to prevent loops)',
      },
    },
    ['address', 'newName', 'type']
  ),

  defineTool(
    'set_comment',
    'Set a comment at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address for the comment',
      },
      comment: {
        type: 'string',
        description: 'Comment text',
      },
      type: {
        type: 'string',
        enum: ['EOL', 'PRE', 'POST', 'PLATE', 'REPEATABLE'],
        description: 'Comment type (default: EOL)',
      },
    },
    ['address', 'comment']
  ),

  defineTool(
    'set_data_type',
    'Set the data type at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to set type at',
      },
      dataType: {
        type: 'string',
        description: 'Data type name (e.g., "int", "char*", "MyStruct")',
      },
      length: {
        type: 'number',
        description: 'Length for arrays or undefined types',
      },
      skipSync: {
        type: 'boolean',
        description: 'Skip cross-binary sync (used internally to prevent loops)',
      },
    },
    ['address', 'dataType']
  ),

  defineTool(
    'set_prototype',
    'Set a function\'s prototype/signature. The function\'s calling convention is preserved unless ' +
    'you ask to change it — pass callingConvention, or write it into the prototype the way C does ' +
    '("ushort __stdcall Foo(uint a)"). The resulting convention is reported back.',
    {
      ...sessionIdProp,
      functionAddress: {
        type: 'string',
        description: 'Function address',
      },
      prototype: {
        type: 'string',
        description: 'Function prototype (e.g., "int main(int argc, char **argv)"). A calling-convention keyword in it is understood.',
      },
      callingConvention: {
        type: 'string',
        description: 'Calling convention to set, e.g. "__stdcall", "__cdecl", "__fastcall", "__thiscall". Omit to keep the current one. For register conventions Ghidra has no name for (IDA\'s __usercall), use set_custom_signature.',
      },
      description: {
        type: 'string',
        description: 'Optional description of what this function does. Updates @description in PLATE comment.',
      },
      force: {
        type: 'boolean',
        description: 'Confirm ("yep sure"): apply even if the function has custom/register parameter storage. Without force=true such a function is REFUSED (a plain prototype string would clear its storage and break the decompile with phantom in_EAX/unaff_ params — use set_custom_signature instead). With force=true it clears the storage and returns a warning.',
      },
      skipSync: {
        type: 'boolean',
        description: 'Skip cross-binary sync (used internally to prevent loops)',
      },
    },
    ['functionAddress', 'prototype']
  ),

  defineTool(
    'set_custom_signature',
    'Set a function\'s signature with custom parameter storage. Use this for non-standard calling conventions where parameters are passed in specific registers.',
    {
      ...sessionIdProp,
      functionAddress: {
        type: 'string',
        description: 'Function entry point address',
      },
      returnType: {
        type: 'string',
        description: 'Return type (e.g., "void", "int", "void*")',
      },
      parameters: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Parameter name' },
            dataType: { type: 'string', description: 'Data type (e.g., "int", "void*")' },
            storage: { type: 'string', description: 'Storage location: register name (EAX, ECX, EDX, etc.) or "stack:0x4" for stack offset' },
          },
          required: ['name', 'dataType', 'storage'],
        },
        description: 'Array of parameter definitions with custom storage',
      },
      description: {
        type: 'string',
        description: 'Optional description of what this function does. Updates @description in PLATE comment.',
      },
    },
    ['functionAddress', 'parameters']
  ),

  defineTool(
    'create_structure',
    'Create a new structure data type. Bitfield members are written as C does — dataType "int:3" — ' +
    'and consecutive bitfields at one offset stack from the least significant bit up.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Structure name',
      },
      fields: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            dataType: { type: 'string', description: 'Data type; C bitfield syntax "int:3" is understood' },
            offset: { type: 'number' },
            bitOffset: { type: 'number', description: 'Bitfields only: bit position within the storage unit at offset' },
            comment: { type: 'string' },
          },
          required: ['name', 'dataType'],
        },
        description: 'Structure fields',
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
      packed: {
        type: 'boolean',
        description: 'Create as packed structure (default: false)',
      },
    },
    ['name', 'fields']
  ),

  defineTool(
    'batch_rename',
    'Rename multiple symbols at once. Supports dry-run mode.',
    {
      ...sessionIdProp,
      mappings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            address: { type: 'string' },
            newName: { type: 'string' },
          },
          required: ['address', 'newName'],
        },
        description: 'Array of address to new name mappings',
      },
      dryRun: {
        type: 'boolean',
        description: 'Only validate, don\'t apply changes (default: false)',
      },
      description: {
        type: 'string',
        description: 'Optional description of what these functions do. Updates @description in PLATE comment for each function.',
      },
    },
    ['mappings']
  ),

  // Bookmark management
  defineTool(
    'add_bookmark',
    'Add a bookmark at an address for easy navigation and notes.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address for the bookmark',
      },
      category: {
        type: 'string',
        description: 'Bookmark category (e.g., "Analysis", "TODO")',
      },
      comment: {
        type: 'string',
        description: 'Bookmark comment/description',
      },
      type: {
        type: 'string',
        enum: ['Note', 'Info', 'Warning', 'Error', 'Analysis'],
        description: 'Bookmark type (default: Note)',
      },
    },
    ['address']
  ),

  defineTool(
    'delete_bookmark',
    'Remove a bookmark at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the bookmark to delete',
      },
      type: {
        type: 'string',
        description: 'Bookmark type to delete (deletes all types if not specified)',
      },
    },
    ['address']
  ),

  defineTool(
    'delete_comment',
    'Remove a comment at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the comment to delete',
      },
      type: {
        type: 'string',
        enum: ['EOL', 'PRE', 'POST', 'PLATE', 'REPEATABLE', 'ALL'],
        description: 'Comment type to delete (default: EOL, ALL removes all types)',
      },
    },
    ['address']
  ),

  // Label management
  defineTool(
    'create_label',
    'Create a label/symbol at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address for the label',
      },
      name: {
        type: 'string',
        description: 'Label name',
      },
      namespace: {
        type: 'string',
        description: 'Namespace for the label (optional)',
      },
      primary: {
        type: 'boolean',
        description: 'Make this the primary symbol (default: true)',
      },
    },
    ['address', 'name']
  ),

  defineTool(
    'delete_label',
    'Delete a label/symbol at an address.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the label',
      },
      name: {
        type: 'string',
        description: 'Label name to delete (if multiple labels exist)',
      },
    },
    ['address']
  ),

  // Function management
  defineTool(
    'create_function',
    'Create a function at an address. Ghidra will analyze the function boundaries.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Entry point address for the function',
      },
      name: {
        type: 'string',
        description: 'Function name (optional, auto-generated if not specified)',
      },
    },
    ['address']
  ),

  defineTool(
    'delete_function',
    'Delete a function definition (does not delete the code).',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Entry point address of the function to delete',
      },
    },
    ['address']
  ),

  // Data type creation
  defineTool(
    'create_enum',
    'Create an enumeration data type.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Enum name',
      },
      values: {
        type: 'object',
        description: 'Map of enum member names to values (e.g., {"NONE": 0, "ACTIVE": 1})',
        additionalProperties: { type: 'number' },
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
      size: {
        type: 'number',
        description: 'Size in bytes (1, 2, 4, or 8, default: 4)',
      },
    },
    ['name', 'values']
  ),

  defineTool(
    'create_union',
    'Create a union data type.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Union name',
      },
      fields: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            dataType: { type: 'string' },
            comment: { type: 'string' },
          },
          required: ['name', 'dataType'],
        },
        description: 'Union fields (all start at offset 0)',
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
    },
    ['name', 'fields']
  ),

  defineTool(
    'create_typedef',
    'Create a typedef (type alias).',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Typedef name',
      },
      baseType: {
        type: 'string',
        description: 'Base data type name',
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
    },
    ['name', 'baseType']
  ),

  defineTool(
    'create_funcdef',
    'Create a function-definition datatype (funcdef) - the type a callback field or parameter '
      + 'should have. Refer to it afterwards by name with a trailing * (e.g. "pfnFreeEntry *") in '
      + 'update_structure, set_data_type or set_custom_signature. Give the calling convention '
      + 'explicitly: a funcdef left at the default is the same wrong-convention trap set_prototype '
      + 'used to cause. The response echoes callingConvention, effectiveCallingConvention and '
      + 'hasUnknownCallingConvention off the created type, so omitting one shows up immediately.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Funcdef name, e.g. "pfnLruFreeEntry"',
      },
      returnType: {
        type: 'string',
        description: 'Return type name (default: "void")',
      },
      parameters: {
        type: 'array',
        description: 'Parameters, in order',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Parameter name (default: param_N)' },
            dataType: { type: 'string', description: 'Type name, e.g. "D2UnitStrc *"' },
            comment: { type: 'string', description: 'Parameter comment' },
          },
          required: ['dataType'],
        },
      },
      callingConvention: {
        type: 'string',
        enum: ['__cdecl', '__stdcall', '__thiscall', '__fastcall', '__vectorcall', 'unknown'],
        description: 'Calling convention of the pointed-to function',
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
    },
    ['name']
  ),

  // Function attributes
  defineTool(
    'set_function_attributes',
    'Set function attributes like calling convention, noReturn, inline, and varArgs. All attributes are optional - only specified ones are changed.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      callingConvention: {
        type: 'string',
        enum: ['__cdecl', '__stdcall', '__thiscall', '__fastcall', '__vectorcall', 'unknown'],
        description: 'Calling convention to set',
      },
      noReturn: {
        type: 'boolean',
        description: 'Mark function as no-return',
      },
      inline: {
        type: 'boolean',
        description: 'Mark function as inline',
      },
      varArgs: {
        type: 'boolean',
        description: 'Mark function as having variable arguments',
      },
      force: {
        type: 'boolean',
        description: 'Confirm a destructive change ("yep sure"). Required when setting a standard calling convention on a function that has custom/register parameter storage: without force=true the call is REFUSED with an explanatory error (it would clear that storage and re-derive it). With force=true it proceeds and returns a warning describing what was cleared.',
      },
    }
  ),

  // Function tags
  defineTool(
    'add_function_tag',
    'Add a tag to a function. Creates the tag if it does not exist.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      tag: {
        type: 'string',
        description: 'Tag name to add',
      },
    },
    ['tag']
  ),

  defineTool(
    'remove_function_tag',
    'Remove a tag from a function.',
    {
      ...sessionIdProp,
      ...addressOrNameProps,
      tag: {
        type: 'string',
        description: 'Tag name to remove',
      },
    },
    ['tag']
  ),

  defineTool(
    'batch_tag_symbols',
    'Batch tag symbols (functions or data) with structured tags. Tag format: {type, data?} (e.g., {type:"method", data:"D2GameStrc"} or {type:"not-method"}). For functions, uses function tags. For non-functions, uses bookmarks.',
    {
      ...sessionIdProp,
      operations: {
        type: 'array',
        description: 'Array of tag operations to perform',
        items: {
          type: 'object',
          properties: {
            address: {
              type: 'string',
              description: 'Address of the symbol',
            },
            tag: {
              type: 'object',
              description: 'Structured tag with type and optional data',
              properties: {
                type: {
                  type: 'string',
                  description: 'Tag type (e.g., "method", "static-method", "not-method", "vtable", "dispatch-table")',
                },
                data: {
                  type: 'string',
                  description: 'Optional associated data (e.g., class name for methods)',
                },
              },
              required: ['type'],
            },
            action: {
              type: 'string',
              enum: ['add', 'remove'],
              description: 'Whether to add or remove the tag',
            },
          },
          required: ['address', 'tag', 'action'],
        },
      },
    },
    ['operations']
  ),

  // Namespace management
  defineTool(
    'create_namespace',
    'Create a new namespace or class in the program.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Namespace name',
      },
      parent: {
        type: 'string',
        description: 'Parent namespace (default: Global)',
      },
      isClass: {
        type: 'boolean',
        description: 'Create as class instead of namespace (default: false)',
      },
    },
    ['name']
  ),

  defineTool(
    'move_symbol_to_namespace',
    'Move a function, label, or data symbol to a different namespace.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the symbol to move',
      },
      namespace: {
        type: 'string',
        description: 'Target namespace name',
      },
      type: {
        type: 'string',
        enum: ['function', 'label', 'data'],
        description: 'Type of symbol to move',
      },
    },
    ['address', 'namespace', 'type']
  ),

  defineTool(
    'rename_namespace',
    'Rename an existing namespace.',
    {
      ...sessionIdProp,
      oldName: {
        type: 'string',
        description: 'Current namespace name',
      },
      newName: {
        type: 'string',
        description: 'New namespace name',
      },
    },
    ['oldName', 'newName']
  ),

  defineTool(
    'delete_namespace',
    'Delete a namespace. Useful for removing the empty namespace shell left after moving all symbols out (which otherwise emits an empty file in reconstructions). Refuses if the namespace still contains symbols unless force=true.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Namespace name to delete',
      },
      force: {
        type: 'boolean',
        description: 'Confirm ("yep sure"): delete even if the namespace still contains symbols (removes them). Without force=true, a non-empty namespace is refused with an explanatory error.',
      },
    },
    ['name']
  ),

  // Undo/redo
  defineTool(
    'undo',
    'Undo the last change to the program.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'redo',
    'Redo the last undone change to the program.',
    {
      ...sessionIdProp,
    }
  ),

  // Code manipulation
  defineTool(
    'disassemble',
    'Disassemble bytes at an address, creating code.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address to start disassembly',
      },
      length: {
        type: 'number',
        description: 'Number of bytes to disassemble (optional, auto-detects if not specified)',
      },
    },
    ['address']
  ),

  defineTool(
    'clear_listing',
    'Clear code or data at an address range, returning it to undefined bytes.',
    {
      ...sessionIdProp,
      startAddress: {
        type: 'string',
        description: 'Start address',
      },
      endAddress: {
        type: 'string',
        description: 'End address (optional, clears single item if not specified)',
      },
    },
    ['startAddress']
  ),

  defineTool(
    'set_function_variable_name',
    'Rename a local variable or parameter in a function.',
    {
      ...sessionIdProp,
      functionAddress: {
        type: 'string',
        description: 'Function entry point address',
      },
      oldName: {
        type: 'string',
        description: 'Current variable name',
      },
      newName: {
        type: 'string',
        description: 'New variable name',
      },
      description: {
        type: 'string',
        description: 'Optional description of what this function does. Updates @description in PLATE comment.',
      },
    },
    ['functionAddress', 'oldName', 'newName']
  ),

  defineTool(
    'set_function_variable_type',
    'Change the data type of a local variable or parameter.\n' +
    'The reply echoes resolvedType (the full category path the name landed on), and previousType. ' +
    'A name is matched exactly against the program\'s own types first, then against the builtin ' +
    'aliases case-insensitively, so "DWORD" finds WinDef.h/DWORD when the program has it. ' +
    'If the new type is a different size the reply also carries previousSize/newSize, plus ' +
    'removedVariables and warning when growing a stack slot displaced other locals.',
    {
      ...sessionIdProp,
      functionAddress: {
        type: 'string',
        description: 'Function entry point address',
      },
      variableName: {
        type: 'string',
        description: 'Variable name',
      },
      dataType: {
        type: 'string',
        description: 'New data type. Pass a category-qualified name (WinDef.h/DWORD) to pick one when the bare name is ambiguous.',
      },
      description: {
        type: 'string',
        description: 'Optional description of what this function does. Updates @description in PLATE comment.',
      },
      force: {
        type: 'boolean',
        description: 'If true, automatically remove any overlapping stack variables that conflict with the new type size. Use when applying a struct type that spans over several individually-named locals.',
      },
    },
    ['functionAddress', 'variableName', 'dataType']
  ),

  defineTool(
    'update_structure',
    'Update an existing structure data type. Operations:\n' +
    '- "replaceAll": Nuclear rebuild — deletes ALL fields and re-adds from scratch. Has safety check: rejects if new size < old size (use force=true to override). Use "updateFields" instead if you only need to change specific fields.\n' +
    '- "updateFields": Surgical batch update — rename, retype, or comment specific fields by name or offset. All other fields preserved.\n' +
    '- "insertField": Insert new field(s), struct grows.\n' +
    '- "deleteField": Delete a field by name, struct shrinks.\n' +
    'Deprecated aliases still work: "replace"→"replaceAll", "addField"→"insertField", "removeField"→"deleteField".\n' +
    'Bitfields: give dataType as C does, "int:3" or "uint:1". Consecutive bitfields at the same offset ' +
    'stack from the least significant bit up, so flag bits end up in one storage unit instead of ' +
    'scattered into separate bytes; pass bitOffset to place one explicitly.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Structure name',
      },
      operation: {
        type: 'string',
        enum: ['replaceAll', 'updateFields', 'insertField', 'deleteField'],
        description: 'Operation: "replaceAll" rebuild all fields, "updateFields" change specific fields, "insertField" to add, "deleteField" to remove',
      },
      fields: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Field name (for replaceAll/insertField)' },
            dataType: { type: 'string', description: 'Data type (for replaceAll/insertField). C bitfield syntax "int:3" is understood.' },
            offset: { type: 'number', description: 'Offset in struct' },
            bitOffset: { type: 'number', description: 'Bitfields only: bit position within the storage unit at offset (default: packed after the previous bitfield there)' },
            comment: { type: 'string', description: 'Field comment' },
            fieldName: { type: 'string', description: 'Identify field by name (for updateFields)' },
            newName: { type: 'string', description: 'Rename field to this (for updateFields)' },
            newDataType: { type: 'string', description: 'Retype field to this (for updateFields)' },
          },
        },
        description: 'For replaceAll/insertField: fields with name+dataType+offset. For updateFields: fields with fieldName/offset + newName/newDataType/comment.',
      },
      fieldName: {
        type: 'string',
        description: 'Field name for deleteField operation',
      },
      category: {
        type: 'string',
        description: 'Data type category path (to disambiguate)',
      },
      force: {
        type: 'boolean',
        description: 'Override replaceAll size safety check (default: false)',
      },
    },
    ['name', 'operation']
  ),

  defineTool(
    'delete_data_type',
    'Delete a data type (structure, enum, union, or typedef).',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Data type name',
      },
      category: {
        type: 'string',
        description: 'Data type category path (to disambiguate)',
      },
    },
    ['name']
  ),
];

// =============================================================================
// Phase 5: Advanced Tools
// =============================================================================

export const advancedTools: ToolDefinition[] = [
  defineTool(
    'list_data_types',
    'List available data types including structures, enums, and typedefs. Function-definition '
      + 'types also report callingConvention (the declared name, "unknown" when none is set), '
      + 'effectiveCallingConvention (what the decompiler actually applies - the compiler spec '
      + 'default when the declared name does not resolve) and hasUnknownCallingConvention. Those '
      + 'three are null on every other kind of data type.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
      category: {
        type: 'string',
        description: 'Filter by category path',
      },
    }
  ),

  defineTool(
    'get_data_type',
    'Get detailed information about a data type including structure fields and enum values. For a '
      + 'function definition this reports callingConvention verbatim, so a funcdef carrying '
      + '"unknown" reads as "unknown" rather than as no convention at all, plus '
      + 'effectiveCallingConvention and hasUnknownCallingConvention.',
    {
      ...sessionIdProp,
      name: {
        type: 'string',
        description: 'Data type name',
      },
      category: {
        type: 'string',
        description: 'Data type category path',
      },
    },
    ['name']
  ),

  defineTool(
    'list_comments',
    'List comments in the program.',
    {
      ...sessionIdProp,
      ...paginationProps,
      type: {
        type: 'string',
        enum: ['EOL', 'PRE', 'POST', 'PLATE', 'REPEATABLE'],
        description: 'Filter by comment type',
      },
      inFunction: {
        type: 'string',
        description: 'Filter by function name',
      },
    }
  ),

  defineTool(
    'list_bookmarks',
    'List bookmarks in the program.',
    {
      ...sessionIdProp,
      ...paginationProps,
      type: {
        type: 'string',
        description: 'Filter by bookmark type',
      },
      category: {
        type: 'string',
        description: 'Filter by category',
      },
    }
  ),

  defineTool(
    'list_equates',
    'List equates (symbolic names for numeric constants) in the program.',
    {
      ...sessionIdProp,
      ...paginationProps,
      ...filterProps,
      value: {
        type: 'number',
        description: 'Filter by exact numeric value',
      },
    }
  ),

  defineTool(
    'set_equate',
    'Set an equate (symbolic name for a numeric constant) at an instruction operand.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the instruction',
      },
      operandIndex: {
        type: 'number',
        description: 'Operand index (default: 0)',
      },
      value: {
        type: 'number',
        description: 'The numeric value to name',
      },
      name: {
        type: 'string',
        description: 'Symbolic name for the constant',
      },
    },
    ['address', 'value', 'name']
  ),

  defineTool(
    'get_undo_history',
    'Get the undo/redo history for the current program. Shows available undo and redo operations.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'reanalyze',
    'Re-run Ghidra auto-analysis on a specific function or the entire program.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of function to re-analyze (omit for entire program)',
      },
    }
  ),

  defineTool(
    'delete_equate',
    'Remove an equate reference at an instruction operand. If no more references remain, the equate is deleted entirely.',
    {
      ...sessionIdProp,
      address: {
        type: 'string',
        description: 'Address of the instruction',
      },
      operandIndex: {
        type: 'number',
        description: 'Operand index (default: 0)',
      },
      name: {
        type: 'string',
        description: 'Equate name to remove',
      },
    },
    ['address', 'name']
  ),

  defineTool(
    'get_dirty_symbols',
    'Get the list of symbols (functions, data types, globals) that have been modified since the last clean mark. Used for incremental reconstruction.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'mark_clean',
    'Mark the current program state as clean, clearing all dirty tracking. Call after a successful reconstruction or extraction.',
    {
      ...sessionIdProp,
    }
  ),
];

// =============================================================================
// Debugging Tools
// =============================================================================

export const debuggingTools: ToolDefinition[] = [
  defineTool(
    'get_logs',
    'Query daemon and worker logs for debugging. Returns recent log entries filtered by session, level, or component.',
    {
      sessionId: {
        type: 'string',
        description: 'Filter logs by session ID',
      },
      workerId: {
        type: 'string',
        description: 'Filter logs by worker ID',
      },
      level: {
        type: 'string',
        enum: ['ERROR', 'WARN', 'INFO', 'DEBUG'],
        description: 'Minimum log level to include (default: INFO)',
      },
      component: {
        type: 'string',
        description: 'Filter by component name (e.g., "WorkerPool", "GhidraEngine")',
      },
      since: {
        type: 'number',
        description: 'Only return logs after this Unix timestamp (milliseconds)',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of log entries to return (default: 100)',
      },
    }
  ),
];

// =============================================================================
// Version Tracking Tools
// =============================================================================

export const versionTrackingTools: ToolDefinition[] = [
  defineTool(
    'vt_create_session',
    'Create a Version Tracking session between two loaded programs. Both programs must be loaded in the same worker (same .gpr project). ' +
    'Use list_programs to see loaded programs.',
    {
      ...sessionIdProp,
      sourceProgramPath: {
        type: 'string',
        description: 'Path of the source program (the one with names/types to transfer FROM)',
      },
      destProgramPath: {
        type: 'string',
        description: 'Path of the destination program (the one to transfer names/types TO)',
      },
    },
    ['sourceProgramPath', 'destProgramPath']
  ),

  defineTool(
    'vt_run_correlator',
    'Run a correlator algorithm to find matching functions between source and destination. ' +
    'Each correlator uses a different matching strategy. Run multiple for best coverage.',
    {
      ...sessionIdProp,
      correlatorName: {
        type: 'string',
        description: 'Name of the correlator (e.g., "Exact Symbol Name Match", "Exact Function Bytes Match")',
      },
    },
    ['correlatorName']
  ),

  defineTool(
    'vt_list_matches',
    'List matches found by correlators. Filter by minimum similarity score.',
    {
      ...sessionIdProp,
      minScore: {
        type: 'number',
        description: 'Minimum similarity score (0.0-1.0, default: 0.0)',
      },
      limit: {
        type: 'number',
        description: 'Maximum matches to return (default: 100)',
      },
    }
  ),

  defineTool(
    'vt_accept_matches',
    'Accept matches for markup transfer. Only accepted matches will have their markup applied.',
    {
      ...sessionIdProp,
      acceptAll: {
        type: 'boolean',
        description: 'Accept all available matches (filtered by minScore if set)',
      },
      minScore: {
        type: 'number',
        description: 'Only accept matches with score >= this value (default: 0.0)',
      },
    }
  ),

  defineTool(
    'vt_apply_markup',
    'Apply markup (function names, types, comments, etc.) from accepted matches to the destination program. ' +
    'Run vt_accept_matches first.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'vt_get_correlators',
    'List available Version Tracking correlator algorithms.',
    {
      ...sessionIdProp,
    }
  ),
];

// =============================================================================
// Cross-Binary Link Tools
// =============================================================================

// =============================================================================
// Type Archive Tools
// =============================================================================

export const typeArchiveTools: ToolDefinition[] = [
  defineTool(
    'export_type_archive',
    'Export data types from a session into a Ghidra .gdt archive file. ' +
    'Use categories to filter (e.g., ["/Diablo2"] for all D2 types).',
    {
      ...sessionIdProp,
      archivePath: {
        type: 'string',
        description: 'Output path for the .gdt archive file',
      },
      categories: {
        type: 'array',
        items: { type: 'string' },
        description: 'Category paths to export (e.g., ["/Diablo2"]). Omit for all types.',
      },
    },
    ['archivePath']
  ),

  defineTool(
    'import_type_archive',
    'Import data types from a .gdt archive file into a session. ' +
    'Replaces existing types with matching names. Use this to share types across programs.',
    {
      ...sessionIdProp,
      archivePath: {
        type: 'string',
        description: 'Path to the .gdt archive file to import',
      },
      categories: {
        type: 'array',
        items: { type: 'string' },
        description: 'Only import types under these categories. Omit for all types.',
      },
    },
    ['archivePath']
  ),
];

// =============================================================================
// Cross-Binary Link Tools
// =============================================================================

export const linkTools: ToolDefinition[] = [
  defineTool(
    'create_link',
    'Create a cross-binary link between two addresses in different sessions. ' +
    'Links track corresponding functions/data across platforms (e.g., Windows ↔ Mac). ' +
    'Set anchor=true for high-confidence links from table discovery.',
    {
      sourceSession: {
        type: 'string',
        description: 'Session ID or alias of the source binary',
      },
      sourceAddress: {
        type: 'string',
        description: 'Address in the source binary (e.g., "0x00401234")',
      },
      targetSession: {
        type: 'string',
        description: 'Session ID or alias of the target binary',
      },
      targetAddress: {
        type: 'string',
        description: 'Address in the target binary',
      },
      linkType: {
        type: 'string',
        description: 'Type of link: "function", "data", "table_entry" (default: "function")',
      },
      anchor: {
        type: 'boolean',
        description: 'Whether this is a high-confidence anchor link (default: false)',
      },
      metadata: {
        type: 'object',
        description: 'Optional metadata (e.g., {tableName: "...", entryIndex: 5})',
      },
    },
    ['sourceSession', 'sourceAddress', 'targetSession', 'targetAddress']
  ),

  defineTool(
    'remove_link',
    'Remove a cross-binary link by its ID.',
    {
      id: {
        type: 'string',
        description: 'The link ID to remove',
      },
    },
    ['id']
  ),

  defineTool(
    'query_links',
    'Query cross-binary links. Filter by session, address, type, or anchor status.',
    {
      sessionId: {
        type: 'string',
        description: 'Filter by session ID or alias (matches source or target)',
      },
      address: {
        type: 'string',
        description: 'Filter by address (matches source or target)',
      },
      type: {
        type: 'string',
        description: 'Filter by link type (e.g., "function", "data")',
      },
      anchor: {
        type: 'boolean',
        description: 'Filter by anchor status',
      },
    }
  ),

  defineTool(
    'bulk_create_links',
    'Create multiple cross-binary links in a single transaction. Much faster than individual create_link calls for large batches.',
    {
      links: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            sourceSession: { type: 'string', description: 'Source session ID or alias' },
            sourceAddress: { type: 'string', description: 'Address in the source binary' },
            targetSession: { type: 'string', description: 'Target session ID or alias' },
            targetAddress: { type: 'string', description: 'Address in the target binary' },
            linkType: { type: 'string', description: 'Link type (default: "function")' },
            anchor: { type: 'boolean', description: 'Anchor flag (default: false)' },
            metadata: { type: 'object', description: 'Optional metadata' },
          },
          required: ['sourceSession', 'sourceAddress', 'targetSession', 'targetAddress'],
        },
        description: 'Array of links to create',
      },
    },
    ['links']
  ),

  defineTool(
    'clear_links',
    'Delete all cross-binary links, optionally scoped to specific source/target sessions. Returns the number of links deleted.',
    {
      sourceSession: {
        type: 'string',
        description: 'Only delete links from this source session (optional)',
      },
      targetSession: {
        type: 'string',
        description: 'Only delete links to this target session (optional)',
      },
    }
  ),

  defineTool(
    'discover_table_anchors',
    'Discover and create anchor links by reading known function-pointer tables on both platforms. ' +
    'Same table index = same function, creating guaranteed 1:1 links.',
    {
      winSession: {
        type: 'string',
        description: 'Windows session ID or alias',
      },
      macSession: {
        type: 'string',
        description: 'Mac session ID or alias',
      },
      dryRun: {
        type: 'boolean',
        description: 'Preview without creating links (default: false)',
      },
      tables: {
        type: 'array',
        items: { type: 'string' },
        description: 'Only process these table names (default: all known tables)',
      },
    },
    ['winSession', 'macSession']
  ),

  defineTool(
    'sync_status',
    'Show recent cross-binary sync operations. Displays renames/retypes that were propagated between linked sessions.',
    {
      limit: {
        type: 'number',
        description: 'Maximum number of recent syncs to return (default: 50)',
      },
    }
  ),
];

// =============================================================================
// Dependency Validation Tools
// =============================================================================

export const dependencyTools: ToolDefinition[] = [
  defineTool(
    'validate_dependencies',
    'Validate that reconstructed source files only include headers from modules in their dependency tree. ' +
    'Parses #include directives and checks against the module graph in project.json.',
    {
      projectJsonPath: {
        type: 'string',
        description: 'Path to project.json (default: auto-detect from reconstructed directory)',
      },
    }
  ),
];

// =============================================================================
// Export All Tools
// =============================================================================

export function getAllToolDefinitions(): ToolDefinition[] {
  return [
    ...sessionTools,
    ...aliasTools,
    ...sharedStructureTools,
    ...multiProgramTools,
    ...coreReadTools,
    ...navigationTools,
    ...llmPowerTools,
    ...modificationTools,
    ...advancedTools,
    ...versionTrackingTools,
    ...typeArchiveTools,
    ...linkTools,
    ...dependencyTools,
    ...debuggingTools,
  ];
}

// Alias for compatibility
export const getAllTools = getAllToolDefinitions;

export function getToolByName(name: string): ToolDefinition | undefined {
  return getAllToolDefinitions().find(t => t.name === name);
}
