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
    'Create a new Ghidra session for analyzing a binary or open an existing Ghidra project. ' +
    'Pass a binary path to import and analyze, or a .gpr file path to open an existing project. ' +
    'For .gpr projects with multiple programs, specify programPath to select which one to load. ' +
    'Pass a ghidra://[user:password@]host:port/repo/program/path URL to open a shared program from a Ghidra Server.',
    {
      binaryPath: {
        type: 'string',
        description: 'Path to the binary file to analyze, a path to an existing .gpr project file, or a ghidra://[user:password@]host:port/repo/program URL for a Ghidra Server shared program',
      },
      programPath: {
        type: 'string',
        description: 'Path of program within .gpr project (e.g., "/windows/1.14d/Game.exe"). Required when project has multiple programs.',
      },
      autoAnalyze: {
        type: 'boolean',
        description: 'Automatically run analysis after loading (default: true)',
      },
      analysisTimeout: {
        type: 'number',
        description: 'Maximum time for analysis in milliseconds (default: 300000)',
      },
    },
    ['binaryPath']
  ),

  defineTool(
    'close_session',
    'Close a Ghidra session and terminate its worker process.',
    {
      ...sessionIdProp,
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
    'List all repositories available on the configured Ghidra Server. Requires an active server session.',
    {
      ...sessionIdProp,
    }
  ),

  defineTool(
    'list_programs',
    'List all programs in the open Ghidra project (.gpr). Shows which are loaded.',
    {
      ...sessionIdProp,
    }
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
    'Get detailed information about a specific function including parameters, local variables, and calling convention.',
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
        enum: ['FUNCTION', 'LABEL', 'CLASS', 'NAMESPACE', 'PARAMETER', 'LOCAL_VAR', 'GLOBAL_VAR', 'EXTERNAL'],
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
        description: 'Filter by data type name',
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
    '"bytes" uses hex patterns with ?? wildcards (e.g. "55 8B EC"), not regex.',
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
    },
    ['type']
  ),

  defineTool(
    'find_functions_matching',
    'Find functions that match compound criteria. Essential for finding related code patterns.',
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
      limit: {
        type: 'number',
        description: 'Maximum results (default: 50)',
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
    'Set a function\'s prototype/signature.',
    {
      ...sessionIdProp,
      functionAddress: {
        type: 'string',
        description: 'Function address',
      },
      prototype: {
        type: 'string',
        description: 'Function prototype (e.g., "int main(int argc, char **argv)")',
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
    'Create a new structure data type.',
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
            dataType: { type: 'string' },
            offset: { type: 'number' },
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
    'Change the data type of a local variable or parameter.',
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
        description: 'New data type',
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
    'Deprecated aliases still work: "replace"→"replaceAll", "addField"→"insertField", "removeField"→"deleteField".',
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
            dataType: { type: 'string', description: 'Data type (for replaceAll/insertField)' },
            offset: { type: 'number', description: 'Offset in struct' },
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
    'List available data types including structures, enums, and typedefs.',
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
    'Get detailed information about a data type including structure fields and enum values.',
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
