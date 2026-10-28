/**
 * The tools the gateway exposes, and why every other daemon tool is not exposed.
 *
 * This list is the security boundary's first gate: a tool that is not named in
 * EXPOSED_TOOLS is refused before anything else looks at the call, whatever its
 * name. Every daemon tool must appear exactly once across EXPOSED_TOOLS and
 * EXCLUDED_GROUPS - the unit tests fail when the daemon gains a tool nobody has
 * classified, so a new write tool can never become public by default.
 */

/** cheap: bounded single-object reads. costly: decompiler/graph/whole-program work. */
export type ToolTier = 'cheap' | 'costly';

export interface ExposedTool {
  tier: ToolTier;
  /**
   * Arguments the daemon accepts that the gateway removes from the schema and
   * refuses on input, beyond the session/program arguments refused for every tool.
   */
  dropArgs?: readonly string[];
  /** Numeric arguments clamped to a ceiling; a default is supplied when the daemon's own is unbounded. */
  clamp?: Readonly<Record<string, { max: number; default?: number }>>;
  /** Array arguments refused when longer than this. */
  maxItems?: Readonly<Record<string, number>>;
  /**
   * When set, only these top-level keys of the tool's JSON answer reach the
   * caller. For tools whose answer describes where the program lives rather
   * than what is in it.
   */
  keepKeys?: readonly string[];
}

const PAGE = { limit: { max: 500 } } as const;

export const EXPOSED_TOOLS: Readonly<Record<string, ExposedTool>> = {
  // Program and function metadata.
  // path is the import path on the importer's disk; version fields describe the server.
  get_program_info: {
    tier: 'cheap',
    keepKeys: ['name', 'format', 'languageId', 'compiler', 'imageBase', 'minAddress', 'maxAddress',
      'endianness', 'pointerSize'],
  },
  list_functions: { tier: 'cheap', clamp: PAGE },
  get_function_info: { tier: 'cheap' },
  get_function_summary: { tier: 'cheap', clamp: { maxCalls: { max: 200 }, maxCallers: { max: 200 } } },
  get_stack_frame: { tier: 'cheap' },
  get_basic_blocks: { tier: 'cheap' },
  get_class_info: { tier: 'cheap' },

  // Listing, bytes and data.
  get_disassembly: { tier: 'cheap', clamp: { count: { max: 2000 }, context: { max: 200 } } },
  read_memory: { tier: 'cheap', clamp: { length: { max: 65536 } } },
  get_hexdump: { tier: 'cheap', clamp: { length: { max: 65536 } } },
  read_data_value: { tier: 'cheap' },
  get_data_at_address: { tier: 'cheap', clamp: { lookAhead: { max: 64 } } },
  get_symbol_after: { tier: 'cheap', clamp: { count: { max: 200 } } },
  get_switch_table: { tier: 'cheap' },
  // applyType/name would create a data type at the address.
  detect_table: { tier: 'cheap', dropArgs: ['applyType', 'name'], clamp: { maxEntries: { max: 1024 } } },

  // Symbol and type listings.
  list_strings: { tier: 'cheap', clamp: PAGE },
  list_imports: { tier: 'cheap', clamp: PAGE },
  list_exports: { tier: 'cheap', clamp: PAGE },
  list_symbols: { tier: 'cheap', clamp: PAGE },
  list_data_symbols: { tier: 'cheap', clamp: PAGE },
  list_segments: { tier: 'cheap', clamp: PAGE },
  list_namespaces: { tier: 'cheap', clamp: PAGE },
  list_data_types: { tier: 'cheap', clamp: PAGE },
  get_data_type: { tier: 'cheap' },
  list_comments: { tier: 'cheap', clamp: PAGE },
  list_bookmarks: { tier: 'cheap', clamp: PAGE },
  list_equates: { tier: 'cheap', clamp: PAGE },
  get_xrefs: { tier: 'cheap', clamp: PAGE },
  get_analysis_hints: { tier: 'cheap' },

  // Decompiler, graph and whole-program scans.
  decompile: { tier: 'costly', clamp: { decompileTimeout: { max: 60 } } },
  batch_decompile: {
    tier: 'costly',
    clamp: { limit: { max: 20, default: 20 }, decompileTimeout: { max: 60 } },
    maxItems: { addresses: 20, names: 20 },
  },
  get_pcode: { tier: 'costly' },
  batch_pcode: { tier: 'costly', maxItems: { addresses: 20 } },
  get_xrefs_with_context: { tier: 'costly', clamp: { limit: { max: 200 }, contextLines: { max: 20 } } },
  get_call_graph: { tier: 'costly', clamp: { depth: { max: 5 }, maxNodes: { max: 500 } } },
  find_call_path: { tier: 'costly', clamp: { maxDepth: { max: 10 } } },
  trace_data_flow: { tier: 'costly', clamp: { depth: { max: 10 } } },
  search: { tier: 'costly', clamp: { limit: { max: 500 }, maxFunctions: { max: 200, default: 200 } } },
  find_functions_matching: { tier: 'costly', clamp: PAGE },
};

/**
 * Arguments refused on every tool: they select a session, program, repository
 * or file, and the gateway alone decides which program a call reads.
 */
export const PINNING_ARGS: readonly string[] = [
  'sessionId', 'session', 'alias', 'winSession', 'macSession', 'sourceSession', 'targetSession',
  'path', 'programPath', 'binaryPath', 'repo', 'folder', 'filePath', 'archivePath',
  'projectJsonPath', 'sourceProgramPath', 'destProgramPath', 'workerId',
];

/**
 * The programs the public surface serves, by name. Callers pick one of these
 * names; which server path each name opens lives in the origin's configuration
 * and never in a request.
 */
export const PUBLIC_PROGRAMS = ['win', 'mac'] as const;
export type PublicProgram = typeof PUBLIC_PROGRAMS[number];
export const DEFAULT_PROGRAM: PublicProgram = 'win';
/**
 * The name get_program_info reports for each program. The database name on the
 * server carries internal suffixes; callers see the binary's own file name.
 */
export const PUBLIC_PROGRAM_NAMES: Readonly<Record<PublicProgram, string>> = { win: 'Game.exe', mac: 'DiabloII_macho' };
/** The one argument that selects a program, and only from PUBLIC_PROGRAMS. */
export const PROGRAM_ARG = 'program';

export function isPublicProgram(v: unknown): v is PublicProgram {
  return typeof v === 'string' && (PUBLIC_PROGRAMS as readonly string[]).includes(v);
}

/**
 * Keys removed from every JSON answer, at any depth: they name sessions,
 * workers, files on the server or on someone's disk, server hosts and users,
 * or the server's version bookkeeping.
 */
export const DENIED_RESPONSE_KEYS: readonly string[] = [
  'sessionId', 'workerId', 'pid', 'host', 'user', 'owner', 'repo', 'folder', 'project',
  'programPath', 'binaryPath', 'projectPath', 'archivePath', 'localPath', 'url', 'executablePath', 'fsrl',
  'sourceProgram', 'sourcePath', 'destProgram', 'destPath', 'checkoutId', 'checkoutType', 'checkedOut',
  'version', 'latestVersion', 'versionLoadedAt', 'lastCleanVersion', 'cacheVersion', 'changeSeq',
];

/**
 * set_output_format is answered by the gateway itself, per caller, and never
 * forwarded: the daemon's own format setting is per connection.
 */
export const GATEWAY_LOCAL_TOOLS = ['set_output_format'] as const;

export interface ExcludedGroup {
  reason: string;
  tools: readonly string[];
}

export const EXCLUDED_GROUPS: Readonly<Record<string, ExcludedGroup>> = {
  sessions: {
    reason: 'sessions are pinned by the gateway; these open, close, list or re-point them and expose other callers\' sessions',
    tools: [
      'list_sessions', 'create_session', 'close_session', 'save_session', 'set_default_session',
      'set_session_alias', 'remove_session_alias', 'list_session_aliases', 'load_program',
    ],
  },
  repository: {
    reason: 'the repository holding 1.14d also holds non-public builds; listing or opening it leaks them',
    tools: [
      'list_repos', 'list_programs', 'list_checkouts', 'create_repo', 'import_program', 'import_status',
      'delete_program', 'move_program', 'terminate_checkout', 'request_upload',
    ],
  },
  leaky: {
    reason: 'reveal daemon logs, edit history or other programs\' state rather than the pinned program',
    tools: [
      'get_logs', 'get_changes', 'get_undo_history', 'get_dirty_symbols', 'sync_status',
      'analyze_status', 'query_links', 'list_shared_structures', 'vt_list_matches', 'vt_get_correlators',
    ],
  },
  code: {
    reason: 'runs caller-supplied code or reads daemon-side files',
    tools: ['execute_script', 'validate_dependencies', 'export_type_archive', 'import_type_archive'],
  },
  writes: {
    reason: 'mutate the program, even in memory on a read-only session; writes go through a separate proposal flow',
    tools: [
      'rename_symbol', 'set_comment', 'set_data_type', 'set_prototype', 'set_custom_signature',
      'create_structure', 'batch_rename', 'add_bookmark', 'delete_bookmark', 'delete_comment',
      'create_label', 'delete_label', 'create_function', 'delete_function', 'create_enum', 'create_union',
      'create_typedef', 'create_funcdef', 'set_function_attributes', 'add_function_tag',
      'remove_function_tag', 'batch_tag_symbols', 'create_namespace', 'move_symbol_to_namespace',
      'rename_namespace', 'delete_namespace', 'undo', 'redo', 'disassemble', 'clear_listing',
      'set_function_variable_name', 'set_function_variable_type', 'update_structure', 'delete_data_type',
      'set_equate', 'delete_equate', 'set_switch_override', 'mark_clean',
      'create_shared_structure', 'update_shared_structure', 'delete_shared_structure', 'sync_shared_structures',
      'create_link', 'remove_link', 'bulk_create_links', 'clear_links', 'discover_table_anchors',
      'vt_create_session', 'vt_run_correlator', 'vt_accept_matches', 'vt_apply_markup',
    ],
  },
  admin: {
    reason: 'commit, analyse or save change the server copy or burn the shared worker for minutes',
    tools: ['commit', 'analyze', 'reanalyze'],
  },
};

export function isExposed(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(EXPOSED_TOOLS, name);
}

export function isGatewayLocal(name: string): boolean {
  return (GATEWAY_LOCAL_TOOLS as readonly string[]).includes(name);
}

/** The group a refused tool belongs to, for the refusal message and the audit line. */
export function exclusionGroupOf(name: string): string | undefined {
  for (const [group, { tools }] of Object.entries(EXCLUDED_GROUPS)) {
    if (tools.includes(name)) return group;
  }
  return undefined;
}
