/**
 * Public tool schemas, derived from the daemon's own definitions, and the
 * argument check every incoming call passes before it is forwarded.
 *
 * It has no runtime dependencies: the daemon's tool definitions are passed in.
 */

import {
  DEFAULT_PROGRAM,
  EXPOSED_TOOLS,
  GATEWAY_LOCAL_TOOLS,
  PINNING_ARGS,
  PROGRAM_ARG,
  PUBLIC_PROGRAMS,
  exclusionGroupOf,
  isExposed,
  isGatewayLocal,
  isPublicProgram,
  type ExposedTool,
  type PublicProgram,
  type ToolTier,
} from './allowlist.js';

/** The shape of one daemon tool definition, as @ghidra-mcp/mcp exports it. */
export interface ToolDefinitionLike {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

export interface PublicTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
  annotations: {
    readOnlyHint: true;
    destructiveHint: false;
    idempotentHint: true;
    openWorldHint: false;
  };
  /** The tool's cost tier, so a front that rate-limits can charge costly tools more. */
  _meta?: { [TIER_META_KEY]: ToolTier };
}

export const TIER_META_KEY = 'ghidra-mcp/tier';

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const PROGRAM_SCHEMA = {
  type: 'string',
  enum: [...PUBLIC_PROGRAMS],
  default: DEFAULT_PROGRAM,
  description: 'Which build to read: "win" (Windows 1.14d Game.exe, default) or "mac" (Mac 1.14d).',
} as const;

const SET_OUTPUT_FORMAT: PublicTool = {
  name: 'set_output_format',
  description: 'Set the output format for your calls: "toon" (default, compact) or "json". Remembered per caller.',
  inputSchema: {
    type: 'object',
    properties: { format: { type: 'string', enum: ['toon', 'json'] } },
    required: ['format'],
  },
  annotations: READ_ONLY,
};

/** Thrown for a call that is refused; the message is safe to show the caller. */
export class RefusedError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
    this.name = 'RefusedError';
  }
}

function strippedArgs(spec: ExposedTool): Set<string> {
  return new Set([...PINNING_ARGS, PROGRAM_ARG, ...(spec.dropArgs ?? [])]);
}

function describeLimits(spec: ExposedTool): string {
  const parts: string[] = [];
  for (const [arg, { max }] of Object.entries(spec.clamp ?? {})) parts.push(`${arg} <= ${max}`);
  for (const [arg, max] of Object.entries(spec.maxItems ?? {})) parts.push(`${arg}: at most ${max} entries`);
  return parts.length ? ` Limits: ${parts.join(', ')}.` : '';
}

/**
 * The exposed tools as the public sees them: pinning arguments gone, the
 * program enum added, limits stated, read-only annotated.
 */
export function buildPublicTools(definitions: readonly ToolDefinitionLike[]): PublicTool[] {
  const tools: PublicTool[] = [];
  for (const def of definitions) {
    const spec = EXPOSED_TOOLS[def.name];
    if (!spec) continue;
    const drop = strippedArgs(spec);
    const properties: Record<string, unknown> = {};
    for (const [key, schema] of Object.entries(def.inputSchema.properties)) {
      if (drop.has(key)) continue;
      const bound = spec.clamp?.[key];
      const items = spec.maxItems?.[key];
      properties[key] = bound
        ? { ...(schema as object), maximum: bound.max }
        : items
          ? { ...(schema as object), maxItems: items }
          : schema;
    }
    properties[PROGRAM_ARG] = PROGRAM_SCHEMA;
    const required = def.inputSchema.required?.filter((r) => !drop.has(r));
    tools.push({
      name: def.name,
      description: def.description + describeLimits(spec),
      inputSchema: {
        type: 'object',
        properties,
        ...(required && required.length ? { required } : {}),
      },
      annotations: READ_ONLY,
      _meta: { [TIER_META_KEY]: spec.tier },
    });
  }
  tools.push(SET_OUTPUT_FORMAT);
  return tools;
}

export interface CheckedCall {
  name: string;
  /** Always one of PUBLIC_PROGRAMS; never forwarded as an argument. */
  program: PublicProgram;
  /** The arguments to forward, with limits applied and the program argument removed. */
  args: Record<string, unknown>;
}

/**
 * Checks calls against the allowlist and the public schemas built from one
 * set of daemon definitions.
 */
export class CallChecker {
  readonly tools: PublicTool[];
  private readonly byName: Map<string, PublicTool>;

  constructor(definitions: readonly ToolDefinitionLike[]) {
    this.tools = buildPublicTools(definitions);
    this.byName = new Map(this.tools.map((t) => [t.name, t]));
  }

  /** The tool names answered, including the ones answered locally. */
  names(): string[] {
    return [...this.byName.keys()];
  }

  /**
   * Check a call and return what to forward. Unknown arguments are refused
   * rather than dropped, so a caller who tries to name a session or a path
   * learns that it cannot.
   */
  check(name: unknown, args: unknown): CheckedCall {
    if (typeof name !== 'string' || !name) throw new RefusedError('Tool name is required.', 'bad_request');
    if (!isExposed(name) && !isGatewayLocal(name)) {
      const group = exclusionGroupOf(name);
      throw new RefusedError(
        group ? `Tool "${name}" is not available on this read-only server.` : `Unknown tool "${name}".`,
        group ? `excluded:${group}` : 'unknown_tool',
      );
    }
    if (args !== undefined && (typeof args !== 'object' || args === null || Array.isArray(args))) {
      throw new RefusedError('Tool arguments must be an object.', 'bad_request');
    }
    const input = (args ?? {}) as Record<string, unknown>;
    const tool = this.byName.get(name);
    if (!tool) throw new RefusedError(`Unknown tool "${name}".`, 'unknown_tool');

    for (const key of Object.keys(input)) {
      if (PINNING_ARGS.includes(key)) {
        throw new RefusedError(
          `Argument "${key}" is not accepted: choose a build with "program" ("win" or "mac").`,
          'pinning_arg',
        );
      }
      if (!Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, key)) {
        throw new RefusedError(`Argument "${key}" is not accepted by ${name}.`, 'unknown_arg');
      }
    }

    if (isGatewayLocal(name)) return { name, program: DEFAULT_PROGRAM, args: { ...input } };

    const { [PROGRAM_ARG]: rawProgram, ...rest } = input;
    if (rawProgram !== undefined && !isPublicProgram(rawProgram)) {
      throw new RefusedError('Argument "program" must be "win" or "mac".', 'pinning_arg');
    }
    const program: PublicProgram = rawProgram ?? DEFAULT_PROGRAM;

    const spec = EXPOSED_TOOLS[name];
    const out: Record<string, unknown> = { ...rest };
    for (const [key, max] of Object.entries(spec.maxItems ?? {})) {
      const v = out[key];
      if (v === undefined) continue;
      if (!Array.isArray(v)) throw new RefusedError(`Argument "${key}" must be an array.`, 'bad_request');
      if (v.length > max) {
        throw new RefusedError(`Argument "${key}" has ${v.length} entries; at most ${max} are allowed.`, 'batch_too_large');
      }
    }
    for (const [key, { max, default: dflt }] of Object.entries(spec.clamp ?? {})) {
      const v = out[key];
      if (v === undefined) {
        if (dflt !== undefined) out[key] = dflt;
        continue;
      }
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new RefusedError(`Argument "${key}" must be a number.`, 'bad_request');
      }
      if (v > max) out[key] = max;
    }
    return { name, program, args: out };
  }
}

/**
 * Remove what describes the server rather than the program from a JSON answer:
 * DENIED_RESPONSE_KEYS at any depth, and for tools with keepKeys everything
 * else at the top level. Text that is not JSON is returned unchanged.
 */
export function stripResponseKeys(toolName: string, data: unknown, denied: readonly string[]): unknown {
  const deny = new Set(denied);
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v === null || typeof v !== 'object') return v;
    const out: Record<string, unknown> = {};
    for (const [k, inner] of Object.entries(v as Record<string, unknown>)) {
      if (!deny.has(k)) out[k] = walk(inner);
    }
    return out;
  };
  let result = walk(data);
  const keep = EXPOSED_TOOLS[toolName]?.keepKeys;
  if (keep && result !== null && typeof result === 'object' && !Array.isArray(result)) {
    const kept: Record<string, unknown> = {};
    for (const k of keep) if (k in (result as Record<string, unknown>)) kept[k] = (result as Record<string, unknown>)[k];
    result = kept;
  }
  return result;
}
