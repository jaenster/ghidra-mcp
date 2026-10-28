/**
 * Public tool schemas, derived from the daemon's own definitions, and the
 * argument check every incoming call passes before it is forwarded.
 */

import { getAllToolDefinitions } from '@ghidra-mcp/mcp';
import {
  EXPOSED_TOOLS,
  GATEWAY_LOCAL_TOOLS,
  PINNING_ARGS,
  exclusionGroupOf,
  isExposed,
  isGatewayLocal,
  type ExposedTool,
} from './allowlist.js';

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
}

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
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

/** Thrown for a call the gateway refuses; the message is safe to show the caller. */
export class RefusedError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
    this.name = 'RefusedError';
  }
}

function strippedArgs(spec: ExposedTool): Set<string> {
  return new Set([...PINNING_ARGS, ...(spec.dropArgs ?? [])]);
}

function describeLimits(spec: ExposedTool): string {
  const parts: string[] = [];
  for (const [arg, { max }] of Object.entries(spec.clamp ?? {})) parts.push(`${arg} <= ${max}`);
  for (const [arg, max] of Object.entries(spec.maxItems ?? {})) parts.push(`${arg}: at most ${max} entries`);
  return parts.length ? ` Gateway limits: ${parts.join(', ')}.` : '';
}

/** The exposed tools as the public sees them: pinning arguments gone, limits stated, read-only annotated. */
export function buildPublicTools(): PublicTool[] {
  const tools: PublicTool[] = [];
  for (const def of getAllToolDefinitions()) {
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
    });
  }
  tools.push(SET_OUTPUT_FORMAT);
  return tools;
}

let publicToolsCache: Map<string, PublicTool> | null = null;

function publicToolMap(): Map<string, PublicTool> {
  if (!publicToolsCache) publicToolsCache = new Map(buildPublicTools().map((t) => [t.name, t]));
  return publicToolsCache;
}

/** The tool names the gateway answers, including the ones it answers itself. */
export function publicToolNames(): string[] {
  return [...publicToolMap().keys()];
}

/**
 * Check a call against the allowlist and the tool's public schema, and return
 * the arguments to forward. Unknown arguments are refused rather than dropped,
 * so a caller who tries to name a session or a program learns that it cannot.
 */
export function checkCall(name: unknown, args: unknown): { name: string; args: Record<string, unknown> } {
  if (typeof name !== 'string' || !name) throw new RefusedError('Tool name is required.', 'bad_request');
  if (!isExposed(name) && !isGatewayLocal(name)) {
    const group = exclusionGroupOf(name);
    throw new RefusedError(
      group
        ? `Tool "${name}" is not available on this read-only gateway (${group}).`
        : `Unknown tool "${name}".`,
      group ? `excluded:${group}` : 'unknown_tool',
    );
  }
  if (args !== undefined && (typeof args !== 'object' || args === null || Array.isArray(args))) {
    throw new RefusedError('Tool arguments must be an object.', 'bad_request');
  }
  const input = (args ?? {}) as Record<string, unknown>;
  const tool = publicToolMap().get(name)!;

  for (const key of Object.keys(input)) {
    if (PINNING_ARGS.includes(key)) {
      throw new RefusedError(
        `Argument "${key}" is not accepted: this gateway reads one fixed program.`,
        'pinning_arg',
      );
    }
    if (!Object.prototype.hasOwnProperty.call(tool.inputSchema.properties, key)) {
      throw new RefusedError(`Argument "${key}" is not accepted by ${name}.`, 'unknown_arg');
    }
  }

  if ((GATEWAY_LOCAL_TOOLS as readonly string[]).includes(name)) return { name, args: { ...input } };

  const spec = EXPOSED_TOOLS[name];
  const out: Record<string, unknown> = { ...input };
  for (const [key, max] of Object.entries(spec.maxItems ?? {})) {
    const v = out[key];
    if (v === undefined) continue;
    if (!Array.isArray(v)) throw new RefusedError(`Argument "${key}" must be an array.`, 'bad_request');
    if (v.length > max) {
      throw new RefusedError(`Argument "${key}" has ${v.length} entries; the gateway allows at most ${max}.`, 'batch_too_large');
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
  return { name, args: out };
}
