/**
 * The gateway's call path, independent of HTTP: allowlist and argument check,
 * quota, forward on the pinned session of the chosen program, strip, scrub,
 * redact and cap the output, audit.
 */

import { formatResponse } from '@ghidra-mcp/mcp';
import { DENIED_RESPONSE_KEYS, EXPOSED_TOOLS, PUBLIC_PROGRAM_NAMES, type PublicProgram } from './allowlist.js';
import { stripResponseKeys } from './public-tools.js';
import { Redactor } from './redact.js';
import type { AuditLog, Outcome } from './audit.js';
import type { Identity } from './auth.js';
import type { QuotaManager } from './quota.js';
import { RefusedError, buildPublicTools, checkCall, type PublicTool } from './tools.js';
import { UpstreamError, type PinnedSession } from './upstream.js';

export interface GatewayOptions {
  /** Responses longer than this many bytes (UTF-8) are cut, with a marker saying so. */
  maxResponseBytes: number;
  cheapTimeoutMs: number;
  costlyTimeoutMs: number;
}

export type CallResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

export type Format = 'toon' | 'json';

export interface CallOptions {
  /** Output format chosen by the caller elsewhere (the edge); overrides set_output_format. */
  format?: Format;
}

export type ProgramSessions = Readonly<Record<PublicProgram, PinnedSession>>;

export class Gateway {
  private readonly tools: PublicTool[] = buildPublicTools();
  private readonly formats = new Map<string, Format>();
  private readonly redactor = new Redactor();

  constructor(
    private readonly sessions: ProgramSessions,
    private readonly quota: QuotaManager,
    private readonly audit: AuditLog,
    private readonly options: GatewayOptions,
  ) {}

  listTools(): PublicTool[] {
    return this.tools;
  }

  async callTool(identity: Identity, name: unknown, args: unknown, callOptions: CallOptions = {}): Promise<CallResult> {
    const started = performance.now();
    const toolName = typeof name === 'string' ? name : String(name);
    let program: PublicProgram | undefined;
    let redactions = 0;
    const finish = (result: CallResult, outcome: Outcome, reason?: string, truncated?: boolean): CallResult => {
      this.audit.record({
        identity,
        tool: toolName,
        program,
        args,
        durationMs: performance.now() - started,
        bytes: Buffer.byteLength(result.content.map((c) => c.text).join('')),
        outcome,
        reason,
        truncated,
        redactions,
      });
      return result;
    };

    let call: ReturnType<typeof checkCall>;
    try {
      call = checkCall(name, args);
    } catch (err) {
      if (err instanceof RefusedError) return finish(errorResult(err.message), 'refused', err.reason);
      throw err;
    }

    if (call.name === 'set_output_format') {
      const format = call.args.format;
      if (format !== 'toon' && format !== 'json') {
        return finish(errorResult('format must be "toon" or "json".'), 'refused', 'bad_request');
      }
      this.formats.set(identity.key, format);
      return finish(textResult(`Output format set to: ${format}`), 'ok');
    }

    program = call.program;
    const tier = EXPOSED_TOOLS[call.name].tier;
    const decision = this.quota.acquire(identity.key, tier);
    if (!decision.ok) {
      const what = decision.reason === 'busy'
        ? 'The server is busy with other costly calls'
        : decision.reason === 'costly_rate_limited'
          ? `Rate limit reached for costly tools (${call.name})`
          : 'Rate limit reached';
      return finish(errorResult(`${what}; retry in ${decision.retryAfterSeconds}s.`), 'rate_limited', decision.reason);
    }

    try {
      const session = this.sessions[call.program];
      const timeout = tier === 'costly' ? this.options.costlyTimeoutMs : this.options.cheapTimeoutMs;
      const res = await session.call(call.name, call.args, timeout);
      if (res.isError) {
        // Daemon error text names sessions, paths and internals; the caller gets its class only.
        return finish(errorResult(publicError(res.text)), 'error', errorClass(res.text));
      }
      const format = callOptions.format ?? this.formats.get(identity.key) ?? 'toon';
      const shaped = this.shape(call.name, call.program, res.text, format, session.id);
      redactions = shaped.redactions;
      const { text: capped, truncated } = capBytes(shaped.text, this.options.maxResponseBytes);
      return finish(textResult(capped), 'ok', undefined, truncated);
    } catch (err) {
      if (err instanceof UpstreamError) return finish(errorResult(err.publicMessage), 'upstream_error', err.message);
      throw err;
    } finally {
      decision.release();
    }
  }

  /**
   * The daemon answers in JSON: drop what describes the server, report the
   * program under its public name, redact every string, re-encode, scrub what is left.
   */
  private shape(toolName: string, program: PublicProgram, text: string, format: Format, sessionId: string | null): { text: string; redactions: number } {
    let out: string;
    let redactions: number;
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
    if (data === undefined) {
      const r = this.redactor.redact(text);
      out = r.text;
      redactions = r.count;
    } else {
      let shaped = stripResponseKeys(toolName, data, DENIED_RESPONSE_KEYS);
      if (toolName === 'get_program_info' && shaped !== null && typeof shaped === 'object' && !Array.isArray(shaped) && 'name' in shaped) {
        shaped = { ...shaped, name: PUBLIC_PROGRAM_NAMES[program] };
      }
      const r = this.redactor.redactTree(shaped);
      out = formatResponse(r.value, format);
      redactions = r.count;
    }
    out = out.replace(/ghidra:\/\/[^\s"',)]+/g, '[redacted]');
    if (sessionId) out = out.split(sessionId).join('[redacted]');
    return { text: out, redactions };
  }
}

/** The class of a daemon error, for the audit line. */
function errorClass(text: string): string {
  if (/not found|no such|does not exist|no function|unknown (function|symbol|address|data type)/i.test(text)) return 'not_found';
  if (/timed? ?out|timeout/i.test(text)) return 'timeout';
  if (/invalid|must be|cannot parse|could not parse|malformed|out of range|required|expected/i.test(text)) return 'invalid';
  return 'failed';
}

/** A message that says what kind of failure happened and nothing about the daemon. */
export function publicError(daemonText: string): string {
  switch (errorClass(daemonText)) {
    case 'not_found': return 'Not found in this program.';
    case 'timeout': return 'The call took too long; narrow it and try again.';
    case 'invalid': return 'Invalid arguments for this tool.';
    default: return 'The call failed.';
  }
}

function textResult(text: string): CallResult {
  return { content: [{ type: 'text', text }] };
}

function errorResult(text: string): CallResult {
  return { content: [{ type: 'text', text: text.startsWith('Error:') ? text : `Error: ${text}` }], isError: true };
}

/** Cut to at most maxBytes of UTF-8 including the marker, never splitting a character. */
export function capBytes(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const total = Buffer.byteLength(text);
  if (total <= maxBytes) return { text, truncated: false };
  const marker = (shown: number) =>
    `\n[truncated: ${shown} of ${total} bytes shown; narrow the query (limit/offset, filter, fewer items)]`;
  const budget = Math.max(0, maxBytes - Buffer.byteLength(marker(maxBytes)));
  const buf = Buffer.from(text);
  let end = budget;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString('utf8') + marker(end), truncated: true };
}
