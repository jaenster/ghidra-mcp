/**
 * The gateway's call path, independent of HTTP: allowlist and argument check,
 * quota, forward on the pinned session, scrub and cap the output, audit.
 */

import { formatResponse } from '@ghidra-mcp/mcp';
import { EXPOSED_TOOLS } from './allowlist.js';
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

type Format = 'toon' | 'json';

export class Gateway {
  private readonly tools: PublicTool[] = buildPublicTools();
  private readonly formats = new Map<string, Format>();

  constructor(
    private readonly session: PinnedSession,
    private readonly quota: QuotaManager,
    private readonly audit: AuditLog,
    private readonly options: GatewayOptions,
  ) {}

  listTools(): PublicTool[] {
    return this.tools;
  }

  async callTool(identity: Identity, name: unknown, args: unknown): Promise<CallResult> {
    const started = performance.now();
    const toolName = typeof name === 'string' ? name : String(name);
    const finish = (result: CallResult, outcome: Outcome, reason?: string, truncated?: boolean): CallResult => {
      this.audit.record({
        identity,
        tool: toolName,
        args,
        durationMs: performance.now() - started,
        bytes: Buffer.byteLength(result.content.map((c) => c.text).join('')),
        outcome,
        reason,
        truncated,
      });
      return result;
    };

    let call: { name: string; args: Record<string, unknown> };
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

    const tier = EXPOSED_TOOLS[call.name].tier;
    const decision = this.quota.acquire(identity.key, tier);
    if (!decision.ok) {
      const what = decision.reason === 'busy'
        ? 'The gateway is busy with other costly calls'
        : decision.reason === 'costly_rate_limited'
          ? `Rate limit reached for costly tools (${call.name})`
          : 'Rate limit reached';
      return finish(errorResult(`${what}; retry in ${decision.retryAfterSeconds}s.`), 'rate_limited', decision.reason);
    }

    try {
      const timeout = tier === 'costly' ? this.options.costlyTimeoutMs : this.options.cheapTimeoutMs;
      const res = await this.session.call(call.name, call.args, timeout);
      const text = this.scrub(res.isError ? res.text : this.reformat(res.text, identity.key));
      const { text: capped, truncated } = capBytes(text, this.options.maxResponseBytes);
      return finish(
        res.isError ? errorResult(capped) : textResult(capped),
        res.isError ? 'error' : 'ok',
        undefined,
        truncated,
      );
    } catch (err) {
      if (err instanceof UpstreamError) return finish(errorResult(err.message), 'upstream_error');
      throw err;
    } finally {
      decision.release();
    }
  }

  /** The daemon answers in JSON; re-encode in the caller's format. */
  private reformat(text: string, identityKey: string): string {
    const format = this.formats.get(identityKey) ?? 'toon';
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return text;
    }
    return formatResponse(data, format);
  }

  /** Remove what identifies the daemon's side: the pinned session id and server URLs. */
  private scrub(text: string): string {
    let out = text.replace(/ghidra:\/\/[^\s"',)]+/g, 'ghidra://<server>');
    const sid = this.session.id;
    if (sid) out = out.split(sid).join('<session>');
    return out;
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
    `\n[gateway: response truncated, ${shown} of ${total} bytes shown; narrow the query (limit/offset, filter, fewer items)]`;
  const budget = Math.max(0, maxBytes - Buffer.byteLength(marker(maxBytes)));
  const buf = Buffer.from(text);
  let end = budget;
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString('utf8') + marker(end), truncated: true };
}
