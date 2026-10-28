/**
 * One structured line per call. Arguments are hashed, never written out, and
 * tokens never reach this module at all.
 */

import { createHash } from 'node:crypto';
import type { Identity } from './auth.js';

export type Outcome = 'ok' | 'error' | 'refused' | 'rate_limited' | 'unauthenticated' | 'upstream_error';

export interface AuditRecord {
  identity: Identity | null;
  tool: string;
  args: unknown;
  durationMs: number;
  bytes: number;
  outcome: Outcome;
  reason?: string;
  truncated?: boolean;
}

export type AuditSink = (line: string) => void;

/** Key order does not change the hash, so the same query always hashes the same. */
export function hashArgs(args: unknown): string {
  return createHash('sha256').update(stableStringify(args ?? {})).digest('hex').slice(0, 16);
}

function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const obj = v as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

export class AuditLog {
  constructor(private readonly sink: AuditSink = (line) => process.stdout.write(line + '\n')) {}

  record(r: AuditRecord): void {
    this.sink(JSON.stringify({
      ts: new Date().toISOString(),
      event: 'tool_call',
      identity: r.identity?.key ?? null,
      githubId: r.identity?.githubId ?? null,
      login: r.identity?.login ?? null,
      tool: r.tool,
      argsHash: hashArgs(r.args),
      durationMs: Math.round(r.durationMs),
      bytes: r.bytes,
      outcome: r.outcome,
      ...(r.reason ? { reason: r.reason } : {}),
      ...(r.truncated ? { truncated: true } : {}),
    }));
  }
}
