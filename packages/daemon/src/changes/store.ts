import { EventEmitter } from 'node:events';
import type { ChangeEvent } from '@ghidra-mcp/shared/protocol';

export type { ChangeEvent };

const DEFAULT_CAPACITY = 10_000;

/**
 * A bounded, in-order buffer of recent changes per session, and the fan-out to whoever is
 * listening.
 *
 * The durable copy lives on the worker, in the journal file beside the project. This is a
 * cache in front of it so that the common case - a subscriber that is connected and merely
 * blinked - is served without a round trip to the worker. A subscriber that has fallen
 * further behind than `capacity` cannot be served from here; `hasFrom` says so and the
 * caller falls back to the worker's `get_changes`. Silently serving a truncated range
 * would look exactly like "nothing else changed", which is the one answer that must never
 * be wrong.
 */
export class ChangeStore {
  private readonly buffers = new Map<string, ChangeEvent[]>();
  private readonly heads = new Map<string, number>();
  private readonly emitter = new EventEmitter();

  constructor(private readonly capacity: number = DEFAULT_CAPACITY) {
    // A subscriber per session plus the dashboard is well under Node's default warning
    // threshold, but a long-lived daemon reconnecting is not, and the warning is noise.
    this.emitter.setMaxListeners(0);
  }

  /** Append a batch from the worker. Out-of-order or replayed batches are ignored. */
  append(sessionId: string, events: ChangeEvent[]): ChangeEvent[] {
    if (events.length === 0) return [];

    const head = this.heads.get(sessionId) ?? 0;
    const fresh = events.filter((e) => e.seq > head).sort((a, b) => a.seq - b.seq);
    if (fresh.length === 0) return [];

    const buffer = this.buffers.get(sessionId) ?? [];
    buffer.push(...fresh);
    if (buffer.length > this.capacity) {
      buffer.splice(0, buffer.length - this.capacity);
    }
    this.buffers.set(sessionId, buffer);
    this.heads.set(sessionId, fresh[fresh.length - 1]!.seq);

    this.emitter.emit(sessionId, fresh);
    return fresh;
  }

  /** The highest sequence this store has seen for a session; 0 if none. */
  head(sessionId: string): number {
    return this.heads.get(sessionId) ?? 0;
  }

  /**
   * Whether everything after `since` is still buffered. False means the caller must ask
   * the worker instead - the range has been evicted, or this daemon never saw it (a
   * restart, or a worker that reconnected to a different daemon).
   */
  hasFrom(sessionId: string, since: number): boolean {
    const buffer = this.buffers.get(sessionId);
    if (!buffer || buffer.length === 0) return since >= this.head(sessionId);
    return buffer[0]!.seq <= since + 1;
  }

  /** Buffered events with `seq > since`, oldest first. */
  since(sessionId: string, since: number, limit = this.capacity): ChangeEvent[] {
    const buffer = this.buffers.get(sessionId);
    if (!buffer) return [];
    const out: ChangeEvent[] = [];
    for (const e of buffer) {
      if (e.seq <= since) continue;
      out.push(e);
      if (out.length >= limit) break;
    }
    return out;
  }

  subscribe(sessionId: string, listener: (events: ChangeEvent[]) => void): () => void {
    this.emitter.on(sessionId, listener);
    return () => this.emitter.off(sessionId, listener);
  }

  /** Drop a session's buffer. The worker's journal remains the durable record. */
  forget(sessionId: string): void {
    this.buffers.delete(sessionId);
    this.heads.delete(sessionId);
    this.emitter.removeAllListeners(sessionId);
  }
}
