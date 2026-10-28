/**
 * Per-identity rate limits: a token bucket for all calls and a tighter one for
 * costly calls, plus a gateway-wide cap on costly calls in flight - the pinned
 * session is one Ghidra worker, and a decompile queue there stalls everyone.
 */

import type { ToolTier } from './allowlist.js';

export interface QuotaOptions {
  callsPerMinute: number;
  costlyPerMinute: number;
  maxConcurrentCostly: number;
  now?: () => number;
}

export type QuotaDecision =
  | { ok: true; release: () => void }
  | { ok: false; reason: 'rate_limited' | 'costly_rate_limited' | 'busy'; retryAfterSeconds: number };

class Bucket {
  private tokens: number;
  private last: number;

  constructor(private readonly perMinute: number, now: number) {
    this.tokens = perMinute;
    this.last = now;
  }

  private refill(now: number): void {
    const elapsed = Math.max(0, now - this.last);
    this.tokens = Math.min(this.perMinute, this.tokens + (elapsed * this.perMinute) / 60_000);
    this.last = now;
  }

  has(now: number): boolean {
    this.refill(now);
    return this.tokens >= 1;
  }

  take(): void {
    this.tokens -= 1;
  }

  secondsUntilNext(): number {
    return Math.max(1, Math.ceil(((1 - this.tokens) * 60) / this.perMinute));
  }

  full(now: number): boolean {
    this.refill(now);
    return this.tokens >= this.perMinute;
  }
}

export class QuotaManager {
  private readonly calls = new Map<string, Bucket>();
  private readonly costly = new Map<string, Bucket>();
  private costlyInFlight = 0;
  private readonly now: () => number;

  constructor(private readonly options: QuotaOptions) {
    this.now = options.now ?? Date.now;
  }

  /** Charge one call to the identity, or say why it may not run now. */
  acquire(identityKey: string, tier: ToolTier): QuotaDecision {
    const now = this.now();
    const calls = this.bucket(this.calls, identityKey, this.options.callsPerMinute, now);
    if (!calls.has(now)) return { ok: false, reason: 'rate_limited', retryAfterSeconds: calls.secondsUntilNext() };

    if (tier === 'costly') {
      const costly = this.bucket(this.costly, identityKey, this.options.costlyPerMinute, now);
      if (!costly.has(now)) {
        return { ok: false, reason: 'costly_rate_limited', retryAfterSeconds: costly.secondsUntilNext() };
      }
      if (this.costlyInFlight >= this.options.maxConcurrentCostly) {
        return { ok: false, reason: 'busy', retryAfterSeconds: 5 };
      }
      costly.take();
      this.costlyInFlight++;
    }
    calls.take();

    let released = tier !== 'costly';
    return {
      ok: true,
      release: () => {
        if (released) return;
        released = true;
        this.costlyInFlight--;
      },
    };
  }

  /** Drop buckets that have refilled completely; they hold no information. */
  sweep(): void {
    const now = this.now();
    for (const map of [this.calls, this.costly]) {
      for (const [k, b] of map) if (b.full(now)) map.delete(k);
    }
  }

  private bucket(map: Map<string, Bucket>, key: string, perMinute: number, now: number): Bucket {
    let b = map.get(key);
    if (!b) {
      b = new Bucket(perMinute, now);
      map.set(key, b);
    }
    return b;
  }
}
