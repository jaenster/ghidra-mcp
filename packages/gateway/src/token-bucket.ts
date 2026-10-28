/**
 * A per-minute token bucket. Its state is two numbers, so a holder that
 * persists it (a Durable Object) can store and restore it as is.
 */

export interface BucketState {
  tokens: number;
  last: number;
}

export class TokenBucket {
  private tokens: number;
  private last: number;

  constructor(private readonly perMinute: number, now: number, state?: BucketState) {
    this.tokens = state ? Math.min(perMinute, state.tokens) : perMinute;
    this.last = state ? state.last : now;
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

  state(): BucketState {
    return { tokens: this.tokens, last: this.last };
  }
}
