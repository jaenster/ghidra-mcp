import { describe, expect, it } from 'vitest';
import { serverUnhealthyMs, shouldReplaceForServer } from '../src/ghidra/pool.js';

describe('replacing a worker that lost its Ghidra Server connection', () => {
  const now = 1_000_000;

  it('replaces a replaceable worker unhealthy for longer than the threshold', () => {
    expect(shouldReplaceForServer({ healthy: false, unhealthySince: now - 200_000, replaceable: true }, now, 180_000)).toBe(true);
  });

  it('waits out the threshold, so the worker gets to recover on its own first', () => {
    expect(shouldReplaceForServer({ healthy: false, unhealthySince: now - 60_000, replaceable: true }, now, 180_000)).toBe(false);
  });

  it('never replaces a worker holding edits that are not checked in', () => {
    expect(shouldReplaceForServer({ healthy: false, unhealthySince: now - 3_600_000, replaceable: false }, now, 180_000)).toBe(false);
  });

  it('leaves healthy workers and workers that report nothing alone', () => {
    expect(shouldReplaceForServer({ healthy: true, replaceable: true }, now, 180_000)).toBe(false);
    expect(shouldReplaceForServer(undefined, now, 180_000)).toBe(false);
  });

  it('reads the threshold from the environment', () => {
    expect(serverUnhealthyMs({})).toBe(180_000);
    expect(serverUnhealthyMs({ GHIDRA_MCP_SERVER_UNHEALTHY_MS: '5000' })).toBe(5000);
  });
});
