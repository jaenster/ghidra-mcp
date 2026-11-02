import { describe, expect, it } from 'vitest';
import { ChangeStore, type ChangeEvent } from '../src/changes/store.js';

const ev = (epoch: string | undefined, seq: number): ChangeEvent => ({
  epoch,
  seq,
  mod: seq,
  ts: 0,
  kind: 'function.changed',
  target: 'function',
  key: `00${seq}`,
});

describe('ChangeStore across journal epochs', () => {
  it('drops replays within one epoch', () => {
    const store = new ChangeStore();
    expect(store.append('s', [ev('a', 1), ev('a', 2)])).toHaveLength(2);
    expect(store.append('s', [ev('a', 2)])).toHaveLength(0);
    expect(store.head('s')).toBe(2);
    expect(store.epoch('s')).toBe('a');
  });

  it('replaces the buffer when a respawned worker starts a new epoch at seq 1', () => {
    const store = new ChangeStore();
    store.append('s', [ev('a', 1), ev('a', 2), ev('a', 3)]);

    // Before the epoch existed this batch was silently dropped: 1 <= old head 3.
    const accepted = store.append('s', [ev('b', 1)]);
    expect(accepted.map((e) => e.seq)).toEqual([1]);
    expect(store.epoch('s')).toBe('b');
    expect(store.head('s')).toBe(1);
    expect(store.since('s', 0).map((e) => [e.epoch, e.seq])).toEqual([['b', 1]]);
  });

  it('tells subscribers about the new-epoch events', () => {
    const store = new ChangeStore();
    const seen: Array<[string | undefined, number]> = [];
    store.subscribe('s', (batch) => batch.forEach((e) => seen.push([e.epoch, e.seq])));
    store.append('s', [ev('a', 5)]);
    store.append('s', [ev('b', 1)]);
    expect(seen).toEqual([['a', 5], ['b', 1]]);
  });

  it('keeps events from a journal that predates epochs', () => {
    const store = new ChangeStore();
    store.append('s', [ev(undefined, 1)]);
    expect(store.append('s', [ev(undefined, 2)])).toHaveLength(1);
    expect(store.epoch('s')).toBeUndefined();
  });
});
