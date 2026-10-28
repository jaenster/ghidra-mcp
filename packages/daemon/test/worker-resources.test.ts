import { describe, expect, it } from 'vitest';
import { workerResources } from '../src/ghidra/launcher/k8s-pod-launcher.js';

describe('worker pod resources', () => {
  it('requests the heap and limits heap plus headroom by default', () => {
    expect(workerResources(2560, 3072, {})).toEqual({
      requests: { memory: '2560Mi' }, limits: { memory: '3072Mi' },
    });
  });

  it('requests the full limit when guaranteed, with CPU alike when given', () => {
    expect(workerResources(2560, 3072, { GHIDRA_MCP_WORKER_GUARANTEED: '1' })).toEqual({
      requests: { memory: '3072Mi' }, limits: { memory: '3072Mi' },
    });
    expect(workerResources(2560, 3072, { GHIDRA_MCP_WORKER_GUARANTEED: '1', GHIDRA_MCP_WORKER_CPU: '1' })).toEqual({
      requests: { memory: '3072Mi', cpu: '1' }, limits: { memory: '3072Mi', cpu: '1' },
    });
  });
});
