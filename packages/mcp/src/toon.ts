/**
 * TOON format integration for Ghidra MCP
 * Uses official @toon-format/toon package
 */

import { encode as toonEncode } from '@toon-format/toon';

/**
 * Global format setting - fallback for stateless contexts.
 * Per-connection format is stored on GhidraToolHandler instances.
 */
let globalFormat: 'toon' | 'json' = 'toon';

export function setGlobalFormat(format: 'toon' | 'json'): void {
  globalFormat = format;
}

export function getGlobalFormat(): 'toon' | 'json' {
  return globalFormat;
}

/**
 * Encode data to TOON format
 */
export function toToon(data: unknown): string {
  return toonEncode(data);
}

/**
 * Format a response according to a given format setting
 */
export function formatResponse(data: unknown, format?: 'toon' | 'json'): string {
  const fmt = format ?? globalFormat;
  if (fmt === 'json') {
    return JSON.stringify(data, null, 2);
  }
  return toonEncode(data);
}

export { toonEncode as encode };
