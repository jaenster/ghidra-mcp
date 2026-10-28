/**
 * The public tool surface, built from the daemon's own definitions.
 */

import { getAllToolDefinitions } from '@ghidra-mcp/mcp';
import { CallChecker, type CheckedCall, type PublicTool } from './public-tools.js';

export { RefusedError, type CheckedCall, type PublicTool } from './public-tools.js';

let checker: CallChecker | null = null;

function surface(): CallChecker {
  if (!checker) checker = new CallChecker(getAllToolDefinitions());
  return checker;
}

/** The exposed tools as the public sees them. */
export function buildPublicTools(): PublicTool[] {
  return surface().tools;
}

/** The tool names answered, including the ones answered locally. */
export function publicToolNames(): string[] {
  return surface().names();
}

/** Check a call against the allowlist and the public schema; see CallChecker.check. */
export function checkCall(name: unknown, args: unknown): CheckedCall {
  return surface().check(name, args);
}
