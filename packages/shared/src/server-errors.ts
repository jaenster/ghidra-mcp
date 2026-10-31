/**
 * Errors that mean the Ghidra Server connection is gone, as opposed to the call failing.
 *
 * The worker prefixes these with SERVER_UNAVAILABLE once it has tried to reconnect. The
 * raw patterns catch the same failure from a worker that predates the prefix, or one
 * that surfaced on a path the worker does not wrap.
 */

export const SERVER_UNAVAILABLE = 'ghidra_server_unavailable';

const RAW_PATTERNS = [
  /ghidra_server_unavailable/i,
  /no such object in table/i,
  /NoSuchObjectException/,
  /Not connected to (the )?repository server/i,
  /Not connected to (a|the) Ghidra Server/i,
  /\bjava\.rmi\.(Connect|ConnectIO|Unmarshal)Exception\b/,
];

/** True when a daemon or worker error text describes a lost Ghidra Server connection. */
export function isServerUnavailable(text: string): boolean {
  return RAW_PATTERNS.some((re) => re.test(text));
}

/** The error text with the SERVER_UNAVAILABLE prefix, added once. */
export function markServerUnavailable(text: string): string {
  if (!isServerUnavailable(text) || text.includes(SERVER_UNAVAILABLE)) return text;
  return `${SERVER_UNAVAILABLE}: the Ghidra Server connection is down (${text}). Retry shortly.`;
}
