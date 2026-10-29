/**
 * apply_changeset: a set of Ghidra edits applied as exactly one transaction.
 *
 * The op shapes are the Redivivus proposal schema (redivivus-app, src/proposals/schema.ts) without
 * `program`: the session decides which program the changeset lands in. Every op carries the value
 * its author saw (`expect`); the worker checks all of them inside the transaction before applying
 * anything, and rolls the whole transaction back on any mismatch or failure.
 *
 * The normalisers and defHash below are the proposal checker's (src/proposals/check.ts and
 * schema.ts), copied byte for byte so a value that passes the proposal check passes here. The Java
 * worker has its own copy (ghidra-worker ... ProposalNorm.java); all three are held to the shared
 * vectors in packages/shared/test/changeset-vectors.json, which were produced by running the
 * proposal checker's own functions. Change one copy and the vectors fail until all agree.
 *
 * defHash, exactly: take the get_data_type result for the struct (or union), build
 *   {name, category, size, fields: [[offset, name, dataType, size, bitOffset, bitSize], ...]}
 * with every missing value as null and fields in get_data_type's order, serialise it with
 * stableStringify (JSON.stringify for scalars, arrays in order, object keys sorted by UTF-16 code
 * unit, no whitespace), SHA-256 the UTF-8 bytes, and keep the first 16 lowercase hex digits.
 */

export type ChangesetOp =
  | { op: 'rename_function'; address: string; expect: { name: string }; name: string }
  | { op: 'rename_global'; address: string; expect: { name: string }; name: string }
  | { op: 'rename_local'; function: string; storage: string; expect: { name: string }; name: string }
  | { op: 'retype_local'; function: string; storage: string; expect: { type: string }; type: string }
  | { op: 'set_prototype'; address: string; expect: { signature: string; callingConvention: string }; signature: string; callingConvention: string }
  | { op: 'set_global_type'; address: string; expect: { type: string; size: number }; type: string }
  | { op: 'struct_field'; typePath: string; offset: number | string; expect: { name: string; type: string; defHash: string }; name?: string; type?: string };

export type ChangesetOpKind = ChangesetOp['op'];

export const CHANGESET_OP_KINDS: readonly ChangesetOpKind[] = [
  'rename_function', 'rename_global', 'rename_local', 'retype_local', 'set_prototype', 'set_global_type', 'struct_field',
];

export const CHANGESET_MAX_OPS = 20;

export interface ChangesetApplied {
  index: number;
  op: ChangesetOpKind;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export interface ChangesetOpError {
  index: number;
  op: string;
  errors: string[];
}

export interface ApplyChangesetResult {
  ok: boolean;
  dryRun: boolean;
  /** The Ghidra transaction the changeset was committed in; absent when nothing was committed. */
  transactionId?: number;
  description: string;
  /** What changed (or, on a dry run, what would change). Empty when the changeset was refused. */
  applied: ChangesetApplied[];
  errors?: ChangesetOpError[];
}

// Shapes, as the proposal schema checks them.

export const ADDRESS_RE = /^(0x)?[0-9a-fA-F]{1,16}$/;
export const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const TYPE_RE = /^[A-Za-z_][A-Za-z0-9_ *[\]:]*$/;
export const CALLING_CONVENTION_RE = /^(__[a-z][a-z0-9_]*|unknown)$/;
export const SIGNATURE_RE = /^[^()]*\(.*\)\s*$/s;
export const STORAGE_RE = /^(Stack\[-?0x[0-9a-fA-F]+\]|[A-Za-z][A-Za-z0-9]{1,5}|HASH:[0-9a-fA-F]+)(:\d+)?$/;
export const TYPE_PATH_RE = /^(\/[A-Za-z0-9_ .+-]+)*\/?[A-Za-z_][A-Za-z0-9_]*$/;
export const DEF_HASH_RE = /^[0-9a-f]{16}$/;

/** "0x00401000", "00401000" or "0x401000"; always "0x" plus at least 8 lowercase hex digits. */
export function normAddress(s: string): string {
  const hex = s.trim().replace(/^0x/i, '').replace(/^0+(?=.)/, '').toLowerCase();
  return `0x${hex.padStart(8, '0')}`;
}

/** Storage as get_function_info prints it ("Stack[-0x10]:4", "ECX:4") without the size. */
export function normStorage(s: string): string {
  const bare = s.trim().replace(/:\d+$/, '');
  const stack = /^stack\[(-?)0x([0-9a-f]+)\]$/i.exec(bare);
  if (stack) return `Stack[${stack[1]}0x${stack[2].replace(/^0+(?=.)/, '').toLowerCase()}]`;
  if (/^hash:/i.test(bare)) return `HASH:${bare.slice(5).toLowerCase()}`;
  return bare.toUpperCase();
}

export function addrEq(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = a.trim().replace(/^0x/i, '');
  const hb = b.trim().replace(/^0x/i, '');
  if (!/^[0-9a-f]+$/i.test(ha) || !/^[0-9a-f]+$/i.test(hb)) return false;
  return BigInt(`0x${ha}`) === BigInt(`0x${hb}`);
}

export function normType(s: unknown): string {
  return String(s ?? '').trim().replace(/\s+/g, ' ').replace(/\s*\*\s*/g, '*').replace(/\s*\[\s*/g, '[').replace(/\s*\]/g, ']');
}

export function normSignature(s: unknown): string {
  return normType(s).replace(/\s*([(),])\s*/g, '$1');
}

export function normConvention(s: unknown): string {
  return String(s ?? '').trim().toLowerCase().replace(/^_+/, '');
}

/** JSON with object keys sorted, no whitespace. */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const obj = v as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

export async function sha256Hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The struct definition's fingerprint, from a get_data_type result. See the header. */
export async function defHash(dt: any): Promise<string> {
  const fields = (Array.isArray(dt?.fields) ? dt.fields : []).map((f: any) => [
    f.offset ?? null, f.name ?? null, f.dataType ?? null, f.size ?? null, f.bitOffset ?? null, f.bitSize ?? null,
  ]);
  return (await sha256Hex(stableStringify({ name: dt?.name ?? null, category: dt?.category ?? null, size: dt?.size ?? null, fields }))).slice(0, 16);
}

/** "D2UnitStrc" or "/Category/D2UnitStrc", as get_data_type's name and category arguments. */
export function splitTypePath(typePath: string): { name: string; category?: string } {
  const parts = typePath.split('/').filter(Boolean);
  const name = parts.pop()!;
  return parts.length ? { name, category: `/${parts.join('/')}` } : { name };
}
