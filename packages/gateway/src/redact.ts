/**
 * Output redaction for the public surface: deny patterns applied to every
 * answer before it leaves.
 *
 * Daemon answers are JSON, so every string value is redacted on its own
 * (`redactTree`) before the answer is encoded. Text that is not JSON goes
 * through `redact`, which reads TOON or JSON text: a multi-line value such as the
 * pseudocode of a function sits on one physical line as a quoted string with
 * escaped newlines. Each quoted string is decoded and redacted on its own:
 *
 * - inside a multi-line string, a "line" pattern replaces only the line it
 *   occurs on (with a comment marker when the string is code, so the rest still
 *   reads as C) and the line count stays the same;
 * - in a single-line string or in the unquoted text around it, a "line" pattern
 *   replaces only the match;
 * - a "fragment" pattern always replaces only the match.
 */

export interface DenyPattern {
  /** Short label for logs; never the matched text. */
  name: string;
  /** Regular expression source. */
  pattern: string;
  /** Regular expression flags; "g" is always added. */
  flags?: string;
  mode: 'line' | 'fragment';
}

export const REDACTION_MARKER = '[redacted]';

export const DEFAULT_DENY_PATTERNS: readonly DenyPattern[] = [
  // Mentions of D2R are fine; the debug build's number and repository paths are not.
  { name: 'd2r-build', pattern: String.raw`3\.0\.91923`, mode: 'line' },
  { name: 'd2r-debug-path', pattern: String.raw`debug_d2r|/windows/d2r`, flags: 'i', mode: 'line' },
  { name: 'reverse-marker', pattern: String.raw`___D2_REVERSE`, mode: 'line' },
  { name: 'repository', pattern: String.raw`Diablo2Lod|A2Racer2|ClaudeVM|Factorio|SimTower|UT2004`, flags: 'i', mode: 'line' },
  { name: 'server-host', pattern: String.raw`[a-z0-9.-]*\btypeguru\.nl\b[^\s"'<>]*|ghidra://[^\s"'<>]*`, flags: 'i', mode: 'fragment' },
  { name: 'home-path', pattern: String.raw`/Users/[^\s"'<>]*|[A-Za-z]:\\Users\\[^\s"'<>]*|/home/[^\s"'<>]*`, mode: 'fragment' },
  { name: 'docs-data', pattern: String.raw`[^\s"'<>]*docs/data/[^\s"'<>]*`, mode: 'fragment' },
  // Session ids are UUIDs. PlotDeck node ids are ULIDs; the pattern needs a
  // non-hex letter so a run of hex bytes is never taken for one.
  { name: 'uuid', pattern: String.raw`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`, flags: 'i', mode: 'fragment' },
  { name: 'ulid', pattern: String.raw`\b(?=[0-9A-Z]{26}\b)(?=[0-9A-F]*[G-HJKMNP-TV-Z])[0-7][0-9A-HJKMNP-TV-Z]{25}\b`, mode: 'fragment' },
];

export interface RedactionResult {
  text: string;
  count: number;
  byPattern: Record<string, number>;
}

interface Compiled {
  name: string;
  re: RegExp;
}

/** A multi-line string is treated as C when it has a block comment or a line ending in ; { or }. */
function looksLikeCode(s: string): boolean {
  return s.includes('/*') || /[;{}][ \t]*$/m.test(s);
}

/**
 * Whether a block comment is open at the end of `line`, given whether one was
 * open at its start. String and character literals and // comments are skipped.
 */
function commentOpenAfter(line: string, open: boolean): boolean {
  for (let i = 0; i < line.length; i++) {
    const two = line.slice(i, i + 2);
    if (open) {
      if (two === '*/') {
        open = false;
        i++;
      }
      continue;
    }
    if (two === '/*') {
      open = true;
      i++;
    } else if (two === '//') {
      return false;
    } else if (line[i] === '"' || line[i] === "'") {
      const q = line[i];
      for (i++; i < line.length && line[i] !== q; i++) if (line[i] === '\\') i++;
    }
  }
  return open;
}

/**
 * The marker for a removed line of code. It keeps the line's indentation and
 * the block-comment state on both sides: a line inside a comment becomes plain
 * text, a line that opened or closed one keeps that, and a line of code becomes
 * a comment of its own.
 */
function codeMarker(line: string, openBefore: boolean, openAfter: boolean): string {
  const indent = /^[ \t]*/.exec(line)![0];
  return `${indent}${openBefore ? '' : '/* '}${REDACTION_MARKER}${openAfter ? '' : ' */'}`;
}

export class Redactor {
  private readonly lines: Compiled[];
  private readonly fragments: Compiled[];

  constructor(patterns: readonly DenyPattern[] = DEFAULT_DENY_PATTERNS) {
    const compile = (p: DenyPattern): Compiled => ({
      name: p.name,
      re: new RegExp(p.pattern, (p.flags ?? '').replace(/g/g, '') + 'g'),
    });
    this.lines = patterns.filter((p) => p.mode === 'line').map(compile);
    this.fragments = patterns.filter((p) => p.mode === 'fragment').map(compile);
  }

  /** Replace every match of every pattern in a single line of text. */
  private matches(s: string, bump: (name: string) => void): string {
    let out = s;
    for (const c of [...this.lines, ...this.fragments]) {
      out = out.replace(c.re, () => {
        bump(c.name);
        return REDACTION_MARKER;
      });
    }
    return out;
  }

  /** Redact one decoded string value: per line when it has several, per match when it has one. */
  redactValue(value: string, bump: (name: string) => void): string {
    if (!value.includes('\n')) return this.matches(value, bump);
    const code = looksLikeCode(value);
    let open = false;
    return value
      .split('\n')
      .map((line) => {
        const before = open;
        open = code ? commentOpenAfter(line, open) : false;
        for (const c of this.lines) {
          c.re.lastIndex = 0;
          if (c.re.test(line)) {
            bump(c.name);
            return code ? codeMarker(line, before, open) : REDACTION_MARKER;
          }
        }
        return this.matches(line, bump);
      })
      .join('\n');
  }

  /** Redact one physical line of TOON or JSON text: each quoted string as a value, the rest per match. */
  private redactRawLine(line: string, bump: (name: string) => void): string {
    let out = '';
    let i = 0;
    while (i < line.length) {
      const start = line.indexOf('"', i);
      if (start < 0) {
        out += this.matches(line.slice(i), bump);
        break;
      }
      out += this.matches(line.slice(i, start), bump);
      let end = start + 1;
      while (end < line.length && line[end] !== '"') end += line[end] === '\\' ? 2 : 1;
      if (end >= line.length) {
        // An unterminated quote: no string to decode, so the rest is plain text.
        out += this.matches(line.slice(start), bump);
        break;
      }
      const token = line.slice(start, end + 1);
      let decoded: string | null = null;
      try {
        decoded = JSON.parse(token) as string;
      } catch {
        decoded = null;
      }
      if (decoded === null) {
        out += this.matches(token, bump);
      } else {
        let hits = 0;
        const redacted = this.redactValue(decoded, (n) => {
          hits++;
          bump(n);
        });
        out += hits ? JSON.stringify(redacted) : token;
      }
      i = end + 1;
    }
    return out;
  }

  /** Redact every string (keys included) in a parsed JSON answer. */
  redactTree(data: unknown): { value: unknown; count: number; byPattern: Record<string, number> } {
    const byPattern: Record<string, number> = {};
    let count = 0;
    const bump = (name: string) => {
      byPattern[name] = (byPattern[name] ?? 0) + 1;
      count++;
    };
    const walk = (v: unknown): unknown => {
      if (typeof v === 'string') return this.redactValue(v, bump);
      if (Array.isArray(v)) return v.map(walk);
      if (v === null || typeof v !== 'object') return v;
      const out: Record<string, unknown> = {};
      for (const [k, inner] of Object.entries(v as Record<string, unknown>)) out[this.redactValue(k, bump)] = walk(inner);
      return out;
    };
    return { value: walk(data), count, byPattern };
  }

  redact(text: string): RedactionResult {
    const byPattern: Record<string, number> = {};
    let count = 0;
    const bump = (name: string) => {
      byPattern[name] = (byPattern[name] ?? 0) + 1;
      count++;
    };
    const out = text.split('\n').map((line) => this.redactRawLine(line, bump));
    return { text: count ? out.join('\n') : text, count, byPattern };
  }
}

/**
 * Parse a deny-pattern list from configuration (a JSON array of DenyPattern).
 * Every pattern is compiled here so a bad one fails at startup, not mid-call.
 */
export function parseDenyPatterns(json: string): DenyPattern[] {
  const raw = JSON.parse(json) as unknown;
  if (!Array.isArray(raw)) throw new Error('deny patterns must be a JSON array');
  return raw.map((p, i) => {
    const o = p as Partial<DenyPattern>;
    if (typeof o.name !== 'string' || typeof o.pattern !== 'string' || (o.mode !== 'line' && o.mode !== 'fragment')) {
      throw new Error(`deny pattern ${i} needs name, pattern and mode ("line" or "fragment")`);
    }
    new RegExp(o.pattern, o.flags);
    return { name: o.name, pattern: o.pattern, flags: o.flags, mode: o.mode };
  });
}
