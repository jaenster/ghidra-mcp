/**
 * Output redaction for the public surface: deny patterns applied to every
 * answer before it leaves. A pattern either removes the whole line it occurs
 * on (names whose mere mention is the leak) or only the matching fragment
 * (paths, hosts and identifiers inside otherwise useful lines).
 */

export interface DenyPattern {
  /** Short label for logs; never the matched text. */
  name: string;
  /** Regular expression source. */
  pattern: string;
  /** Regular expression flags; "g" is always added. */
  flags?: string;
  /** "line" replaces the whole line, "fragment" only the match. */
  mode: 'line' | 'fragment';
}

export const REDACTION_MARKER = '[redacted]';

/**
 * The default deny set. Order does not matter: line patterns run first, then
 * fragments on what is left.
 */
export const DEFAULT_DENY_PATTERNS: readonly DenyPattern[] = [
  { name: 'd2r', pattern: String.raw`\bd2r\b|debug_d2r|/windows/d2r|/debug_d2r`, flags: 'i', mode: 'line' },
  { name: 'd2r-build', pattern: String.raw`3\.0\.91923`, mode: 'line' },
  { name: 'hellfire', pattern: String.raw`hellfire`, flags: 'i', mode: 'line' },
  { name: 'storm-pdb', pattern: String.raw`storm\.pdb`, flags: 'i', mode: 'line' },
  { name: 'reverse-marker', pattern: String.raw`___D2_REVERSE`, mode: 'line' },
  { name: 'repository', pattern: String.raw`Diablo2Lod|A2Racer2|ClaudeVM|Factorio|SimTower|UT2004`, flags: 'i', mode: 'line' },
  { name: 'server-host', pattern: String.raw`[a-z0-9.-]*\btypeguru\.nl\b[^\s"'<>]*|ghidra://[^\s"'<>]*`, flags: 'i', mode: 'fragment' },
  { name: 'home-path', pattern: String.raw`/Users/[^\s"'<>]*|[A-Za-z]:\\Users\\[^\s"'<>]*|/home/[^\s"'<>]*`, mode: 'fragment' },
  { name: 'docs-data', pattern: String.raw`[^\s"'<>]*docs/data/[^\s"'<>]*`, mode: 'fragment' },
  // Session ids are UUIDs; PlotDeck node ids are ULIDs. The ULID pattern needs a
  // non-hex letter so a run of hex bytes is never taken for one.
  { name: 'uuid', pattern: String.raw`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`, flags: 'i', mode: 'fragment' },
  { name: 'ulid', pattern: String.raw`\b(?=[0-9A-Z]{26}\b)(?=[0-9A-F]*[G-HJKMNP-TV-Z])[0-7][0-9A-HJKMNP-TV-Z]{25}\b`, mode: 'fragment' },
];

interface Compiled {
  name: string;
  re: RegExp;
  mode: 'line' | 'fragment';
}

export interface RedactionResult {
  text: string;
  /** Replacements made, total. */
  count: number;
  /** Replacements per pattern name, for the log. */
  byPattern: Record<string, number>;
}

export class Redactor {
  private readonly lines: Compiled[];
  private readonly fragments: Compiled[];

  constructor(patterns: readonly DenyPattern[] = DEFAULT_DENY_PATTERNS) {
    const compiled = patterns.map((p) => ({
      name: p.name,
      re: new RegExp(p.pattern, (p.flags ?? '').replace(/g/g, '') + 'g'),
      mode: p.mode,
    }));
    this.lines = compiled.filter((c) => c.mode === 'line');
    this.fragments = compiled.filter((c) => c.mode === 'fragment');
  }

  redact(text: string): RedactionResult {
    const byPattern: Record<string, number> = {};
    let count = 0;
    const bump = (name: string, n: number) => {
      if (!n) return;
      byPattern[name] = (byPattern[name] ?? 0) + n;
      count += n;
    };

    const out = text.split('\n').map((line) => {
      for (const c of this.lines) {
        c.re.lastIndex = 0;
        if (c.re.test(line)) {
          bump(c.name, 1);
          return REDACTION_MARKER;
        }
      }
      let l = line;
      for (const c of this.fragments) {
        l = l.replace(c.re, () => {
          bump(c.name, 1);
          return REDACTION_MARKER;
        });
      }
      return l;
    });
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
