/** The words the product no longer uses on screen. Plan 107, D2 and D13.
 *
 *  A regex walk over the source of every screen, not a rendered-DOM check: the strings
 *  that reach a person are JSX text nodes and string literals, and both are visible in the
 *  file without mounting anything. Comments are stripped first, because the maintainer's
 *  register is deliberately left alone (plan 107, section 7).
 *
 *  The list is the negative of D2's table. A hit names the file, the line and the word.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

import { describe, expect, it } from "vitest";

// Vitest resolves relative to the Vite root, which is `frontend/`, wherever it is run from.
const ROOT = join(process.cwd(), "src");
const SCANNED = [join(ROOT, "features"), join(ROOT, "components"), join(ROOT, "App.tsx")];

/** Every `.tsx` under the scanned roots, tests excluded. */
function sources(): string[] {
  const found: string[] = [];
  const walk = (path: string) => {
    if (statSync(path).isDirectory()) {
      for (const entry of readdirSync(path)) walk(join(path, entry));
    } else if (path.endsWith(".tsx") && !path.endsWith(".test.tsx")) {
      found.push(path);
    }
  };
  for (const root of SCANNED) walk(root);
  return found.sort();
}

/** The file with every comment blanked out, line structure kept so a hit can name its
 *  line. `/* … *\/`, `// …` to end of line, and JSX `{/* … *\/}` — the last is the first
 *  with braces round it, so one pattern covers both. */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (match) => match.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`])\/\/[^\n]*/g, (match, lead: string) =>
      lead + " ".repeat(match.length - lead.length),
    );
}

/** A string literal that is code rather than copy: a route, an icon name, a key, a CSS
 *  class, a prop that takes a closed vocabulary. Decided by what sits before the quote. */
const CODE_LITERAL = /(?:icon|to|href|key|className|name|id|path|kind|tone|type|rel|target|import|from)\s*[=:(]?\s*$/;

/** The user-visible text of a file: string literals (single, double and template) and
 *  JSX text nodes, each tagged with the line it starts on.
 *
 *  A JSX text node is what sits between a `>` and the next `<` or `{` — which also
 *  matches the gaps between tags and the tail of an arrow function, so a candidate that
 *  carries code punctuation (`;`, `=`) is dropped. Identifiers, imports and props are
 *  never captured, so `run_id` in code is invisible and `run` in a sentence is not. */
function visibleText(stripped: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  const lineOf = (index: number) => stripped.slice(0, index).split("\n").length;
  for (const match of stripped.matchAll(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/g)) {
    const at = match.index ?? 0;
    const before = stripped.slice(Math.max(0, at - 16), at);
    const text = match[0].slice(1, -1).replace(/\$\{[^}]*\}/g, " ");
    if (text.startsWith("/") || text.startsWith(".") || CODE_LITERAL.test(before)) continue;
    // A bare identifier — an icon name in a type union, an object key, a class — is not
    // a sentence. A single visible word is always JSX text or a ternary branch, and the
    // ternary's quote is preceded by `?` or `:`, which is what the second test keeps.
    if (/^[a-z][\w-]*$/.test(text) && !/[?:]\s*$/.test(before)) continue;
    out.push({ line: lineOf(at), text });
  }
  for (const match of stripped.matchAll(/>([^<{]+)</g)) {
    const text = match[1];
    // `;` and `=` are code; so is the `) : x ? (` tail of a ternary between two elements.
    if (/[;=]|^\s*\)\s*:|\?\s*\(\s*$/.test(text)) continue;
    out.push({ line: lineOf(match.index ?? 0), text });
  }
  return out;
}

/** Each entry is the word as a person would read it; every pattern is case-insensitive
 *  and word-bounded so `door` does not match `indoors` and `run` does not match `prune`. */
const FORBIDDEN: { word: string; pattern: RegExp }[] = [
  { word: "door", pattern: /\bdoor\b/i },
  { word: "mint", pattern: /\bmint(?:ed|ing|s)?\b/i },
  { word: "refus…", pattern: /\brefus/i },
  { word: "admitted", pattern: /\badmitted\b/i },
  { word: "ceiling", pattern: /\bceiling/i },
  { word: "dial", pattern: /\bdial(?:s|led|ling)?\b/i },
  { word: "vetted", pattern: /\bvetted\b/i },
  { word: "consent flow", pattern: /\bconsent flow/i },
  { word: "Create MCP", pattern: /\bCreate MCP\b/i },
  { word: "run", pattern: /\brun\b|\bruns\b|\brunning\b/i },
];

/** Strings that are not the product's own words. A `mono` argument name, a CLI flag
 *  quoted for an administrator, or an id prefix the API itself uses. Kept short on
 *  purpose: every entry here is a sentence somebody has to read past. */
const ALLOWED = [
  // The CLI command the connect card tells a person to type; "Run" is the verb for it.
  /Run the command in a terminal/,
];

describe("the vocabulary on screen", () => {
  const files = sources();

  it("scans the screens", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  for (const file of files) {
    it(`${relative(ROOT, file)} uses no retired word`, () => {
      const stripped = stripComments(readFileSync(file, "utf8"));
      const hits: string[] = [];
      for (const { line, text } of visibleText(stripped)) {
        if (ALLOWED.some((ok) => ok.test(text))) continue;
        for (const { word, pattern } of FORBIDDEN) {
          if (pattern.test(text)) hits.push(`line ${line}: "${word}" in ${JSON.stringify(text.trim())}`);
        }
      }
      expect(hits).toEqual([]);
    });
  }
});
