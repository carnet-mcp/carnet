/** The dialect table — the two properties every entry keeps, and the reason rule. */

import { describe, expect, it } from "vitest";

import { DEFAULT_DIALECT, DIALECTS, dialect, unreachable } from "./dialects";

const URL = "https://ship.acme.com/api/mcp";

describe("every dialect", () => {
  it("says <your token> and carries the door's URL, or is a reason", () => {
    for (const entry of DIALECTS) {
      if (entry.auth === "oauth") {
        // Step 083: an OAuth client connects with the URL alone — no header, no token.
        expect(unreachable(entry, URL)).toBeNull();
        expect(entry.snippet(URL)).toBe(URL);
        expect(entry.where).toMatch(/sign in and approve/);
        continue;
      }
      const text = entry.snippet(URL);
      expect(text, entry.id).toContain(URL);
      expect(text, entry.id).toContain("Bearer <your token>");
      expect(text, entry.id).not.toMatch(/art_m_/);
    }
  });

  it("shows where to paste only when tried against the real client", () => {
    // Only Claude Code was tried from this machine (plan 075); anything else marked
    // verified needs the plan to say how.
    expect(DIALECTS.filter((d) => d.verified).map((d) => d.id)).toEqual(["claude-code"]);
    for (const entry of DIALECTS.filter((d) => d.verified)) {
      expect(entry.where.length).toBeGreaterThan(0);
    }
  });

  it("has unique ids and a default that exists", () => {
    const ids = DIALECTS.map((d) => d.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(dialect(DEFAULT_DIALECT).id).toBe(DEFAULT_DIALECT);
    expect(dialect("no-such").id).toBe(DEFAULT_DIALECT);
  });
});

describe("the reason", () => {
  it("is https, and only https, since the door speaks OAuth", () => {
    const oauth = dialect("claude-ai");
    expect(unreachable(oauth, "http://localhost:8000/mcp")).toMatch(/plain http:\/\//);
    expect(unreachable(oauth, URL)).toBeNull();
    const strict = { ...dialect("cursor"), needsHttps: true };
    expect(unreachable(strict, "http://localhost:8000/mcp")).toMatch(/plain http:\/\//);
    expect(unreachable(strict, URL)).toBeNull();
    expect(unreachable(dialect("cursor"), "http://localhost:8000/mcp")).toBeNull();
  });
});
