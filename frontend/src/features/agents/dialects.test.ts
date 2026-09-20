/** The dialect table — the two properties every entry keeps, and the reason rule. */

import { describe, expect, it } from "vitest";

import { DEFAULT_DIALECT, DIALECTS, dialect, frameworks, ordered, unreachable } from "./dialects";

const URL = "https://ship.acme.com/api/mcp";

describe("every dialect", () => {
  it("says <your token> and carries the MCP server's URL, or is a reason", () => {
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
    // Claude Code was tried from this machine (plan 075). The four frameworks were each
    // run against a fileborne door on 2026-09-19/20 (plan 111's addendum: list, call,
    // refusal, with the library versions). Anything else marked verified needs the plan
    // to say how.
    expect(DIALECTS.filter((d) => d.verified).map((d) => d.id)).toEqual([
      "claude-code",
      "langchain",
      "crewai",
      "openai-agents",
      "autogen",
    ]);
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

describe("the frameworks (111)", () => {
  it("are four, code rather than config, and kept out of the clients' groups", () => {
    expect(frameworks().map((d) => d.id)).toEqual(["langchain", "crewai", "openai-agents", "autogen"]);
    for (const entry of frameworks()) {
      expect(entry.group).toBe("framework");
      expect(entry.auth).toBe("header");
      // A library imports something; a client pastes a file. The snippet is Python.
      expect(entry.snippet(URL), entry.id).toMatch(/^from \w/);
      expect(entry.snippet(URL), entry.id).toContain(URL);
      expect(entry.snippet(URL), entry.id).toContain("Bearer <your token>");
      // `where` is where in the code it goes, and starts with the install line.
      expect(entry.where, entry.id).toMatch(/^pip install /);
    }
    for (const url of ["https://ship.example.com/api/mcp", "http://localhost:8000/mcp"]) {
      const { primary, more } = ordered(url);
      for (const entry of [...primary, ...more]) expect(entry.group).toBe("client");
    }
    // Every dialect is in exactly one group.
    const grouped = new Set([...ordered(URL).primary, ...ordered(URL).more, ...frameworks()].map((d) => d.id));
    expect(grouped.size).toBe(DIALECTS.length);
  });
});

describe("the reason", () => {
  it("is https, and only https, since the MCP server speaks OAuth", () => {
    const oauth = dialect("claude-ai");
    expect(unreachable(oauth, "http://localhost:8000/mcp")).toMatch(/requires an https:\/\/ address/);
    expect(unreachable(oauth, URL)).toBeNull();
    const strict = { ...dialect("cursor"), needsHttps: true };
    expect(unreachable(strict, "http://localhost:8000/mcp")).toMatch(/requires an https:\/\/ address/);
    expect(unreachable(strict, URL)).toBeNull();
    expect(unreachable(dialect("cursor"), "http://localhost:8000/mcp")).toBeNull();
  });
});
