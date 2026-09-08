/** The claim this chunk rests on: **the form cannot produce an invalid scope.**
 *
 * `_validate_scope_matches_tools` refuses in both directions — a granted tool whose
 * resource type has no scope entry at its effect, and a scope entry no granted tool
 * touches — and 010b's finding is that a form deriving its scope from the same catalogue
 * the validator reads cannot violate either. "Correct by construction" is worth exactly
 * the test behind it, so this file is that test rather than the comment.
 *
 * ## Two halves, because one language cannot prove it alone
 *
 * The rule lives in Python. This is TypeScript. So the assertion is split:
 *
 *   here          for every subset of the seeded tenant's tools, `toConfig` produces a
 *                 scope whose `(type, effect)` pairs are **exactly** the pairs the ticked
 *                 tools declare. The rule, restated — short enough to be visibly the same
 *                 rule rather than a paraphrase of it.
 *
 *   the fixture   those same configs, written to `draft.fixture.json` and checked in.
 *                 `backend/tests/test_api.py` posts every one of them to
 *                 `POST /agents/validate` and requires a 200 — which is the real
 *                 validator, over the wire, on the exact bytes this file generates.
 *
 * Neither side can drift quietly. Change the derivation and this test fails with a diff;
 * regenerate deliberately with `UPDATE_DRAFT_FIXTURE=1 npm test` and the backend test
 * re-proves the new output against the real rule. Change the seeded catalogue and the
 * backend test fails on the tool list before it validates anything.
 */

import fs from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

import {
  EMPTY,
  type Draft,
  clearDraft,
  loadDraft,
  nameIsUsable,
  requiredRows,
  rowKey,
  fromConfig,
  patchFrom,
  saveDraft,
  scopeOf,
  slugify,
  toConfig,
} from "./draft";
import { UNREAD } from "../features/agents/AgentDetailPage";
import type { ToolGroup } from "./types";

/** The seeded tenant's catalogue, exactly.
 *
 *  Copied from `tools.catalogue()` after `bootstrap.seed_tenant` rather than invented —
 *  and the backend test asserts the fixture's tool list still matches that seed, so this
 *  cannot rot silently. `github_mcp_issue_read` is the one worth noticing: two read tools
 *  on one resource type, which is what makes the "many tools, one row" case real rather
 *  than hypothetical. */
const CATALOGUE: ToolGroup[] = [
  {
    origin: "builtin",
    id: "",
    description: "Tools that ship with the platform.",
    tools: [
      tool("post_message", "write", ["chat.channel"]),
    ],
  },
  {
    origin: "connector",
    id: "github-mcp",
    description: "Official GitHub MCP server (read path: issues).",
    tools: [
      tool("github_mcp_list_issues", "read", ["github.repo"]),
      tool("github_mcp_issue_read", "read", ["github.repo"]),
      tool("github_mcp_add_issue_comment", "write", ["github.repo"]),
    ],
  },
];

function tool(name: string, effect: "read" | "write", resources: string[]) {
  return {
    name,
    remote_name: null,
    description: "",
    note: "",
    effect,
    identity: "service" as const,
    resources: resources.map((type) => ({ type })),
    max_response_bytes: null,
    vetted_by: "",
    vetted_at: "",
  };
}

const ALL = CATALOGUE.flatMap((g) => g.tools.map((t) => t.name));

function draft(over: Partial<Draft> = {}): Draft {
  return { ...EMPTY, name: "triage-bot", ...over };
}

/** Every subset of the catalogue, smallest first. 2^4 = 16. */
function subsets<T>(items: T[]): T[][] {
  return items.reduce<T[][]>((acc, item) => [...acc, ...acc.map((s) => [...s, item])], [[]]);
}

/** `(type, effect)` pairs the ticked tools declare — `needed`, in the validator's words. */
function needed(tools: string[]): Set<string> {
  const pairs = new Set<string>();
  for (const group of CATALOGUE) {
    for (const t of group.tools) {
      if (!tools.includes(t.name)) continue;
      for (const ref of t.resources) pairs.add(rowKey(ref.type, t.effect));
    }
  }
  return pairs;
}

/** `(type, effect)` pairs a scope grants — `granted`. */
function granted(scope: Record<string, Record<string, string[]>>): Set<string> {
  const pairs = new Set<string>();
  for (const [type, effects] of Object.entries(scope)) {
    for (const effect of Object.keys(effects)) pairs.add(rowKey(type, effect));
  }
  return pairs;
}

/** A draft with every implied row answered, one way or the other. */
function answered(tools: string[], any: boolean): Draft {
  const reach: Draft["reach"] = {};
  for (const row of requiredRows(tools, CATALOGUE)) {
    reach[rowKey(row.resource, row.effect)] = any
      ? { any: true, ids: [] }
      : { any: false, ids: [`example/${row.resource.replace(".", "-")}`] };
  }
  return draft({ tools, reach });
}

describe("the scope is derived, in both directions", () => {
  it.each(subsets(ALL).map((s) => [s.join(", ") || "(nothing ticked)", s] as const))(
    "%s — every granted tool has a scope row, and no row is unused",
    (_label, tools) => {
      for (const any of [true, false]) {
        const scope = scopeOf(answered([...tools], any), CATALOGUE);
        // The rule itself: needed == granted, as a set equality. Not "no error was
        // thrown" — this is what `_validate_scope_matches_tools` computes.
        expect([...granted(scope)].sort()).toEqual([...needed([...tools])].sort());
      }
    },
  );

  it("drops a tool's row when it is unticked — the direction a form leaves stale", () => {
    const both = answered(["post_message", "github_mcp_list_issues"], false);
    expect(Object.keys(scopeOf(both, CATALOGUE)).sort()).toEqual([
      "chat.channel",
      "github.repo",
    ]);

    // The identifiers are deliberately NOT thrown away — see `draft.ts`. What matters is
    // that they cannot reach the config while the row is unasked.
    const fewer = { ...both, tools: ["github_mcp_list_issues"] };
    expect(Object.keys(scopeOf(fewer, CATALOGUE))).toEqual(["github.repo"]);
    expect(fewer.reach[rowKey("chat.channel", "write")]).toBeDefined();
  });

  it("keeps one row for two tools that touch the same thing the same way", () => {
    const rows = requiredRows(["github_mcp_list_issues", "github_mcp_issue_read"], CATALOGUE);

    expect(rows).toHaveLength(1);
    expect(rows[0].through).toEqual(["github_mcp_list_issues", "github_mcp_issue_read"]);
  });

  it("splits a read and a write on one resource type into two rows", () => {
    // `github.repo` at read and at write are different questions with different answers,
    // and collapsing them would grant write reach to whoever only meant to allow reading.
    const rows = requiredRows(
      ["github_mcp_list_issues", "github_mcp_add_issue_comment"],
      CATALOGUE,
    );

    expect(rows.map((r) => `${r.resource}|${r.effect}`)).toEqual([
      "github.repo|write",
      "github.repo|read",
    ]);
  });

  it("asks about writes first", () => {
    const rows = requiredRows(ALL, CATALOGUE);
    expect(rows.map((r) => r.effect)).toEqual(["write", "write", "read"]);
  });

  it("asks nothing for a tool that touches no resource", () => {
    const none: ToolGroup[] = [
      { origin: "builtin", id: "", description: "", tools: [tool("think", "read", [])] },
    ];
    expect(requiredRows(["think"], none)).toEqual([]);
    expect(scopeOf(draft({ tools: ["think"] }), none)).toEqual({});
  });
});

describe("patterns are produced, never taught", () => {
  it('"anything" is the only thing that generates a wildcard', () => {
    const scope = scopeOf(answered(["post_message"], true), CATALOGUE);
    expect(scope["chat.channel"].write).toEqual(["**"]);
  });

  it("a typed identifier is passed through exactly as written", () => {
    // Somebody who already knows the syntax can still use it; nothing here teaches it.
    const d = draft({
      tools: ["post_message"],
      reach: { [rowKey("chat.channel", "write")]: { any: false, ids: ["#eng", "team/*"] } },
    });
    expect(scopeOf(d, CATALOGUE)["chat.channel"].write).toEqual(["#eng", "team/*"]);
  });

  it("trims and drops blank lines rather than sending an empty pattern", () => {
    // `patterns.validate` refuses an empty string, so the alternative is a 422 about a
    // field somebody was halfway through typing. Not silent: the review step renders the
    // result through the same component the agent's own page uses.
    const d = draft({
      tools: ["post_message"],
      reach: {
        [rowKey("chat.channel", "write")]: { any: false, ids: ["  #eng  ", "", "   "] },
      },
    });
    expect(scopeOf(d, CATALOGUE)["chat.channel"].write).toEqual(["#eng"]);
  });
});

describe("what the config carries", () => {
  it("is a name and a permission list, and nothing else — step 081", () => {
    // The door reads `permissions.tools` and `permissions.scope` on every call and reads
    // no other config key, so those are the only keys this form authors. Written as an
    // exact key set rather than as absences, because the failure this guards is a field
    // *added* back — a per-run ceiling, a briefing, an answer schema — which an
    // enumeration of today's absences would not catch.
    expect(Object.keys(toConfig(draft(), CATALOGUE)).sort()).toEqual([
      "name",
      "permissions",
    ]);
  });
});

describe("the name", () => {
  it.each([
    ["Triage Bot", "triage-bot"],
    ["  Triage   Bot  ", "triage-bot"],
    ["Nightly GitHub → Slack", "nightly-github-slack"],
    ["v2.0 reporter", "v2-0-reporter"],
    ["already-a-slug", "already-a-slug"],
    ["!!!", ""],
  ])("%o becomes %o", (typed, expected) => {
    expect(slugify(typed)).toBe(expected);
  });

  it("never produces a name the server would refuse", () => {
    // The slug is shown rather than applied silently, so this is not load-bearing for
    // correctness — it is load-bearing for not offering somebody a suggestion that fails.
    for (const typed of ["Triage Bot", "---x---", "a".repeat(200), "v2.0", "ÉTÉ report"]) {
      const slug = slugify(typed);
      if (slug) expect(nameIsUsable(slug)).toBe(true);
    }
  });

  it.each(["Triage Bot", "TriageBot", "x_y", "-x", "x-", "x--y", "x.y", "a".repeat(65)])(
    "%o is refused",
    (name) => expect(nameIsUsable(name)).toBe(false),
  );
});

describe("the draft survives a reload", () => {
  beforeEach(() => sessionStorage.clear());

  it("round-trips", () => {
    const d = answered(["post_message"], false);
    saveDraft(d);
    expect(loadDraft()).toEqual(d);
  });

  it("is cleared on success and only on success", () => {
    saveDraft(draft());
    clearDraft();
    expect(loadDraft()).toEqual(EMPTY);
  });

  it("survives a draft written by an older version of this app", () => {
    // A field added to `Draft` next week is absent from a draft written today, and a
    // restored draft missing `reach` would be a crash on step 3 rather than a fresh start.
    sessionStorage.setItem("carnet.draft.v1", JSON.stringify({ name: "old" }));
    expect(loadDraft()).toEqual({ ...EMPTY, name: "old" });
  });

  it("**a draft written by the app before 081 cannot smuggle its removed fields**", () => {
    // The upgrade path, and the one edge this step actually creates. Somebody had the
    // wizard open across a deploy: their draft carries `limits`, `maxTokens`,
    // `privateRuns`, `outputText`, `system` and `model`, because the form asked for them
    // an hour ago. `loadDraft` spreads it over `EMPTY`, so those keys survive on the
    // object — and none of them may reach the wire, because nothing in this tree reads
    // them and the config they would produce is the one 081 exists to stop.
    const stale = {
      typed: "Triage bot",
      name: "triage-bot",
      tools: ["post_message"],
      reach: { [rowKey("chat.channel", "write")]: { any: true, ids: [] } },
      system: "You summarise.",
      model: "claude-sonnet-5",
      maxTokens: 400,
      privateRuns: true,
      limits: { max_calls: 3, max_writes: 0 },
      outputText: '{"type":"object","additionalProperties":false}',
    };
    sessionStorage.setItem("carnet.draft.v1", JSON.stringify(stale));

    const restored = loadDraft();
    // It restores rather than resetting — losing somebody's tool ticks to an upgrade
    // would be the wrong half of this to get right.
    expect(restored.name).toBe("triage-bot");
    expect(restored.tools).toEqual(["post_message"]);

    // And the config it produces is the config 081 defines, whatever the object carries.
    expect(Object.keys(toConfig(restored, CATALOGUE)).sort()).toEqual([
      "name",
      "permissions",
    ]);
    // Same for an edit built from it — `patchFrom` reads `FORM_KEYS`, not the draft.
    const { original } = fromConfig({ name: "triage-bot", system: "kept" }, CATALOGUE);
    expect(Object.keys(patchFrom(restored, original, CATALOGUE))).toEqual(["permissions"]);
  });

  it("survives nonsense in storage", () => {
    sessionStorage.setItem("carnet.draft.v1", "{not json");
    expect(loadDraft()).toEqual(EMPTY);
  });
});

// --- the half the real validator checks ---------------------------------------------

const FIXTURE = path.join(__dirname, "draft.fixture.json");

describe("the fixture the backend validates", () => {
  it("is what this code produces", () => {
    const cases = subsets(ALL).flatMap((tools) =>
      [true, false].map((any) => ({
        tools,
        reach: any ? "anything" : "specific",
        config: toConfig(answered(tools, any), CATALOGUE),
      })),
    );

    const generated = {
      note:
        "Generated by draft.test.ts and validated by backend/tests/test_api.py against " +
        "the real POST /agents/validate. Regenerate with UPDATE_DRAFT_FIXTURE=1 npm test.",
      tools: ALL,
      // Step 081. The config keys `AgentDraft` accepts, that the door does not read, and
      // that `AgentDetailPage` therefore shows under *Stored, and not read here*. Carried
      // in this fixture because it is a claim about the **server's** schema that only the
      // server can check: `test_api.py` asserts this is exactly `AgentDraft`'s fields less
      // `name` and `permissions`, so a field added there and not listed here — stored,
      // unread and invisible — is a red build rather than a silence.
      unread: UNREAD.map(({ key }) => key).sort(),
      cases,
    };

    if (process.env.UPDATE_DRAFT_FIXTURE) {
      fs.writeFileSync(FIXTURE, JSON.stringify(generated, null, 2) + "\n");
    }

    expect(JSON.parse(fs.readFileSync(FIXTURE, "utf8"))).toEqual(generated);
  });
});


// --- editing: the round trip that must NOT be lossless -------------------------------
//
// `fromConfig` is deliberately not the inverse of `toConfig`, and these are the
// assertions that keep it that way. The finding is confirmed rather than hypothetical:
// the shipped `issue-reporter` carries `default_task` and `deny_demo_task`, and nothing
// in this form has ever asked about either.

/** The shipped agent, trimmed to what matters here. Its two extra fields are the point. */
const STORED = {
  name: "issue-reporter",
  runtime: "simple",
  system: "You read GitHub issues and summarize them.",
  permissions: {
    tools: ["github_mcp_list_issues", "post_message"],
    scope: {
      "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
      "chat.channel": { write: ["#eng"] },
    },
  },
  default_task: "Summarize the open issues.",
  deny_demo_task: "Summarize torvalds/linux and post to #random.",
};

describe("loading a stored agent into the form", () => {
  it("reads the scope back as the answers that produced it", () => {
    const { draft } = fromConfig(STORED, CATALOGUE);

    expect(draft.tools).toEqual(["github_mcp_list_issues", "post_message"]);
    expect(draft.reach[rowKey("github.repo", "read")]).toEqual({
      any: false,
      ids: ["anthropics/anthropic-sdk-python"],
    });
    expect(draft.reach[rowKey("chat.channel", "write")]).toEqual({
      any: false,
      ids: ["#eng"],
    });
  });

  it("reads `**` back as \"anything\", and only `**`", () => {
    const wide = fromConfig(
      { ...STORED, permissions: { ...STORED.permissions, scope: {
        "github.repo": { read: ["**"] },
        "chat.channel": { write: ["#eng", "#ops"] },
      } } },
      CATALOGUE,
    ).draft;

    expect(wide.reach[rowKey("github.repo", "read")]).toEqual({ any: true, ids: [] });
    // A hand-written multi-entry list is not "anything" and must come back as text —
    // somebody typed those and has to be shown what they typed.
    expect(wide.reach[rowKey("chat.channel", "write")]).toEqual({
      any: false,
      ids: ["#eng", "#ops"],
    });
  });

  it("keeps the whole config beside the draft rather than reconstructing it", () => {
    expect(fromConfig(STORED, CATALOGUE).original).toBe(STORED);
  });
});

describe("saving it back", () => {
  it("sends nothing at all when nothing was touched", () => {
    const { draft, original } = fromConfig(STORED, CATALOGUE);

    expect(patchFrom(draft, original, CATALOGUE)).toEqual({});
  });

  it("does not report a reordered scope as a change", () => {
    // **This failed when it was written, and the defect was real.** `scopeOf` emits
    // writes first while a stored config lists whatever order it was written in, so a
    // plain string comparison called an untouched `permissions` block changed — which
    // would put `permissions` in the 409's `changed` list every time two people edit one
    // agent, on the one message that has to be exact.
    const reordered = {
      ...STORED,
      permissions: {
        ...STORED.permissions,
        scope: {
          "chat.channel": { write: ["#eng"] },
          "github.repo": { read: ["anthropics/anthropic-sdk-python"] },
        },
      },
    };
    const { draft, original } = fromConfig(reordered, CATALOGUE);

    expect(patchFrom(draft, original, CATALOGUE)).toEqual({});
  });

  it("**preserves every unread stored field, because nothing can send one**", () => {
    // Step 081, and it is a stronger claim than the three guards it replaces. `patchFrom`
    // used to carry a special case per field — do not send `model` when the stored config
    // named none, do not send an `""` `system` an absent one was read back as, do not send
    // an unticked `private_runs` — each needed because the draft carried a field it then
    // had to be careful not to send. The draft carries none of them, so this is a property
    // of the shape rather than a rule somebody can forget.
    const loaded = {
      ...STORED,
      system: "You summarise.",
      model: "claude-sonnet-5",
      max_tokens: 400,
      runtime: "simple",
      private_runs: true,
      limits: { max_calls: 3, max_writes: 0 },
      output: { schema: { type: "object", additionalProperties: false } },
    };
    const { draft, original } = fromConfig(loaded, CATALOGUE);

    // Untouched: an empty patch, so a save that changed nothing changes nothing.
    expect(patchFrom(draft, original, CATALOGUE)).toEqual({});

    // And a real permission change sends the permission change **alone** — every unread
    // key survives a save that rewrote the agent's whole reach.
    const patch = patchFrom({ ...draft, tools: ["post_message"] }, original, CATALOGUE);
    expect(Object.keys(patch)).toEqual(["permissions"]);
  });

  it("does not report an absent `limits` as having become empty", () => {
    // An agent with no `limits` and an agent with `limits: {}` are the same agent. This
    // used to need an is-empty-object guard in `patchFrom`; since 081 the form does not
    // author `limits` at all, so the key can never appear in a patch from either side.
    const { draft, original } = fromConfig(STORED, CATALOGUE);
    expect(original).not.toHaveProperty("limits");

    expect(patchFrom(draft, original, CATALOGUE)).not.toHaveProperty("limits");
    const capped = fromConfig({ ...STORED, limits: { max_calls: 3 } }, CATALOGUE);
    expect(patchFrom(capped.draft, capped.original, CATALOGUE)).not.toHaveProperty("limits");
  });

  it("**never sends the fields no step asks about**", () => {
    // The whole reason `PATCH` takes a partial config. A whole-config save built from
    // this form deletes these, and nothing anywhere would report it.
    const { draft, original } = fromConfig(STORED, CATALOGUE);

    const patch = patchFrom({ ...draft, tools: ["post_message"] }, original, CATALOGUE);

    expect(patch).not.toHaveProperty("default_task");
    expect(patch).not.toHaveProperty("deny_demo_task");
    // And not `runtime`, which until 081 the *server* wrote into every API-created agent
    // — `AgentDraft.runtime` defaulted to `DEFAULT_RUNTIME`, so the shipped example and an
    // agent made over HTTP disagreed about the shape of a config.
    expect(patch).not.toHaveProperty("runtime");
  });

  it("sends the whole permissions block when either half changes", () => {
    const { draft, original } = fromConfig(STORED, CATALOGUE);

    const patch = patchFrom(
      { ...draft, tools: ["post_message"] },
      original,
      CATALOGUE,
    );

    // `tools` and `scope` are cross-checked in both directions, so a patch carrying one
    // and not the other is the one way to produce a config the validator refuses through
    // a route that looks like it is working. The derived scope drops the github row with
    // the tool that implied it.
    expect(patch.permissions).toEqual({
      tools: ["post_message"],
      scope: { "chat.channel": { write: ["#eng"] } },
    });
  });

});

