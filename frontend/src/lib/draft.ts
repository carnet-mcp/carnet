/** The agent being built, and the one idea 10c is actually about.
 *
 * ## The scope is derived, not authored
 *
 * A scope is `{resource_type: {effect: [patterns]}}`, and three things go into it:
 *
 *     resource type   github.repo      from the catalogue, because a tool was ticked
 *     effect          read / write     from the catalogue, because the tool declares it
 *     patterns        ["a/b", "**"]    the only thing a person supplies
 *
 * So this module never stores a scope. It stores **tool names and identifiers**, and
 * `toConfig` computes the scope from the catalogue at the moment it is needed. That is
 * not a tidiness choice, it is what makes the form correct by construction:
 * `_validate_scope_matches_tools` refuses in *both* directions — a granted tool whose
 * resource type has no scope entry at its effect, **and** a scope entry no granted tool
 * touches — and a scope derived from the same catalogue the validator reads cannot
 * violate either.
 *
 * The second direction is the one a form leaves broken. Untick a tool and its rows stop
 * being computed; there is no stale entry to forget to remove, because there was never
 * an entry, only an answer waiting for a question that is no longer asked.
 *
 * **What somebody typed is kept anyway.** `reach` is keyed by row rather than trimmed to
 * the current tools, so unticking a tool and changing your mind does not lose the
 * repository you already typed. Keeping it is safe precisely because it is not the
 * scope — it cannot leak into the config while the row is unasked.
 *
 * ## Nothing here teaches a pattern language
 *
 * "Anything" generates `**`. The interface does not mention wildcards, because a person
 * who does not know what `**` means must not be able to produce one by accident. A typed
 * identifier is passed through **as written**, so somebody who does know the syntax can
 * still enter `org/*` and the server will validate it — but they have to know, which is
 * the correct gate. See `core/patterns.py` for why the language is deliberately not
 * regex; this keeps it out of the interface as well as out of the matcher.
 *
 * ## sessionStorage
 *
 * One key, cleared when the create succeeds. Decision 6 of 010 says what looks like app
 * state is usually server state — a draft genuinely is not, and this is the exception
 * rather than a hole in the rule.
 *
 * It matters more than it would have before 10b: a reload currently costs a sign-in
 * click (the third-party-cookie defect, half-fixed and recorded in plan 010b), so losing
 * an in-progress form to a refresh is a real risk rather than a theoretical one. The
 * draft holds a name, a list of tool names and the identifiers typed against them —
 * nothing sealed, nothing credential-shaped. It held a prompt until step 081; it does
 * not now, because a config is a permission list and nothing on these screens authors
 * anything else.
 */

import type { ToolGroup } from "./types";

/** The identifiers for one derived row: `github.repo` at `read`. */
export interface ReachRow {
  /** True for "anything of this type", which generates `**`. */
  any: boolean;
  /** Written as typed. Empty when `any`. */
  ids: string[];
}

export interface Draft {
  /** What the person typed. Kept beside `name` so the slug can be re-derived while they
   *  are still editing, and so the review step can show what they called it. */
  typed: string;
  /** The slug. Editable — shown, not hidden. */
  name: string;
  tools: string[];
  /** Keyed `resource|effect`. See `rowKey`. */
  reach: Record<string, ReachRow>;
}

export const EMPTY: Draft = {
  typed: "",
  name: "",
  tools: [],
  reach: {},
};

/** One derived scope row: a resource type, an effect, and which ticked tools imply it.
 *
 *  `through` is the same join `_validate_scope_matches_tools` computes and the detail
 *  page's Through column renders. Shown here for the same reason it is shown there: it
 *  turns "fill in github.repo" into "fill this in because you ticked that tool". */
export interface RequiredRow {
  resource: string;
  effect: "read" | "write";
  through: string[];
}

export function rowKey(resource: string, effect: string): string {
  return `${resource}|${effect}`;
}

/** Which scope rows the ticked tools imply, in the order the wizard should ask for them.
 *
 *  **Writes first**, same as everywhere else in this product: the identifiers somebody
 *  is about to hand write access to are the ones worth their attention while they still
 *  have some. Within an effect, by resource type, so the order does not shuffle as tools
 *  are ticked.
 *
 *  A tool that declares no resources contributes no row and needs no scope — which is
 *  correct rather than an omission, and is why `needed` in the validator can legitimately
 *  be smaller than the tool list. */
export function requiredRows(tools: string[], catalogue: ToolGroup[] | null): RequiredRow[] {
  const rows = new Map<string, RequiredRow>();

  for (const group of catalogue ?? []) {
    for (const tool of group.tools) {
      if (!tools.includes(tool.name)) continue;
      for (const ref of tool.resources) {
        const key = rowKey(ref.type, tool.effect);
        const existing = rows.get(key);
        if (existing) existing.through.push(tool.name);
        else rows.set(key, { resource: ref.type, effect: tool.effect, through: [tool.name] });
      }
    }
  }

  return [...rows.values()].sort(
    (a, b) =>
      Number(a.effect === "read") - Number(b.effect === "read") ||
      a.resource.localeCompare(b.resource),
  );
}

/** The scope, computed. Never stored — see the module docstring. */
export function scopeOf(
  draft: Draft,
  catalogue: ToolGroup[] | null,
): Record<string, Record<string, string[]>> {
  const scope: Record<string, Record<string, string[]>> = {};

  for (const row of requiredRows(draft.tools, catalogue)) {
    const answer = draft.reach[rowKey(row.resource, row.effect)];
    (scope[row.resource] ??= {})[row.effect] = answer?.any
      ? // The only place a wildcard is produced, and it is produced rather than typed.
        ["**"]
      : // Trimmed, and blanks dropped. A half-typed line is a line somebody was in the
        // middle of, and `patterns.validate` refuses an empty string — so the choice is
        // between dropping it here and a 422 about a field they cannot see. It is not a
        // silent transformation: the review step renders exactly this, through the same
        // component the agent's own page uses.
        (answer?.ids ?? []).map((id) => id.trim()).filter(Boolean);
  }

  return scope;
}

/** The draft as the config `POST /agents` takes. The request body **is** the config.
 *
 *  **A name and a permission list, and nothing else — step 081.** The door reads
 *  `permissions.tools` and `permissions.scope` on every call and reads no other config
 *  key, so those are the only keys this form authors. `system`, `model`, `max_tokens`,
 *  `private_runs`, `output` and `limits` are all still *accepted* by `AgentDraft` — a
 *  config written by `--seed`, by curl, or for a tree that has a runtime stays valid and
 *  stays intact — but a wizard that wrote them here would be storing a value this
 *  deployment will never read, under a sentence claiming it would. */
export function toConfig(
  draft: Draft,
  catalogue: ToolGroup[] | null,
): Record<string, unknown> {
  return {
    name: draft.name,
    permissions: { tools: draft.tools, scope: scopeOf(draft, catalogue) },
  };
}

/** What `Reach` needs, so the review step renders through the detail page's component. */
export function reachable(draft: Draft, catalogue: ToolGroup[] | null) {
  return { tools: draft.tools, scope: scopeOf(draft, catalogue) };
}

// --- editing --------------------------------------------------------------------------
//
// **`fromConfig` is deliberately NOT the inverse of `toConfig`, and that is decision 8.**
//
// An inverse would be lossy in a way that is not theoretical. The shipped `issue-reporter`
// carries `default_task` and `deny_demo_task`; no wizard step asks about either. Load it
// into the form, save the whole config back, and both are gone with nothing reporting it.
// There is a second edge on the same blade: a stored config can carry keys this form
// never asks about — `default_task`, or `runtime` and `system` on an agent made before
// step 078 — and a whole-config save would delete them. `patchFrom` sends back the form's
// own fields and only where they changed, so an unasked key survives by construction.

/** The keys this form owns. Nothing else is ever sent by an edit.
 *
 *  Written down rather than derived, because "derived from the draft" is how a dropped
 *  key comes back: the draft does not hold it, and an inverse would
 *  invent it again. A list is a thing somebody has to change on purpose.
 *
 *  **One key since 081**, and the list is kept rather than inlined for the reason it was
 *  written down in the first place: what the form owns is a decision, and a second key
 *  added to `Draft` without a line here is a key that silently stops being sent. */
const FORM_KEYS = ["permissions"] as const;

/** A stored config, as the form's fields — with the config kept whole beside them. */
export interface Editable {
  draft: Draft;
  /** The config exactly as the server returned it. The baseline `patchFrom` diffs
   *  against, and the thing that never has to be reconstructed. */
  original: Record<string, unknown>;
}

export function fromConfig(
  config: Record<string, unknown>,
  catalogue: ToolGroup[] | null,
): Editable {
  const permissions = (config.permissions ?? {}) as {
    tools?: string[];
    scope?: Record<string, Record<string, string[]>>;
  };
  const tools = permissions.tools ?? [];
  const scope = permissions.scope ?? {};

  // Answers, read back out of the scope the same way `scopeOf` writes it. `["**"]` is the
  // only pattern this form can produce without somebody typing one, so it is the only one
  // read back as "anything" — a hand-written `org/*` stays in the list as text, which is
  // right: somebody who knew the syntax typed it and must be shown what they typed.
  const reach: Record<string, ReachRow> = {};
  for (const row of requiredRows(tools, catalogue)) {
    const patterns = scope[row.resource]?.[row.effect] ?? [];
    const any = patterns.length === 1 && patterns[0] === "**";
    reach[rowKey(row.resource, row.effect)] = { any, ids: any ? [] : patterns };
  }

  const name = String(config.name ?? "");
  return {
    original: config,
    draft: { typed: name, name, tools: [...tools], reach },
  };
}

/** The `PATCH` body: the form's own keys, and only where they differ from what is stored.
 *
 *  Sending only what changed is not an optimisation. A patch that repeats an unchanged
 *  `permissions` block is a patch that appears in the 409's `changed` list, which turns
 *  "you and somebody else disagree about the tool grant" into noise on every save.
 *
 *  **Since 081 the preservation guarantee is a property of the shape rather than a set of
 *  guards.** This function used to carry three special cases — do not send `model` when
 *  the stored config named none and the form shows the platform default, do not send an
 *  `""` `system` an absent one was read back as, do not send an unticked `private_runs`
 *  — each of which existed because the draft carried a field it then had to be careful
 *  not to send. The draft carries none of them now, so a stored `system`, `limits`,
 *  `model`, `max_tokens`, `private_runs` or `output` survives an edit **because there is
 *  no code that could send it**, which is a stronger version of 010d's finding than the
 *  guards were. `test_a_patch_that_omits_a_field_does_not_delete_it` is unchanged and
 *  still the thing that holds the server's half. */
export function patchFrom(
  draft: Draft,
  original: Record<string, unknown>,
  catalogue: ToolGroup[] | null,
): Record<string, unknown> {
  const candidate: Record<string, unknown> = {
    permissions: { tools: draft.tools, scope: scopeOf(draft, catalogue) },
  };

  const patch: Record<string, unknown> = {};
  for (const key of FORM_KEYS) {
    const next = candidate[key];
    if (next === undefined) continue;
    if (!same(next, original[key])) patch[key] = next;
  }
  return patch;
}

/** Deep equality that does not care what order the keys came back in.
 *
 *  **Found by a test, and it would have been a real defect.** `scopeOf` emits writes
 *  first; the stored config lists whatever order it was written in. A plain
 *  `JSON.stringify` comparison therefore reports an untouched `permissions` block as
 *  changed — which sends it on every save, and puts `permissions` in the 409's `changed`
 *  list every time two people edit one agent. The one thing that message has to be is
 *  exact, so this sorts before it compares.
 *
 *  Arrays keep their order, which is right: `["#eng", "#ops"]` and `["#ops", "#eng"]` are
 *  the same policy and a different thing to look at, and this form renders them in the
 *  order they are stored. */
function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
  );
}

// --- the name ----------------------------------------------------------------------

/** A typed name, as a slug. Shown and editable — never applied silently.
 *
 *  The server **refuses** a name that is not a slug rather than transforming one, and
 *  that asymmetry is deliberate: a name quietly rewritten on the way into the database is
 *  a name that differs from the one somebody approved, in the string that goes into every
 *  audit record of what the agent did. So the transformation happens here, in front of
 *  them, where they can disagree with it.
 *
 *  Deliberately lossy in one direction only: it can produce an empty string (from a name
 *  that is entirely punctuation, or entirely non-Latin), and the form asks rather than
 *  inventing something. Transliterating somebody's language into ASCII and calling the
 *  result their agent's name is a worse answer than "we need a URL-safe name for this". */
export function slugify(typed: string): string {
  return typed
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/, "");
}

/** Mirrors `check_agent_name` in `storage/base.py` and migration 019's CHECK.
 *
 *  A **third** copy of the rule, and worth naming as such. The database owns it, the
 *  Python layer refuses with a sentence, and this exists only so the form can disable a
 *  button rather than let somebody reach step 5 and be refused. If they disagree, the
 *  server wins and says so — which is why the wizard renders the server's message rather
 *  than its own whenever there is one. */
export function nameIsUsable(name: string): boolean {
  return /^[a-z0-9]+(-[a-z0-9]+)*$/.test(name) && name.length <= 64;
}

// --- sessionStorage ------------------------------------------------------------------

const KEY = "carnet.draft.v1";

export function loadDraft(): Draft {
  try {
    const stored = sessionStorage.getItem(KEY);
    if (!stored) return EMPTY;
    // Spread over EMPTY rather than trusting the parse. This is a *previous version of
    // this app's* output — a field added to `Draft` next week is absent from a draft
    // written today, and a restored draft missing `reach` would be a crash on step 3
    // rather than a fresh start.
    return { ...EMPTY, ...(JSON.parse(stored) as Partial<Draft>) };
  } catch {
    // Storage disabled, quota exceeded, or a draft this version cannot read. None of
    // those are worth showing somebody who is trying to create an agent.
    return EMPTY;
  }
}

export function saveDraft(draft: Draft): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(draft));
  } catch {
    /* see above: a draft that cannot be saved is still a draft that can be submitted */
  }
}

export function clearDraft(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* nothing to do, and nothing worth saying */
  }
}


// --- the edit page's draft (step 061) -------------------------------------------------
//
// `CreateAgentPage` has persisted every keystroke since the wizard shipped;
// `EditAgentPage` lost twenty minutes of scope decisions to one mis-click. Same
// mechanism, one addition: the key carries the agent AND the version being edited, so
// a draft over version 7 is never restored onto version 8 — resurrecting an edit
// across somebody else's save is exactly the merge the edit page's 409 branch refuses
// to do silently.

const EDIT_KEY_PREFIX = "carnet.editdraft.v1.";

function editKey(name: string, version: number): string {
  return `${EDIT_KEY_PREFIX}${name}@${version}`;
}

export function loadEditDraft(name: string, version: number): Draft | null {
  try {
    const stored = sessionStorage.getItem(editKey(name, version));
    if (!stored) return null;
    // Spread over EMPTY for `loadDraft`'s reason: this is a previous version of this
    // app's output, and a missing field must degrade to the default, not a crash.
    return { ...EMPTY, ...(JSON.parse(stored) as Partial<Draft>) };
  } catch {
    return null;
  }
}

export function saveEditDraft(name: string, version: number, draft: Draft): void {
  try {
    sessionStorage.setItem(editKey(name, version), JSON.stringify(draft));
  } catch {
    /* a draft that cannot be saved is still a draft that can be submitted */
  }
}

export function clearEditDraft(name: string, version: number): void {
  try {
    sessionStorage.removeItem(editKey(name, version));
  } catch {
    /* nothing to do, and nothing worth saying */
  }
}
