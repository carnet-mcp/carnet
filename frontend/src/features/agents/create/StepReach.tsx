/** Step 3 — what it may reach. **This is the step 10c exists for.**
 *
 * A scope is a permission model, and the person filling it in does not know what a
 * permission model is. The answer is not a friendlier editor for scope patterns; it is
 * that they are never shown one.
 *
 * Every row below was *derived*: a tool was ticked, the catalogue says which resource
 * types it touches and at what effect, and that pair is a question. Untick the tool and
 * the question disappears with it — which is the second direction of
 * `_validate_scope_matches_tools`, the one a form would otherwise leave stale, and it is
 * unreachable here rather than guarded against.
 *
 * The only thing anybody supplies is identifiers.
 *
 *     resource type   github.repo      from the catalogue, because a tool was ticked
 *     effect          read / write     from the catalogue, because the tool declares it
 *     patterns        ["a/b", "**"]    this screen
 *
 * **Nothing teaches a wildcard.** "Anything" produces `**`; the word never appears. A
 * typed identifier is passed through exactly as written, so somebody who already knows
 * the syntax can enter `org/*` and the server will validate it — but they have to know
 * it, which is the right gate. A person who does not know what `**` means must not be
 * able to produce one by accident.
 */

import { Badge, Button, Card, Empty, Notice } from "../../../components/ui";
import {
  type Draft,
  type ReachRow,
  type RequiredRow,
  requiredRows,
  rowKey,
} from "../../../lib/draft";
import type { ToolGroup } from "../../../lib/types";
import type { StepProps } from "./CreateAgentPage";

export function reachBlocker(draft: Draft, catalogue: ToolGroup[] | null): string {
  for (const row of requiredRows(draft.tools, catalogue)) {
    const answer = draft.reach[rowKey(row.resource, row.effect)];
    if (!answer) return `Say which ${row.resource} it may ${row.effect}.`;
    // **The trap this catches is real and would otherwise ship.** "Only these" with an
    // empty list is a perfectly valid config — the scope entry exists, so
    // `_validate_scope_matches_tools` is satisfied — and it denies every call the tool
    // could make. The agent reads as capable and is not, which is the exact failure the
    // validator's *other* direction exists to prevent, arriving through the one door it
    // does not cover.
    if (!answer.any && answer.ids.every((id) => !id.trim())) {
      return `Add at least one ${row.resource}, or choose "anything".`;
    }
  }
  return "";
}

export default function StepReach({ draft, set, catalogue }: StepProps) {
  const rows = requiredRows(draft.tools, catalogue);

  function setRow(row: RequiredRow, next: ReachRow) {
    set({ reach: { ...draft.reach, [rowKey(row.resource, row.effect)]: next } });
  }

  if (rows.length === 0) {
    return (
      <Empty title="Nothing to narrow">
        {draft.tools.length === 0 ? (
          <p>
            This agent is granted no tools, so there is nothing for it to reach. It will
            be able to answer a question and touch nothing.
          </p>
        ) : (
          <p>
            None of the tools you ticked act on a particular thing — they take no
            resource, so there is nothing to point them at.
          </p>
        )}
      </Empty>
    );
  }

  return (
    <>
      <Card
        title="What may it reach?"
        hint={rows.length === 1 ? "one question" : `${rows.length} questions`}
      >
        <p className="sentence">
          These are not extra options. Each one is here because you ticked a tool that
          acts on it, and the agent cannot make a single call until you answer it.
        </p>
      </Card>

      {rows.map((row) => (
        <ReachCard
          key={rowKey(row.resource, row.effect)}
          row={row}
          answer={draft.reach[rowKey(row.resource, row.effect)]}
          onChange={(next) => setRow(row, next)}
        />
      ))}
    </>
  );
}

function ReachCard({
  row,
  answer,
  onChange,
}: {
  row: RequiredRow;
  answer: ReachRow | undefined;
  onChange: (next: ReachRow) => void;
}) {
  const write = row.effect === "write";
  const ids = answer?.ids ?? [];
  const any = answer?.any ?? false;
  const name = `reach-${rowKey(row.resource, row.effect)}`;

  return (
    <Card>
      <div className="tool-head">
        <span className="mono name">{row.resource}</span>
        <Badge tone={write ? "warn" : "waiting"}>{row.effect}</Badge>
        <span className="muted from">
          {/* The same join `_validate_scope_matches_tools` computes and the detail page's
              Through column renders. It turns "fill in github.repo" into "fill this in
              because you ticked that", which is the difference between a form field and
              a question somebody can answer. */}
          because you ticked {row.through.join(", ")}
        </span>
      </div>

      <div className="choices">
        <label className="choice">
          <input
            type="radio"
            name={name}
            checked={!any && answer !== undefined}
            onChange={() => onChange({ any: false, ids })}
          />
          <span>Only the ones I list</span>
        </label>
        <label className="choice">
          <input
            type="radio"
            name={name}
            checked={any}
            onChange={() => onChange({ any: true, ids })}
          />
          <span>Anything of this type</span>
        </label>
      </div>

      {any ? (
        // **The one place this form speaks in its own voice**, because this is the one
        // choice that cannot be narrowed later without somebody noticing. It is also the
        // only choice here that produces a pattern nobody typed.
        <Notice tone="warn" title="This is the widest thing you can grant">
          <p className="sentence">
            Whoever calls through this agent will be able to reach{" "}
            <strong>every {row.resource} their own account can</strong>
            {write ? ", and change it" : ""}. Every call is recorded against their name.
          </p>
        </Notice>
      ) : (
        <Identifiers
          resource={row.resource}
          ids={ids}
          onChange={(next) => onChange({ any: false, ids: next })}
        />
      )}
    </Card>
  );
}

/** The list of identifiers, typed exactly as they will be stored.
 *
 *  No validation of the *contents*: a resource identifier is a string one connector
 *  produces from its own arguments — `anthropics/anthropic-sdk-python` for a repo, `#eng`
 *  for a channel — and this app deliberately does not know how any of them are composed.
 *  Learning that would be the coupling `ResourceType` exists to prevent, and it would be
 *  wrong for the next connector. The server validates the *pattern*; whether the thing
 *  exists is answered by the tool call, by the system that owns it. */
function Identifiers({
  resource,
  ids,
  onChange,
}: {
  resource: string;
  ids: string[];
  onChange: (next: string[]) => void;
}) {
  return (
    <div className="ids">
      {ids.map((id, index) => (
        <div className="spread id-row" key={index}>
          <input
            type="text"
            className="mono"
            value={id}
            aria-label={`${resource} ${index + 1}`}
            placeholder={PLACEHOLDER[resource] ?? "…"}
            onChange={(event) =>
              onChange(ids.map((v, i) => (i === index ? event.target.value : v)))
            }
          />
          <Button kind="quiet" onClick={() => onChange(ids.filter((_, i) => i !== index))}>
            Remove
          </Button>
        </div>
      ))}
      <Button onClick={() => onChange([...ids, ""])}>
        {ids.length === 0 ? `Add a ${resource}` : "Add another"}
      </Button>
      {ids.some((id) => !id.trim()) && (
        <p className="muted">An empty line grants nothing — fill it in or remove it.</p>
      )}
    </div>
  );
}

/** A hint at the *shape* of an identifier, for the two resource types that ship.
 *
 *  A lookup rather than anything cleverer, and it is allowed to be incomplete: an unknown
 *  type gets no placeholder rather than a guess. This is the one place in the app that
 *  knows anything connector-specific, and it is a placeholder attribute — nothing here
 *  parses, validates or composes an identifier. */
const PLACEHOLDER: Record<string, string> = {
  "github.repo": "anthropics/anthropic-sdk-python",
  "chat.channel": "#eng",
};
