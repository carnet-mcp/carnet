/** What a token reaches, read tool-first. Step 069, and the reflect half of it.
 *
 * ## Why this exists beside `Reach`, and not instead of it
 *
 * `Reach.tsx` renders one agent's permission model, and `TokenDetailPage` renders one of
 * them per granted agent — which 035d chose deliberately, because in tool mode a token
 * holds the union of the tools of the agents it is granted, **each tool keeping its own
 * agent's scope**. A single flat `{tools, scope}` would either union those scopes, which
 * invents a permission nobody wrote down, or pick one, which shows a narrower reach than
 * the token has.
 *
 * That decision is right and it is not an answer. The question people arrive with is
 * about a *tool* — *what can this credential do to our repositories* — and the per-agent
 * shape answers it only for somebody willing to read three sections and hold them in
 * their head. **The reader who most needs this is the one who already suspects the token
 * is over-broad**, which is the worst moment to hand somebody a cross-reference exercise.
 *
 * So: the same grants, transposed. One row per tool, every agent that carries it, and —
 * per agent — only the patterns that could actually decide a call to *that* tool.
 *
 * ## Why the server computes it
 *
 * This component holds every input needed to do the transpose in TypeScript: `agents` is
 * right there, and so is the catalogue. Doing it here would be the union rule implemented
 * a second time, in a second language, **by the surface whose entire job is to explain
 * it** — and the first time the two disagreed, this one would be believed, because it is
 * the one on the screen. `TokenReach.by_tool` comes from `door._by_tool`, over the door's
 * own `_candidates`.
 *
 * ## What it deliberately does not claim
 *
 * **Which agent a call would be attributed to.** The union rule is *first allow wins*, so
 * attribution depends on the call's own arguments — a static field naming
 * `granted_by[0]` was in the first build of this and was wrong in exactly the multi-grant
 * case the component exists for. What is true statically is the *order*, so the order is
 * what is shown, with one sentence saying what it means and a pointer at the simulator,
 * which answers it for a given call.
 */

import { Card, Tag } from "../../components/ui";
import type { ToolReach } from "../../lib/types";

export default function EffectiveReach({ rows }: { rows: ToolReach[] }) {
  if (rows.length === 0) return null;

  // Writes first, and stated as a group. *What can this thing change* is the question,
  // and burying two writes among nine reads answers it only for somebody who reads all
  // eleven — `Reach.tsx`'s rule, kept, because the two screens sit on one page and a
  // reader should not have to learn two orderings.
  const writes = rows.filter((row) => row.effect === "write");
  const reads = rows.filter((row) => row.effect !== "write");
  const shared = rows.filter((row) => row.granted_by.length > 1);

  return (
    <Card title="Access by tool" hint="the same grants, by tool">
      <p className="sentence">
        Every tool this token can use, and the agents that grant it. A tool granted by
        more than one agent keeps <em>each</em> agent&rsquo;s scope. A call is attributed
        to the first agent, in the order below, whose scope allows the arguments.
      </p>
      {shared.length > 0 && (
        <p className="muted sentence">
          {shared.length === 1
            ? "One tool here is granted by more than one agent."
            : `${shared.length} tools here are granted by more than one agent.`}{" "}
          Which grant applies is decided per call. Check a specific call below.
        </p>
      )}

      <div className="rows">
        {[...writes, ...reads].map((row) => (
          <ToolRow key={row.tool} row={row} />
        ))}
      </div>
    </Card>
  );
}

function ToolRow({ row }: { row: ToolReach }) {
  return (
    <div className="row">
      <div className="row-top">
        <span className="row-name mono">{row.tool}</span>
        {row.effect === "write" ? (
          <Tag write>writes</Tag>
        ) : row.effect === "read" ? (
          <Tag>reads</Tag>
        ) : (
          // Null effect: a granted name nothing describes. Rare, and shown rather than
          // dropped — a row missing from this list makes the token look narrower than it
          // is, which is the wrong direction to be wrong in.
          <Tag>not described</Tag>
        )}
      </div>

      {row.effect === null && (
        <p className="row-sub">
          No tool in this workspace has this name, so every call to it is denied. It is
          granted by an agent that still names it.
        </p>
      )}

      <div className="stack-sm">
        {row.granted_by.map((grant) => (
          <div key={grant.agent} className="row-sub">
            <span className="mono">{grant.agent}</span>
            {Object.keys(grant.applies).length === 0 ? (
              <span className="muted"> — no resource restriction</span>
            ) : (
              Object.entries(grant.applies).map(([type, patterns]) => (
                <span key={type}>
                  {" — "}
                  <span className="muted">{type}</span>{" "}
                  {patterns.length === 0 ? (
                    // Carries the tool, grants nothing at its effect. A refusal waiting
                    // to happen, and worth reading as one rather than as an empty cell.
                    <span className="muted">no grant at this effect</span>
                  ) : (
                    <span className="mono">{patterns.join("  ")}</span>
                  )}
                </span>
              ))
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
