/** Step 2 — what it may do. The catalogue, with a tick box.
 *
 * `GET /tools` is the form's vocabulary and it is already the right shape: per tool, its
 * effect, its resource types, the description its reviewer stored and where it came
 * from. Nobody is asked to grant `github_mcp_list_issues` on faith.
 *
 * **Writes are stated first and separately**, the same call the detail page makes and for
 * the same reason: *what can this thing change* is the question, and a write buried among
 * reads answers it only for somebody who reads every row. Here it matters more than on a
 * read-only screen, because this is the moment the decision is actually made.
 *
 * ## Two descriptions read very differently, and both are shown as written
 *
 * A connector tool's description is the vendor's own words, captured at vetting time and
 * written for a person. A built-in's is `Tool.description` — the text the **model** is
 * given — and `post_message`'s ends *"You may only post to channels you are permitted to
 * use; the call will be refused otherwise"*, which is addressed to the model and reads
 * oddly to somebody picking tools.
 *
 * Deliberately not fixed here. A second, human-facing description would be a second
 * sentence about one tool, free to drift from the one that actually reaches the model —
 * and the whole reason this screen can be trusted is that everything on it is the string
 * the system itself uses. A known limit, stated rather than papered over.
 */

import { useState } from "react";
import { Link } from "react-router-dom";

import {
  Badge,
  BrandMark,
  Button,
  Card,
  Empty,
  Field,
  Notice,
  Tag,
  brandOf,
} from "../../../components/ui";
import type { Draft } from "../../../lib/draft";
import { useAdmin } from "../../../lib/me";
import type { ToolGroup, ToolSummary } from "../../../lib/types";
import type { StepProps } from "./CreateAgentPage";

export function toolsBlocker(_draft: Draft, catalogue: ToolGroup[] | null): string {
  // **Not** "tick at least one". An agent granted nothing is a coherent thing — it can
  // answer a question and cannot touch anything — and it is the safest agent this
  // product can make. Refusing to create one would be the form having an opinion the
  // permission model does not.
  if (catalogue === null) return "Waiting for the list of tools.";
  return "";
}

export default function StepTools({ draft, set, catalogue, catalogueFailed }: StepProps) {
  // **Client-side, over what `GET /tools` already returned.** Correct at the size that
  // response is today and a query the day it is not — but a server-side filter over a
  // vetting catalogue is a route, and 092 adds none.
  const [filter, setFilter] = useState("");

  const { admin } = useAdmin();
  if (catalogueFailed) {
    return (
      <Notice tone="bad" title="Tools could not be loaded">
        <p className="sentence">Reload the page to try again.</p>
      </Notice>
    );
  }
  if (!catalogue) return null;

  const all = catalogue.flatMap((group) => group.tools);
  const chosen = all.filter((tool) => draft.tools.includes(tool.name));
  const writes = chosen.filter((tool) => tool.effect === "write");

  /** Ticked names that are **no longer in the catalogue**, and therefore have no tick box.
   *
   * **This screen was a dead end without them, and it was found by somebody using it.**
   * A draft lives in `sessionStorage`, so it outlives navigation and reloads; the
   * catalogue does not, because an administrator can re-vet a tool under a different
   * local name at any moment — which is exactly what `storage.vet_tool`'s upsert is for.
   * When that happened, the review step correctly refused to create the agent and said
   * *"go back and change it"* — and going back could not change it, because every control
   * on this page is rendered from the catalogue and a withdrawn name has no control.
   * The only escape was clearing session storage or closing the tab.
   *
   * So they are rendered here, as themselves, with the one action that resolves them.
   * `AgentDetailPage` has said the same thing about a *saved* agent since 10a — this is
   * that sentence arriving one step earlier, where the grant can still be edited.
   */
  const withdrawn = draft.tools.filter(
    (name) => !all.some((tool) => tool.name === name),
  );

  function toggle(name: string) {
    set({
      tools: draft.tools.includes(name)
        ? draft.tools.filter((t) => t !== name)
        : [...draft.tools, name],
    });
  }

  if (all.length === 0) {
    return (
      <Empty title="No tools available">
        <p>
          An administrator adds tools by approving them on a connector.
          {admin ? (
            <>
              {" "}
              <Link to="/admin/connectors">Connectors</Link>
            </>
          ) : null}
        </p>
        <p className="muted">You can still create an agent with no tools.</p>
      </Empty>
    );
  }

  const needle = filter.trim().toLowerCase();
  /** Whether a tool survives the filter. **A ticked tool always does.**
   *
   *  A filter that can conceal a granted write is a filter that will, and the one number
   *  this step exists to make true is *what did I just agree to*. So the box narrows what
   *  is on offer and never what is chosen. */
  const shown = (tool: ToolSummary, group: ToolGroup) =>
    draft.tools.includes(tool.name) ||
    needle === "" ||
    tool.name.toLowerCase().includes(needle) ||
    tool.description.toLowerCase().includes(needle) ||
    group.id.toLowerCase().includes(needle);

  return (
    <>
      <Card
        title="Tools"
        hint={`${chosen.length + withdrawn.length} of ${all.length} selected`}
      >
        <p className="sentence">
          Select the tools this agent may use. Tools marked <strong>write</strong> can
          change data in the connected system.
        </p>

        {/* Only when there is enough to lose something in. A search box over nine tools
            is a control that costs a person a glance and saves them nothing. */}
        {all.length > 8 && (
          <Field label="Find a tool" hint="Narrows by name, description or app. Anything already ticked stays visible.">
            <input
              type="search"
              value={filter}
              placeholder="issues, calendar, github…"
              onChange={(event) => setFilter(event.target.value)}
            />
          </Field>
        )}

        {writes.length > 0 ? (
          <Notice tone="warn" title="This agent can change data">
            <p className="sentence">
              {writes.length === 1
                ? `${writes[0].name} can change data in the connected system.`
                : `${writes.length} of the selected tools can change data in connected systems.`}
            </p>
          </Notice>
        ) : chosen.length > 0 ? (
          <p className="muted">The selected tools only read data.</p>
        ) : null}
      </Card>

      {withdrawn.length > 0 && (
        <Notice tone="warn" title="Selected tools no longer available">
          <p className="sentence">
            {withdrawn.join(", ")}{" "}
            {withdrawn.length === 1 ? "is" : "are"} no longer available. Remove{" "}
            {withdrawn.length === 1 ? "it" : "them"} to continue.
          </p>
          <Button
            onClick={() =>
              set({ tools: draft.tools.filter((name) => !withdrawn.includes(name)) })
            }
          >
            Remove {withdrawn.length === 1 ? "it" : "them"}
          </Button>
        </Notice>
      )}

      {catalogue.map((group) => {
        const visible = group.tools.filter((tool) => shown(tool, group));
        // A group with nothing left in it is a heading over a hole. Hidden entirely,
        // and only ever by the filter — an empty group in the catalogue itself does not
        // reach this component, because `GET /tools` does not return one.
        if (visible.length === 0) return null;
        return (
          <Card
            key={group.origin + group.id}
            title={group.id || "Built in"}
            hint={group.origin === "builtin" ? "built in" : "connector"}
          >
            {/* The connector's mark **on the line with its description**, so *which app
                is this from* looks the same here as it does on the connectors tab. On a
                line of its own it read as a stray glyph under a heading. Nothing for the
                built-in group — it is not a vendor, and `brandOf("")` is null, so the
                whole row is simply absent. */}
            {(group.description || brandOf(group.id)) && (
              <div className="group-head">
                {brandOf(group.id) && <BrandMark hints={[group.id]} size={26} />}
                {group.description && <p className="sentence">{group.description}</p>}
              </div>
            )}
            <div className="tool-list">
              {/* Writes first inside each group too. The grouping is by where a tool came
                  from — which decides who to ask when it is wrong — and the ordering is by
                  what it does, which decides whether to tick it. */}
              {[...visible]
                .sort((a, b) => Number(a.effect === "read") - Number(b.effect === "read"))
                .map((tool) => (
                  <ToolChoice
                    key={tool.name}
                    tool={tool}
                    checked={draft.tools.includes(tool.name)}
                    onToggle={() => toggle(tool.name)}
                  />
                ))}
            </div>
          </Card>
        );
      })}

      {needle !== "" && catalogue.every((group) => !group.tools.some((t) => shown(t, group))) && (
        <Empty title={`Nothing matches "${filter.trim()}"`}>
          <p className="sentence">
            Clear the box to see everything your organisation has approved.
          </p>
        </Empty>
      )}
    </>
  );
}

function ToolChoice({
  tool,
  checked,
  onToggle,
}: {
  tool: ToolSummary;
  checked: boolean;
  onToggle: () => void;
}) {
  const write = tool.effect === "write";

  return (
    <label className={`tool pick${write ? " write" : ""}${checked ? " on" : ""}`}>
      <input type="checkbox" checked={checked} onChange={onToggle} />
      <div className="pick-body">
        <div className="tool-head">
          <span className="mono name">{tool.name}</span>
          <Badge tone={write ? "warn" : "waiting"}>{tool.effect}</Badge>
          {tool.resources.map((ref) => (
            <Tag key={ref.type} write={write}>
              {ref.type}
            </Tag>
          ))}
        </div>

        {tool.description ? (
          <p className="sentence">{tool.description}</p>
        ) : (
          // Every row vetted before migration 018 has none, and a gap where a sentence
          // belongs reads as a rendering bug rather than a fact about the row.
          <p className="muted">No description.</p>
        )}

        {tool.note ? <p className="muted note">{tool.note}</p> : null}
      </div>
    </label>
  );
}
