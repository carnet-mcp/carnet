/** What an agent may reach — the tools it holds and the resources those are scoped to.
 *
 * ## Why this is a file rather than a section of AgentDetailPage
 *
 * **Not for reuse. For identity.** 10c adds a review step: the last thing somebody sees
 * before they press Create. If that step rendered its own summary, this product would
 * hold two descriptions of a permission model — and the gap between *what the form said*
 * and *what the agent does* is precisely where it loses somebody's trust. Not a bug
 * class to be careful about; a bug class that should be inexpressible.
 *
 * So the review step imports this, and what somebody approves is literally what they
 * will see on the agent's page afterwards. If the two ever disagree it is because
 * `GET /agents/{name}` disagrees with what was posted, which is a server bug and a much
 * more interesting one.
 *
 * ## What it renders, unchanged from 10b
 *
 * In the config's own words. A friendlier paraphrase would be a second description of
 * the only thing in this system that decides what an agent may do, and two descriptions
 * that can disagree is how "why doesn't my agent do what the form said" becomes a class
 * of bug. Decision 1, applied to a read.
 *
 * **Writes are grouped and stated first.** *What can this thing change* is the question,
 * and burying two writes among nine reads answers it only for somebody who reads all
 * eleven.
 *
 * The effects and descriptions come from `GET /tools` and are shown as the connector
 * admin wrote them, for the same reason.
 */

import Failure from "../../components/Failure";
import { Badge, Card, Notice, Tag } from "../../components/ui";
import type { ToolGroup, ToolSummary } from "../../lib/types";

/** The part of an agent this component reads.
 *
 *  Deliberately narrower than `AgentDetail`. A saved agent satisfies it structurally and
 *  so does a draft that has never been anywhere near the server — which is the whole
 *  point, because the alternative was for the wizard to fabricate a plausible
 *  `AgentDetail` (name, runtime, `valid: true`) so that a summary would render. Faking
 *  the *validity* of a thing in order to preview it is exactly the shape of lie this
 *  screen exists to prevent. */
export interface Reachable {
  tools: string[];
  /** `{"github.repo": {"read": ["owner/name"]}}` */
  scope: Record<string, Record<string, string[]>>;
}

/** One granted tool, resolved against the catalogue. `null` when the catalogue does not
 *  describe it — which is a real state, not a loading one. */
interface Granted {
  name: string;
  tool: ToolSummary | null;
  /** Which connector contributed it, `""` for a built-in. */
  origin: string;
}

/** Flatten the catalogue and pick out the tools this agent actually holds.
 *
 *  A tool in the grant with no catalogue entry means a connector was un-vetted
 *  underneath a live agent.
 *
 *  **That state cannot currently arrive on the detail page, and saying so is worth more
 *  than the branch below.** The catalogue is built from the same two registries as
 *  `known_names`, and `agents.validate` refuses a grant naming anything outside it — so
 *  an agent with a withdrawn tool answers **422** from `GET /agents/{name}` and this
 *  component never renders. What a person gets instead is the raw failure, which means a
 *  broken agent is visible in the list and cannot be opened. That is 10a's 422 decision
 *  meeting a screen it was not written against, and it becomes acute in 10d, where
 *  opening a broken agent is how you fix it.
 *
 *  The branch stays because it is one `filter`, because the two requests are independent
 *  so a connector withdrawn between them lands here today — and, new in 10c, because the
 *  **wizard can reach it without any of that**: a draft restored from `sessionStorage`
 *  holds tool names chosen against a catalogue that may since have changed. */
export function resolve(tools: string[], catalogue: ToolGroup[] | null): Granted[] {
  const known = new Map<string, { tool: ToolSummary; origin: string }>();
  for (const group of catalogue ?? []) {
    for (const tool of group.tools) known.set(tool.name, { tool, origin: group.id });
  }
  return tools.map((name) => ({
    name,
    tool: known.get(name)?.tool ?? null,
    origin: known.get(name)?.origin ?? "",
  }));
}

export default function Reach({
  agent,
  catalogue,
  failed,
  title = "Resource access",
  hint = "as stored",
}: {
  agent: Reachable;
  catalogue: ToolGroup[] | null;
  failed: unknown;
  /** The review step says "what it will be able to reach" — future tense, because it is
   *  not yet true. That is the *only* difference the two screens are permitted, and it is
   *  a prop rather than a branch so that adding a second one takes an argument. */
  title?: string;
  hint?: string;
}) {
  const granted = resolve(agent.tools, catalogue);
  const writes = granted.filter((g) => g.tool?.effect === "write");
  const reads = granted.filter((g) => g.tool?.effect === "read");
  const unknown = granted.filter((g) => g.tool === null);

  return (
    <Card title={title} hint={hint}>
      {agent.tools.length === 0 ? (
        <p className="muted">This agent has no tools.</p>
      ) : !catalogue ? (
        // Degraded, and it says which half is missing. The names are the agent's own
        // config and are still true; what is absent is the annotation that says which
        // of them change anybody's systems, and a screen that silently dropped that
        // distinction would read as "none of these write".
        <>
          <div className="tags">
            {agent.tools.map((tool) => (
              <Tag key={tool}>{tool}</Tag>
            ))}
          </div>
          <p className="muted stack-sm">
            {failed
              ? "The tool list could not be loaded. Tool effects are not shown."
              : "Loading tool details…"}
          </p>
          {failed ? <Failure error={failed} /> : null}
        </>
      ) : (
        <>
          {/* Writes first, and separated. `post_message` reaching a customer's channel
              and `list_issues` reading one are the same word to somebody deciding
              whether to run an agent — and only one of the two is reversible. */}
          {writes.length > 0 && (
            <>
              <h3>Write tools</h3>
              <p className="sentence">
                {writes.length === 1
                  ? "One tool that can change data in the connected system."
                  : `${writes.length} tools that can change data in connected systems.`}
              </p>
              <div className="tool-list">
                {writes.map((entry) => (
                  <ToolRow key={entry.name} entry={entry} />
                ))}
              </div>
            </>
          )}

          {reads.length > 0 && (
            <>
              <h3>Read tools</h3>
              <p className="sentence">
                {reads.length === 1
                  ? "One tool that reads data and changes nothing."
                  : `${reads.length} tools that read data and change nothing.`}
              </p>
              <div className="tool-list">
                {reads.map((entry) => (
                  <ToolRow key={entry.name} entry={entry} />
                ))}
              </div>
            </>
          )}

          {unknown.length > 0 && (
            <Notice tone="warn" title="Granted, and no longer available">
              <p className="sentence">
                {unknown.map((entry) => entry.name).join(", ")}
                {unknown.length === 1 ? " is" : " are"} granted to this agent and no
                longer available. Calls to this agent are denied until{" "}
                {unknown.length === 1 ? "it is" : "they are"} removed.
              </p>
            </Notice>
          )}
        </>
      )}

      <h3>Resources</h3>
      <Resources agent={agent} granted={granted} known={catalogue !== null} />
    </Card>
  );
}

/** One granted tool: what it is, what it does, and what it touches. */
function ToolRow({ entry }: { entry: Granted }) {
  const tool = entry.tool;
  if (!tool) return null;
  const write = tool.effect === "write";

  return (
    <div className={`tool${write ? " write" : ""}`}>
      <div className="tool-head">
        <span className="mono name">{tool.name}</span>
        <Badge tone={write ? "warn" : "waiting"}>{tool.effect}</Badge>
        {tool.resources.map((ref) => (
          <Tag key={ref.type} write={write}>
            {ref.type}
          </Tag>
        ))}
        <span className="muted from">
          {entry.origin ? `from ${entry.origin}` : "built in"}
        </span>
      </div>

      {tool.description ? (
        <p className="sentence">{tool.description}</p>
      ) : (
        // Said rather than left blank. Every row vetted before migration 018 has no
        // description, and a gap where a sentence should be reads as a rendering bug.
        <p className="muted">No description.</p>
      )}

      {tool.note ? <p className="muted note">{tool.note}</p> : null}
    </div>
  );
}

/** The scope table, with the column that turns a config listing into an explanation.
 *
 *  `agents.validate` already computes exactly this pairing, in both directions — see
 *  `_validate_scope_matches_tools` — so this shows a relationship the system already
 *  enforces rather than inventing one. */
function Resources({
  agent,
  granted,
  known,
}: {
  agent: Reachable;
  granted: Granted[];
  known: boolean;
}) {
  const scopes = Object.entries(agent.scope ?? {});

  if (scopes.length === 0) {
    // With no tools at all there is nothing to say about resources; the caller has
    // already said "This agent has no tools", and a sentence about what *these tools*
    // take would be about nothing.
    if (granted.length === 0) return null;
    // Two true sentences (plan 107, D8). Whether any granted tool declares a resource
    // decides which one; when the catalogue is unknown the tools' resources cannot be
    // read, so the first sentence — the one that says access is open — is the safe one.
    const takesResource =
      !known || granted.some((entry) => (entry.tool?.resources.length ?? 0) > 0);
    return (
      <p className="muted">
        {takesResource
          ? "No resources are selected. These tools can act on any resource the caller's account can reach."
          : "These tools do not take a resource, so they are not restricted to particular items."}
      </p>
    );
  }

  /** Which granted tools touch this resource type at this effect. */
  function usedBy(resource: string, effect: string): string[] {
    return granted
      .filter(
        (entry) =>
          entry.tool?.effect === effect &&
          entry.tool.resources.some((ref) => ref.type === resource),
      )
      .map((entry) => entry.name);
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Resource</th>
          <th>Access</th>
          <th>Items</th>
          <th>Tools</th>
        </tr>
      </thead>
      <tbody>
        {scopes.flatMap(([resource, effects]) =>
          Object.entries(effects).map(([effect, patterns]) => {
            const tools = known ? usedBy(resource, effect) : [];
            return (
              <tr key={`${resource}:${effect}`}>
                <td className="mono">{resource}</td>
                <td>
                  {/* Write is marked. It is the difference between an agent that got
                      something wrong and an agent that told somebody's systems
                      something wrong. */}
                  {effect === "write" ? (
                    <Badge tone="warn">write</Badge>
                  ) : (
                    <Badge tone="waiting">read</Badge>
                  )}
                </td>
                <td className="mono">{patterns.join("  ")}</td>
                <td className="mono">
                  {!known ? (
                    <span className="muted">—</span>
                  ) : tools.length > 0 ? (
                    tools.join("  ")
                  ) : (
                    // A scope entry no granted tool touches. `agents.validate` refuses
                    // this in both directions, so a *valid* agent cannot show it — and
                    // a broken one is rendered here rather than hidden, which is the
                    // same call `GET /agents` makes about listing an invalid row.
                    <span className="muted">no granted tool uses this</span>
                  )}
                </td>
              </tr>
            );
          }),
        )}
      </tbody>
    </table>
  );
}
