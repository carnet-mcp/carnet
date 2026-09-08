import { Link } from "react-router-dom";

import Failure from "../../components/Failure";
import {
  Badge,
  BrandMark,
  Button,
  Empty,
  Icon,
  PageHead,
  Skeleton,
  brandOf,
  type Tone,
} from "../../components/ui";
import { api } from "../../lib/api";
import type { AgentSummary } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** `GET /agents` — whatever `runnable_names` returns for this person, and nothing else.
 *
 * The list may include agents reached **through a group** rather than by a grant naming
 * them, and this screen cannot tell the difference — `GET /agents` returns names, not
 * reasons. That is a known limit rather than an omission, and it is the one that bites
 * first: when an agent disappears from somebody's list the answer is usually a team they
 * were taken out of, and nothing here will say so. `--agent-access` says *how* since 9a;
 * exposing that over HTTP is a route, and neither 10a nor 092 adds one.
 *
 * **092 made it cards, and gave each one the apps it touches.** The row it replaces
 * carried the tool names joined by commas — forty characters of
 * `acme_list_issues, acme_create_issue, post_message` that answered no question anybody
 * has. The connector prefix on those names is the answer to the question people do have,
 * and it was already in the row.
 */
export default function AgentsPage() {
  const { data, error, loading } = useResource(() => api.listAgents(), []);

  return (
    <>
      {/* The action is **outside the loading and error branches**, in the head rather
          than above the list. Creating an agent is the one thing on this screen that does
          not depend on the request having succeeded — a person whose list is empty, or
          whose list failed to load, can still make one, and they are the person most
          likely to want to. */}
      <PageHead
        title="Create MCP"
        lede="Each one is a named set of tools your assistant may call, and how far each may reach. Calls go out as you, with your access."
        actions={
          <Button kind="primary" to="/agents/new">
            <Icon name="plus" />
            New MCP
          </Button>
        }
      />

      {loading && <Skeleton />}
      {error && <Failure error={error} />}

      {data && data.length === 0 && (
        // **Absence is denial, so an empty list is an answer and not a fault.** This is
        // exactly what somebody sees on their first day, and every word that suggests
        // breakage — "error", "failed to load", a retry button — turns a system working
        // as designed into a support ticket.
        <Empty title="No agents here yet">
          <p>
            You are signed in and this is what your account can reach: nothing, so far.
            Agents are shared deliberately, one at a time, by the person who owns them —
            or with a team you belong to.
          </p>
          {/* Two exits, both true (062). The sharing road is the ordinary case in an
              established workspace; the create road is the ONLY road for the first
              administrator of a fresh deployment, who used to be told to ask a person
              who does not exist — on the first screen of the product. The button is in
              the empty state itself because an empty page gives nobody a reason to
              look at its header. */}
          <p className="muted">
            Ask whoever owns the agent you need to share it with you — or make your
            own: an agent is a named set of tools with limits, and creating one is how
            a fresh workspace starts.
          </p>
          <p>
            <Button kind="primary" to="/agents/new">
              <Icon name="plus" />
              Create your first MCP
            </Button>
          </p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <div className="conn-grid">
          {data.map((agent) => (
            <AgentCard key={agent.name} agent={agent} />
          ))}
        </div>
      )}
    </>
  );
}

/** One agent, as a card. Shares `.conn-card` with the connectors page on purpose: two
 *  screens that list the things a workspace has assembled should list them the same way,
 *  and a second grid class would be a second design nobody chose. */
function AgentCard({ agent }: { agent: AgentSummary }) {
  const state = status(agent);
  const apps = appsOf(agent.tools);

  return (
    <Link className="conn-card" to={`/agents/${agent.name}`}>
      <div className="conn-head">
        {/* **The apps, where a connector card puts its vendor tile.** An agent is not a
            vendor and has no mark of its own, and inventing one — a monogram of its
            identifier — would be a glyph that means nothing sitting in the one spot on
            this card the eye goes to first. What belongs there is what it touches.

            Decoration over a sentence that already names them: `BrandMark` is
            `aria-hidden` and `describe()` below says "across GitHub and Slack" in words,
            so nothing here is the only carrier of anything. Three at most — a fourth mark
            is not a fourth fact, it is a smaller row of marks. */}
        <div className="agent-apps">
          {apps.length > 0 ? (
            apps.slice(0, 3).map((app) => (
              <BrandMark key={app.id} hints={[app.id]} size={30} />
            ))
          ) : (
            <BrandMark hints={[agent.name]} size={30} />
          )}
        </div>
        {/* The name alone. A count here as well would put "4 tools" twice on a card
            whose whole body is one sentence — the connector card's sub-line carries a
            *different* fact (its host), and copying the shape without the reason is how
            a design becomes a habit. */}
        <div className="conn-title">
          <strong className="mono">{agent.name}</strong>
        </div>
        <Badge tone={state.tone}>{state.word}</Badge>
      </div>

      <p className="sentence">{describe(agent)}</p>
    </Link>
  );
}

function count(n: number): string {
  return n === 1 ? "1 tool" : `${n} tools`;
}

/** The distinct apps an agent's tools come from, in the order they first appear.
 *
 *  A connector tool's local name is `<connector>_<tool>` — that prefix is what makes
 *  `acme_list_issues` unambiguous — so the apps are derivable from the names the list
 *  already returns, with no second request.
 *
 *  **Only recognised brands survive.** A built-in like `post_message` has no connector in
 *  front of it and would read as an app called "post"; drawing a monogram for that is a
 *  wrong logo, and 091's rule is that a wrong mark is worse than no mark. Exported for the
 *  tests, which is the only way to assert the built-in case without going through a tile
 *  that is deliberately invisible to a screen reader. */
export function appsOf(tools: string[]): { id: string; label: string }[] {
  const seen = new Map<string, string>();
  for (const tool of tools) {
    const prefix = tool.split("_")[0];
    const brand = prefix ? brandOf(prefix) : null;
    if (brand && !seen.has(brand.label)) seen.set(brand.label, prefix);
  }
  return [...seen].map(([label, id]) => ({ id, label }));
}

/** The word on the card, and its colour — `ConnectorsPage.status`'s twin.
 *
 *  Two functions on the same branches for the same reason: a badge is read by somebody
 *  scanning nine cards and a sentence by the one who stops, and they must agree. Keeping
 *  them adjacent is what makes an edit to one obviously an edit to both. */
export function status(agent: AgentSummary): { tone: Tone; word: string } {
  if (!agent.valid) return { tone: "bad", word: "Not valid" };
  if (agent.tools.length === 0) return { tone: "waiting", word: "No tools" };
  return { tone: "good", word: "Ready" };
}

/** One sentence per agent. Three branches, one function, so the states cannot be worded
 *  several ways.
 *
 *  The broken branch is the validator's own sentence and nothing else: `routes_agents.py`
 *  goes out of its way to validate rows itself rather than dropping them, because an
 *  agent that vanishes from the list when it breaks is one somebody re-creates rather
 *  than fixes — and paraphrasing the reason would waste that. */
export function describe(agent: AgentSummary): string {
  if (!agent.valid) return agent.error ?? "Its configuration no longer validates.";
  if (agent.tools.length === 0) {
    return "No tools yet, so it can answer a question and touch nothing.";
  }
  const apps = appsOf(agent.tools).map((app) => app.label);
  if (apps.length === 0) return `${count(agent.tools.length)}, all built in.`;
  const named =
    apps.length === 1
      ? apps[0]
      : `${apps.slice(0, -1).join(", ")} and ${apps[apps.length - 1]}`;
  return `${count(agent.tools.length)}, across ${named}.`;
}
