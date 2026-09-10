import { Button, Notice } from "../../components/ui";
import { api } from "../../lib/api";
import type { AgentDetail, ToolGroup } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** *"This agent reaches Jira, and you have not connected your Jira account."*
 *
 * Step 7b's decision 8, second half: the Connections page is *"reachable from the agent
 * detail page too, where the 'granted, and no longer available' notice already lives —
 * an agent whose tools need a connector the viewer has not connected should say so
 * there, since that is where somebody discovers they cannot run it."*
 *
 * The failure it replaces is specific and bad. Before this, a person opened an agent,
 * pressed Run, and got back either a third party's `401` wrapped in a model's apology or
 * — worse — a perfectly successful run made with **the operator's shared credential**,
 * reaching data that is not theirs and attributed to them in a log kept forever. Neither
 * outcome says "connect your account", and the second does not look like a problem at
 * all.
 *
 * ## Why this asks the server two questions rather than adding a field
 *
 * It joins `GET /tools` — which the detail page already fetches for `Reach` — against
 * `GET /connections`. The alternative, a `needs_connection` field on `AgentDetail`, was
 * not taken: whether *you* have connected something is a fact about the caller, and
 * `AgentDetail` is a description of an agent that every viewer sees identically. Putting
 * a per-caller field on it would make the response uncacheable in principle and would
 * mean `GET /agents/{name}` grew a reason to read the `connections` table.
 *
 * ## What it deliberately does not do
 *
 * It does **not** block the Run button. A connector with a shared credential configured
 * works fine without a personal connection — that is 7a's precedence rule and it is
 * unchanged — so refusing to run would break the ordinary case to warn about the
 * plausible one. This is a sentence, not a gate.
 */
export default function ConnectionNotice({
  agent,
  catalogue,
}: {
  agent: AgentDetail;
  catalogue: ToolGroup[] | null;
}) {
  // Errors are swallowed rather than rendered. This is an advisory notice on somebody
  // else's screen: a Connections request that fails should not put a red box on an agent
  // page about a request the person did not make.
  const { data: connections } = useResource(
    () => api.listConnections().catch(() => []),
    [],
  );

  if (!catalogue || !connections) return null;

  const granted = new Set(agent.tools);

  // Which connectors this agent's granted tools come from. The same question
  // `tools.connectors_for_agent` answers on the server — asked here from the catalogue
  // the page already has rather than by adding a route.
  const needed = new Set(
    catalogue
      .filter(
        (group) =>
          group.origin === "connector" &&
          group.tools.some((tool) => granted.has(tool.name)),
      )
      .map((group) => group.id),
  );

  const missing = connections.filter(
    (row) =>
      needed.has(row.connector_id) &&
      (row.state === "connectable" || row.state === "reconnect"),
  );

  if (missing.length === 0) return null;

  const reconnecting = missing.filter((row) => row.state === "reconnect");

  return (
    <Notice
      tone="warn"
      title={
        reconnecting.length > 0
          ? "A connection needs attention"
          : "This agent uses accounts you have not connected"
      }
    >
      <ul className="sentence">
        {missing.map((row) => (
          <li key={row.connector_id}>
            <strong>{row.connector_id}</strong>
            {row.state === "reconnect"
              ? ` — ${row.reconsent_reason}`
              : " — you have not connected your account."}
          </li>
        ))}
      </ul>
      <p className="muted">
        {/* The honest description of both branches, and the second half is the one worth
            saying: running anyway is not "it will fail", it is "it may act as somebody
            else". That is the thing 7a's delegated credentials exist to prevent and the
            thing a person cannot otherwise tell has happened. */}
        Until you connect, calls to {missing[0].connector_id} are denied or use a shared
        account set up by your administrator.
      </p>
      <Button kind="primary" to="/connections">
        Connections
      </Button>
    </Notice>
  );
}
