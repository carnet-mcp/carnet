import { Link } from "react-router-dom";

import Failure from "../../components/Failure";
import { Badge, Card, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { on } from "../../lib/format";
import type { AgentDetail, AgentVersionSummary } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** Every configuration this agent has had. Step 021.
 *
 * ## What this card is for, and what it is not
 *
 * Until migration 032 an edit **destroyed** the configuration it replaced: `agents.config`
 * was overwritten in place, and the administrative log deliberately records that a config
 * changed and never what it said. So the working prompt from yesterday was gone, and the
 * screen for getting it back could not exist.
 *
 * It is **not the administrative log**, and the difference shows up here as an absence: a
 * save that changed nothing is in the log and not in this list. The history holds distinct
 * *states*; the log holds *writes*. Somebody asking "who saved this on Tuesday" wants the
 * admin screen; somebody asking "what did it say on Tuesday" wants this.
 *
 * ## Why every row says whether it still works
 *
 * `valid` is computed when the list is read, not when the version was written — what may
 * be live moves under stored configs, and a tool un-vetted last week makes a version from
 * last month unrestorable without anything touching the row. A card that showed every
 * version as restorable would be offering a save that cannot land, and the person would
 * find out by clicking. So the row says so first, in the validator's own sentence.
 *
 * ## Shown to anybody who can see the agent
 *
 * Reading history is `user`, like reading the agent: it is the same bytes at a different
 * age, and a second confidentiality level for one string would be a rule that reads as a
 * control and is not one. **Restoring** is `editor`, so the version page offers that
 * button and this card does not — one action per screen, and the screen that acts is the
 * one showing what would be written.
 */
export default function VersionHistory({ agent }: { agent: AgentDetail }) {
  // `agent.version` is in the dependencies, not decoration: it moves exactly when a new
  // version exists, so a page that re-read the agent after a write re-reads this too. The
  // name alone would leave the list one version stale, and `useResource` holds no cache
  // that could have hidden it.
  const { data, error, loading } = useResource(
    () => api.agentVersions(agent.name),
    [agent.name, agent.version],
  );

  // **The count is the agent's version number, not the number of rows** — and the edge
  // hunt is why. The server caps this list, so an agent edited sixty times returns fifty
  // rows and `${data.length} versions` said "50 versions" about an agent that had sixty.
  // A card that miscounts the thing it is a card about is the control that lies.
  //
  // `agent.version` is the honest total because version numbers are dense: the counter
  // advances exactly when a row is written, so the live version *is* how many there have
  // ever been. That is asserted in the contract suite rather than assumed here.
  const total = agent.version;
  const shown = data?.length ?? 0;
  const hint =
    data === null
      ? undefined
      : shown < total
        ? `${shown} most recent of ${total}`
        : `${total} version${total === 1 ? "" : "s"}`;

  return (
    <Card title="History" hint={hint}>
      {loading && <Spinner label="Loading history" />}
      {/* `? :` rather than `&&`, which is `ShareSheet`'s idiom and not a style choice:
          `error` is `unknown`, and a `Card`'s children are `ReactNode`. */}
      {error ? <Failure error={error} /> : null}
      {data && (
        <table>
          <tbody>
            {data.map((version) => (
              <Row key={version.version} agent={agent} version={version} />
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function Row({
  agent,
  version,
}: {
  agent: AgentDetail;
  version: AgentVersionSummary;
}) {
  const live = version.version === agent.version;
  return (
    <tr>
      <td className="mono">
        <Link to={`/agents/${agent.name}/versions/${version.version}`}>
          v{version.version}
        </Link>
      </td>
      <td>{on(version.created_at)}</td>
      <td className="muted">{describeAuthor(version.created_by)}</td>
      <td>
        {live && <Badge tone="good">live</Badge>}
        {version.restored_from !== null && (
          <span className="muted"> restored from v{version.restored_from}</span>
        )}
        {!version.valid && (
          <span className="muted" title={version.error ?? undefined}>
            {" "}
            cannot be restored
          </span>
        )}
      </td>
    </tr>
  );
}

/** An actor string as a sentence. **Not a name**, because two of these are not people.
 *
 *  `created_by` is `kind:id`, and the kinds that appear here are `user`, `system:cli` for
 *  a seeded row, and `migration:032` for the one version that predates this feature.
 *  Rendering all three as names would be inventing two people, and the migration row is
 *  exactly the one somebody will ask about — it is where an agent's history *starts*
 *  rather than where the agent did. */
export function describeAuthor(actor: string): string {
  if (actor.startsWith("migration:")) return "before history was kept";
  if (actor === "system:cli") return "seeded";
  if (actor.startsWith("system:")) return "the platform";
  // A user id, which is opaque here: this screen has no directory to resolve it against,
  // and inventing "someone" would be less true than showing what is stored. `/me` is the
  // only identity this app can resolve, and it is not this one.
  return actor.replace(/^user:/, "");
}
