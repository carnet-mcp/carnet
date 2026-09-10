import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Notice, PageHead, Spinner } from "../../components/ui";
import { ApiError, api } from "../../lib/api";
import { on } from "../../lib/format";
import { useResource } from "../../lib/useResource";
import Reach from "./Reach";
import { describeAuthor } from "./VersionHistory";

/** One stored configuration, and the button that puts it back. Step 021.
 *
 * ## What a restore is, said on the screen because it is not what people expect
 *
 * Restoring v3 while v7 is live does **not** move a pointer back to 3. It writes **v8**,
 * whose content is 3's, and 3 and 7 both stay exactly where they are. That is what keeps
 * *what was live on Tuesday* answerable — a moving pointer would need a second log of
 * every move — and it is what makes a restore itself undoable, which is the sentence this
 * page puts under the button.
 *
 * ## Why this is a button and not the edit form
 *
 * A client cannot compose a restore out of the requests it already has. `PATCH` merges at
 * the top level, so a key this old config does not carry survives from the live one:
 * fetching v3 and patching it back produces neither version whenever a field was added
 * since, silently, while the screen says it worked. There is no way to remove a field
 * over HTTP at all. So the server has a route, and this page calls it.
 *
 * ## Rendered through `Reach`, including when it can no longer run
 *
 * The same component the detail page and the wizard's review step use — for identity
 * rather than reuse, per its own docstring: what somebody is about to restore has to look
 * like what they will get. That includes a version naming a tool this workspace has since
 * un-vetted, which is the first thing to reach `Reach`'s *granted, and no longer
 * available* branch from a screen where it is the **normal** case rather than a broken
 * agent. Hiding it would be recommending a restore that answers 422.
 */
export default function AgentVersionPage() {
  const { name = "", version = "" } = useParams();
  const number = Number(version);
  // A URL is typed and mangled as well as followed. `Number("abc")` is NaN, and letting
  // it through makes a doomed request whose 422 renders as "this agent's configuration
  // is not valid" — a sentence about a different situation. Every real version is a
  // positive integer, so anything else is answered here, in the same shape a missing
  // version gets from the server, without a request.
  const plausible = Number.isInteger(number) && number >= 1;

  const agent = useResource(() => api.getAgent(name), [name]);
  const stored = useResource(
    () =>
      plausible
        ? api.getAgentVersion(name, number)
        : Promise.reject(
            new ApiError(
              404,
              `'${version}' is not a version of anything. Versions are numbered from 1 ` +
                "up to the one that is live now.",
            ),
          ),
    [name, number],
  );
  const catalogue = useResource(() => api.listTools(), []);

  const navigate = useNavigate();
  const [restoring, setRestoring] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  if (agent.error) return <Failure error={agent.error} />;
  if (stored.error) return <Failure error={stored.error} />;
  if (!agent.data || !stored.data) return <Spinner label="Loading" />;

  const live = stored.data.version === agent.data.version;
  const mayRestore =
    agent.data.your_role === "editor" || agent.data.your_role === "owner";
  const conflict =
    failure instanceof ApiError && failure.status === 409 ? failure : null;

  function restore() {
    if (!agent.data) return;
    setRestoring(true);
    setFailure(null);
    api
      .restoreAgentVersion(name, number, agent.data.updated_at)
      .then(() => navigate(`/agents/${name}`))
      .catch((cause: unknown) => {
        setFailure(cause);
        setRestoring(false);
      });
  }

  return (
    <>
      <Link className="back" to={`/agents/${name}`}>
        ← {name}
      </Link>
      <PageHead
        title={`${name} · v${stored.data.version}`}
        lede={
          <>
            Saved {on(stored.data.created_at)} by {describeAuthor(stored.data.created_by)}
            {stored.data.restored_from !== null && (
              <> · restored from v{stored.data.restored_from}</>
            )}
            {live && <> · this is the live version</>}
          </>
        }
      />

      {!stored.data.valid && (
        // **Before the click rather than after it.** Validity is evaluated when a version
        // is read, because what may be live moves under stored configs — so this is the
        // ordinary state of an old version rather than a broken agent, and the restore
        // below is disabled rather than merely failing.
        <Notice tone="warn" title="This version cannot be restored">
          <p className="sentence">{stored.data.error}</p>
          <p className="muted">
            It names a tool or connector that is no longer available in this workspace.
          </p>
        </Notice>
      )}

      <Reach
        agent={{ ...agent.data, ...asAgentShape(stored.data.config) }}
        catalogue={catalogue.data}
        failed={catalogue.error}
      />

      {typeof stored.data.config.system === "string" && stored.data.config.system && (
        <Card title="Instructions" hint="in this version">
          <pre className="block">{stored.data.config.system as string}</pre>
        </Card>
      )}

      {conflict ? (
        // The same event `EditAgentPage` renders, and deliberately a plainer panel: there
        // is no in-progress edit to lose here, so the answer is simply to look again.
        // Reloading is a navigation rather than a state reset, which is why there is no
        // `Conflict` component call — the whole page is derived from two reads.
        <Notice tone="warn" title="Someone else saved this agent">
          <p className="sentence">
            The agent changed since you opened this page. Nothing was written. Open the
            agent to see the current version, then restore again if you still want to.
          </p>
          <Button onClick={() => navigate(`/agents/${name}`)}>Open {name}</Button>
        </Notice>
      ) : failure ? (
        <Failure error={failure} />
      ) : null}

      {mayRestore && !live && (
        <Card title="Restore this version">
          <p className="sentence">
            Restoring creates v{agent.data.version + 1} with this configuration. Versions{" "}
            {stored.data.version} and {agent.data.version} are kept.
          </p>
          <div className="spread">
            <Button
              kind="primary"
              busy={restoring}
              disabled={!stored.data.valid}
              onClick={restore}
            >
              {restoring ? "Restoring" : `Restore v${stored.data.version}`}
            </Button>
            <span className="muted">
              Applies to everyone this agent is shared with, from the next call. Past
              calls are unaffected.
            </span>
          </div>
        </Card>
      )}
    </>
  );
}

/** A stored config in the shape `Reach` reads.
 *
 *  `Reach` takes an `AgentDetail` because that is what the detail page and the review step
 *  hand it; a version is the same data one layer in. Spelled out here rather than making
 *  `Reach` accept two shapes: a component that reads either would be a component with two
 *  contracts, and this is four lines. */
function asAgentShape(config: Record<string, unknown>) {
  const permissions = (config.permissions ?? {}) as {
    tools?: string[];
    scope?: Record<string, Record<string, string[]>>;
  };
  return {
    tools: permissions.tools ?? [],
    scope: permissions.scope ?? {},
    config,
  };
}
