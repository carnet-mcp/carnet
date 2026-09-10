/** The connect card — how an assistant reaches this agent through the MCP door.
 *
 *  Step 044, and it is the page's answer to the product's own premise: *people connect
 *  their own assistant to `/mcp`*. Until now everything before the first call lived
 *  outside the product — the endpoint was word of mouth, and whether the connection
 *  worked was discovered by asking whoever ran the assistant. This card is those ten
 *  minutes: the address, the client config to paste, where the token comes from, and a
 *  line that flips when the first call lands.
 *
 *  ## Rendered for every viewer
 *
 *  The door is the product, and it exists in every deployment. What a viewer of the
 *  agent may see is decided by the grant, same as the rest of the page.
 *
 *  ## The address comes from `/me`, never from `window.location`
 *
 *  `me.mcp_url` is `PUBLIC_ORIGIN + "/mcp"`, configuration the bundle cannot know —
 *  behind a proxy the app's origin and the door's genuinely differ, which is
 *  `config.PUBLIC_ORIGIN`'s own argument about the OAuth callback. An older API sends
 *  nothing, and the card degrades to prose rather than deriving an address that would
 *  be wrong exactly where deployments get interesting.
 *
 *  ## The token is a placeholder, deliberately
 *
 *  This page never sees a secret and must not invite pasting one into it. The snippet
 *  says `<your token>` and the sentence beside it says where a real one is minted. No
 *  copy button on the values — this app has no clipboard idiom (the reveal's
 *  `Reveal` records the decision); selectable text with a keyboard tab stop is what the
 *  CLI offers and it is enough.
 *
 *  ## The dialects (step 075)
 *
 *  One picker over `dialects.ts`. The snippet always says `<your token>`; a client
 *  that cannot reach this door — OAuth-only against a header door, or https-only
 *  against a plain-http deployment — gets the reason instead of a snippet that would
 *  not have worked; and *where to paste it* is shown only for a dialect tried against
 *  the real client, because a wrong path here is worse than no card.
 *
 *  ## The refusal (step 074)
 *
 *  `calls` counts what reached the broker. A call the door turns away at its own
 *  threshold — a token granted no agent that provides the tool, or an acting-for claim
 *  that fails — reaches neither `calls` nor the audit log; it is one denial row. So
 *  the card used to render *nothing tried* and *everything refused* as the same
 *  sentence, for the one person who most needs the difference. `last_refusal` is the
 *  newest denial naming one of this agent's tools, and the card renders the door's own
 *  sentence for it. Shown in the waiting state always, and beside the connected line
 *  only when the refusal is newer than the last admitted call — a second person
 *  pasting a token wrong on an agent somebody else connected is the same failure.
 *
 *  A token the door does not recognise at all is a 401 before any agent is known, and
 *  nothing records it. The waiting line says so rather than implying it would show.
 *
 *  ## The poll
 *
 *  Every 5 seconds, only while the answer is zero and the tab is visible, stopping at
 *  the first nonzero answer. Two scalars per tick, per open page — cheap on purpose,
 *  and it exists precisely for the person watching their assistant's first call. After
 *  contact the line is a fact rendered at load, not a live feed; door traffic has an
 *  administrator's page of its own.
 */

import { useContext, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Badge, Card, Tabs } from "../../components/ui";
import { api } from "../../lib/api";
import { on } from "../../lib/format";
import { MeContext } from "../../lib/me";
import type { DoorActivity, DoorRefusal } from "../../lib/types";
import { useResource } from "../../lib/useResource";
import { DEFAULT_DIALECT, DIALECTS, unreachable } from "./dialects";

const POLL_MS = 5000;

/** The snippet, in the dialect the person picks. Step 075.
 *
 *  044 shipped one dialect and named it a known limit; 071 makes it a picker over
 *  `dialects.ts`. The payload is still a URL and a header — what changes per client is
 *  the file it goes in and the spelling. A client that cannot reach this door gets the
 *  reason in place of a snippet, and the *where to paste it* sentence appears only for
 *  a dialect somebody has tried against the real client. */
function Dialects({ url }: { url: string }) {
  const [client, setClient] = useState(DEFAULT_DIALECT);
  const tabs = DIALECTS.map((entry) => {
    const reason = unreachable(entry, url);
    return {
      id: entry.id,
      label: entry.label,
      panel: reason ? (
        <p className="sentence">
          <Badge tone="warn">cannot connect</Badge> {reason}
        </p>
      ) : entry.auth === "oauth" ? (
        // Step 083. Nothing to paste but the address above: the client reads the door's
        // OAuth documents, sends the person to this deployment's consent page, and holds
        // a token it minted for itself — no header, no secret, nothing this page sees.
        <>
          <p className="sentence">
            Add the URL above to {entry.label}. It sends you here to sign in and approve,
            then holds a token of its own. You can revoke that token on Access tokens.
          </p>
          <p className="muted">{entry.where}</p>
        </>
      ) : (
        <>
          <pre className="block">{entry.snippet(url)}</pre>
          <p className="muted">
            {entry.verified ? (
              entry.where
            ) : (
              <>Untested from here. Check the client&rsquo;s documentation for the file location.</>
            )}
          </p>
        </>
      ),
    };
  });
  return <Tabs tabs={tabs} active={client} onSelect={setClient} label="Client" />;
}

/** The door's own sentence for a refusal, by the denial's `required`. Two values
 *  exist (`door.call_tool` writes them); anything else renders the plain fact. */
function refusalSentence(refusal: DoorRefusal): string {
  const when = on(refusal.at);
  const who = `token ${refusal.token}`;
  if (refusal.reason === "grant") {
    return (
      `The last call, at ${when}, was denied: no agent granted to ${who} provides a ` +
      `tool called '${refusal.tool}'. Check the token's grants. A personal token can use ` +
      `its owner's agents; a service token can use only the agents granted to it.`
    );
  }
  if (refusal.reason === "acting-for") {
    return (
      `The last call, at ${when}, was denied: ${who} called '${refusal.tool}' with an ` +
      `on-behalf-of claim the server could not accept.`
    );
  }
  return `The last call, at ${when}, was denied: ${who} called '${refusal.tool}' (${refusal.reason}).`;
}

/** A refusal is news when nothing has been admitted, or when it is newer than the last
 *  admitted call. Both stamps are ISO-8601 in UTC with millisecond precision from the
 *  same writer, so the string order is the time order. */
function newsworthy(activity: DoorActivity): DoorRefusal | null {
  const refusal = activity.last_refusal ?? null;
  if (!refusal) return null;
  if (activity.calls === 0 || !activity.last_call_at) return refusal;
  return refusal.at > activity.last_call_at ? refusal : null;
}

export default function ConnectCard({ name }: { name?: string }) {
  // `name` optional since 062: the agent-scoped part of this card is exactly one
  // thing — the activity poll that flips "waiting" to "connected" — while the
  // address, the snippet and the token prose are deployment facts. Without a name
  // (the tokens page) the card renders the facts and polls nothing.
  const { me } = useContext(MeContext);
  const activity = useResource(
    () => (name ? api.doorActivity(name) : Promise.resolve(null)),
    [name],
  );

  const waiting = name !== undefined && activity.data !== null && activity.data.calls === 0;
  const { reload } = activity;

  useEffect(() => {
    if (!waiting) return;
    const tick = window.setInterval(() => {
      // A backgrounded tab does not poll — nobody is watching it.
      if (document.visibilityState === "visible") reload();
    }, POLL_MS);
    return () => window.clearInterval(tick);
  }, [waiting, reload]);

  const url = me?.mcp_url ?? "";
  const refusal = activity.data ? newsworthy(activity.data) : null;

  return (
    <Card title="Connect a client">
      <p className="sentence">
        Add this server to Claude, Cursor, VS Code or any MCP client. The client
        authenticates with an access token and can use the tools of the agents that token
        is granted.
      </p>

      {url ? (
        <>
          <div className="reveal">
            <span className="label">MCP server URL</span>
            <code tabIndex={0} aria-label="MCP server URL">
              {url}
            </code>
          </div>
          <Dialects url={url} />
        </>
      ) : (
        <p className="muted">
          The MCP server URL is not configured. It is{" "}
          <code>&lt;the API's origin&gt;/mcp</code>. An operator sets it with{" "}
          <code>CARNET_PUBLIC_ORIGIN</code>.
        </p>
      )}

      <p className="muted">
        Replace <code>&lt;your token&gt;</code> with an access token
        {name ? (
          <>
            {" "}
            from <Link to="/tokens">Access tokens</Link>
          </>
        ) : null}
        . A personal token can use everything shared with you. A service token can use
        only the agents granted to it.
      </p>

      {/* The waiting line. Errors render as silence rather than a warning — this is a
          convenience readout on somebody else's page, and a red box about a poll would
          outshout the page's actual content. */}
      {activity.data && (
        <p className="sentence">
          {activity.data.calls === 0 ? (
            refusal ? (
              <>
                <Badge tone="bad">denied</Badge> {refusalSentence(refusal)} No call has
                been allowed yet. This updates by itself.
              </>
            ) : (
              <>
                <Badge tone="warn">no calls yet</Badge> Waiting for the first call. This
                updates by itself. A token the server does not recognise leaves no record
                here.
              </>
            )
          ) : (
            <>
              <Badge tone="good">connected</Badge> {activity.data.calls}{" "}
              {activity.data.calls === 1 ? "request" : "requests"}
              {activity.data.last_call_at
                ? `, the last at ${on(activity.data.last_call_at)}`
                : ""}
              .
              {refusal ? (
                <>
                  {" "}
                  <Badge tone="bad">denied since</Badge> {refusalSentence(refusal)}
                </>
              ) : null}
            </>
          )}
        </p>
      )}
    </Card>
  );
}
