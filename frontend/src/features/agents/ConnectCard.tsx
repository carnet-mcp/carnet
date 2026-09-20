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
 *  ## The frameworks (step 111)
 *
 *  A second group in the same picker: LangChain, CrewAI, the OpenAI Agents SDK and
 *  AutoGen, each of which ships an MCP adapter that speaks the door's transport. The
 *  snippet is code rather than a file, so the unverified caveat is about the library's
 *  API rather than a path — but the rule is the same one: *where it goes* is shown only
 *  for an entry somebody has run against the real library and a real door. The point of
 *  the group is that the four lines were true before it existed and written nowhere.
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

import { Badge, Button, Card, CopyButton, Notice, Tabs } from "../../components/ui";
import { api } from "../../lib/api";
import { on } from "../../lib/format";
import { MeContext } from "../../lib/me";
import type { DoorActivity, DoorRefusal, MintedToken } from "../../lib/types";
import { useResource } from "../../lib/useResource";
import MintForm from "../tokens/MintForm";
import { type Dialect, defaultDialect, frameworks, ordered, unreachable } from "./dialects";

const POLL_MS = 5000;

/** The snippet, in the dialect the person picks. Step 075.
 *
 *  044 shipped one dialect and named it a known limit; 071 makes it a picker over
 *  `dialects.ts`. The payload is still a URL and a header — what changes per client is
 *  the file it goes in and the spelling. A client that cannot reach this door gets the
 *  reason in place of a snippet, and the *where to paste it* sentence appears only for
 *  a dialect somebody has tried against the real client. */
function Dialects({ url, secret }: { url: string; secret: string }) {
  const [client, setClient] = useState(defaultDialect(url));
  const { primary, more } = ordered(url);
  const [moreChoice, setMoreChoice] = useState(more[0]?.id ?? "");
  const libraries = frameworks();
  const [frameworkChoice, setFrameworkChoice] = useState(libraries[0]?.id ?? "");

  /** The snippet with the secret in it, for the reveal's lifetime (107 D9). The two
   *  things a person has to paste are on one screen for the only moment the secret
   *  exists; after **Done** the placeholder is back. */
  const shown = (entry: Dialect) =>
    secret ? entry.snippet(url).replaceAll("<your token>", secret) : entry.snippet(url);

  const panel = (entry: Dialect) => {
    const reason = unreachable(entry, url);
    if (reason) {
      return (
        <p className="sentence">
          <Badge tone="warn">cannot connect</Badge> {reason}
        </p>
      );
    }
    if (entry.auth === "oauth") {
      // Step 083. Nothing to paste but the address above: the client reads the door's
      // OAuth documents, sends the person to this deployment's consent page, and holds
      // a token it minted for itself — no header, no secret, nothing this page sees.
      return (
        <>
          <p className="sentence">
            Add the URL above to {entry.label}. It sends you here to sign in and approve,
            then holds a token of its own. You can revoke that token on Access tokens.
          </p>
          <p className="muted">{entry.where}</p>
        </>
      );
    }
    return (
      <>
        <div className="spread">
          <pre className="block">{shown(entry)}</pre>
          <CopyButton value={shown(entry)} label="the config" />
        </div>
        <p className="muted">
          {entry.verified ? (
            entry.where
          ) : entry.group === "framework" ? (
            <>
              From {entry.label}&rsquo;s own documentation, not yet run from here. If the
              library&rsquo;s MCP API has moved, its documentation is right and this is
              behind.
            </>
          ) : (
            <>Untested from here. Check the client&rsquo;s documentation for the file location.</>
          )}
        </p>
      </>
    );
  };

  const tabs = primary.map((entry) => ({ id: entry.id, label: entry.label, panel: panel(entry) }));
  if (libraries.length > 0) {
    // The frameworks (step 111), one tab with a picker, before *More*: a person wiring
    // a library is not looking for a file, and should not have to look under the
    // clients' overflow to find that the library already speaks this door.
    const chosen = libraries.find((entry) => entry.id === frameworkChoice) ?? libraries[0];
    tabs.push({
      id: "frameworks",
      label: "Frameworks",
      panel: (
        <>
          <p className="sentence">
            An agent you build in a framework connects the same way: its MCP adapter
            takes the URL above and the header. Nothing from Carnet to install.
          </p>
          <label className="field">
            <span className="label">Framework</span>
            <select
              aria-label="Framework"
              value={chosen.id}
              onChange={(event) => setFrameworkChoice(event.target.value)}
            >
              {libraries.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
          {panel(chosen)}
        </>
      ),
    });
  }
  if (more.length > 0) {
    // The rest, under one tab with a picker: seven tabs in a strip is a strip nobody
    // reads, and the four in front are where nearly everybody starts.
    const chosen = more.find((entry) => entry.id === moreChoice) ?? more[0];
    tabs.push({
      id: "more",
      label: "More",
      panel: (
        <>
          <label className="field">
            <span className="label">Client</span>
            <select
              aria-label="Other clients"
              value={chosen.id}
              onChange={(event) => setMoreChoice(event.target.value)}
            >
              {more.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
          {panel(chosen)}
        </>
      ),
    });
  }
  return <Tabs tabs={tabs} active={client} onSelect={setClient} label="Client" />;
}

/** Generate a token here, for this agent (107 D9). A service token is granted the agent
 *  in the same request when the viewer may share it; the secret is substituted into the
 *  snippet above for as long as the reveal is open, and **Done** puts the placeholder
 *  back. The tokens page has the same form; this is the one place the two things a
 *  person has to paste are on one screen. */
function GenerateHere({
  agent,
  canGrant,
  onMinted,
  onDone,
  minted,
}: {
  agent: string;
  canGrant: boolean;
  onMinted: (made: MintedToken) => void;
  onDone: () => void;
  minted: MintedToken | null;
}) {
  const [open, setOpen] = useState(false);

  if (minted) {
    return (
      <Notice tone="warn" title="Token created">
        <p>
          <strong>Copy the token and store it somewhere safe.</strong> You can&rsquo;t
          view it again. The config above has it filled in until you press Done.
        </p>
        <div className="reveal">
          <span className="label">Token</span>
          <div className="spread">
            <code tabIndex={0} aria-label="Token">
              {minted.token}
            </code>
            <CopyButton value={minted.token} label="token" />
          </div>
        </div>
        {!minted.acts_as_owner && !canGrant && (
          <p className="muted">
            This token has no agents yet. An editor can grant it this agent from the{" "}
            <strong>Share</strong> dialog, as <code>machine:{minted.id}</code>.
          </p>
        )}
        <div className="spread">
          <Button onClick={onDone}>Done</Button>
        </div>
      </Notice>
    );
  }

  if (!open) {
    return (
      <div className="spread">
        <Button onClick={() => setOpen(true)}>Generate a token</Button>
        <span className="muted">
          Or use one from <Link to="/tokens">Access tokens</Link>.
        </span>
      </div>
    );
  }

  return (
    <MintForm
      grantAgent={agent}
      canGrant={canGrant}
      onCancel={() => setOpen(false)}
      onMinted={(made) => {
        setOpen(false);
        onMinted(made);
      }}
    />
  );
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

export default function ConnectCard({ name, role = "" }: { name?: string; role?: string }) {
  // `name` optional since 062: the agent-scoped part of this card is exactly one
  // thing — the activity poll that flips "waiting" to "connected" — while the
  // address, the snippet and the token prose are deployment facts. Without a name
  // (the tokens page) the card renders the facts and polls nothing. `role` is the
  // viewer's on the agent (107 D9): an editor or owner may grant a service token the
  // agent as it is generated here; anybody may generate a personal one.
  const { me } = useContext(MeContext);
  const [minted, setMinted] = useState<MintedToken | null>(null);
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
        Add this server to Claude, Cursor, VS Code, an agent framework or any MCP
        client. The client authenticates with an access token and can use the tools of
        the agents that token is granted.
      </p>

      {url ? (
        <>
          <div className="reveal">
            <span className="label">MCP server URL</span>
            <div className="spread">
              <code tabIndex={0} aria-label="MCP server URL">
                {url}
              </code>
              <CopyButton value={url} label="the MCP server URL" />
            </div>
          </div>
          <Dialects url={url} secret={minted?.token ?? ""} />
        </>
      ) : (
        <p className="muted">
          The MCP server URL is not configured. It is{" "}
          <code>&lt;the API's origin&gt;/mcp</code>. An operator sets it with{" "}
          <code>CARNET_PUBLIC_ORIGIN</code>.
        </p>
      )}

      {name && url ? (
        <GenerateHere
          agent={name}
          canGrant={role === "owner" || role === "editor"}
          minted={minted}
          onMinted={setMinted}
          onDone={() => setMinted(null)}
        />
      ) : null}

      <p className="muted">
        {minted ? (
          <>The config above has the new token in it. </>
        ) : (
          <>
            Replace <code>&lt;your token&gt;</code> with an access token.{" "}
          </>
        )}
        A personal token can use everything shared with you. A service token can use only
        the agents granted to it.
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
