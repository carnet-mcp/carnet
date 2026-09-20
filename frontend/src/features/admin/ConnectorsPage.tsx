import { Fragment, useState } from "react";

import Failure from "../../components/Failure";
import {
  BrandMark,
  Button,
  Card,
  Empty,
  Badge,
  FieldGroup,
  Notice,
  PageHead,
  Spinner,
  Tag,
  type Tone,
} from "../../components/ui";
import { api } from "../../lib/api";
import type { ConnectorSummary, HostEntry } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** Connector onboarding, in the order migration 021 forces — read as a screen, not as a
 * proof. Step 091.
 *
 * ```
 * approve a host   →   add a connector   →   open it   →   approve the tools it may offer
 * ```
 *
 * **The ordering is real and it is no longer the first thing on the page.** A credential
 * cannot be sealed against a connector that does not exist, and no MCP server lists its
 * tools to an unauthenticated caller — so *connect, look, then decide whether to register*
 * is not expressible, and the row genuinely has to come first. Registration then checks the
 * URL's host against the allowlist, so the address genuinely has to come before that. All
 * of that is still enforced. What 091 changed is that the enforcement is a disabled stage
 * with one sentence rather than a card of reasoning above everything else: the page now
 * opens with **what is connected**, offers **adding one** second, and keeps the allowlist —
 * plumbing, and the answer to a question nobody asks first — at the bottom.
 *
 * **The sentence explaining a refusal is still the server's.** This screen does not get to
 * invent an explanation for a rule it does not own.
 *
 * The two later stages — looking at a server, and switching on its tools one at a time —
 * are on the connector's own page, because they are about one server and because a URL
 * naming it is a thing an administrator sends to a colleague.
 *
 * ## Where the words went
 *
 * Every paragraph of *why* on this page was true and is now in these comments. Three
 * sentences are load-bearing in the other direction — somebody got the opposite impression
 * once — and all three stayed, shortened: registering approves nothing, revoking a host
 * strands connectors rather than deleting them, and an asserted identity is believed
 * without verification. Step 107 then put every sentence on this screen into the plain
 * register the rest of the product uses (*approved hosts*, *approve*, *OAuth app*); the
 * structure 091 gave it is unchanged.
 */
export default function ConnectorsPage() {
  const hosts = useResource(() => api.listHosts(), []);
  const connectors = useResource(() => api.listConnectors(), []);

  const live = connectors.data ?? [];

  return (
    <>
      <PageHead
        title="Connectors"
        lede="A connector is an MCP server or REST API that agents can use tools from. Tools are unavailable until approved."
      />

      {/* **What is connected, first and as cards.** The page used to reach this last, as a
          stack of full-width rows whose only visual difference was the length of their
          sentence. A person who comes here to look at what is connected now gets that
          answer above the fold. */}
      <Card
        title="Your connectors"
        hint={live.length > 0 ? `${live.length} connected` : undefined}
      >
        {connectors.loading && <Spinner label="Loading…" />}
        {connectors.error ? <Failure error={connectors.error} /> : null}

        {connectors.data && live.length === 0 && (
          <Empty title="No connectors" icon="connectors">
            <p className="sentence">
              Add one. Until then, agents can only use the built-in tools.
            </p>
          </Empty>
        )}

        {live.length > 0 && (
          <div className="conn-grid">
            {live.map((connector) => (
              <ConnectorCard key={connector.connector_id} connector={connector} />
            ))}
          </div>
        )}

        {/* **Only when the list actually loaded** — `your_role`'s lesson: a
            non-administrator who deep-links here gets the server's 403, and a button to
            a setup they cannot perform under it would read as a bug rather than a rule.
            The setup itself is its own pages since 107 D4 (`/admin/connectors/new`):
            one question per screen, in the order the backend needs them, which a stack
            of cards on this page could never make visible. */}
        {connectors.data && (
          <div className="conn-foot">
            <Button kind="primary" to="/admin/connectors/new">
              Add a connector
            </Button>
          </div>
        )}
      </Card>

      {/* Plumbing, and last. The setup approves a host where the question is asked; this
          card is where the whole allowlist is read and where one is withdrawn. */}
      <Hosts resource={hosts} />
    </>
  );
}

/** Stage 1: the egress allowlist, under a name somebody outside this repository can read.
 *
 * The refusals are the interesting part and both are the server's own words. A pasted URL
 * is a 400 saying what to strip — which is why the host goes in the request body rather
 * than a path segment, since a `/` in a path is a bare 404 with nothing to say. A host
 * that can never be dialled is approved anyway and carries a **warning**: the row is real,
 * the control is not in force, and being told plain *yes* about that is the exact failure
 * the egress module is written against.
 */
function Hosts({ resource }: { resource: ReturnType<typeof useResource<HostEntry[]>> }) {
  const [host, setHost] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [warning, setWarning] = useState("");
  const [stranded, setStranded] = useState<string[]>([]);
  // The host whose Revoke is one click from happening (061): revoking was the app's
  // one destructive control that acted on first click, and it is the one that can
  // strand every connector on the host — which deserves the two-step everything
  // else already has. One at a time, because confirming two revocations at once is
  // not a state a person is in.
  const [confirming, setConfirming] = useState("");

  const approve = () => {
    setBusy(true);
    setFailure("");
    setWarning("");
    setStranded([]);
    api
      .approveHost(host.trim(), note.trim())
      .then((outcome) => {
        setWarning(outcome.warning);
        setHost("");
        setNote("");
        resource.reload();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const revoke = (which: string) => {
    setFailure("");
    setWarning("");
    setConfirming("");
    api
      .revokeHost(which)
      .then((outcome) => {
        // `stranded` is why revoke answers with a body. Those connectors keep their
        // registration and their whole vetting record and simply stop connecting, which
        // is the opposite of what somebody assumes happened.
        setStranded(outcome.stranded);
        resource.reload();
      })
      .catch((cause: unknown) =>
        setFailure(cause instanceof Error ? cause.message : String(cause)),
      );
  };

  return (
    <Card title="Approved hosts" hint="the hosts connectors may connect to">
      {resource.loading && <Spinner label="Loading hosts…" />}
      {resource.error ? <Failure error={resource.error} /> : null}

      {resource.data && resource.data.length === 0 && (
        <p className="sentence">
          No approved hosts. Connectors can only connect to approved hosts.
        </p>
      )}

      {resource.data && resource.data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Address</th>
              <th>Allowed by</th>
              <th>Note</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {resource.data.map((row) => (
              <Fragment key={row.host}>
                <tr>
                  <td className="mono">
                    {row.host}
                    {/* Marked in the list and not only at the moment of approval: this row
                        looks exactly like a working one otherwise, and whoever reads the
                        allowlist next was not the person who approved it. */}
                    {row.warning && <Tag write>not reachable</Tag>}
                  </td>
                  <td className="mono">{row.allowed_by}</td>
                  <td className="row-sub">{row.warning || row.note}</td>
                  <td>
                    <Button kind="quiet" onClick={() => setConfirming(row.host)}>
                      Revoke
                    </Button>
                  </td>
                </tr>
                {confirming === row.host && (
                  <tr>
                    <td colSpan={4}>
                      {/* The house two-step (061). The sentence carries the part nobody
                          assumes: connectors on this host keep their registration and
                          their whole vetting record and simply STOP CONNECTING at their
                          next dial — the stranding the post-revoke notice below reports
                          after the fact, said here before it. */}
                      <Notice tone="warn" title={`Revoke ${row.host}?`}>
                        <p className="sentence">
                          Every connector on this host stops connecting. Their tools
                          become unavailable to every caller. Registrations and
                          approved tools are kept, and approving the host again
                          restores them.
                        </p>
                        <div className="spread">
                          <Button onClick={() => setConfirming("")}>Cancel</Button>
                          <Button kind="primary" onClick={() => revoke(row.host)}>
                            Revoke
                          </Button>
                        </div>
                      </Notice>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}

      {/* **Only when the allowlist actually loaded**, which is `your_role`'s lesson
          arriving in a screen written by somebody who had just written that lesson down.
          A non-administrator who deep-links here gets the server's 403 *and*, until this
          condition existed, a complete host-approval form underneath it — a control that
          refuses the person who pressed it, which reads as a bug rather than as a rule.
          Found by pointing a browser at `/admin/connectors` as the second person, which
          is the only way it could have been found. */}
      {resource.data && (
        <div className="inline-form">
          <FieldGroup label="Approve a host" hint="Hostname only, without scheme, port or path.">
            <div className="spread">
              <input
                value={host}
                placeholder="mcp.acme.com"
                onChange={(e) => setHost(e.target.value)}
              />
              <input
                value={note}
                placeholder="Note (optional)"
                onChange={(e) => setNote(e.target.value)}
              />
              <Button busy={busy} disabled={!host.trim()} onClick={approve}>
                Approve
              </Button>
            </div>
          </FieldGroup>
        </div>
      )}

      {failure && (
        <Notice tone="warn">
          {/* The server's sentence. For a pasted URL it names what is wrong and what to
              pass instead, which is the whole reason this field is a body and not a path. */}
          <p className="sentence">{failure}</p>
        </Notice>
      )}
      {warning && (
        <Notice tone="warn" title="Approved, and not reachable">
          <p className="sentence">{warning}</p>
        </Notice>
      )}
      {stranded.length > 0 && (
        <Notice tone="warn" title="Connectors on this host">
          <p className="sentence">
            {stranded.join(", ")} cannot connect until the host is approved again. Their
            registrations and approved tools are kept.
          </p>
        </Notice>
      )}
    </Card>
  );
}

/** One connector, as a card.
 *
 * **A card rather than a row, and a mark rather than nothing** — 091. Nine full-width rows
 * distinguished only by the length of their sentence is a list nobody scans; nine tiles
 * with a logo, a name and a status word is one somebody reads across in two seconds. The
 * facts on it are the same four the row carried.
 */
function ConnectorCard({ connector }: { connector: ConnectorSummary }) {
  const state = status(connector);
  return (
    <div className="conn-card">
      <div className="conn-head">
        <BrandMark hints={[connector.connector_id, connector.host]} />
        <div className="conn-title">
          <strong>{connector.connector_id}</strong>
          <span className="row-sub mono">{connector.host}</span>
        </div>
        <Badge tone={state.tone}>{state.word}</Badge>
      </div>

      {connector.description && <p className="muted">{connector.description}</p>}
      <p className="sentence">{describe(connector)}</p>

      {(connector.writes > 0 || connector.allow_asserted_identity) && (
        <div className="conn-tags">
          {connector.writes > 0 && (
            <Tag write>
              {connector.writes} can change things
            </Tag>
          )}
          {/* Marked, and marked only where it is true. This page's other two tags mark
              exceptions — an address that will not be dialled, a connector with writes —
              and false here is the posture, the schema's default and every connector's
              state until somebody decides otherwise. A tag on all of them saying *verified
              only* would bury the one card a security review came to find. */}
          {connector.allow_asserted_identity && <Tag write>asserted identity</Tag>}
        </div>
      )}
      {asserted(connector) && <p className="sentence muted">{asserted(connector)}</p>}

      <div className="conn-foot">
        <Button to={`/admin/connectors/${connector.connector_id}`}>Open</Button>
      </div>
    </div>
  );
}

/** The word on the card, and its colour. Step 091.
 *
 *  **A second function beside `describe()`, on the same branches.** It is not folded in
 *  because a badge and a sentence are read at different speeds by different people: the
 *  badge is what somebody scanning nine cards sees, and the sentence is what the one who
 *  stops reads. They must agree, so they are computed from the same three conditions in
 *  the same order — and keeping them adjacent is what makes a later edit to one obviously
 *  an edit to both. */
export function status(connector: ConnectorSummary): { tone: Tone; word: string } {
  if (!connector.host_allowed) return { tone: "warn", word: "Paused" };
  if (connector.vetted === 0) return { tone: "waiting", word: "Needs setup" };
  return { tone: "good", word: "Ready" };
}

/** One sentence per connector, saying which of the three things is still missing.
 *
 * One function so the states cannot be worded several ways, and each branch says what is
 * true **and** what it means — a tool count on its own does not tell an administrator
 * whether anybody can use this, and the answer differs by state.
 *
 * **091 rewrote every branch and changed none of them; 107 rewrote them again**, in the
 * register of the reference consoles: *vetted* is "approved", *the allowlist* is "an
 * approved host", and the oauth split — the whole of 7a and 7b — is "the shared
 * credential" against "users can connect their own accounts". The vocabulary a customer
 * meets here is the vocabulary of the other consoles they use; the vocabulary of the
 * schema is in the schema.
 */
export function describe(connector: ConnectorSummary): string {
  if (!connector.host_allowed) {
    return `${connector.host} is not an approved host. This connector cannot connect until the host is approved again. Its approved tools are kept.`;
  }
  if (connector.vetted === 0) {
    return "No tools approved yet. Open it to discover and approve tools.";
  }
  const tools = `${connector.vetted} tool${connector.vetted === 1 ? "" : "s"} approved`;
  if (!connector.oauth) {
    return `${tools}. No OAuth app, so users cannot connect their own accounts. Calls use the shared credential if one is configured.`;
  }
  return `${tools}. Users can connect their own accounts.`;
}

/** Whether the MCP door believes a caller's claim about who it acts for — 033c, and a
 *  **second function beside `describe()` rather than a branch inside it.**
 *
 *  `describe()` answers one question with a three-branch state machine: *is this reachable,
 *  and whose account does a call use*. This is orthogonal to all three: it is independently
 *  true or false in every branch, so folding it in would turn three branches into six and
 *  make one sentence answer two questions.
 *
 *  And they are the two questions that get confused. `VettedTool.identity` is *whose account
 *  a tool acts as*; this is *whether the door believes a caller's claim about who they are*.
 *  One sentence carrying both is how those merge in somebody's head. 035f made the same call
 *  putting `lapse()` beside `ConnectionsPage`'s `describe()`.
 *
 *  Empty on the resting posture, deliberately — see the tag's comment. */
export function asserted(connector: ConnectorSummary): string {
  if (!connector.allow_asserted_identity) return "";
  return "Accepts asserted identity: a calling service may name who it acts on behalf of without verification. Such calls are logged as asserted, not verified.";
}
