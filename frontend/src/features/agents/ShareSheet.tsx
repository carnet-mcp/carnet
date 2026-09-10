/** Who can reach this agent, **and how** — and the controls to change it.
 *
 * ## The third column is the decision, not a nicety
 *
 * Since 9a a person can reach an agent with no grant of their own. The moment unsharing
 * exists in a UI, somebody revokes a grant, watches the agent stay visible through a
 * group, and concludes the revoke failed. `unshare` already refuses that case loudly with
 * a sentence naming the group — this screen has to say the same thing *before* they try,
 * which is what "through oncall" in a row is for.
 *
 * ## Two lists, deliberately
 *
 * A pending grant is a different kind of fact: nobody has that access, and somebody
 * *will* if a person ever arrives at that address. Merging it into the list of people
 * who can reach the agent would report access that does not exist — and nothing expires
 * these, so an address somebody's account never carries waits forever.
 *
 * `share_by_email` has returned `"granted"` or `"pending"` since 006 and 006 made that
 * invisible to the sharer. It stops being invisible here: the two look identical on a
 * screen and only one of them means anybody has access.
 *
 * ## Sharing with a group — 035h, and this docstring described it long before it existed
 *
 * The paragraph here used to say the sheet *"offers a picker over the groups an agent is
 * already shared with"*, on the grounds that `access/groups.py` needed a `system`
 * principal because no tenant-admin role existed. Both halves were false. 12b built the
 * role and the six group routes; and there was **no picker of any kind** — `ShareBox`
 * passed `email` as the grantee kind literally, so sharing an agent with a group was
 * reachable from the CLI and from nowhere in the product.
 *
 * Four places argued `GET /groups` open on the strength of *"the menu an editor picks
 * from when sharing"*, and the editor never arrived. The route, the `editor` check in
 * `grants.share`, the storage guard that refuses a group nobody created and the audit
 * record have all been in place since 9a. This is the caller.
 *
 * **The chooser is one control, not a second Share button.** `PUT /agents/{name}/grants/
 * {kind}/{grantee}` has one shape, and the form takes the same one: pick who — an address
 * or a group — then the level, then Share. Two sections with two buttons would read as two
 * verbs where there is one, and would need two role choosers that can disagree.
 *
 * ## What is not here
 *
 * **Making a group.** That is `POST /groups`, administrator surface, and a create control
 * on a sharing screen is how somebody invents a group to solve a share and leaves an
 * unmanaged one behind. An empty list says so as a sentence instead.
 *
 * **`owner` for anybody**, and for a group doubly: `grants.share` refuses it with a
 * sentence about accountability — a group-owned agent is one everybody may delete and
 * nobody answers for — so the option would exist only to be refused.
 *
 * There is no link sharing, no `viewer` role and no public flag. The 44-screen reference
 * this product's decomposition came from has all three, and each is the permissive branch
 * at a fork where 006 took the restrictive one.
 */

import { useState } from "react";

import Failure from "../../components/Failure";
import { Badge, Button, Card, Field, Notice } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import type {
  AgentAccessEntry,
  AgentDetail,
  GroupSummary,
  OwnedToken,
} from "../../lib/types";
import type { Resource } from "../../lib/useResource";
import { useResource } from "../../lib/useResource";

/** The levels a person can be given from here.
 *
 *  `owner` is absent, and it is absent rather than disabled: granting ownership is a
 *  **transfer** — the server routes it to `transfer`, which demotes whoever holds it now
 *  — and a thing that changes two people's access at once does not belong in the same
 *  control as "share this with Sam". */
/** Who a share names. The `kind` in `PUT /agents/{name}/grants/{kind}/{grantee}`, as a
 *  control — `email` is not a grantee kind, and that is the point of it: an address is how
 *  a person thinks about sharing and whether it lands as a grant or as a pending row is a
 *  fact about whether they have ever logged in. `user` is absent for the same reason it is
 *  absent from `AddMember`: there is no route that turns an address into a principal, so a
 *  raw `u_…` is something only the log and this sheet's own table can supply. */
const WHO = [
  { id: "email", label: "A person", hint: "by their email address" },
  { id: "group", label: "A group", hint: "everybody in it, now and later" },
  // **The verb that makes a minted token do anything** (065). The route has taken
  // `machine` since the door existed and the CLI has always called it; the form had no
  // option, so a token minted in the browser could only be granted at a terminal.
  { id: "machine", label: "A token", hint: "a client connecting to the MCP server" },
];

const ROLES = [
  { id: "user", label: "Can use", hint: "Use its tools and see its settings." },
  { id: "editor", label: "Can edit", hint: "Also edit and share it." },
];

export default function ShareSheet({ agent }: { agent: AgentDetail }) {
  const sheet = useResource(() => api.agentAccess(agent.name), [agent.name]);
  const [failure, setFailure] = useState<unknown>(null);

  // `editor` is what every write below needs, and it is the ladder's own answer rather
  // than a flag per verb — see `AgentDetail.your_role`.
  const mayShare = agent.your_role === "editor" || agent.your_role === "owner";

  function act(work: Promise<unknown>) {
    setFailure(null);
    work.then(() => sheet.reload()).catch((cause: unknown) => setFailure(cause));
  }

  return (
    <Card title="Sharing" hint="who has access">
      {sheet.loading && <p className="muted">Loading…</p>}
      {sheet.error ? <Failure error={sheet.error} /> : null}

      {sheet.data && (
        <>
          <table>
            <thead>
              <tr>
                <th>Who</th>
                <th>Role</th>
                <th>How</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sheet.data.access.map((row) => (
                <Row
                  key={`${row.kind}:${row.id}`}
                  row={row}
                  mayShare={mayShare}
                  onRevoke={() =>
                    act(api.unshareAgent(agent.name, row.kind, row.id))
                  }
                />
              ))}
            </tbody>
          </table>

          {/* Step 033e, and the obligation this sheet inherited when membership stopped
              being a table: with a directory-backed group the list above is everybody who
              has SIGNED IN since being placed in it, not everybody who is in it. Said
              plainly here rather than by quietly showing a shorter list — the same reason
              the waiting shares below are a separate section rather than merged in. */}
          {(() => {
            const followed = sheet.data.access.filter(
              (row) => row.kind === "group" && row.directory,
            );
            if (followed.length === 0) return null;
            return (
              <p className="sentence muted">
                {followed.map((row) => row.id).join(", ")}{" "}
                {/* Agreeing with `--agent-access`, which pluralises the same sentence:
                    one fact should not read two ways depending on which door you are
                    standing at. */}
                {followed.length === 1 ? "follows" : "follow"} your directory. Members who
                have not signed in since being added are listed after their next sign-in.
              </p>
            );
          })()}

          {sheet.data.waiting.length > 0 && (
            <>
              <h3>Pending first sign-in</h3>
              <p className="sentence">
                These people have not signed in yet. Access is granted when they first sign
                in with this address.
              </p>
              <table>
                <tbody>
                  {sheet.data.waiting.map((pending) => (
                    <tr key={pending.email}>
                      <td className="mono">{pending.email}</td>
                      <td>
                        <Badge tone="waiting">{pending.role}</Badge>
                      </td>
                      <td>
                        {mayShare && (
                          <Button
                            kind="quiet"
                            onClick={() =>
                              act(api.unshareAgent(agent.name, "email", pending.email))
                            }
                          >
                            Cancel
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}

      {failure ? <Failure error={failure} /> : null}
      {failure instanceof ApiError && failure.status === 400 ? (
        // The server's sentence is already rendered above. This adds what it means:
        // `unshare` refuses rather than deleting nothing and reporting success, because
        // whoever pressed it would otherwise believe the access is gone and stop looking.
        <p className="muted">
          Nothing was changed. Remove them from the group, or remove the group's access.
        </p>
      ) : null}

      {mayShare ? (
        <ShareBox agent={agent} onShared={() => sheet.reload()} />
      ) : (
        <p className="muted">Only editors and the owner can change sharing.</p>
      )}
    </Card>
  );
}

function Row({
  row,
  mayShare,
  onRevoke,
}: {
  row: AgentAccessEntry;
  mayShare: boolean;
  onRevoke: () => void;
}) {
  const inherited = row.direct === null;
  // The house two-step (061): removing access acted on first click, alone among the
  // app's destructive controls, per row.
  const [confirming, setConfirming] = useState(false);

  return (
    <tr>
      <td className="mono">
        {/* A machine is labelled for the same reason a group is: an opaque `m_...`
            beside a `u_...` reads as another person, and "who can reach this agent" is
            the one question this screen answers. */}
        {row.kind === "group"
          ? `group ${row.id}`
          : row.kind === "machine"
            ? `token ${row.id}`
            : row.id}
      </td>
      <td>
        <Badge tone={row.role === "owner" ? "warn" : "waiting"}>{row.role}</Badge>
      </td>
      <td>
        {/* The column this screen exists for. "Through oncall" is what stops somebody
            revoking a row that is not there and concluding the revoke failed. */}
        {inherited ? (
          <span className="muted">through {row.via.join(", ")}</span>
        ) : row.via.length > 0 ? (
          <span className="muted">
            directly, and also through {row.via.join(", ")}
          </span>
        ) : row.kind === "group" ? (
          // Step 033e: for a group whose membership comes from the directory,
          // "everybody in this group" is exactly the claim this sheet can no longer
          // make — the rows below it are the people who have signed in since being
          // placed there. Said here rather than left to be inferred.
          <span className="muted">
            {row.directory
              ? "everybody your directory puts in it"
              : "everybody in this group"}
          </span>
        ) : row.kind === "machine" ? (
          <span className="muted">an access token</span>
        ) : (
          <span className="muted">shared with them</span>
        )}
      </td>
      <td>
        {mayShare && row.role !== "owner" && !inherited && !confirming && (
          <Button kind="quiet" onClick={() => setConfirming(true)}>
            Remove
          </Button>
        )}
        {mayShare && row.role !== "owner" && !inherited && confirming && (
          // The confirm carries the two facts a remover assumes wrongly: it is
          // immediate, and it does not touch group-inherited access — the exact
          // "revoked and still visible" confusion this sheet's `via` column exists
          // to prevent, prevented before the click instead of explained after.
          <span className="spread">
            <span className="muted tiny">
              {row.kind === "group"
                ? "Everyone in this group loses access now."
                : "Their direct access ends now. Access through a group is kept."}
            </span>
            <Button kind="quiet" onClick={() => setConfirming(false)}>
              Keep
            </Button>
            <Button kind="primary" onClick={onRevoke}>
              Remove
            </Button>
          </span>
        )}
        {row.role === "owner" && <span className="muted">owns it</span>}
        {inherited && (
          // Deliberately not a disabled Remove button. A control that exists and does
          // nothing reads as a bug; a sentence saying where the access comes from is the
          // thing that gets acted on.
          <span className="muted">remove them from the group</span>
        )}
      </td>
    </tr>
  );
}

/** Share it with an address, or with one of the tenant's groups.
 *
 *  **The group half arrived in 035h**, long after the route that exists to serve it.
 *  `api.listGroups()` is fetched here rather than in `ShareSheet` so that a person who can
 *  only *read* the sheet makes no request for a tenant-wide listing: this component renders
 *  only when `mayShare`, which is the same `editor` the write needs.
 *
 *  One `who` chooser, one level, one Share — see the module docstring. */
function ShareBox({ agent, onShared }: { agent: AgentDetail; onShared: () => void }) {
  const [kind, setKind] = useState("email");
  const [email, setEmail] = useState("");
  const [group, setGroup] = useState("");
  const [token, setToken] = useState("");
  const [role, setRole] = useState("user");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const [outcome, setOutcome] = useState<{ email: string; pending: boolean } | null>(null);
  const [shared, setShared] = useState<GroupSummary | null>(null);
  const [sharedToken, setSharedToken] = useState<OwnedToken | null>(null);

  // No deps: the tenant's groups do not change while somebody types an address, and a
  // listing that refetched on every keystroke would be a poll with extra steps.
  const groups = useResource(() => api.listGroups(), []);
  // The sharer's own tokens, for the same reason and on the same terms as the groups
  // above: this component renders only when `mayShare`, and a listing does not change
  // while somebody chooses from it.
  const tokens = useResource(() => api.myTokens(), []);

  const picked = groups.data?.find((row) => row.group_id === group) ?? null;
  const pickedToken = tokens.data?.find((row) => row.id === token) ?? null;
  const grantee = kind === "email" ? email.trim() : kind === "group" ? group : token;

  // **A machine is offered at `user` and nothing else.** The route would take `editor`;
  // an editor that is a program can rewrite the permission list that bounds it, and the
  // confirmation nobody reads would be a program's. Plan 065.
  const effectiveRole = kind === "machine" ? "user" : role;

  function share() {
    if (!grantee || busy) return;
    setBusy(true);
    setFailure(null);
    setOutcome(null);
    setShared(null);
    setSharedToken(null);
    api
      .shareAgent(agent.name, kind, grantee, effectiveRole)
      .then((result) => {
        if (kind === "email") {
          setOutcome({ email: grantee, pending: result.outcome === "pending" });
          setEmail("");
        } else if (kind === "group") {
          setShared(picked);
          setGroup("");
        } else {
          setSharedToken(pickedToken);
          setToken("");
        }
        onShared();
      })
      .catch((cause: unknown) => setFailure(cause))
      .finally(() => setBusy(false));
  }

  return (
    <>
      <h3>Share</h3>
      <p className="sentence">
        People you share with use the agent with their own access. Every call is logged
        under their name.
      </p>

      {/* The kind in the URL, as a control. `shareAgent` takes `email | user | group`
          and the form has one shape because the route has one. */}
      <div className="choices">
        {WHO.map((choice) => (
          <label key={choice.id} className={`choice${kind === choice.id ? " on" : ""}`}>
            <input
              type="radio"
              name="share-kind"
              checked={kind === choice.id}
              onChange={() => {
                setKind(choice.id);
                setFailure(null);
              }}
            />
            <span>
              <strong>{choice.label}</strong>
              <span className="muted"> — {choice.hint}</span>
            </span>
          </label>
        ))}
      </div>

      {kind === "email" ? (
        <Field label="Email address" hint="Somebody at your organisation.">
          <input
            type="email"
            value={email}
            disabled={busy}
            placeholder="colleague@yourcompany.com"
            onChange={(event) => setEmail(event.target.value)}
          />
        </Field>
      ) : kind === "group" ? (
        <GroupPicker
          groups={groups}
          value={group}
          busy={busy}
          onChange={setGroup}
          picked={picked}
        />
      ) : (
        <TokenPicker
          tokens={tokens}
          value={token}
          busy={busy}
          onChange={setToken}
          picked={pickedToken}
        />
      )}

      {kind === "machine" ? (
        <p className="sentence muted">
          A token is granted <strong>Can use</strong>. It can use the agent's tools and
          cannot edit the agent.
        </p>
      ) : (
        <div className="choices">
          {ROLES.map((choice) => (
          <label key={choice.id} className={`choice${role === choice.id ? " on" : ""}`}>
            <input
              type="radio"
              name="share-role"
              checked={role === choice.id}
              onChange={() => setRole(choice.id)}
            />
            <span>
              <strong>{choice.label}</strong>
              <span className="muted"> — {choice.hint}</span>
            </span>
          </label>
          ))}
        </div>
      )}

      <div className="spread">
        <Button kind="primary" busy={busy} disabled={!grantee} onClick={share}>
          Share
        </Button>
      </div>

      {failure ? <Failure error={failure} /> : null}

      {outcome &&
        (outcome.pending ? (
          // **The distinction 006 hid from the sharer.** These two look identical on a
          // screen and only one of them means anybody actually has access.
          <Notice tone="warn" title="Pending first sign-in">
            <p className="sentence">
              Nobody has signed in as <span className="mono">{outcome.email}</span> yet.
              Access is granted when they first sign in with this address.
            </p>
          </Notice>
        ) : (
          <Notice tone="info" title="Shared">
            <p className="sentence">
              <span className="mono">{outcome.email}</span> can use this agent now.
            </p>
          </Notice>
        ))}

      {/* A group share has no pending half — a group exists or the write is refused — so
          the confirmation says the one thing a `granted` outcome cannot: **who** that is,
          which for a directory-backed group is not a list anybody here can produce. */}
      {/* A token's confirmation says the thing a person's does not need to: **what the
          assistant holding it does next**. Nothing is sent to anybody — the secret was
          shown once, at mint — so a share that produced no visible effect anywhere is
          exactly the case somebody re-does twice. */}
      {sharedToken && (
        <Notice tone="info" title="Shared">
          <p className="sentence">
            A client using <strong>{sharedToken.name}</strong> can use this agent&rsquo;s
            tools now. They appear in its next <span className="mono">tools/list</span>.
          </p>
        </Notice>
      )}

      {shared && (
        <Notice tone="info" title="Shared">
          <p className="sentence">
            Everyone in <strong>{shared.name}</strong> can use this agent now
            {shared.directory
              ? ", including anyone your directory adds later, from their next sign-in."
              : ", including anyone an administrator adds later."}
          </p>
        </Notice>
      )}
    </>
  );
}

/** The sharer's own **service** tokens, as the thing an agent is granted to.
 *
 *  **Personal tokens are not here, and their absence is the point.** A personal token
 *  resolves its *owner's* grants and holds none of its own — `TokenDetailPage` says so in
 *  its own words — so a grant written against one changes nothing while looking exactly
 *  like a grant that did. The filter is `acts_as_owner === false`, and the empty state
 *  names the reason rather than reporting "no tokens" to somebody looking at three.
 *
 *  Revoked tokens are excluded on the plainer ground that nothing can present them. */
function TokenPicker({
  tokens,
  value,
  busy,
  onChange,
  picked,
}: {
  tokens: Resource<OwnedToken[]>;
  value: string;
  busy: boolean;
  onChange: (id: string) => void;
  picked: OwnedToken | null;
}) {
  if (tokens.loading) return <p className="muted">Loading tokens…</p>;
  if (tokens.error) return <Failure error={tokens.error} />;

  const grantable = (tokens.data ?? []).filter(
    (row) => !row.acts_as_owner && row.revoked_at === null,
  );

  if (grantable.length === 0) {
    const personal = (tokens.data ?? []).some(
      (row) => row.acts_as_owner && row.revoked_at === null,
    );
    return (
      <p className="sentence muted">
        {personal
          ? "Your active tokens are all personal. A personal token can already use every agent shared with you. Generate a service token to grant narrower access."
          : "You have no service tokens. Generate one on Access tokens, then grant it this agent."}
      </p>
    );
  }

  return (
    <>
      <Field label="Token" hint="The service token a client connects with.">
        <select
          value={value}
          disabled={busy}
          onChange={(event) => onChange(event.target.value)}
        >
          <option value="">Choose a token…</option>
          {grantable.map((row) => (
            <option key={row.id} value={row.id}>
              {row.name} — {row.id}
            </option>
          ))}
        </select>
      </Field>
      {picked && (
        <p className="muted">
          A client using <strong>{picked.name}</strong> can use this agent&rsquo;s tools.
          A token granted several agents can use all of them.
        </p>
      )}
    </>
  );
}

/** The groups of this tenant, as the menu `GET /groups` was opened to be.
 *
 *  **Both kinds are labelled, and that is a departure from 035g's device**, which marked
 *  one state on `ConnectorsPage` and left the norm silent. It worked there because the
 *  norm was safe and the exception was the hazard. Here neither state is a hazard and
 *  *which one is the norm depends on the deployment*: in a tenant that syncs everything
 *  from Entra, a "from your directory" badge is noise and the hand-made group is the
 *  surprise; in a hand-managed tenant it is the other way round. A single mark would be
 *  read as *the exception* by every reader and half of them would read it backwards.
 *
 *  The wording is this screen's own and deliberately not `GroupsPage`'s. An administrator
 *  is asking *may I edit this*; a sharer is asking *who does this reach*. One sentence
 *  answering both would answer neither, and two screens describing one fact in identical
 *  words is what makes a page-wide assertion worthless. */
function GroupPicker({
  groups,
  value,
  busy,
  onChange,
  picked,
}: {
  groups: Resource<GroupSummary[]>;
  value: string;
  busy: boolean;
  onChange: (id: string) => void;
  picked: GroupSummary | null;
}) {
  if (groups.loading) return <p className="muted">Loading groups…</p>;
  if (groups.error) return <Failure error={groups.error} />;

  // An empty answer renders as the sentence it is — and it names who makes one, because
  // this screen deliberately cannot.
  if (!groups.data || groups.data.length === 0) {
    return (
      <p className="sentence muted">No groups yet. An administrator creates groups.</p>
    );
  }

  return (
    <>
      <Field label="Group" hint="Everyone in the group, now and later.">
        <select
          value={value}
          disabled={busy}
          onChange={(event) => onChange(event.target.value)}
        >
          <option value="">Choose a group…</option>
          {groups.data.map((row) => (
            <option key={row.group_id} value={row.group_id}>
              {row.name} —{" "}
              {row.directory
                ? "whoever your directory puts in it"
                : "whoever an administrator puts in it"}
            </option>
          ))}
        </select>
      </Field>
      {/* The consequence, once there is one to state. A directory-backed group is the
          case where "who will this reach" has no answer anybody on this screen can give:
          membership arrives from the provider at each person's next sign-in. */}
      {picked && (
        <p className="muted">
          {picked.directory ? (
            <>
              <strong>{picked.name}</strong> follows your directory. Everyone in it can use
              this agent from their next sign-in. Its members are not listed here.
            </>
          ) : (
            <>
              <strong>{picked.name}</strong> is managed by an administrator. Everyone in it
              can use this agent, including anyone added later.
            </>
          )}
        </p>
      )}
    </>
  );
}
