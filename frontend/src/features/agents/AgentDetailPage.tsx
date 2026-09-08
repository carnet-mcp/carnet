import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Notice, PageHead, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import type { AgentDetail } from "../../lib/types";
import { useResource } from "../../lib/useResource";
import ConnectCard from "./ConnectCard";
import ConnectionNotice from "./ConnectionNotice";
import Reach from "./Reach";
import RenameBox from "./RenameBox";
import ShareSheet from "./ShareSheet";
import VersionHistory from "./VersionHistory";

/** One agent: what it may reach, and a box to ask it something.
 *
 * ## The screen this chunk exists for
 *
 * 10a rendered an agent's granted tools as a row of names:
 *
 *     github_mcp_list_issues        post_message
 *
 * Those two are a read and a write, and nothing on the screen said so — because nothing
 * over HTTP *could* say so. The read/write annotation is the one thing MCP cannot tell
 * us about itself; a connector admin sits down and vets a server tool by tool, and it
 * has been in `vetted_tools` since migration 003, exposed to nobody.
 *
 * `GET /tools` is what changed. The plan's argument for the catalogue is that a scope
 * cannot be **built** without one; the other half, which 10a made visible, is that a
 * permission cannot be **read** without one either — and reading comes first, because
 * the detail screen exists today and is wrong today, in the direction where the mistake
 * is unrecoverable.
 *
 * **That section now lives in `Reach.tsx`**, which the wizard's review step imports too.
 * Not for reuse — for identity: what somebody approves in the form is literally what
 * they will see here afterwards, so the two cannot develop a disagreement. See the
 * docstring there. What is left in this file is what only this screen has: the
 * stored-and-unread card, the history and the sheet.
 *
 * ## What 10d added
 *
 * **A broken agent renders here now**, which it never did: `GET /agents/{name}` answered
 * 422 for four steps, so the one agent somebody needed to fix was the one screen they
 * could not open. Reach's *"granted, and no longer available"* branch, which 10a
 * shipped for this state, becomes reachable for the first time.
 *
 * **Edit, delete and the share sheet.** Which of those are offered comes from
 * `your_role`, and the alternative is buttons that answer 404 to the person they were
 * rendered for. It is the ladder's own word rather than a flag per verb — three flags is
 * three things that can disagree with `access/grants.py`.
 */
export default function AgentDetailPage() {
  const { name = "" } = useParams();
  const { data, error, loading } = useResource(() => api.getAgent(name), [name]);

  // A second request, and deliberately not merged into the first. The catalogue is a
  // property of the *tenant* — every agent screen shows the same one — while the agent
  // is a property of this URL. Folding the catalogue into `GET /agents/{name}` would
  // make one route answer two questions and re-send the whole vetting record on every
  // agent a person opens.
  const catalogue = useResource(() => api.listTools(), []);

  return (
    <>
      <Link className="back" to="/agents">
        ← Agents
      </Link>
      <PageHead title={name} />

      {loading && <Spinner label="Loading" />}
      {error && <Failure error={error} />}
      {data && (
        <>
          <Actions agent={data} />
          {/* **Above the connect card**, because it is about the call somebody is one
              click away from making. Below it, the sentence arrives after the decision. */}
          <ConnectionNotice agent={data} catalogue={catalogue.data} />
          {/* What this page is: everything that makes an agent a **permission list** —
              its reach, its versions and who it is shared with — because
              that is what the door scopes by, and it is the whole of what an agent is
              for a caller at `/mcp`. The connect card first, because it is about the
              call somebody is minutes away from making. */}
          <ConnectCard name={data.name} />
          <Reach agent={data} catalogue={catalogue.data} failed={catalogue.error} />
          <StoredNotRead agent={data} />
          {/* **Above the share sheet**, which is where a builder
              looks rather than where an auditor does: history is part of working on an
              agent, and the sheet is about other people. */}
          <VersionHistory agent={data} />
          <ShareSheet agent={data} />
        </>
      )}
    </>
  );
}

/** What this agent's stored config carries that this deployment does not read. Step 081.
 *
 *  ## What this replaces, and why one card rather than three
 *
 *  Three cards stood here: *Instructions* over `system`, *The answer it must give* over
 *  `output.schema` (*"every run is checked against this before it is called complete"*),
 *  and *Ceilings — per run* over `limits`. Each rendered a stored value as though
 *  something enforced it. Nothing does: the door reads `permissions.tools` and
 *  `permissions.scope` and no other config key, `agents.check_output` had no caller and
 *  is deleted, and the per-agent `limits` block reached enforcement only through
 *  `Budget.for_agent` ← `RunContext.start`, which nothing called.
 *
 *  **Step 084 deleted both of those**, so the sentence above is history rather than a
 *  path somebody can go and look at. What survives of `limits` is the *vocabulary*:
 *  `agents.KNOWN_LIMITS` still refuses an unknown key at write, because a block rendered
 *  under this heading is a block somebody must be able to read back correctly.
 *
 *  So the choice 080 section B poses — refuse these at write, drop them silently, or
 *  accept them and say so — is answered here in its third form. **The values are still
 *  shown**, because somebody who authored a schema over the API must be able to read back
 *  what they stored, and hiding it would be the second dishonesty. What changes is that
 *  they are shown under a heading that does not claim anything enforces them.
 *
 *  **Rendered only when the config carries at least one**, which is the precedent both
 *  cards it replaces already set: an agent with none of them is the majority case, and a
 *  card on every page announcing a non-fact is a card about nothing.
 *
 *  `UNREAD` is a list rather than "every key that is not `name` or `permissions`", and the
 *  difference is deliberate: an unknown key is refused by `AgentDraft`'s `extra="forbid"`
 *  before it can be stored, so a config cannot legitimately carry one this list has not
 *  heard of — and a new accepted field wants a person to decide how it reads here rather
 *  than defaulting into a JSON dump. `draft.test.ts` pins the list against the schema. */
export const UNREAD: { key: string; label: string }[] = [
  { key: "system", label: "Instructions" },
  { key: "model", label: "Model" },
  { key: "max_tokens", label: "Answer-length ceiling" },
  { key: "runtime", label: "Runtime tier" },
  { key: "private_runs", label: "Private runs" },
  { key: "limits", label: "Per-run ceilings" },
  { key: "output", label: "Answer schema" },
];

function StoredNotRead({ agent }: { agent: AgentDetail }) {
  const present = UNREAD.filter(({ key }) => agent.config[key] !== undefined);
  if (present.length === 0) return null;

  return (
    <Card
      title="Stored, and not read here"
      hint="kept exactly as written — nothing reads them when a call is made"
    >
      <p className="sentence">
        This deployment brokers tool calls. What it reads out of an agent on every call is
        the tool list and the scope above, and nothing else; the fields below were written
        by an earlier version of this form, by the API, or for a deployment that runs
        agents. They are kept exactly as they were — an edit here never removes them.
      </p>
      <p className="muted">
        They are still checked for shape when somebody writes them, so none of these is a
        value nobody looked at. What no longer happens is anything acting on them: no
        ceiling is enforced from here, no answer is checked against a schema, and nothing
        is hidden from a colleague. What bounds this agent is the token it is called with.
      </p>
      <table>
        <tbody>
          {present.map(({ key, label }) => (
            <tr key={key}>
              <td>{label}</td>
              <td className="mono">
                <pre className="block">{render(agent.config[key])}</pre>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

/** A config value as text. Strings verbatim — a system prompt is prose and quoting it
 *  would add characters nobody wrote — and everything else pretty-printed JSON. */
function render(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

/** Edit, rename and delete, offered only to somebody the server would let do them.
 *
 *  `PATCH` is `editor`; `DELETE` and `POST .../rename` are `owner` — the asymmetry 10d
 *  argues, and the first code that makes migration 011's ladder sentence true: `owner` is
 *  the level that may *delete it, and hand it to somebody else*. An editor who may delete
 *  an agent can do worse than orphan it, which `unshare` already refuses on the same
 *  grounds; and 025's argument for putting rename at the same altitude is that an editor
 *  changes what an agent *does* while this changes what it is *called*.
 *
 *  **One expression per level, not one per verb.** `mayOwn` gates both owner verbs. Three
 *  flags would be three things free to disagree with `access/grants.py`, which is the
 *  reason `your_role` is a rung rather than a set of booleans in the first place.
 *
 *  Rendering an owner verb for an editor is not a cosmetic mistake: `grants.require` says
 *  the same sentence for ungranted, held-too-low and absent, so the press answers **404**
 *  — *"no agent named 'triage'"*, about the agent currently on screen. */
function Actions({ agent }: { agent: AgentDetail }) {
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  const mayEdit = agent.your_role === "editor" || agent.your_role === "owner";
  const mayOwn = agent.your_role === "owner";
  if (!mayEdit && !mayOwn) return null;

  return (
    <>
      <div className="toolbar">
        {mayEdit && <Button to={`/agents/${agent.name}/edit`}>Edit</Button>}
        {mayOwn && !renaming && !confirming && (
          <Button kind="quiet" onClick={() => setRenaming(true)}>
            Rename
          </Button>
        )}
        {mayOwn && !confirming && !renaming && (
          <Button kind="quiet" onClick={() => setConfirming(true)}>
            Delete
          </Button>
        )}
      </div>

      {renaming && <RenameBox agent={agent} onCancel={() => setRenaming(false)} />}

      {confirming && (
        // **No undo, said before rather than discovered after.** `admin_audit` records
        // that it happened and holds what the agent could reach — enough to rebuild it by
        // hand, deliberately not enough to make an undo button look feasible.
        <Notice tone="bad" title={`Delete ${agent.name}?`}>
          <p className="sentence">
            This cannot be undone. Everyone it is shared with loses it, and anybody who
            reached it through a team loses it too. Every call it admitted stays in the
            audit record, and any token granted only this agent can call nothing.
          </p>
          {failure ? <Failure error={failure} /> : null}
          <div className="spread">
            <Button
              kind="danger"
              busy={deleting}
              onClick={() => {
                setDeleting(true);
                setFailure(null);
                api
                  .deleteAgent(agent.name)
                  .then(() => navigate("/agents"))
                  .catch((cause: unknown) => {
                    setFailure(cause);
                    setDeleting(false);
                  });
              }}
            >
              {deleting ? "Deleting" : "Delete it"}
            </Button>
            <Button disabled={deleting} onClick={() => setConfirming(false)}>
              Keep it
            </Button>
          </div>
        </Notice>
      )}
    </>
  );
}

