/** Renaming an agent, from the browser. **`owner`.** Step 035i.
 *
 * `POST /agents/{name}/rename` has existed since step 025 and had no client at all — the
 * API and the CLI were the parity floor and the affordance *"rides the next screens
 * step"*, which is this one.
 *
 * ## What this screen has to carry, and the CLI already does
 *
 * A rename is the one operation on an agent whose whole cost lands on somebody who is not
 * in the room. `--rename-agent` prints two things and this prints the same two, in the
 * same order:
 *
 *     Its grants and history came with it. Anything holding the old
 *     URL — a bookmark, a runbook, another system's config — now points at nothing.
 *
 * **Both halves, and the survival half first.** Saying only the breakage would make a
 * rename read as more destructive than it is, and that misapprehension has a known
 * consequence: it is what makes people delete the agent and build a new one instead,
 * which is the operation a rename exists to stop being. Before migration 035 that was
 * genuinely the only way, and it cascaded away the grants and the version history. Now nothing is lost, and the person deciding is
 * entitled to know that before they decide.
 *
 * And the breakage is real and is exactly one thing: **the old URL is an ordinary 404
 * afterwards.** No redirect, no memory of former names — decision 9 of 025 — because a
 * name freed by a rename has to be genuinely free, or the next agent to take it inherits
 * an address that points somewhere else. The register's phrasing is that *"the owner who
 * renames owns the broken bookmarks"*, and until this file that sentence existed only in
 * a terminal.
 *
 * ## Why the refusals are rendered here and never by `Failure`
 *
 * `Failure` titles a 422 *"This agent's configuration is not valid"* and follows it with
 * *"It exists and cannot run until somebody fixes it."* Every word of that is false here:
 * the configuration is fine, the agent runs, and the thing that is wrong is a name in a
 * box. It titles a 409 *"The server refused (409)"*, which is the status code as prose.
 *
 * So all three server refusals render as the server's own sentence, beside the input,
 * with no title and no branch on the status — which is what `_rename_agent` does with the
 * identical three (`parser.error(str(exc))`), so a person reads the same words whichever
 * door they came in at.
 *
 * ## What the form pre-empts, and what it deliberately does not
 *
 * Pre-empted, because the server's answer would have no words:
 *
 *   - **Empty.** `AgentRename.new_name` is `min_length=1`, which is *pydantic's* refusal,
 *     which arrives as a list `detail`, which `readProblem` replaces with the one generic
 *     sentence it uses for every malformed body. It is the only refusal on this control
 *     with nothing written for it, and this is the only place it can be given words.
 *   - **The name it already has.** A state this form produces by *default* — open the
 *     box, change nothing, submit — and the server's answer is a paragraph about version
 *     history, which is not what that person needs. `EditAgentPage`'s Save disables on
 *     the same fact with *"Nothing has changed yet."*
 *   - **Not a usable identifier**, through `nameIsUsable`, which is the wizard's own
 *     helper and already documents itself as the third copy of the rule. Calling it from
 *     a second form adds no copy, and it is here for the wizard's stated reason: a button
 *     that can be disabled beats a refusal that has to be earned.
 *
 * **Not** pre-empted:
 *
 *   - **The reserved names.** The refusal stays entirely the server's, because the
 *     sentence is the point — *"It is already a path in this product, so an agent called
 *     that would have a URL that means two things"* — and no client-side `if` reproduces
 *     it. The wizard does not check them either.
 *   - **The 409.** Only the server knows what exists, and `AgentNameTaken` deliberately
 *     does not name the owner of the colliding agent: doing so would answer *"does
 *     `payroll-bot` exist and who runs it"* through a status code, which is the
 *     enumeration the 404 rule exists to close. A browser pre-check would be that
 *     enumeration with extra steps.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { Button, Field, Notice } from "../../components/ui";
import { ApiError, api } from "../../lib/api";
import { nameIsUsable } from "../../lib/draft";
import type { AgentDetail } from "../../lib/types";

/** Why the button is off, or `""`. The wizard's `nameBlocker` idiom: a sentence rather
 *  than a silent disable, because a greyed-out button with no explanation is the thing
 *  the blockers exist to avoid. */
export function renameBlocker(agent: AgentDetail, typed: string): string {
  const next = typed.trim();
  if (!next) return "Enter the new name.";
  if (next === agent.name) return `The name is already ${agent.name}.`;
  if (!nameIsUsable(next))
    return "Use lowercase letters, digits and single hyphens, for example triage-bot.";
  return "";
}

export default function RenameBox({
  agent,
  onCancel,
}: {
  agent: AgentDetail;
  onCancel: () => void;
}) {
  const navigate = useNavigate();
  const [typed, setTyped] = useState(agent.name);
  const [renaming, setRenaming] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  const next = typed.trim();
  const blocker = renameBlocker(agent, typed);
  // Every refusal from this route is a sentence written for whoever typed the name, so
  // there is one branch and not four. Anything that is not an `ApiError` — the network
  // being gone — still has a message worth showing and no server sentence to show.
  const refusal =
    failure instanceof ApiError
      ? failure.detail
      : failure instanceof Error
        ? failure.message
        : null;

  function rename() {
    setRenaming(true);
    setFailure(null);
    api
      .renameAgent(agent.name, next)
      // The response carries the whole agent and a new ETag; both are thrown away, because
      // every card on this page is keyed by the name in the URL and re-fetches under the
      // new one. Navigating *is* the reload.
      .then(() => navigate(`/agents/${encodeURIComponent(next)}`))
      .catch((cause: unknown) => {
        setFailure(cause);
        setRenaming(false);
      });
  }

  return (
    <Notice tone="warn" title={`Rename ${agent.name}?`}>
      <p className="sentence">Grants, history and sharing are kept.</p>
      <p className="sentence">
        The URL changes. Bookmarks and client configurations that use the old name stop
        working. There is no redirect.
      </p>

      <Field
        label="New name"
        hint="Lowercase letters, digits and single hyphens. Used in the URL and in the audit log."
      >
        <input
          type="text"
          className="mono"
          value={typed}
          autoFocus
          disabled={renaming}
          onChange={(event) => setTyped(event.target.value)}
        />
      </Field>

      {/* The two addresses, as they will actually read. Rendered live rather than after
          the fact, because the whole point of saying it here is that it is said while the
          decision is still open — and a person recognises their own bookmark faster than
          they recognise a sentence about bookmarks. */}
      {!blocker && (
        <p className="sentence mono">
          /agents/{agent.name} → /agents/{next}
        </p>
      )}

      {refusal && <p className="sentence">{refusal}</p>}

      <div className="spread">
        <Button kind="primary" busy={renaming} disabled={Boolean(blocker)} onClick={rename}>
          {renaming ? "Renaming" : "Rename"}
        </Button>
        <Button disabled={renaming} onClick={onCancel}>
          Cancel
        </Button>
        {blocker && <span className="muted">{blocker}</span>}
      </div>
    </Notice>
  );
}
