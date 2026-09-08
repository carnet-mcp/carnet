/** Editing an agent. **The wizard's steps, and not the wizard's shape.**
 *
 * Decision 8 of 010d. The five step components are the vocabulary — they are where the
 * wording of every question about permissions lives, and a second set would be a second
 * description of the only thing in this system that decides what an agent may do. What
 * does *not* transfer is the forward-only gating: editing is not a sequence. Somebody
 * arrives to change one thing, so every section is on the screen at once.
 *
 * ## Why the save is a patch and not a config
 *
 * `frontend/src/lib/draft.ts` has `toConfig` and no inverse, and building one would be
 * lossy in a way that is not theoretical: the shipped `issue-reporter` carries
 * `default_task` and `deny_demo_task`, and no step here asks about either. An edit screen
 * that loaded that agent into the form and saved the whole config **deletes both**, and
 * nothing anywhere would report it.
 *
 * So `fromConfig` fills in the fields this form owns and keeps the config whole beside
 * them, and `patchFrom` sends back those fields and only where they changed. The question
 * "what happened to `default_task`" never arises, because this screen never had it. The
 * server's top-level merge is what makes that safe — see `agents.merge`.
 *
 * ## Why it is conditional
 *
 * `editor` has existed since migration 011 with nothing to edit, so this screen is the
 * first moment two people can be editing one agent. `If-Match` carries the version this
 * form was built from; a save from a version that is gone is a **409**, and the body says
 * which top-level keys the two disagree about. Without it, the second person to press
 * save silently reverts the first person's scope narrowing — which fails invisibly, which
 * is why it is refused rather than merged.
 */

import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Notice, PageHead, Spinner } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import {
  type Draft,
  type Editable,
  clearEditDraft,
  fromConfig,
  loadEditDraft,
  patchFrom,
  saveEditDraft,
} from "../../lib/draft";
import { useResource } from "../../lib/useResource";
import type { StepProps } from "./create/CreateAgentPage";
import StepName, { nameBlocker } from "./create/StepName";
import StepReach, { reachBlocker } from "./create/StepReach";
import StepTools, { toolsBlocker } from "./create/StepTools";

export default function EditAgentPage() {
  const { name = "" } = useParams();
  const navigate = useNavigate();
  const agent = useResource(() => api.getAgent(name), [name]);
  const catalogue = useResource(() => api.listTools(), []);

  // Built once, from the config **and** the catalogue: `fromConfig` reads the scope back
  // into per-row answers, and which rows exist is a fact about the catalogue. Two
  // independent requests, so this waits for both rather than rebuilding when the second
  // lands — rebuilding would throw away whatever had been typed in between.
  const [editable, setEditable] = useState<Editable | null>(null);
  // **Which agent and version `editable` was actually built from** (step 064), and the
  // reason it is tracked rather than read back off `agent.data`: `useResource` keeps
  // the previous `data` while a refetch is in flight, so after a 409 and a Reload the
  // two disagree for exactly as long as the refetch takes. Reading the version off
  // `agent.data` in that window is what wrote a v1 draft under v2's key — the
  // cross-version resurrection 061's key exists to forbid, through the one path built
  // to refuse it.
  const [builtFrom, setBuiltFrom] = useState<{ name: string; version: number } | null>(
    null,
  );
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  useEffect(() => {
    if (!agent.data || !catalogue.data) return;
    // Keyed on what it was built from, not on `editable` being null. The old guard
    // returned early once anything was built, so a version arriving *after* the
    // rebuild had already run against stale data was silently never rendered —
    // the colleague's save stayed invisible on the screen that exists to react to it.
    if (
      builtFrom &&
      builtFrom.name === name &&
      builtFrom.version === agent.data.version
    ) {
      return;
    }
    const built = fromConfig(agent.data.config, catalogue.data);
    // A draft saved earlier for THIS version resumes silently, create's own rule
    // (061). `original` stays the stored config, so `patchFrom` and the blockers
    // measure the restored draft against the truth, not against itself — and a
    // draft keyed to any other version is simply never read, because resurrecting
    // an edit across somebody else's save is the merge the 409 branch refuses.
    const kept = loadEditDraft(name, agent.data.version);
    setBuiltFrom({ name, version: agent.data.version });
    setEditable(kept ? { ...built, draft: kept } : built);
  }, [builtFrom, agent.data, catalogue.data, name]);

  // Persisted per keystroke, like the wizard has always done — sessionStorage, so a
  // mis-click, a reload or a closed sidebar costs nothing (061). Saving the pristine
  // build too is harmless: restoring it is a no-op.
  //
  // Stored under the version it was **built from**, so a draft is written against the
  // config it was written against, by construction rather than by the two happening to
  // agree at the moment the effect runs.
  useEffect(() => {
    if (editable && builtFrom) {
      saveEditDraft(builtFrom.name, builtFrom.version, editable.draft);
    }
  }, [editable, builtFrom]);

  function set(patch: Partial<Draft>) {
    setEditable((current) =>
      current ? { ...current, draft: { ...current.draft, ...patch } } : current,
    );
  }

  function reload() {
    // Throws the in-progress edit away, deliberately and only on request. This is what a
    // person presses after a 409, and pressing it is a decision — merging two people's
    // intent is not something this screen can do, and pretending otherwise is worse than
    // asking. The stored draft goes with it (061): "reload" restoring the thing it
    // exists to discard would make the one deliberate discard a no-op.
    //
    // Cleared and re-marked by what was built, not by `agent.data` — which is still
    // the version being discarded until the refetch lands. Nulling `builtFrom` is also
    // what makes the rebuild happen when the version has NOT moved: without it, a
    // Reload on an unchanged agent would rebuild from nothing.
    if (builtFrom) clearEditDraft(builtFrom.name, builtFrom.version);
    setEditable(null);
    setBuiltFrom(null);
    setFailure(null);
    agent.reload();
  }

  if (agent.error) return <Failure error={agent.error} />;
  // The catalogue is this form's whole vocabulary — which tools exist, which scope rows
  // they imply — so a screen without it cannot be filled in rather than merely looking
  // sparse. Refused loudly, the same call `StepTools` makes.
  if (catalogue.error) return <Failure error={catalogue.error} />;
  // `editable` is built in an effect once both requests have landed, so this covers the
  // render between the second answer and that effect as well as the wait itself.
  if (!agent.data || !editable) return <Spinner label="Loading" />;

  const { draft, original } = editable;
  const conflict =
    failure instanceof ApiError && failure.status === 409 ? failure : null;
  // **A 422 on this screen is not what `Failure` says it is.** Found by the browser pass,
  // the same way the 409 branch below was: `Failure` titles it *"This agent's
  // configuration is not valid"* — which is true of the config being *sent* and reads as
  // being about the stored one — and then says *"It exists and cannot run until somebody
  // fixes it. Nothing you can do from this page changes that yet."* on the one page in
  // the product that is somebody fixing it. Every word of that second sentence is false
  // here, and it sits directly under the box whose contents earned the refusal.
  //
  // The 409 already had this branch and the argument is the same one written there: a
  // generic panel repeating the server's sentence under a wrong title is one event
  // producing two messages, worse one first. This was reachable before 035i — a scope or
  // a tool refusal earns it — and 035i is what made it ordinary, because a schema is the
  // one field on this form whose *valid* values are the ones a person has to get right.
  const refused =
    failure instanceof ApiError && failure.status === 422 ? failure : null;
  const patch = patchFrom(draft, original, catalogue.data);
  const nothingChanged = Object.keys(patch).length === 0;

  const props: StepProps = {
    draft,
    set,
    catalogue: catalogue.data,
    catalogueFailed: catalogue.error,
    locked: true,
  };

  // Every blocker, together rather than one at a time. The wizard shows one because it
  // gates one step; this shows all of them because somebody can be looking at any
  // section, and a Save that is disabled for a reason two sections away is the greyed-out
  // button with no explanation that the blockers exist to avoid.
  const blockers = [
    nameBlocker(draft),
    toolsBlocker(draft, catalogue.data),
    reachBlocker(draft, catalogue.data),
  ].filter(Boolean);

  function save() {
    if (!agent.data) return;
    setSaving(true);
    setFailure(null);
    api
      .updateAgent(name, patch, agent.data.updated_at)
      .then(() => {
        // The saved config IS the draft now; a kept copy would resurrect it as an
        // "unsaved edit" of the next version's predecessor (061). Keyed off what was
        // built, so what is cleared is the draft that was actually stored (064).
        if (builtFrom) clearEditDraft(builtFrom.name, builtFrom.version);
        navigate(`/agents/${name}`);
      })
      .catch((cause: unknown) => {
        setFailure(cause);
        setSaving(false);
      });
  }

  return (
    <>
      <Link className="back" to={`/agents/${name}`}>
        ← {name}
      </Link>
      <PageHead
        title={`Edit ${name}`}
        lede="Changing what an agent may reach changes it for everybody it is shared with, from the next run onwards. Nothing here affects a run that has already happened."
      />

      {!agent.data.valid && (
        <Notice tone="warn" title="This agent cannot run as it is">
          <p className="sentence">{agent.data.error}</p>
          <p className="muted">
            You can open and edit it — this is where it gets fixed. It will start working
            again as soon as the configuration below is one the server accepts.
          </p>
        </Notice>
      )}

      <StepName {...props} />
      <StepTools {...props} />
      <StepReach {...props} />

      {/* **The ceilings, the answer schema and their two notices are gone — step 081.**
          What stood here was `StepLimits` (a `max_writes` tick box, three per-run dials, a
          `max_tokens` field and the *"each person's runs are private to them"* card),
          `SchemaEditor`, and a warning about a ceiling that cannot be cleared over HTTP.
          Every one of them authored a config key nothing in this tree reads, so each was a
          control whose sentence was a promise about enforcement that does not happen here.

          The stored values are untouched. `patchFrom` sends only `permissions` now, so an
          agent carrying `system`, `limits`, `max_tokens`, `private_runs` or `output` keeps
          all of them through a save **because there is no code that could send them** —
          and the detail page shows them, under a heading saying they are not read. */}
      {/* **A 409 is rendered by `Conflict` and by nothing else.** It used to render both,
          and the screenshot of that is why this is a branch: the generic panel repeated
          the server's sentence above a panel that said the same thing better, so one
          event produced two messages and the less useful one came first. Every other
          status still goes to `Failure`, which is where the 404/403/422 reasoning lives. */}
      {conflict ? (
        <Conflict name={name} original={original} failure={conflict} onReload={reload} />
      ) : refused ? (
        <Notice tone="warn" title="The server would not store that">
          {/* Verbatim. Every 422 from this route is `InvalidAgentError`, whose message is
              written to be read by whoever typed the thing — the scope sentences, the
              tool cross-check, and step 024's schema paragraphs. Nothing is added to it
              except a true sentence about what to do next. */}
          <p className="sentence">{refused.detail}</p>
          <p className="muted">
            Nothing was saved and nothing has changed. The agent is exactly as it was; fix
            what the sentence names above and save again.
          </p>
        </Notice>
      ) : failure ? (
        <Failure error={failure} />
      ) : null}

      <div className="spread wizard-nav">
        <Button
          kind="primary"
          busy={saving}
          disabled={nothingChanged || blockers.length > 0}
          onClick={save}
        >
          {saving ? "Saving" : "Save changes"}
        </Button>
        <Button to={`/agents/${name}`}>Cancel</Button>
        {blockers.length > 0 ? (
          <span className="muted">{blockers.join(" ")}</span>
        ) : nothingChanged ? (
          <span className="muted">Nothing has changed yet.</span>
        ) : (
          <span className="muted">
            {Object.keys(patch).length === 1
              ? "One thing will change."
              : `${Object.keys(patch).length} things will change.`}
          </span>
        )}
      </div>
    </>
  );
}

/** A 409, rendered as the thing that actually happened.
 *
 *  ## The question the server cannot answer, and this can
 *
 *  The 409 body's `changed` is *"the keys your save would write whose stored value is not
 *  what you are sending"* — which is what a server holding no history can compute, and it
 *  is **not** what somebody staring at this wants to know. Two tabs, one narrows the
 *  scope, the other edits only the instructions: the second gets `["system"]`, which is
 *  merely the field it was editing. The narrowing it is being protected from does not
 *  appear at all.
 *
 *  **Found by opening two tabs in a browser**, which is the only place that reads as
 *  wrong — every test asserted the field the failing tab was changing and was satisfied.
 *
 *  The client is the one that can answer it, because it holds the version it loaded. So
 *  this re-reads the agent and diffs the *current* config against that baseline: the keys
 *  that moved underneath, which is what "what did they do" means. **The server's sentence
 *  is not rendered at all** — this panel is the 409's only message, which is the branch
 *  above and its argument: one event producing two messages puts the less useful one
 *  first. (That clause read *"stays on screen above this"*, describing the arrangement
 *  this component replaced; found by 035l, which copied this panel to a second table.)
 *
 *  There is no "save anyway" and there will not be one — the whole reason the server
 *  refused is that saving anyway is how a scope narrowing gets reverted by somebody who
 *  never saw it. */
function Conflict({
  name,
  original,
  failure,
  onReload,
}: {
  name: string;
  original: Record<string, unknown>;
  failure: ApiError;
  onReload: () => void;
}) {
  const yours = Array.isArray(failure.extra.changed)
    ? (failure.extra.changed as string[])
    : [];
  const theirs = useResource(
    () =>
      api.getAgent(name).then((current) =>
        [...new Set([...Object.keys(current.config), ...Object.keys(original)])]
          .filter(
            (key) =>
              JSON.stringify(current.config[key]) !== JSON.stringify(original[key]),
          )
          .sort(),
      ),
    [name],
  );

  return (
    <Notice tone="warn" title="Somebody else saved while this was open">
      {theirs.data ? (
        theirs.data.length > 0 ? (
          <p className="sentence">
            Since you opened this, they changed <strong>{theirs.data.join(", ")}</strong>.
          </p>
        ) : (
          <p className="sentence">
            The version moved, and nothing in the configuration is different — somebody
            saved without changing anything.
          </p>
        )
      ) : (
        <p className="muted">Finding out what they changed…</p>
      )}

      {yours.length > 0 ? (
        <p className="sentence">
          You were about to write <strong>{yours.join(", ")}</strong>. Reload to take their
          version, then make your change again.
        </p>
      ) : (
        <p className="sentence">
          Nothing you were about to save differs from what is stored now, so reloading
          loses nothing.
        </p>
      )}
      <Button onClick={onReload}>Reload this agent</Button>
    </Notice>
  );
}
