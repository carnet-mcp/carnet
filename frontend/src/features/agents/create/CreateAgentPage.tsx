/** The form. Four steps over one draft, and the risk it retires is a single sentence:
 *
 *   > Can somebody who has never seen a scope pattern produce a correct one?
 *
 * ## The shape of the answer
 *
 * They are never asked for one. `lib/draft.ts` holds tool names and identifiers; the
 * scope is *computed* from the catalogue at the moment it is submitted. The two things a
 * scope needs that a person cannot be expected to supply — the resource type and the
 * effect — come from the same catalogue `agents.validate` reads, so
 * `_validate_scope_matches_tools` cannot fail in either direction. See the docstring
 * there; it is the argument, and this file is only its interface.
 *
 * ## Why the steps are separate files
 *
 * Not size. Each step asks a different *kind* of question, and the wording of each is
 * the deliverable rather than the layout:
 *
 *     1  who is this           a name, and what it is for
 *     2  what may it DO        tick tools — writes stated first, as everywhere else
 *     3  what may it REACH     identifiers, for rows the ticked tools imply
 *     4  review               rendered by the detail page's own component
 *
 * Step 4 imports `Reach` rather than describing the draft itself. That is decision 8,
 * and it is about identity rather than reuse: a review step with its own summary is a
 * second description of a permission model, and the gap between what the form said and
 * what the agent does is exactly where this product would lose somebody's trust.
 *
 * ## What is deliberately absent
 *
 * **Sharing.** 010 and 010b both put it here, and 10c takes it out — a control that can
 * grant access and cannot revoke it is worse than no control, and every revoke route is
 * 10d. An agent created and not shared is private to its owner, which is a coherent
 * state and the one every agent is in the instant after it is created regardless.
 */

import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import Failure from "../../../components/Failure";
import { Button, Icon, PageHead, Spinner } from "../../../components/ui";
import { api, ApiError } from "../../../lib/api";
import {
  type Draft,
  clearDraft,
  loadDraft,
  saveDraft,
  toConfig,
} from "../../../lib/draft";
import type { ToolGroup } from "../../../lib/types";
import { useResource } from "../../../lib/useResource";
import StepName, { nameBlocker } from "./StepName";
import StepReach, { reachBlocker } from "./StepReach";
import StepReview from "./StepReview";
import StepTools, { toolsBlocker } from "./StepTools";

export interface StepProps {
  draft: Draft;
  set: (patch: Partial<Draft>) => void;
  catalogue: ToolGroup[] | null;
  catalogueFailed: unknown;
  /** True on the edit screen, where the name is **not** a field.
   *
   *  The name is the URL, the storage key, the identity the broker enforces against and
   *  the string in every record of what the agent did; `PATCH` refuses a body carrying a
   *  different one with a 400. A disabled input saying why is a better answer than an
   *  editable one that fails at save — and this is a prop rather than a second component
   *  because the *other* half of that step, "what is it for", is identical in both
   *  places and two copies of it would be two wordings. */
  locked?: boolean;
}

/** A step, and — the part worth having — **why it will not let you continue**.
 *
 *  A greyed-out Next with no explanation is the most common way a form wastes somebody's
 *  time, and it is worse here than usual: the blockers are all about permissions, so
 *  "you cannot continue" without a reason reads as the system refusing rather than as a
 *  field being empty. Every blocker returns a sentence, and the sentence is shown. */
/** **Nouns in the strip, questions on the cards — step 092.** These used to read
 *  *Name · What it may do · What it may reach · Review*, two of which are sentences. A
 *  step strip is a map, glanced at; the heading inside the step is where the question
 *  belongs, and both cards still ask theirs in exactly the words they always did. */
const STEPS: {
  title: string;
  blocker: (draft: Draft, catalogue: ToolGroup[] | null) => string;
}[] = [
  { title: "Name", blocker: nameBlocker },
  { title: "Tools", blocker: toolsBlocker },
  { title: "Access", blocker: reachBlocker },
  // **Four since 081, and the fourth used to be *Ceilings*.** It asked for a `limits`
  // block, a `max_tokens` and a `private_runs` flag, none of which anything in this tree
  // reads — so every one of its controls stored a number under a sentence promising an
  // enforcement that does not happen here. A step that exists only to say *nothing to set*
  // is a click that teaches nothing, so what bounds an agent is said on Review instead,
  // where somebody is deciding.
  { title: "Review", blocker: () => "" },
];

export default function CreateAgentPage() {
  const navigate = useNavigate();
  const [draft, setDraft] = useState<Draft>(loadDraft);
  const [step, setStep] = useState(0);
  const [creating, setCreating] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  // The same request the detail page makes, and it is the form's whole vocabulary. Not
  // cached — decision 6 of 010 — and cheap for the same reason it is cheap there.
  const catalogue = useResource(() => api.listTools(), []);

  // Every keystroke, deliberately. A draft that survives *most* reloads is a draft
  // somebody stops trusting, and this is a few hundred bytes of JSON.
  useEffect(() => saveDraft(draft), [draft]);

  function set(patch: Partial<Draft>) {
    setDraft((current) => ({ ...current, ...patch }));
  }

  const props: StepProps = {
    draft,
    set,
    catalogue: catalogue.data,
    catalogueFailed: catalogue.error,
  };
  const blocker = STEPS[step].blocker(draft, catalogue.data);
  const last = step === STEPS.length - 1;

  function create() {
    setCreating(true);
    setFailure(null);
    api
      .createAgent(toConfig(draft, catalogue.data))
      .then((created) => {
        // Cleared only on success. A create refused for any reason at all leaves the
        // draft exactly where it was, because the alternative is somebody losing ten
        // minutes of work to a name collision.
        clearDraft();
        navigate(`/agents/${created.name}`);
      })
      .catch((cause: unknown) => {
        setFailure(cause);
        setCreating(false);
        // A taken name is a step-1 problem, so put them on step 1 rather than leaving
        // them on a review screen with a message about a field they cannot see.
        if (cause instanceof ApiError && cause.status === 409) setStep(0);
      });
  }

  return (
    <>
      <Link className="back" to="/agents">
        ← Create MCP
      </Link>
      <PageHead
        title="New MCP"
        lede="Pick the tools it may use and how far each one reaches. You own it from the moment it exists, and nobody else can see it until you share it."
      />

      <ol className="steps">
        {STEPS.map((s, i) => (
          <li key={s.title} className={i === step ? "on" : i < step ? "done" : ""}>
            <button
              type="button"
              // Backwards only. Skipping ahead past an unanswered step is how somebody
              // arrives at Review with a scope row they never filled in, and the review
              // step's job is to be the last honest look rather than the first.
              disabled={i > step}
              onClick={() => setStep(i)}
            >
              {/* A step you have been through is ticked rather than numbered. The number
                  is how far along you are; once it is behind you the useful fact is that
                  it is answered — and the tick is not the only thing saying so, since the
                  row is also lit and the step is clickable. */}
              <span className="n">
                {i < step ? <Icon name="check" size={12} /> : i + 1}
              </span>
              {s.title}
            </button>
          </li>
        ))}
      </ol>

      {catalogue.loading && <Spinner label="Loading what you can grant" />}

      {step === 0 && <StepName {...props} />}
      {step === 1 && <StepTools {...props} />}
      {step === 2 && <StepReach {...props} />}
      {step === 3 && <StepReview {...props} />}

      {failure ? <Failure error={failure} /> : null}

      <div className="spread wizard-nav">
        <Button disabled={step === 0 || creating} onClick={() => setStep(step - 1)}>
          Back
        </Button>
        {last ? (
          <Button kind="primary" busy={creating} onClick={create}>
            {creating ? "Creating" : "Create this agent"}
          </Button>
        ) : (
          <Button
            kind="primary"
            disabled={blocker !== ""}
            onClick={() => setStep(step + 1)}
          >
            Continue
          </Button>
        )}
        {blocker && !last ? <span className="muted">{blocker}</span> : null}
      </div>
    </>
  );
}
