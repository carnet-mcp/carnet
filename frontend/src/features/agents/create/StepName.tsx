/** Step 1 — what it is called, and what it is for.
 *
 * The name is four things at once: the identity the broker enforces against, the key the
 * row is stored under, the path segment in `GET /agents/{name}`, and the string written
 * into every audit record this agent ever produces. Asking a non-technical person for
 * something URL-safe is asking them to think about URLs.
 *
 * So they type a name and the slug is **shown**, not applied silently. That asymmetry is
 * the decision: the server refuses a bad name rather than transforming one, because a
 * name quietly rewritten on the way into the database differs from the one somebody
 * approved — in the string that will appear in every record of what the agent did. The
 * transformation happens here, in front of them, where they can disagree with it.
 */

import { Card, Field, Notice } from "../../../components/ui";
import { type Draft, nameIsUsable, slugify } from "../../../lib/draft";
import type { StepProps } from "./CreateAgentPage";

export function nameBlocker(draft: Draft): string {
  if (!draft.typed.trim()) return "Give it a name first.";
  if (!draft.name) return "That name has no letters or digits in it — try another.";
  if (!nameIsUsable(draft.name)) return "That identifier cannot be used. Edit it below.";
  return "";
}

export default function StepName({ draft, set, locked = false }: StepProps) {
  if (locked) {
    // Editing. The name half of this step is not a field — see `StepProps.locked` — so
    // what is left is the half that *is* editable, rendered by the same component so the
    // two screens cannot develop two wordings for "what is it for".
    //
    // **This paragraph used to be wrong on two of its three clauses, and 035i fixed it.**
    // It said a rename would change *"every grant that names it and every record of what
    // it has done"*. Neither is true and neither has been:
    //
    //   - Grants are keyed by `agent_id` since migration 035, so they survive whole. The
    //     route says *"everything survives it"* and `--rename-agent` prints *"Its grants,
    //     schedules, triggers and history came with it."* This screen said the opposite,
    //     about the same operation, one door away.
    //   - `audit.agent`, `admin_audit.target_id` and the denial log deliberately **keep
    //     the name that was current when they were written** — an append-only log that
    //     rewrote itself would be worse than one that is merely quiet. So a rename
    //     changes no record at all; it is the *reason* the register carries a row about
    //     reconstructing a log across one.
    //
    // It also said *"It cannot be changed"*, which stopped being true at step 025 and is
    // now untrue in the browser too. What is left is the clause that was always right —
    // this is a different operation — plus where to find it.
    return (
      <>
        <Card title="What is it called?">
          <Field
            label="Identifier"
            hint="Its address, and the name in every record of what it does."
          >
            <input type="text" className="mono" value={draft.name} disabled readOnly />
          </Field>
          <p className="muted">
            Renaming an agent changes its URL and nothing else — its grants and history
            come with it, and every record of what it has already
            done keeps the name it had at the time. It is a different operation and this is
            not it: it is on the agent's own page, and it belongs to whoever owns the agent.
          </p>
        </Card>
      </>
    );
  }

  return <FullStep draft={draft} set={set} />;
}

function FullStep({ draft, set }: Pick<StepProps, "draft" | "set">) {
  /** Whether the identifier is still following the typed name.
   *
   *  Derived rather than stored as a flag: once somebody edits the slug it stops matching
   *  what `slugify` would produce, and that difference *is* the fact "they took it over".
   *  A boolean beside it would be a second copy of the same information, free to disagree
   *  with the field it describes. */
  const following = draft.name === slugify(draft.typed);

  return (
    <>
      <Card title="What is it called?">
        <Field
          label="Name"
          hint="What you would call it. This is what people see in their list."
        >
          <input
            type="text"
            value={draft.typed}
            placeholder="Triage bot"
            autoFocus
            onChange={(event) => {
              const typed = event.target.value;
              set(following ? { typed, name: slugify(typed) } : { typed });
            }}
          />
        </Field>

        <Field
          label="Identifier"
          hint="Its web address, and the name in every record of what it does. Made from the name above — change it if you would rather."
        >
          <input
            type="text"
            className="mono"
            value={draft.name}
            onChange={(event) => set({ name: event.target.value })}
          />
        </Field>

        {draft.name && !nameIsUsable(draft.name) && (
          // Said here rather than only at submit. The rule is enforced by the database
          // (migration 019) and refused with a sentence by the server; this exists so
          // nobody reaches step 5 to find out. Where the two disagree the server wins,
          // and its message is what gets rendered.
          <Notice tone="warn" title="That identifier will not be accepted">
            <p className="sentence">
              Use lowercase letters, digits and single hyphens between them — like{" "}
              <span className="mono">triage-bot</span>. It has to work in a URL and read
              unambiguously in an audit log, so two names that look alike in a list cannot
              be different agents.
            </p>
          </Notice>
        )}

        {draft.typed.trim() && !draft.name && (
          <Notice tone="warn" title="We need something to call it in a URL">
            <p className="sentence">
              There is nothing in that name we can use as an address. Type an identifier
              above using letters and digits — the name you chose stays as it is.
            </p>
          </Notice>
        )}
      </Card>
    </>
  );
}
