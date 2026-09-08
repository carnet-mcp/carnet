/** Step 4 — review, then create.
 *
 * ## The permission model is rendered by the detail page's own component
 *
 * `Reach` is imported, not reimplemented. Decision 8, and it is about identity rather
 * than reuse: a review step that described the draft in its own words would be a second
 * description of a permission model, and the gap between *what the form said* and *what
 * the agent does* is precisely where this product loses somebody's trust. If the two ever
 * disagreed the bug should be impossible rather than caught — so what somebody approves
 * here is literally the screen they will see afterwards.
 *
 * ## The dry run, and why it is a route rather than a client-side check
 *
 * `POST /agents/validate` runs the **same function** the create will run,
 * `agents.validate_draft`, and writes nothing. Two things come of that.
 *
 * The UX one is secondary and real: a wizard whose last step fails with a server error is
 * a wizard nobody trusts, and this is where a person is deciding whether to trust it.
 *
 * The primary one is that 010b's finding — *a form that derives its scope from the
 * catalogue cannot violate `_validate_scope_matches_tools` in either direction* — is a
 * claim of the form "correct by construction", and such a claim is worth exactly the test
 * behind it. This route is what lets that test exist without creating rows and cleaning
 * them up. See `draft.test.ts`.
 *
 * It cannot tell you whether the name is free. That is a 409, it is a race whatever asks
 * it, and only the create can answer it — so the one failure this screen cannot pre-empt
 * is the one it hands back to step 1.
 */

import { useEffect, useState } from "react";

import Failure from "../../../components/Failure";
import { Card, Notice, Spinner } from "../../../components/ui";
import { api } from "../../../lib/api";
import { reachable, toConfig } from "../../../lib/draft";
import Reach from "../Reach";
import type { StepProps } from "./CreateAgentPage";

export default function StepReview({ draft, catalogue, catalogueFailed }: StepProps) {
  const [verdict, setVerdict] = useState<"checking" | "ok" | Error>("checking");

  // Re-run whenever anything that reaches the server changes. Stringified rather than
  // depended on field by field, because the thing being checked is the *config* — and a
  // dependency list enumerating the draft's fields would be a fourth place its shape is
  // written down.
  const config = JSON.stringify(toConfig(draft, catalogue));

  useEffect(() => {
    let live = true;
    setVerdict("checking");
    api
      .validateDraft(JSON.parse(config) as unknown)
      .then(() => live && setVerdict("ok"))
      .catch((cause: unknown) => {
        if (live) setVerdict(cause instanceof Error ? cause : new Error(String(cause)));
      });
    return () => {
      live = false;
    };
  }, [config]);

  return (
    <>
      <Card title={draft.typed || draft.name}>
        <table>
          <tbody>
            <tr>
              <td>Its address</td>
              <td className="mono">/agents/{draft.name}</td>
            </tr>
            <tr>
              <td>Owner</td>
              {/* Stated because it is a consequence rather than a field: nobody chose
                  this, and it is the difference between an agent that works and an agent
                  nobody can run. */}
              <td>You, from the moment it exists. Nobody else can see it.</td>
            </tr>
          </tbody>
        </table>
      </Card>

      {/* The detail page's component, over the draft. Nothing is faked to make it
          render — see `Reachable`, which is deliberately narrower than `AgentDetail`. */}
      <Reach
        agent={reachable(draft, catalogue)}
        catalogue={catalogue}
        failed={catalogueFailed}
        title="What it will be able to reach"
        hint="exactly what its own page will show once it exists"
      />

      {/* **What actually bounds this agent, named where somebody is deciding — step 081.**
          The card this replaces rendered the draft's `limits` under the heading *Ceilings
          — per run*, and on a door-only deployment there are no runs and nothing reads
          that block: `Budget.for_agent` was reached only from `RunContext.start`, which
          had no caller, while the door hands the broker a `TokenBudget` whose `reserve`
          ignores the tool entirely. So the per-agent dials bounded nothing and the
          `max_writes: 0` line under them — *"every write is refused before it reaches a
          system"* — was false. **Step 084 deleted the machinery**, so there is no longer
          even a path to trace; the door's ceiling below is the whole of it.

          There is a real ceiling and it is a different shape: per token, per UTC day, set
          by the operator. Saying so here rather than nowhere is the difference between a
          removed control and a removed answer. */}
      <Card title="What bounds it" hint="not set here, and not per agent">
        <p className="sentence">
          What limits this agent is the <strong>token</strong> it is called with: how many
          calls it may make in a day, and how much it may spend. That ceiling belongs to
          the token rather than to the agent, because one token is one caller and one
          agent may be reached by several.
        </p>
        <p className="muted">
          The operator sets it for the whole deployment, and each token&apos;s own page
          shows what it has spent against it today.
        </p>
      </Card>

      {verdict === "checking" && <Spinner label="Checking this with the server" />}

      {verdict === "ok" && (
        <Notice tone="info" title="The server accepts this">
          <p className="sentence">
            Checked against the same rules the create will use, without writing anything.
            The one thing left that could refuse it is the name already being taken.
          </p>
        </Notice>
      )}

      {verdict instanceof Error && (
        <Notice tone="bad" title="The server will not accept this">
          {/* The server's own sentence, rendered rather than paraphrased. These messages
              were written to be read by a person at 3am, and that person is now the one
              filling in the form — which is the whole reason they read the way they do. */}
          <Failure error={verdict} />
          <p className="muted">
            Go back and change it. Nothing has been created.
          </p>
        </Notice>
      )}
    </>
  );
}
