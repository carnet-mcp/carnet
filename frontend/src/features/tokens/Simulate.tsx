/** Would this call be admitted, and which rule decided. Step 069, the simulate half.
 *
 * ## What it is, and the one thing it must never become
 *
 * A read. It asks the server the question the door answers on every call — over the
 * door's own `_granted_agents`, `_candidates` and `_adjudicate` — with the tool never
 * executed, no session opened, no credential resolved and no row written anywhere.
 * `POST` carries the arguments and changes nothing; 041's rule that nothing on an admin
 * screen changes anything holds here by construction rather than by care.
 *
 * ## Why the form asks for these fields and no others
 *
 * `permissions.check` reads exactly two things off a call: the arguments a tool declares
 * as *resources*, and whether any argument is credential-shaped. Everything else in a
 * tool's input is invisible to it. So a form that asked for the whole input schema would
 * be collecting values that decide nothing and implying they decide something — and it
 * could not be built anyway, because the server answers this from the vetting and has no
 * input schema to render.
 *
 * Hence: a tool name, and free-form `name = value` pairs. The reader supplies the
 * resource arguments; anything else they type is ignored by the check, exactly as it is
 * on a real call.
 *
 * ## `considered` is the answer
 *
 * The verdict is what somebody could have got by making the call. What they could not get
 * — and what the union rule makes genuinely hard — is *all three of my agents said no,
 * and here is each one's reason*. Read the other way when one allows, the same list is
 * what turns "it works, somehow" into "it works because `triage` grants `acme/*`".
 *
 * So the per-agent list is not a detail pane behind a disclosure. It is the body.
 */

import { useState } from "react";

import Failure from "../../components/Failure";
import { Badge, Button, Card, Field, FieldGroup } from "../../components/ui";
import { api } from "../../lib/api";
import type { Rule, Simulation } from "../../lib/types";

/** What each `not_checked` key means, in the reader's terms.
 *
 *  A map rather than sentences from the server, on 010b's rule: text that explains a
 *  permission belongs where somebody can review it as code. The server sends stable keys
 *  and an unknown one renders as itself rather than vanishing — a new thing this stops
 *  short of must be visible before it is explained, never after. */
const NOT_CHECKED: Record<string, string> = {
  authentication: "whether the token is active. See the token card above.",
  binding: "whether the tool's connector answers. Nothing was called.",
  "acting-for":
    "whether an on-behalf-of claim could be verified. That check comes first and can deny on its own.",
  credential: "whether an account is connected for it. No credential was read.",
  budget: "the daily rate limit. See usage above.",
};

/** What each `rule` name means, in a few words.
 *
 *  Same shape and same rule as `NOT_CHECKED`: the server sends a stable name, this maps
 *  it to a label somebody can review as code, and a name it does not know renders as
 *  itself. Typed against `Rule` so a branch the server adds fails the typecheck here
 *  the moment the list in `types.ts` learns of it — and until then it still renders,
 *  because a refusal whose rule vanished is a refusal with no reason given. */
export const RULES: Record<Rule, string> = {
  credential_smuggled: "credential in the arguments",
  not_described: "no such tool",
  not_granted: "tool not granted",
  resource_missing: "resource argument missing",
  composed_separator: "separator in a composed resource",
  no_grant_for_effect: "no grant at this effect",
  outside_scope: "outside the scope",
  unsupported_reference: "unsupported caller reference",
  headless_principal: "headless caller",
};

function ruleLabel(rule: string): string {
  return (RULES as Record<string, string>)[rule] ?? rule;
}

export default function Simulate({ tokenId }: { tokenId: string }) {
  const [tool, setTool] = useState("");
  const [pairs, setPairs] = useState<{ name: string; value: string }[]>([
    { name: "", value: "" },
  ]);
  const [answer, setAnswer] = useState<Simulation | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function ask(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFailure(null);
    // Cleared before the request, not after it. A stale verdict sitting under a spinner
    // is a wrong answer to the question being asked, and it is the answer somebody
    // screenshots.
    setAnswer(null);
    try {
      const args: Record<string, string> = {};
      for (const pair of pairs) {
        // A row with no name is a row nobody filled in — dropped, because an argument
        // called `""` is not what an empty box means. The **value** is sent exactly as
        // typed, including its spaces: a resource identifier may legitimately contain
        // them, and the door does not trim one either.
        if (pair.name.trim()) args[pair.name.trim()] = pair.value;
      }
      // **The tool name is sent untrimmed, and the edge pass is why.** Trimming it made
      // this browser more forgiving than the door: ` post_message` is refused by
      // `tools/call` with *a tool name must match …*, and answering about `post_message`
      // instead would be this screen quietly correcting the question it was asked. On a
      // surface whose whole claim is *the same verdict the door would give*, one
      // character class of leniency is still a different verdict — and the refusal is a
      // better teacher than the correction, because it names the rule.
      setAnswer(await api.simulateCall(tokenId, tool, args));
    } catch (cause: unknown) {
      setFailure(cause);
    } finally {
      setBusy(false);
    }
  }

  function setPair(index: number, part: "name" | "value", value: string) {
    setPairs((current) => {
      const next = current.map((pair, i) =>
        i === index ? { ...pair, [part]: value } : pair,
      );
      // One spare row, always — so adding a second argument needs no button and the form
      // never presents an "Add" that does nothing but make a row appear.
      const last = next[next.length - 1];
      if (last.name.trim() || last.value.trim()) next.push({ name: "", value: "" });
      return next;
    });
  }

  return (
    <Card title="Check a call">
      <p className="sentence">
        See whether a call would be allowed and which rule decides it. Nothing is called.
      </p>
      <p className="muted sentence">
        Only the arguments the tool declares as resources are checked. Nothing is
        executed and no record is written.
      </p>

      <form onSubmit={ask}>
        <Field label="Tool" hint="the tool name as granted">
          <input
            className="input mono"
            value={tool}
            onChange={(event) => setTool(event.target.value)}
            placeholder="github_mcp_list_issues"
            required
          />
        </Field>

        <FieldGroup label="Arguments" hint="the resource this call would use">
          {pairs.map((pair, index) => (
            <div key={index} className="pair">
              <input
                className="input mono"
                aria-label={`Argument ${index + 1} name`}
                value={pair.name}
                onChange={(event) => setPair(index, "name", event.target.value)}
                placeholder="owner"
              />
              <input
                className="input mono"
                aria-label={`Argument ${index + 1} value`}
                value={pair.value}
                onChange={(event) => setPair(index, "value", event.target.value)}
                placeholder="acme"
              />
            </div>
          ))}
        </FieldGroup>

        <div className="spread">
          <Button kind="primary" type="submit" disabled={busy || !tool.trim()}>
            {busy ? "Checking…" : "Check"}
          </Button>
        </div>
      </form>

      {failure != null && <Failure error={failure} />}
      {answer && <Verdict answer={answer} />}
    </Card>
  );
}

function Verdict({ answer }: { answer: Simulation }) {
  const allowed = answer.verdict === "allowed";

  return (
    <div className="verdict">
      <div className="row-top">
        <Badge tone={allowed ? "good" : "bad"}>
          {allowed ? "Would be allowed" : "Would be denied"}
        </Badge>
        {/* The rule, as a label beside the badge rather than inside the sentence. It is
            the one thing on this page a reader can grep the server for, so the raw name
            rides along as the title. `""` is an allow, and an allow names no rule. */}
        {answer.rule && (
          <span className="tag" title={`rule: ${answer.rule}`}>
            {ruleLabel(answer.rule)}
          </span>
        )}
        <span className="mono">{answer.tool}</span>
      </div>

      {answer.attributed_to && (
        <p className="sentence">
          {/* Two sentences, because "attributed to" beside a refusal reads as *this is the
              one that let it through*. What it names on a refusal is the agent the denial
              would be **recorded** under, which is a different and less reassuring fact. */}
          {allowed
            ? `Attributed to ${answer.attributed_to}, the first granted agent whose scope allows these arguments. The audit log would name it.`
            : `Recorded under ${answer.attributed_to}. No granted agent allows this call. The denial is logged against the first of them.`}
        </p>
      )}

      {/* **Only when `considered` is empty**, which is the tool-nobody-grants case.
          Otherwise this line is the attributed candidate's reason and it is already in
          the list below, word for word — printing it twice was the first thing looking
          at the rendered page showed, and it made the answer read as two findings. */}
      {answer.reason && answer.considered.length === 0 && (
        <p className="sentence mono tiny">{answer.reason}</p>
      )}

      {answer.considered.length > 0 && (
        <div className="rows">
          {answer.considered.map((candidate) => (
            <div key={candidate.agent} className="row">
              <div className="row-top">
                <span className="row-name mono">{candidate.agent}</span>
                {candidate.rule && (
                  <span className="tag" title={`rule: ${candidate.rule}`}>
                    {ruleLabel(candidate.rule)}
                  </span>
                )}
                <Badge tone={candidate.allowed ? "good" : "bad"}>
                  {candidate.allowed ? "allows" : "denies"}
                </Badge>
              </div>
              {candidate.reason && <p className="row-sub">{candidate.reason}</p>}
            </div>
          ))}
        </div>
      )}

      {answer.considered.length === 0 && !allowed && (
        <p className="muted sentence">
          {/* Deliberately says *no agent was considered* rather than *no agent carries
              that tool*. Both refusals with an empty list arrive here — nothing granted
              answers to the name, and a name that could not be a tool name at all — and
              the second one's cause is the sentence above, not this one. Asserting a
              cause that fits only one of two cases is how a true sentence becomes a
              misleading one. The disclaimer is the part that matters and it fits both. */}
          No agent was checked. This does not say whether the tool exists.
        </p>
      )}

      {/* Never collapsed and never dropped. A verdict that implies more than it checked
          is worse than no verdict, and the three things below are exactly what somebody
          would otherwise assume it covered. */}
      <div className="stack-sm">
        <p className="muted tiny">Not checked:</p>
        <ul className="muted tiny">
          {answer.not_checked.map((key) => (
            <li key={key}>{NOT_CHECKED[key] ?? key}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
