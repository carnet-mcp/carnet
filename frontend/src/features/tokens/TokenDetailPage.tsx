import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import Failure from "../../components/Failure";
import { Button, Card, Notice, PageHead, Spinner } from "../../components/ui";
import { api } from "../../lib/api";
import { money, on, tokens } from "../../lib/format";
import type { OwnedToken, SpentWindow, TokenReach, TokenSpend } from "../../lib/types";
import { useResource } from "../../lib/useResource";
import Reach from "../agents/Reach";
import EffectiveReach from "./EffectiveReach";
import Simulate from "./Simulate";
import { Kind, Moment, State } from "./TokenMarks";

/** One token, and the question nobody could ask before: **what would this actually see?**
 *
 * ## The gap this closes
 *
 * A token's reach has always been computable — in tool mode it is the union of the tools
 * of the agents it is granted, each tool keeping its own agent's scope, resolved through
 * the owner's grants and groups for a personal one. Every row that answer is made of is
 * already in the database, and until 035d the only way to read it was to **present the
 * token to `/mcp` and look at `tools/list`**.
 *
 * That is the worst possible instrument for the job. It needs the secret, which the
 * person asking usually does not have; it needs an MCP client; and the moment somebody
 * asks *what can this credential reach* is the moment they suspect it reaches too much —
 * which is exactly when they should not be using it.
 *
 * ## Why this is a list of sections and not one table
 *
 * The union rule is *a call is allowed if **any** granted agent carrying the tool would
 * allow it, and that agent is the one the call is attributed to*. The names are the easy
 * half — one union, one list. The scope is not: `triage` may read `acme/*` while
 * `security-triage` reads `acme/secrets-*`, both granting `search_issues`, and which one
 * applies is decided **per call**, against the arguments of that call.
 *
 * So a single flat *what it may reach* would have to either union those scopes — which
 * invents a permission nobody wrote down — or pick one, which shows a narrower reach than
 * the token has. One section per granted agent is the only shape that is true, and it is
 * `Reach.tsx` unmodified, once per agent, with the agent's name in its `title`.
 *
 * ## What is granted, and whether it works, are two facts
 *
 * The route ignores whether the credential is alive: a revoked, expired or
 * owner-disabled token still reports what it was granted. That is not an oversight — it
 * is the offboarding question, asked most often about a credential somebody has just
 * killed, and a page answering *"refused: this token was revoked"* would read as *"it
 * reaches nothing"* to the one person who needs the opposite.
 *
 * So both facts are on screen and neither pretends to be the other: the state badge comes
 * from the listing row's four stamps, the reach comes from the grant, and when they
 * disagree the page says so in a sentence rather than leaving somebody to infer it.
 *
 * ## The page answers two questions, and the second one is 035e
 *
 * *What can this credential do* is the reach below. *Why did it stop working* is the
 * other one somebody arrives with, and it had three possible answers of which the page
 * showed only two: revoked and expired are stamps on the listing row, and **exhausted
 * its daily ceiling** was readable nowhere in the product. `mcp_budget` has been written
 * on every admitted door call since migration 040 and read by nothing outside the test
 * suite — the refusal names the ceiling, and only the caller holding the token ever sees
 * that sentence.
 *
 * The budget sits **between** identity and reach rather than under it. It is two lines
 * against N agent cards, and burying a one-line answer under the long one is the wrong
 * way round for the reader who is in a hurry; it also groups with the state badge, since
 * both are *does this work today* while the reach is deliberately liveness-blind.
 *
 * ## Three requests, none of them merged
 *
 * `myTokens` is your listing and is what this page's identity comes from — which is what
 * keeps the reach response from becoming a second `OwnedToken`. `tokenReach` is this
 * token's grants. `tokenBudget` is what it has spent. `listTools` is a property of the
 * **tenant** that every agent screen already fetches on its own, for `AgentDetailPage`'s
 * stated reason: folding it into a per-object route would make one route answer two
 * questions and re-send the whole vetting record every time somebody opens an object.
 *
 * Four now, and each keeps its own `Spinner` and its own `Failure`: a 503 on the budget
 * must not take the reach off the screen, and the reverse. They are separate facts from
 * separate tables and a reader wants whichever of them arrived.
 *
 * One consequence, stated: the route also answers for an **administrator** reading
 * somebody else's token, and this page never exercises that — the identity comes from
 * your own listing, so an admin typing another person's id is told they own no such token
 * before the reach route is ever called. A smaller surface than the rule permits.
 *
 * ## Nothing here grants anything — but revocation lives here now
 *
 * Plan 035's category 2 said no mint, no revoke, no form. Step 044 reopened exactly one
 * verb, and it is the one that *removes* authority: the owner (or an administrator) can
 * revoke this token, behind a confirmation that says what stops. A mint surface without
 * a revoke surface means a leaked secret waits for an operator with a shell, and
 * revocation must never be the hard direction. Minting is the listing page's; granting
 * remains the share sheet's; this page still writes nothing else.
 */
export default function TokenDetailPage() {
  const { tokenId = "" } = useParams();
  const listing = useResource(() => api.myTokens(), []);
  const reach = useResource(() => api.tokenReach(tokenId), [tokenId]);
  const budget = useResource(() => api.tokenBudget(tokenId), [tokenId]);
  const catalogue = useResource(() => api.listTools(), []);

  const token = listing.data?.find((row) => row.id === tokenId) ?? null;

  return (
    <>
      <Link className="back" to="/tokens">
        ← Access tokens
      </Link>
      <PageHead title={token ? token.name : tokenId} />

      {listing.loading && <Spinner label="Loading tokens…" />}
      {/* Before the not-yours sentence and never beside it. **A failed listing is not an
          absent token** — the same distinction `TokensPage` asserts, where a 503 would
          otherwise say *you have no tokens* to somebody who has four. Here it would say
          *no token of yours has that id* about one they own. */}
      {listing.error && <Failure error={listing.error} />}

      {listing.data && !token && (
        <Notice tone="warn" title="Token not found">
          <p className="sentence">
            This page shows only your own tokens. A colleague&rsquo;s token is visible to
            them and to administrators through the API.
          </p>
        </Notice>
      )}

      {token && <Identity token={token} reach={reach.data} />}

      {/* Under the identity card, whose `State` row is what it changes. Absent — not
          disabled — once the token is dead: revoking a revoked token is a true no-op
          the server would even answer 200 to, and a control that does nothing is
          clutter on the page people read during incidents. */}
      {token && token.revoked_at === null && (
        <RevokeBox token={token} onRevoked={listing.reload} />
      )}

      {budget.loading && <Spinner label="Loading usage…" />}
      {budget.error && <Failure error={budget.error} />}
      {budget.data && <Spent spend={budget.data} />}

      {reach.loading && <Spinner label="Loading access…" />}
      {reach.error && <Failure error={reach.error} />}

      {reach.data && (
        <Reached
          reach={reach.data}
          catalogue={catalogue.data}
          failed={catalogue.error}
        />
      )}

      {/* Last, and only when there is something to ask about. The form is the narrowest
          thing on the page — one call, one answer — so it reads as a follow-up to the
          listings above rather than as the page's subject.

          After the budget card and after the log on purpose: the verdict says it did not
          check the budget, and it answers about a call nobody has made — so the two
          things it does not know should already have been read by the time it is asked. */}
      {reach.data && reach.data.tools.length > 0 && <Simulate tokenId={tokenId} />}
    </>
  );
}

/** The one write on this page, behind a confirmation that says what stops. Step 044.
 *
 *  Two clicks on purpose — the second inside a `Notice` naming the token and the
 *  consequence — because this is immediate and permanent. The row survives (`--revoke-token`'s
 *  rule: old records still need to resolve the id), which is why the page after a revoke
 *  is this same page with the state changed rather than a redirect away from a thing
 *  that still exists. */
function RevokeBox({
  token,
  onRevoked,
}: {
  token: OwnedToken;
  onRevoked: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);

  async function revoke() {
    setBusy(true);
    setFailure(null);
    try {
      await api.revokeToken(token.id);
      onRevoked();
    } catch (cause: unknown) {
      setFailure(cause);
      setBusy(false);
    }
  }

  if (!confirming) {
    return (
      <div className="spread">
        <Button onClick={() => setConfirming(true)}>Revoke token</Button>
      </div>
    );
  }

  return (
    <Notice tone="warn" title={`Revoke "${token.name}"?`}>
      <p className="sentence">
        Immediate and permanent. Every request it makes from now on is denied. The token
        stays listed as <code className="mono">{token.id}</code>. Its name can be reused.
      </p>
      {failure ? <Failure error={failure} /> : null}
      <div className="spread">
        <Button onClick={() => setConfirming(false)} disabled={busy}>
          Cancel
        </Button>
        <Button kind="primary" busy={busy} onClick={revoke}>
          {busy ? "Revoking" : "Revoke"}
        </Button>
      </div>
    </Notice>
  );
}

/** What the token *is*, in the listing's own words plus the one the listing cannot say.
 *
 *  `Kind`, `State` and `Moment` are imported rather than rewritten: personal-versus-service
 *  and revoked-versus-expired-versus-live are the sentences somebody reads to decide
 *  whether a credential is a problem, and two descriptions of those that can drift apart
 *  is the failure this whole file's `Reach` import exists to prevent one level up.
 *
 *  `resolved_as` is the addition. On the listing, whose grants answer is always yours and
 *  saying so would be noise. Here it stops being always-yours the moment the token is
 *  personal — the access on this page is then a *person's*, live as theirs changes, and
 *  which person is the entire point of an offboarding review. */
function Identity({ token, reach }: { token: OwnedToken; reach: TokenReach | null }) {
  return (
    <Card title="Token" hint="identity and state">
      <table>
        <tbody>
          <tr>
            <th>ID</th>
            <td className="mono">{token.id}</td>
          </tr>
          <tr>
            <th>Kind</th>
            <td>
              <Kind token={token} />
              {/* Only once the server has said so. Deriving it from `acts_as_owner`
                  here would be a second reader of the fact `personal_owner` owns, which
                  is the drift this product keeps paying for. */}
              {reach && (
                <div className="tiny muted mono token-note">{reach.resolved_as}</div>
              )}
            </td>
          </tr>
          <tr>
            <th>Created</th>
            <td className="mono">{on(token.created_at)}</td>
          </tr>
          <tr>
            <th>Expires</th>
            <td>
              <Moment iso={token.expires_at} absent="never" />
            </td>
          </tr>
          <tr>
            <th>Last used</th>
            <td>
              {/* **Reading this page did not move it**, which is worth knowing on the one
                  screen most likely to be opened during an offboarding review: the route
                  authorizes on ownership and never resolves the token, so the column that
                  answers *is this credential still in use* is not rewritten by the act of
                  asking. */}
              <Moment iso={token.last_used_at} absent="never" />
            </td>
          </tr>
          <tr>
            <th>State</th>
            <td>
              <State token={token} />
            </td>
          </tr>
        </tbody>
      </table>
    </Card>
  );
}

/** What it has spent through the door, and against what. Step 035e.
 *
 *  ## Three renderings, and two of them exist because the obvious one is wrong
 *
 *  **Not metered.** `TokenBudget.reserve` returns ALLOW *before touching storage* when
 *  the ceiling is not positive — an operator's explicit decision to run unmetered, and
 *  *"rows nobody will read are not a record"*. So on such a deployment a token making
 *  thousands of calls an hour has **no rows at all**, and any figure drawn from that —
 *  `0 / 0`, `0 / 1000`, a bar at 0% — would say *this credential has barely been used*
 *  about the opposite. The dial being off is its own answer and gets its own sentence,
 *  with no figure beside it to be read instead.
 *
 *  `warn` rather than `info`, so it carries `role="alert"`: the failure this guards
 *  against is somebody skimming past it and taking the silence for a low number.
 *
 *  **Metered, and nothing in a week.** A sentence, not seven rows of zeros — the rule
 *  `TokensPage` and the empty reach below both follow, because empty-denies is this
 *  product's default and a table of zeros reads as a load that half-failed. Deliberately
 *  **not** reachable from the unmetered branch, where identical zeros mean something
 *  else entirely.
 *
 *  **Metered.** The figure, the ceiling beside it, and the week.
 *
 *  ## Admitted, not attempted, said on the screen and not only here
 *
 *  A call refused by the permission check never reaches the budget, and one refused *by*
 *  the ceiling writes nothing either. So a token being denied five hundred times a day
 *  appears here as whatever it succeeded at — which is the direction that matters, since
 *  the person reading this is usually investigating exactly those refusals. The sentence
 *  names where the other half lives; it does not link, because both of those pages need
 *  the admin role and this one deliberately does not.
 *
 *  ## A plain figure, and no chart
 *
 *  Plan 035's instruction and its reason is right: the question is *is this the reason*,
 *  not *what is the trend*. A bar is also precisely what the unmetered case breaks — it
 *  is the most confident possible rendering of a number nobody is counting. */
function Spent({ spend }: { spend: TokenSpend }) {
  const week = <Week windows={spend.history} today={spend.window} />;

  if (!spend.metered) {
    return (
      <Card title="Usage" hint="through the MCP server">
        <Notice tone="warn" title="Requests are not metered">
          <p className="sentence">
            The daily request limit on this deployment is {spend.ceiling}, which turns
            metering off. Requests are allowed without being counted.{" "}
            <strong>Nothing is recorded here.</strong>
          </p>
          <p className="muted sentence">
            Every allowed request is still in the audit log. An administrator can read
            the request log and the access denied log.
          </p>
        </Notice>
        {/* Rendered anyway, and captioned. Turning the dial off deletes nothing, so a
            deployment that ran metered until Tuesday still has Monday's rows — and a
            zero since is not a quiet day. */}
        {week}
        <p className="muted sentence">
          The figures above were counted while metering was on. A zero may be a day
          nobody was counting.
        </p>
        {/* **Rendered in this branch too, and the omission would have been a real gap.**
            The call dial and the money dials are three independent settings: a deployment
            that stopped counting calls may still be bounding spend, and a page that hid
            the money because the call meter was off would be silent about the ceiling
            that is actually refusing this credential. */}
        <Cost spend={spend} />
      </Card>
    );
  }

  const quiet = spend.history.every((window) => window.calls === 0);

  return (
    <Card title="Usage" hint="through the MCP server">
      {quiet ? (
        // A sentence rather than seven rows of zeros. Safe here and not above: the
        // ceiling is on, so a zero really is a day with no admitted calls.
        <p className="sentence">
          No requests were allowed in the last seven days. The rate limit is{" "}
          {spend.ceiling.toLocaleString()} requests a day.
        </p>
      ) : (
        <>
          <p className="sentence">
            <strong>
              {spend.calls.toLocaleString()} of {spend.ceiling.toLocaleString()}
            </strong>{" "}
            requests allowed today, the UTC day beginning {spend.window}.
          </p>
          {week}
        </>
      )}

      {spend.calls >= spend.ceiling && (
        <Notice tone="warn" title="Rate limit reached">
          <p className="sentence">
            Further requests are denied until midnight UTC. The token is not revoked and
            its access below is unchanged.
          </p>
          <p className="muted sentence">
            The rate limit is set by an operator for the whole deployment.
          </p>
        </Notice>
      )}

      {/* The label's honesty, said where the number is rather than in a tooltip. */}
      <p className="muted sentence">
        <strong>Allowed requests only.</strong> A denied request costs nothing and is not
        counted here. An administrator can see denied requests on the access denied log.
      </p>

      {/* Whose day this is. Said once for the whole card, because the calls above and
          the cost below share the subject — and for a personal token the honest reading
          of "3 of 1000" on this laptop includes the desktop's morning. */}
      {spend.keyed_by === "owner" ? (
        <p className="muted sentence">
          <strong>Shared with your other personal tokens.</strong> Every figure on this
          card is yours for the day, across every personal token you hold. A second
          machine draws on the same allowance, and a limit reached there is reached here.
        </p>
      ) : (
        <p className="muted sentence">
          <strong>This token&apos;s own allowance.</strong> A service token&apos;s day is
          its own; another token, even one with the same owner, has a separate one.
        </p>
      )}

      <Cost spend={spend} />
    </Card>
  );
}

/** What it spent at a model today, against the two money ceilings. Step 045b.
 *
 *  ## A second section under the same card, and a second subject worth naming
 *
 *  Everything above counts *calls* and this counts *money*, and since step 108 both are
 *  keyed on the same subject — `keyed_by`: the owner for a personal token, the token for
 *  a service one. The card says which once, above this section, so the two halves are
 *  read as one thing without either repeating the sentence.
 *
 *  ## Three renderings again, and for `Spent`'s reasons
 *
 *  **Neither dial on.** The ordinary deployment, and it gets a sentence rather than
 *  `$0.00 of $0.00` — a figure against a limit nobody is enforcing is the most confident
 *  possible rendering of a number nobody is counting.
 *
 *  **On, and nothing reported.** Also the ordinary deployment today: a brokered tool call
 *  spends tokens at somebody else's vendor and reports nothing, so `$0.00` is honest and
 *  the sentence says what would change it. Not folded into the case above, because *the
 *  ceiling is off* and *the ceiling is on and nothing has been spent* are different
 *  answers to *why is this zero*.
 *
 *  **On, with spend.** The figure, the ceiling beside it — this page's standing rule
 *  that a number without its limit is not an answer — and the models the price list
 *  could not value, named rather than silently dropped.
 *
 *  The two dials are independent and each gets its own row, because a deployment that
 *  bounds tokens without pricing anything has an honest $0 under a live token ceiling.
 *  That is not an edge case: the built-in rate list knows three model families, and a
 *  customer brokering any other provider is in it from the first call. */
function Cost({ spend }: { spend: TokenSpend }) {
  const metered = spend.usd_metered || spend.tokens_metered;

  if (!metered) {
    return (
      <p className="muted sentence">
        <strong>No spend limit.</strong> Model spend is not limited on this deployment.
        What is spent is still recorded on every call.
      </p>
    );
  }

  return (
    <>
      <hr />
      <p className="sentence">
        <strong>
          {spend.usd_metered
            ? `${money(spend.usd)} of ${money(spend.usd_ceiling)}`
            : `${tokens(spend.tokens)} of ${tokens(spend.tokens_ceiling)}`}
        </strong>{" "}
        spent at a model today, the same UTC day. The limit resets at midnight UTC.
      </p>

      {/* Both rows when both dials are on, because whichever is met first refuses and a
          reader who only saw the dollar figure would not understand a token refusal. */}
      {spend.usd_metered && spend.tokens_metered && (
        <p className="muted sentence">
          Also {tokens(spend.tokens)} of {tokens(spend.tokens_ceiling)} tokens. Whichever
          limit is reached first denies the next call.
        </p>
      )}

      {spend.tokens === 0 ? (
        <p className="muted sentence">
          Nothing has been spent at a model today. Most tools spend nothing here. A token
          count appears only when a tool reports one.
        </p>
      ) : null}

      {spend.unpriced_models.length > 0 && (
        <p className="muted sentence">
          The dollar figure <strong>excludes</strong> {spend.unpriced_models.join(", ")},
          which {spend.unpriced_models.length === 1 ? "has" : "have"} no rate in the
          price list. {spend.unpriced_models.length === 1 ? "Its" : "Their"} tokens count
          against the token limit only. An operator can add rates to the price list.
        </p>
      )}

      {(spend.usd_metered && spend.usd >= spend.usd_ceiling) ||
      (spend.tokens_metered && spend.tokens >= spend.tokens_ceiling) ? (
        <Notice tone="warn" title="Spend limit reached">
          <p className="sentence">
            Further requests are denied until midnight UTC. The call that crossed the
            limit completed.
          </p>
        </Notice>
      ) : null}
    </>
  );
}

/** The week, as a table. Seven rows of a date and an integer is not a series.
 *
 *  Oldest first, which is the order the server sends and every log reader in this product
 *  shares — reversing it here would be a second ordering to remember. Today is marked
 *  rather than moved, because *is today unusual* is answered by seeing it beside the
 *  others. */
function Week({ windows, today }: { windows: SpentWindow[]; today: string }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Day (UTC)</th>
          <th>Requests allowed</th>
        </tr>
      </thead>
      <tbody>
        {windows.map((window) => (
          <tr key={window.window_start}>
            <td className="mono">
              {window.window_start}
              {window.window_start === today && (
                <span className="tiny muted token-note">today</span>
              )}
            </td>
            <td className="mono">{window.calls.toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The reach itself: the union, then one section per granted agent.
 *
 *  The sentence above the sections is not decoration — it is the union rule in words a
 *  person can act on. Without it, somebody seeing `search_issues` under two agents at two
 *  different scopes reads it as a contradiction, or worse, assumes the narrower one wins. */
function Reached({
  reach,
  catalogue,
  failed,
}: {
  reach: TokenReach;
  catalogue: Parameters<typeof Reach>[0]["catalogue"];
  failed: unknown;
}) {
  if (reach.agents.length === 0) {
    return (
      <Card title="Access" hint="as granted">
        {/* **A sentence, not an empty table.** Empty-denies is this product's default, so
            nothing here is a loading failure — and a blank table is read as one. */}
        <p className="sentence">
          This token has no agents. A client using it gets an empty{" "}
          <code>tools/list</code>, and every call is denied.
        </p>
        <p className="muted sentence">
          {reach.acts_as_owner ? (
            <>
              A personal token uses its owner&rsquo;s access. Share an{" "}
              <Link to="/agents">agent</Link> with yourself to use it here.
            </>
          ) : (
            <>
              Grant one from the <Link to="/agents">agent</Link>&rsquo;s{" "}
              <strong>Share</strong> dialog.
            </>
          )}
        </p>
        {reach.invalid_agents.length > 0 && <Broken names={reach.invalid_agents} />}
      </Card>
    );
  }

  return (
    <>
      <Card title="Access" hint="as granted">
        <p className="sentence">
          {reach.tools.length === 1 ? "One tool" : `${reach.tools.length} tools`}, through{" "}
          {reach.agents.length === 1 ? "one agent" : `${reach.agents.length} agents`}.
          {reach.acts_as_owner
            ? " These are its owner's grants and change when the owner's do."
            : " These are the token's own grants."}
        </p>
        {/* The union rule, said once, above the thing that would otherwise look like a
            contradiction. One tool under two agents at two scopes is not a mistake and
            neither scope is the winner: the call decides, from its own arguments. */}
        <p className="muted sentence">
          A tool granted by more than one agent keeps <em>each</em> agent&rsquo;s scope.
          Which one applies is decided per call.
        </p>
        {/* Rendered as text rather than as tags: it is the answer to "does this match what
            my client shows", which somebody reads across rather than scans. */}
        <p className="mono tiny muted">{reach.tools.join("  ")}</p>
        {reach.invalid_agents.length > 0 && <Broken names={reach.invalid_agents} />}
      </Card>

      {/* **Between the summary and the per-agent detail, and looking at the rendered
          page is what decided it.** Three grants produce three near-identical cards —
          the same tool, the same description, three scopes — and the transpose was a
          thousand pixels beneath them, past the point a reader has given up and started
          comparing by eye. It belongs where it is the *better* version of the line above
          it: `reach.tools` is the union of names as bare text, and this is that list with
          the composition attached. The per-agent cards are the working underneath. */}
      <EffectiveReach rows={reach.by_tool} />

      {reach.agents.map((agent) => (
        // `Reach.tsx` unmodified, once per agent. Not a copy of it and not a variant:
        // what somebody approves in the create wizard, what an agent's own page shows,
        // and what a token reaches through that agent are the same rendering — so none of
        // the three can develop a disagreement with the other two.
        <Reach
          key={agent.name}
          agent={agent}
          catalogue={catalogue}
          failed={failed}
          title={agent.name}
          hint="through this agent"
        />
      ))}
    </>
  );
}

/** Granted, and the agent will not load.
 *
 *  The door skips such an agent and says nothing, on purpose: one broken config must not
 *  remove every *other* agent's tools from a client's list. Silence is wrong here, on the
 *  one page whose question is a count — *two agents* about a token granted three, with
 *  nothing saying where the third went, is an absence that reads as a fact. */
function Broken({ names }: { names: string[] }) {
  return (
    <Notice tone="warn" title="Granted, and not valid">
      <p className="sentence">
        {names.join(", ")} {names.length === 1 ? "is" : "are"} granted to this token, and{" "}
        {names.length === 1 ? "its" : "their"} configuration is not valid. The MCP server
        skips {names.length === 1 ? "it" : "them"}, and nothing above counts{" "}
        {names.length === 1 ? "it" : "them"}. Fix{" "}
        {names.length === 1 ? "it" : "them"} on <Link to="/agents">Agents</Link>.
      </p>
    </Notice>
  );
}
