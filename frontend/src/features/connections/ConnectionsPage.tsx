import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";

import Failure from "../../components/Failure";
import {
  Badge,
  BrandMark,
  Button,
  Empty,
  Notice,
  PageHead,
  Skeleton,
  Tag,
  type Tone,
} from "../../components/ui";
import { api } from "../../lib/api";
import { runConsent } from "../../lib/consentWindow";
import { day, passed } from "../../lib/format";
import type { ConnectionSummary } from "../../lib/types";
import { useResource } from "../../lib/useResource";

/** The first screen in this product that is about **you** rather than about an agent.
 *
 * Step 7b's deliverable, and the plan is explicit that it is the deliverable rather than
 * a garnish: `frontend/src` contained no connections surface at all, so shipping the two
 * routes without this would have left the only caller an engineer with `curl` instead of
 * an engineer with the CLI, and the problem — *an operator obtains and sees every
 * person's third-party token* — untouched.
 *
 * It is a page rather than a section of an agent's detail view because **the same
 * connection serves every agent that touches that connector**. Putting it under one agent
 * would imply otherwise, and would make disconnecting look like it affected only that
 * agent.
 *
 * ## Three states, and the third is the one that took thought
 *
 *     Jira      Connected as priya@acme.com          [Disconnect]
 *     GitHub    Not connected                        [Connect]
 *     Linear    Not connected — no consent flow yet   ask an administrator
 *
 * A **Connect** button on the third would be the *"a control that exists and does nothing
 * reads as a bug"* failure 10d's share sheet already learned: somebody presses it, nothing
 * happens, and they conclude the product is broken rather than that an administrator has
 * a task. So there is no button and there is a sentence.
 *
 * There is a fourth, and it is a half: **connected and no longer usable**. A person can
 * revoke consent at their provider at any moment, and before this screen the first anyone
 * heard of it was a run failing. It renders as its own row with the provider's own reason.
 *
 * ## Why connecting is a real browser navigation, and why it happens in a popup
 *
 * `api.startConnect` returns a URL rather than a redirect, because `fetch` follows a 302
 * transparently and would land the provider's consent HTML in a promise nobody can
 * render. The browser genuinely has to *go* to the provider.
 *
 * **It goes there in a popup, and that is a bug fix rather than a preference.** This
 * navigated the whole page at first, and connecting an account signed people out — every
 * time. This app's own token lives in memory by design, every screen before 7b was
 * click-through so nothing ever unloaded the page, and the silent renewal meant to cover
 * a reload depends on a third-party cookie that browsers are removing. So the one feature
 * that must leave the origin was also the one that could not survive coming back.
 *
 * A popup means the page that started the flow never unloads and its token is still
 * there. See `consentWindow.ts` for the two things that has to get right, and for why the
 * fallback when a popup is blocked is the old navigation rather than an error.
 *
 * The token never comes back here either way. It goes from the provider's token endpoint
 * straight into storage, server-side; this page learns only *that* a connector is now
 * connected — from a message when the popup closes, or from the query string when the
 * fallback navigation brings it back.
 */
export default function ConnectionsPage() {
  const { data, error, loading, reload } = useResource(() => api.listConnections(), []);
  const [params, setParams] = useSearchParams();

  // What the callback told us on the way back in. Read once and then cleared from the
  // URL, so a reload does not re-announce a connection made ten minutes ago and a
  // copied link does not claim somebody else's success.
  const connected = params.get("connected") ?? "";
  const failed = params.get("failed") ?? "";
  const clearOutcome = () => {
    params.delete("connected");
    params.delete("failed");
    setParams(params, { replace: true });
  };

  // The popup's outcome arrives as a message rather than on the URL, so it is put on the
  // URL here — one place that renders an outcome, whichever way it got here. `replace`,
  // so Back does not walk through a connection you already dismissed.
  const showOutcome = (outcome: { connected: string; failed: string }) => {
    const next = new URLSearchParams(params);
    next.delete("connected");
    next.delete("failed");
    if (outcome.connected) next.set("connected", outcome.connected);
    if (outcome.failed) next.set("failed", outcome.failed);
    setParams(next, { replace: true });
  };

  return (
    <>
      <PageHead
        title="Connections"
        lede="Sign in to the apps your agents use, with your own account. Anything an agent does there is done as you, with your access."
      />

      {connected && (
        <Notice tone="info" title={`${connected} is connected`}>
          <p className="sentence">
            Agents you run can now reach {connected} as you. Nobody here saw the
            credential — it went from {connected} straight into storage and is never sent
            anywhere except to {connected} itself.
          </p>
          <Button kind="quiet" onClick={clearOutcome}>
            Dismiss
          </Button>
        </Notice>
      )}

      {failed && (
        <Notice tone="warn" title="That did not finish">
          {/* The server's own sentence. It covers a person pressing Deny, a link that
              expired, and a `state` we never issued — and this page must not guess which,
              because two of those are ordinary and one is somebody probing. */}
          <p className="sentence">{failed}</p>
          <p className="muted">Nothing was stored. You can try again below.</p>
          <Button kind="quiet" onClick={clearOutcome}>
            Dismiss
          </Button>
        </Notice>
      )}

      {loading && <Skeleton />}
      {error && <Failure error={error} />}

      {data && data.length === 0 && (
        <Empty title="Nothing to connect yet" icon="connections">
          <p className="sentence">
            Your organisation has not set up any connectors. Until it does, agents here
            can only use the tools that ship with the platform.
          </p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <div className="conn-grid">
          {data.map((row) => (
            <ConnectionRow
              key={row.connector_id}
              row={row}
              onChange={reload}
              onOutcome={showOutcome}
            />
          ))}
        </div>
      )}
    </>
  );
}

function ConnectionRow({
  row,
  onChange,
  onOutcome,
}: {
  row: ConnectionSummary;
  onChange: () => void;
  onOutcome: (outcome: { connected: string; failed: string }) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");

  // Abandon any flow in progress when this row goes away. Without it, navigating off the
  // page while a consent popup is open leaves a poll running for the life of the tab and
  // a message listener that calls back into a component React has already unmounted.
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);

  const connect = () => {
    setBusy(true);
    setNote("");
    // **In a popup, so this page never unloads.** Connecting used to navigate away, and
    // navigating away destroys the in-memory token this app signs in with — so every
    // successful connection ended on a sign-in screen. See `consentWindow.ts`; the
    // fallback is that old navigation, for a browser that blocks the popup.
    abort.current?.abort();
    abort.current = new AbortController();
    runConsent(
      () => api.startConnect(row.connector_id, "/connections").then((s) => s.authorize_url),
      { fallback: (url) => window.location.assign(url), signal: abort.current.signal },
    )
      .then((outcome) => {
        setBusy(false);
        // null means they closed it without deciding. Nothing happened, and saying so
        // would be inventing an event.
        if (!outcome) return;
        onOutcome(outcome);
        onChange();
      })
      .catch((cause: unknown) => {
        setBusy(false);
        setNote(cause instanceof Error ? cause.message : String(cause));
      });
  };

  const disconnect = () => {
    setBusy(true);
    setNote("");
    api
      .disconnect(row.connector_id)
      .then((outcome) => {
        // **`revoked_upstream === false` is said out loud.** The local credential is gone
        // either way — decision 12, so a provider outage cannot trap somebody in a
        // connection they asked to end — but a person who disconnects reasonably believes
        // the token is dead everywhere, and here it is not. Saying nothing would make
        // this page the reason they believe something untrue.
        if (outcome.revoked_upstream === false) {
          setNote(
            `Disconnected here, but ${row.connector_id} could not be told to revoke the ` +
              `token. It may still be live there — revoke it in your ${row.connector_id} ` +
              `account settings if that matters to you.`,
          );
        }
        onChange();
      })
      .catch((cause: unknown) =>
        setNote(cause instanceof Error ? cause.message : String(cause)),
      )
      .finally(() => setBusy(false));
  };

  const lapsing = lapse(row);
  const asking = asks(row);

  const state = status(row);

  return (
    // `connection` carries no styles and is not decoration: it is the handle
    // `scripts/e2e_browser_admin.py` picks this card out by, on a page whose other
    // elements are also `.conn-card` once 093 gave connections the connectors page's
    // shape.
    <div className="conn-card connection">
      <div className="conn-head">
        {/* The vendor's own mark, from the connector id — the same tile the connectors
            tab draws for the same connector. This page is a list of other people's
            services, which is exactly the list a logo is for. */}
        <BrandMark hints={[row.connector_id]} />
        <div className="conn-title">
          <strong>{row.connector_id}</strong>
        </div>
        <Badge tone={state.tone}>{state.word}</Badge>
      </div>

      <div className="conn-body">
        {row.credential_kind === "static" && (
          // Worth marking, because the two are not the same thing to the person
          // reading. A static credential is a token somebody pasted in on a server —
          // which means an operator held it — and it cannot renew itself.
          <div className="conn-tags">
            <Tag>added by an administrator</Tag>
          </div>
        )}
        {row.description && <p className="muted">{row.description}</p>}
        <p className="sentence">{describe(row)}</p>

        {/* A full sentence rather than a muted note, because on the row it appears on it
            *corrects* the one above it: `describe` says "Connected as priya@acme.com" for
            a pasted credential that expired last March, and this is the half that says so. */}
        {lapsing && <p className="sentence">{lapsing}</p>}

        {/* **Before the button, not after it.** The alternative is that the first time
            somebody learns what they are agreeing to is on a third party's page, at the
            moment they are trying to get past it. */}
        {asking && <p className="muted">{asking}</p>}

        {/* What those scopes *permit*, in words — migration 051, and the reader this
            whole column was added for.

            The sentence above is honest and useless on its own: it says
            `write:jira-work`, to somebody who is not an administrator and has not read
            Atlassian's documentation, immediately before they grant it. This is the half
            that says what it means.

            **Only where a decision is being made.** Beside a *connected* row it would be
            describing what the app asks for now rather than what this person granted —
            `asks` already carries that caveat for the scope list and a paragraph of prose
            cannot carry it legibly. A scope with no note renders as it did before, which
            is the honest default: nobody here has written a sentence for it. */}
        {(row.state === "connectable" || row.state === "reconnect") &&
          row.scopes.some((scope) => row.scope_notes[scope]) && (
            <ul className="scope-notes">
              {row.scopes.map((scope) => {
                const note = row.scope_notes[scope];
                if (!note) return null;
                return (
                  <li key={scope}>
                    <strong>{note.name || scope}</strong>{" "}
                    <Tag write={note.access === "write"}>{note.access}</Tag>
                    {note.description && (
                      <span className="muted"> {note.description}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

        {/* Last, and small, because it is the answer to a question somebody arrives with
            rather than something the row is *about*: migration 013's *"when did this last
            change is the first question asked when somebody's agent starts failing"*. */}
        {row.updated_at && (
          <p className="tiny muted">Last changed {day(row.updated_at)}.</p>
        )}

        {note && (
          <Notice tone="warn">
            <p className="sentence">{note}</p>
          </Notice>
        )}
      </div>

      <div className="conn-foot">
        {(row.state === "connectable" || row.state === "reconnect") && (
          <Button kind="primary" busy={busy} onClick={connect}>
            {row.state === "reconnect" ? "Reconnect" : "Connect"}
          </Button>
        )}
        {row.state === "connected" && (
          <Button busy={busy} onClick={disconnect}>
            Disconnect
          </Button>
        )}
        {/* `unavailable` renders no control at all, deliberately. See the page docstring. */}
      </div>
    </div>
  );
}

/** Whether anything is behind this connection when it lapses — 035f, and one function
 *  for `describe`'s reason: three cases, and the wrong one is reassuring.
 *
 *  **`expires_at` alone is not renderable, which is why this reads three fields.** The
 *  schema says the access token's expiry *"is only interesting for the ones without"* a
 *  refresh token, and the sharper version is about timing: `refresh_for_run` renews at the
 *  **start of a run**, so a healthy OAuth connection's `expires_at` sits in the past for
 *  most of the time it exists and is renewed to a future instant moments before anything
 *  needs it. Rendering it on an OAuth row would tell the *majority of healthy connections*
 *  that they had expired, and invite somebody to reconnect one that is fine — which is the
 *  opposite of what a screen about access is for.
 *
 *  So the three cases are:
 *
 *      static, with an expiry     nothing renews a pasted token, so the instant is real
 *      oauth, refresh expiry      when the connection itself lapses, past which renewing
 *                                 cannot help — migration 024's whole argument
 *      anything else              nothing
 *
 *  **The last case's silence is not a promise.** A null refresh expiry means the provider
 *  did not say — most do not — and it is also what an OAuth connection carrying no refresh
 *  token at all looks like, until the next refresh turns it into `reconnect` with its own
 *  reason. Inventing "this will not lapse" out of a null is the reassuring direction again.
 *
 *  Only on a `connected` row. A `reconnect` row is already broken and already carries the
 *  provider's reason; a second sentence about a future lapse there is noise on top of a
 *  fact that has already happened.
 *
 *  The past/future comparison is a client-side derivation and is safe for the reason
 *  `TokenMarks.State` gives: it is not a control. The server refuses an expired connection
 *  whatever this renders, with a sentence naming this same date. Note that the same
 *  derivation on an OAuth row would *not* be safe, which is the whole paragraph above. */
function lapse(row: ConnectionSummary): string {
  if (row.state !== "connected") return "";

  if (row.credential_kind === "static" && row.expires_at) {
    const when = day(row.expires_at);
    return passed(row.expires_at)
      ? `This credential expired on ${when}. Nothing here can renew it — somebody pasted it in, so it stays expired until an administrator replaces it.`
      : `This credential expires on ${when}. Nothing here can renew it, so an administrator will have to replace it.`;
  }

  if (row.credential_kind === "oauth" && row.refresh_expires_at) {
    const when = day(row.refresh_expires_at);
    // **Both tenses, and the past one is the row that most needs a sentence.** A
    // connection nobody has run for six months has a lapsed refresh token, an empty
    // `reconsent_reason` — because nothing has tried and failed yet — and a `state` of
    // `connected`. So this branch is reached with a date in the past, and saying "lapses
    // on 1 January 2020, it renews itself until then" is a future-tense claim about
    // something that has already happened, on exactly the connection whose next run will
    // fail. Found by rendering one.
    return passed(row.refresh_expires_at)
      ? `This connection lapsed on ${when}. Renewing cannot fix that, so the next agent that needs it will fail — connect the account again.`
      : `This connection lapses on ${when}. It renews itself until then; after that you will need to connect it again.`;
  }

  return "";
}

/** What the connector will ask for, or asks for — 035f, and the sentence has to say which.
 *
 *  **`scopes` is the OAuth application's configured ask and not a granted scope**, which
 *  is the trap in the field's name. It is the list the authorize URL is built from, so it
 *  describes what a consent flow would request *right now*. What a person consented to is
 *  stored nowhere: there is no `granted_scopes` column and the provider's `scope` echo is
 *  dropped on the way in.
 *
 *  That makes the obvious fix — deleting the `state === "connectable"` condition this
 *  replaced — actively wrong. An administrator who widens the app's scopes afterwards
 *  would have this page claim a live credential carries scopes it never had, on a screen
 *  whose subject is access, with nothing for the reader to tell the difference by. So:
 *
 *      connectable, reconnect     future tense, before the button that agrees to it
 *      connected + oauth          present tense, and the sentence says what it is not
 *      connected + static         nothing: a pasted token never met a consent screen,
 *                                 and the connector may have an OAuth app regardless
 *
 *  **`reconnect` is a fix rather than a widening.** The old gate named a state where it
 *  meant a condition — *there is a button here that sends somebody to a consent screen* —
 *  and `reconnect` grew one of those buttons without the gate being revisited. The page's
 *  own argument (*"the alternative is that the first time somebody learns what they are
 *  agreeing to is on a third party's page"*) applied there all along.
 *
 *  The caveat is inside the sentence rather than beside it, so no later layout change can
 *  separate a claim about access from its qualification. */
function asks(row: ConnectionSummary): string {
  if (row.scopes.length === 0) return "";
  // **A joined string cannot distinguish two scopes from one containing a comma**, and
  // 035f's edge pass confirmed against real Postgres that the second is storable — a
  // comma is legal in RFC 6749's scope-token, and the admin form takes scopes *space*
  // separated while this sentence renders them comma separated, which is what makes the
  // mistake reachable. Left as it is deliberately: no provider anybody has met ships one,
  // and the fix — a scope per element — changes 7b's sentence for every deployment to
  // disambiguate a case none of them have. Recorded here rather than in the register,
  // because the fix is at this line and nowhere else.
  const list = row.scopes.join(", ");

  if (row.state === "connectable" || row.state === "reconnect") {
    return `${row.connector_id} will be asked for: ${list}`;
  }

  if (row.state === "connected" && row.credential_kind === "oauth") {
    return `${row.connector_id} asks for: ${list} — what this connector requests today, not a record of what this connection was granted.`;
  }

  return "";
}

/** The word on the card, and its colour — `ConnectorsPage.status`'s twin, on this page's
 *  own four states. Step 093.
 *
 *  **Named `status` and not `state`**, which is the field it reads: a second `state` in
 *  this file would shadow the one thing every branch here turns on. And it is a function
 *  beside `describe()` rather than a branch inside it, for `describe()`'s reason — a badge
 *  is read by somebody scanning a page of them and a sentence by the one who stops, and
 *  they must be computed from the same switch so they cannot drift.
 *
 *  `unavailable` is `waiting` rather than `bad`: nothing is broken, an administrator has
 *  a task, and a red badge over a working system is how a support ticket gets raised
 *  about a rule. */
export function status(row: ConnectionSummary): { tone: Tone; word: string } {
  switch (row.state) {
    case "connected":
      return { tone: "good", word: "Connected" };
    case "reconnect":
      return { tone: "warn", word: "Needs reconnecting" };
    case "connectable":
      return { tone: "waiting", word: "Not connected" };
    case "unavailable":
      return { tone: "waiting", word: "Not available yet" };
  }
}

/** The row's own sentence. One function so the four states cannot be worded four ways.
 *
 * Every branch says what a state **means for a run**, because "not connected" on its own
 * does not tell somebody whether their agent will fail or quietly act as somebody else —
 * and the answer differs by state.
 *
 * **The state itself is `status()`'s job since 093, and three of these branches stopped
 * saying it twice.** They used to open with the words the badge beside them now carries:
 * *"Not connected. Agents you run will use…"*, *"Needs connecting again: <reason>"*. On a
 * row that was the only carrier, so the repetition did not exist; on a card with a badge
 * it is the same fact printed an inch apart, and the version that survives is the half the
 * badge cannot say. `connected` keeps its opening word because what follows it is the
 * account name rather than a restatement.
 */
function describe(row: ConnectionSummary): string {
  switch (row.state) {
    case "connected":
      return row.account_label
        ? `Connected as ${row.account_label}.`
        : "Connected. This connector did not say which account, so there is no name to show.";
    case "reconnect":
      // The provider's own reason, verbatim. The badge is what to do; this is what
      // says whether doing it will help — and if consent was withdrawn deliberately,
      // the person needs to know that is what they are undoing.
      return row.reconsent_reason;
    case "connectable":
      // What connecting *buys* you, first — that is the question somebody looking at a
      // Connect button has — and then what happens if they do not.
      return `Sign in and agents you run will act as you in ${row.connector_id}. Until then they use your organisation's shared account, if it set one up.`;
    case "unavailable":
      // **The sentence 093a rewrote.** It used to read *"There is no way to connect it
      // yourself yet — nobody has set up a sign-in flow for this connector. Ask whoever
      // administers your workspace."* Three problems, and they compound: it opened with
      // a passive negative, it explained the block in the product's own vocabulary
      // (*consent flow*, softened to *sign-in flow*, and *connector* — a word for the
      // thing an administrator registers, not for the app a person recognises), and it
      // asked somebody to go to an administrator without saying what to ask for.
      //
      // So: who is blocked, what is missing in words a person owns, what to ask for by
      // name, and what happens meanwhile. The badge beside it already says the state.
      return `Nobody has switched on personal sign-in for ${row.connector_id} yet, so you cannot use your own account here. Ask an administrator to set it up. Until then agents use your organisation's shared account, if it set one up.`;
  }
}
