import { useState } from "react";
import { Link } from "react-router-dom";

import Failure from "../../components/Failure";
import {
  Button,
  Card,
  Empty,
  Field,
  Notice,
  PageHead,
  Spinner,
} from "../../components/ui";
import { api } from "../../lib/api";
import { on } from "../../lib/format";
import ConnectCard from "../agents/ConnectCard";
import type { MintedToken } from "../../lib/types";
import { useResource } from "../../lib/useResource";
import { Kind, Moment, State } from "./TokenMarks";

/** The API tokens you own — *which of my machines exist, what can each of them reach,
 * and is this one still alive* — and, since step 044, where a new one is minted.
 *
 * **This is 035c's deliverable, and it closes a gap of a shape neither sibling had.**
 * `/admin/door-calls` and `/admin/denials` were routes nothing called. This route has
 * been called since 022b. What was missing was a **field**: `acts_as_owner` has been a
 * column since migration 042 and was dropped between the store and the wire, because the
 * server's `OwnedToken` never declared it and a pydantic model drops what it does not
 * name. So the property that decides a credential's blast radius was legible from
 * `--list-tokens` and from nowhere else, and there was no page to have shown it on.
 *
 * ## Personal and service are not a decoration
 *
 * A **service** token holds grants of its own. Somebody decided, one agent at a time,
 * what it may reach — which is what you want for a CI pipeline, because its access
 * should not widen when whoever minted it joins a team.
 *
 * A **personal** token resolves its *owner's* access: their grants and their group
 * memberships, live, as those change, capped at `user`. That is what makes an editor
 * plugin able to do what its owner can do without an administrative action per token —
 * and it means revoking one credential and reviewing one person are two different jobs.
 *
 * Both are legitimate and the difference is the entire question an offboarding review
 * asks. It gets a `Badge` here, and a plain-text suffix in the two pickers, where a
 * native `<option>` admits no markup at all.
 *
 * ## Minting is here now, and what it reversed is written where it is enforced
 *
 * This page said *no mint, no revoke, no form* for two steps, on plan 035's category 2:
 * a stolen bearer token minting itself a durable successor. Step 044 narrowed that rule
 * to what it always protected — the **route** refuses every machine caller, so no
 * credential that survives its presenter can create another — and let a *session* mint
 * for itself. The form mints a token **owned by you**; there is no owner field, and the
 * secret is shown once below and never again.
 * Revocation is on each token's own page, beside what the token reaches.
 *
 * It is also **not** the register's `GET /admin/tokens`: that one is everyone's tokens
 * for an operations team, it needs a role, and it stays open and unbuilt. This one is
 * yours and needs none — which is why the route is `/tokens` rather than `/admin/…` and
 * why the nav link is outside the administrative group.
 *
 * ## Dead rows are listed, because the listing is a record
 *
 * Revoked and expired tokens arrive with the rest and are marked rather than hidden. The
 * *picker* is what excludes what cannot fire. A page that filtered them would answer
 * "you have no tokens" to somebody who has three dead ones — and would hide the reason
 * a caller stopped getting in, which is the single most likely reason anybody opens this.
 *
 * No polling, and no filters: a person's tokens are few by construction — one live name
 * each — and the route takes no `limit`, so there is nothing here that could be
 * truncated into a lie.
 */
export default function TokensPage() {
  const { data, error, loading, reload } = useResource(() => api.myTokens(), []);

  return (
    <>
      <PageHead
        title="Your tokens"
        lede={
          <>
            The API tokens you own — the machines that can act in this workspace on your
            behalf. Revoked and expired ones are listed too, because this is a record of
            what exists and what happened to it.
          </>
        }
      />

      {loading && <Spinner label="Reading your tokens…" />}
      {/* Before the empty state and never beside it. **A failed listing is not an empty
          listing**, and that is not a hypothetical distinction: a card once shipped the
          other way round, so a 503 made its form say "you have no machine" and point
          at the mint, about a token the person may well have owned. Here the same
          fall-through would say "you have no credentials" to somebody who has four. */}
      {error && <Failure error={error} />}

      {data && data.length === 0 && (
        <Empty title="You have no tokens">
          <p className="sentence">
            A token is how something that is not you acts in this workspace — an
            assistant talking to the MCP door, or a service acting for its users.
            Your own sign-in is not one, and does not need to be.
          </p>
          <p className="muted sentence">
            Mint one below. The secret is shown once, at the moment it is made, and never
            again — it is stored as a hash, so nothing here or in the database can show
            it twice.
          </p>
        </Empty>
      )}

      {data && data.length > 0 && (
        <Card title={`${data.length} ${data.length === 1 ? "token" : "tokens"}`}>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Acts as</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {data.map((token) => (
                // Keyed by id, unlike the two log pages: a token is a row with a primary
                // key, not an append-only record whose identity is its position.
                <tr key={token.id}>
                  <td>
                    {/* **A link, and deliberately not a disclosure toggle** — 035d.
                        Plan 035 asked for reach as "a section on the token row", which
                        built literally is a button per row. The rows stay button-free
                        (the mint form below is the page's one control): a link is what
                        this app says it wants everywhere else — an incident is shared as
                        a URL, and "a tab index is not a URL" appears twice in `App.tsx`.
                        What a credential reaches is exactly the thing somebody pastes
                        into a channel. */}
                    <Link to={`/tokens/${encodeURIComponent(token.id)}`}>
                      {token.name}
                    </Link>
                    {/* The id, under the name, because it is what every record the
                        machine writes actually says — `machine:m_8f2c…` in an audit row,
                        in a denial, in a run's principal. Somebody holding one of those
                        strings comes here to find out whose it is. */}
                    <div className="mono tiny muted token-note">{token.id}</div>
                  </td>
                  <td>
                    <Kind token={token} />
                  </td>
                  <td className="mono">{on(token.created_at)}</td>
                  <td>
                    <Moment iso={token.expires_at} absent="never" />
                  </td>
                  <td>
                    <Moment iso={token.last_used_at} absent="never" />
                  </td>
                  <td>
                    <State token={token} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* After the listing, whatever the listing said: the form belongs on this page in
          all three of its states, and rendering it under a `Failure` is deliberate —
          not being able to list what exists does not prevent minting something new. */}
      {!loading && <MintBox onMinted={reload} />}

      {/* The door, on the page that mints its key (062). Until now the endpoint and
          the client snippet lived only on an agent's detail page — unreachable for a
          fresh deployment's first administrator, who has no agent yet — and nothing
          here named the URL a token is FOR. Nameless, so it renders the deployment
          facts and polls nothing. */}
      {!loading && <ConnectCard />}
    </>
  );
}

/** The mint form, closed by default, and the one-time reveal it turns into.
 *
 *  A button, then an `.inline-form`, then the thing that was made. The reveal is
 *  rendered from the
 *  create response held in component state, never re-fetched, no copy button (this app
 *  has no clipboard idiom; selectable text with a keyboard tab stop is the affordance),
 *  and dismissed on purpose rather than by navigation so nobody loses the secret to a
 *  stray click. */
function MintBox({ onMinted }: { onMinted: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [personal, setPersonal] = useState(true);
  const [expiresDays, setExpiresDays] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<unknown>(null);
  const [minted, setMinted] = useState<MintedToken | null>(null);

  if (minted) {
    return (
      <Notice tone="warn" title={`Token "${minted.name}" exists now`}>
        <p>
          <strong>Copy the token now — it is shown once and cannot be retrieved.</strong>{" "}
          It is stored as a hash, so nothing here or in the database can show it again.
          If it is lost, revoke this token on its page and mint another.
        </p>
        {/* `tabIndex` for a keyboard finding:
            `<code>` is not focusable, and the only other tab stop here destroys the
            value. */}
        <div className="reveal">
          <span className="label">Token — what the machine presents</span>
          <code tabIndex={0} aria-label="Token, what the machine presents">
            {minted.token}
          </code>
        </div>
        {minted.acts_as_owner ? (
          <p className="muted">
            It can run whatever you can run, from this moment and as your access changes.
            Grant nothing to the token itself — share agents with yourself, and every
            personal token you hold follows. When your account is disabled, it stops.
          </p>
        ) : (
          <p className="muted">
            It can run nothing yet. Share an agent with{" "}
            <code>machine:{minted.id}</code> to grant it one — a service token holds only
            what is granted to it directly.
          </p>
        )}
        <div className="spread">
          <Button onClick={() => setMinted(null)}>I have copied it</Button>
        </div>
      </Notice>
    );
  }

  if (!open) {
    return (
      <div className="spread">
        <Button onClick={() => setOpen(true)}>Mint a token</Button>
      </div>
    );
  }

  async function mint() {
    setBusy(true);
    setFailure(null);
    try {
      const made = await api.mintToken({
        name: name.trim(),
        acts_as_owner: personal,
        // Omitted when blank — "no expiry" is spelled by omission, the server's rule.
        ...(expiresDays.trim() === ""
          ? {}
          : { expires_days: Number(expiresDays) }),
      });
      setMinted(made);
      setOpen(false);
      setName("");
      setExpiresDays("");
      onMinted();
    } catch (cause: unknown) {
      setFailure(cause);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="inline-form">
      <Field
        label="Name"
        hint="What the listing shows somebody deciding what to revoke. One live token per name."
      >
        <input
          value={name}
          placeholder="my-assistant"
          onChange={(event) => setName(event.target.value)}
        />
      </Field>

      <div className="choices stacked">
        <label className={`choice big${personal ? " on" : ""}`}>
          <input
            type="radio"
            name="token-kind"
            checked={personal}
            onChange={() => setPersonal(true)}
          />
          <span>
            <strong>Personal — acts as you.</strong>
            <span className="muted">
              {" "}
              It can run whatever you can run, live, as your access changes — the shape
              for connecting your own assistant. It dies with your account.
            </span>
          </span>
        </label>
        <label className={`choice big${personal ? "" : " on"}`}>
          <input
            type="radio"
            name="token-kind"
            checked={!personal}
            onChange={() => setPersonal(false)}
          />
          <span>
            <strong>Service — holds only its own grants.</strong>
            <span className="muted">
              {" "}
              It can run nothing until an agent is shared with it, and its access does
              not widen when yours does — the shape for CI and shared machinery. Tools
              vetted to act as the person calling them are beyond it: no person stands
              behind it, so there is no account for such a call to act as.
            </span>
          </span>
        </label>
      </div>

      <Field
        label="Expires after (days)"
        hint="Blank means never — revoke it to end it."
      >
        <input
          value={expiresDays}
          inputMode="numeric"
          placeholder="never"
          onChange={(event) => {
            // Digits or nothing — the rule the wizard's ceilings step set, and the last
            // place it survives now that 081 has deleted that step: a field that cannot
            // hold a bad value needs no sentence about one.
            if (/^\d*$/.test(event.target.value)) setExpiresDays(event.target.value);
          }}
        />
      </Field>

      {failure ? <Failure error={failure} /> : null}

      <div className="spread">
        <Button onClick={() => setOpen(false)} disabled={busy}>
          Cancel
        </Button>
        <Button
          kind="primary"
          busy={busy}
          disabled={name.trim() === ""}
          onClick={mint}
        >
          {busy ? "Minting" : "Mint this token"}
        </Button>
      </div>
    </div>
  );
}
