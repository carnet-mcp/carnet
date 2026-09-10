/** The three marks a token row carries, in one place because two screens carry them.
 *
 * Split out of `TokensPage.tsx` by 035d, which added `/tokens/:id` and would otherwise
 * have had to describe *personal or service* and *revoked or expired or live* a second
 * time. Two descriptions of the same fact that can disagree is the shape `Reach.tsx`'s
 * own docstring refuses one level up, and it is worse here: these are the words somebody
 * reads to decide whether a credential is a problem.
 *
 * No behaviour changed in the move; the sentences below are 035c's, verbatim.
 */

import { Badge } from "../../components/ui";
import { on } from "../../lib/format";
import type { OwnedToken } from "../../lib/types";

/** Personal or service, as a word and a colour and never a colour alone.
 *
 *  Neither is an alarm, so neither is `bad`: minting a personal token is a deliberate,
 *  recorded trust decision (`token.mint` carries `acts_as_owner`), not an accident to be
 *  flagged. `warn` on the wider one, because *this credential reaches whatever its owner
 *  reaches* is the fact a review has to stop on, and `good` on the narrower one, because
 *  a stated, bounded access is the thing this product keeps arguing for. */
export function Kind({ token }: { token: OwnedToken }) {
  if (token.acts_as_owner) {
    return (
      <>
        <Badge tone="warn">personal</Badge>
        <div className="tiny muted token-note">your access</div>
      </>
    );
  }
  return (
    <>
      <Badge tone="good">service</Badge>
      <div className="tiny muted token-note">its own grants</div>
    </>
  );
}

/** A moment, or the word for not having one.
 *
 *  Three nulls on this row mean three different things — never expires, never revoked,
 *  never used — and each is an answer rather than a missing value. Rendered as a word for
 *  the reason `DoorTrafficPage` renders *"nobody named"* and `DenialsPage` renders
 *  *"nothing"*: a blank cell reads as a field the server failed to send, and *never used*
 *  is exactly what somebody reviewing a departing colleague's credentials came to read. */
export function Moment({ iso, absent }: { iso: string | null; absent: string }) {
  if (!iso) return <span className="muted">{absent}</span>;
  return <span className="mono">{on(iso)}</span>;
}

/** Live, expired, or revoked.
 *
 *  Revocation wins over expiry, because it is the deliberate act: a token revoked before
 *  its expiry date is a decision somebody made and should be able to see they made.
 *
 *  **This is deliberately not what `--list-tokens` prints, and the difference is a column
 *  count rather than a disagreement.** The CLI resolves `revoked → has an expiry → live`
 *  and shows `expires 2020-01-01` for a date that passed years ago, because it has one
 *  column and has to pack the instant and the state into it. This table has an Expires
 *  column of its own, so this one is free to carry the *verdict* — which is the question
 *  somebody actually opened the page with, that being "why did this stop working".
 *
 *  The verdict is a client-side derivation and the only one on this page. Safe because it
 *  is not a control: the server refuses an expired token whatever this renders, and
 *  `tokens.act_for` says so in words. It is the same shape as the pickers' `revoked_at`
 *  filter, which `DEFERRED.md` already carries a row about. */
export function State({ token }: { token: OwnedToken }) {
  if (token.revoked_at) {
    return (
      <>
        <Badge tone="bad">revoked</Badge>
        {/* Who, as well as when. An owner whose token was revoked by an administrator
            rather than by themselves is the case this column exists for, and "revoked"
            with no actor leaves them with nobody to ask. */}
        <div className="tiny muted mono token-note">
          {on(token.revoked_at)}
          {token.revoked_by ? ` by ${token.revoked_by}` : ""}
        </div>
      </>
    );
  }
  // Compared here rather than on the server, and it is the one derivation on this page.
  // Safe because it is not a control: the server refuses an expired token whatever this
  // renders, and `expires_at` is an instant the row already carries — the same shape as
  // the pickers' `revoked_at === null`, which `DEFERRED.md` already has a row about.
  // No date repeated under it: the Expires column beside this one already carries the
  // instant, and the same value twice in one row reads as two facts.
  if (token.expires_at && new Date(token.expires_at).getTime() < Date.now()) {
    return <Badge tone="bad">expired</Badge>;
  }
  return <Badge tone="good">live</Badge>;
}
