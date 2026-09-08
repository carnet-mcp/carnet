import { ApiError, NotSignedIn } from "../lib/api";
import { Notice } from "./ui";

/** A failed request, rendered as the thing that actually happened.
 *
 * This API's status codes carry meaning that a generic "something went wrong" throws
 * away, and two of them are decisions somebody argued about:
 *
 *   - **404 is also "you have no grant on this".** Deliberately indistinguishable from
 *     an agent that does not exist, because a 403 sweep over plausible names enumerates
 *     every agent in the company. So this screen must not helpfully guess which it was —
 *     the server's one sentence is the whole answer, and adding "perhaps ask an
 *     administrator for access to this agent" would leak exactly what the 404 protects.
 *   - **403 is not a reason to sign in again.** It means authenticated and still not
 *     allowed, and `deps.py` returns a message written to be actionable by a person —
 *     "your domain is not registered" is something they take to their admin. A UI that
 *     bounced them back to the identity provider would loop on a login that cannot help.
 *
 * **422 was one caller's case promoted to the general one, and 066 demotes it.** It read
 * *"This agent's configuration is not valid"*, written when the only 422 a page could
 * meet was an agent whose stored config no longer validated. That stopped being the only
 * one: `/admin/denials` refuses a `resource_kind` its column cannot hold, and `066` gives
 * `/admin/door-calls` five more closed vocabularies that do the same.
 *
 * The cost of the old wording was recorded rather than theoretical. `DenialsPage` holds
 * its filters in React state instead of in the URL — against this codebase's repeated
 * argument that an administrator sends a link to a colleague — for exactly one concrete
 * reason: *"a filter in the URL is one keystroke from `?kind=banana`, and a screen
 * answering a typo with a confident sentence about a different noun is worth less than
 * the deep link is worth."* `DEFERRED.md` carried the fix and the trigger with it —
 * *"worth doing before the second log screen wants the same thing"* — and 066 is the
 * second log screen.
 *
 * So a 422 now says what a 422 means: the request was not in a shape the server accepts.
 * The server's own `detail` carries the specifics, as it always did, and it is the
 * agent-configuration sentence when that is what happened — because that sentence is
 * written by `routes_agents.py`, not by this file.
 */
export default function Failure({ error }: { error: unknown }) {
  if (error instanceof NotSignedIn) {
    // The gate is about to take over. Saying anything here would flash a message at
    // somebody who is on their way to a sign-in screen.
    return null;
  }

  if (error instanceof ApiError) {
    switch (error.status) {
      case 404:
        return (
          <Notice tone="warn" title="Not here">
            <p className="sentence">{error.detail}</p>
          </Notice>
        );
      case 403:
        return (
          <Notice tone="bad" title="Your account may not use this">
            <p className="sentence">{error.detail}</p>
            <p className="muted">
              Signing in again will not change this. This is something to take to
              whoever administers your workspace.
            </p>
          </Notice>
        );
      case 422:
        return (
          <Notice tone="warn" title="The server would not accept that request">
            <p className="sentence">{error.detail}</p>
            <p className="muted">
              Nothing has changed. If you arrived here from a link, check the part after
              the <code>?</code> — a value the server does not recognise is refused
              rather than ignored.
            </p>
          </Notice>
        );
      case 503:
        return (
          <Notice tone="bad" title="The service cannot reach its database">
            <p className="sentence">{error.detail}</p>
            <p className="muted">Nothing has been lost. Try again shortly.</p>
          </Notice>
        );
      default:
        return (
          <Notice tone="bad" title={`The server refused (${error.status})`}>
            <p className="sentence">{error.detail}</p>
          </Notice>
        );
    }
  }

  return (
    <Notice tone="bad" title="Could not reach the server">
      <p className="sentence">
        {error instanceof Error ? error.message : String(error)}
      </p>
    </Notice>
  );
}
