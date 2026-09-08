/** Who the caller is — shared from the one place that asks.
 *
 *  Step 042. `AppShell` fetches `GET /me` for the administration links, and every page
 *  that needs the same answer reads it from here: a second `useResource(() => api.me())`
 *  would be a second request per page load and a second answer that can disagree with
 *  the first while one of them is in flight.
 *
 *  **The first React context in this codebase, and it is deliberately the smallest one
 *  that can exist.** What this project has declined is dependencies — no UI library, no
 *  state library, no router beyond the one it uses — not React's own primitives. The
 *  alternative was threading `me` from `App` into `AppShell` as a prop, which does not
 *  work here for a structural reason rather than a stylistic one: the routes are
 *  `AppShell`'s children, created in `App`'s render, so `App` is *outside* the fetch and
 *  a prop would have to come from a third fetch above both.
 */
import { createContext, useContext } from "react";

import type { Me } from "./types";

export interface MeState {
  /** Null until `/me` answers, and null again if it fails. */
  me: Me | null;
  /** Whether the request has finished, however it finished. Told apart from `me === null`
   *  so a consumer can render nothing while the answer is unknown rather than rendering
   *  the answer for "no" and then replacing it — a NotFound that flashes and becomes a
   *  page is worse than a beat of blank. */
  settled: boolean;
}

export const MeContext = createContext<MeState>({ me: null, settled: false });

/** Whether this reader may administer the tenant, from the shell's one `/me`.
 *
 *  Added in 013c: a page that needs to know is otherwise a second `api.me()` request
 *  per screen, and the shell has already asked. `settled` matters — an administrator whose `/me`
 *  is still in flight would otherwise see the non-administrator page for a beat and
 *  watch sections appear under them.
 *
 *  **Render-only.** Every administrative read is gated on the server, so being wrong
 *  here shows or hides a section and never grants one. That is the same contract
 *  `Me.admin` carries and the reason it may be trusted for layout at all. */
export function useAdmin(): MeState & { admin: boolean } {
  const state = useContext(MeContext);
  return { ...state, admin: state.me?.admin === true };
}
