import type { ReactNode } from "react";
import { useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useSyncExternalStore } from "react";

import { api } from "../lib/api";
import { current, signOut, subscribe } from "../lib/auth";
import { useResource } from "../lib/useResource";
import { MeContext } from "../lib/me";
import { Icon, type IconName } from "./ui/Icon";
import Boundary from "./Boundary";

/** Where the collapsed state is kept between visits.
 *
 *  `localStorage`, and this is not the rule `auth.ts` breaks by refusing it: that rule is
 *  about **credentials**, which live in memory because a token in storage is a token an
 *  XSS can read. This is a boolean about how wide a column is. */
const COLLAPSED_KEY = "ui.sidebar";

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === "collapsed";
  } catch {
    // Private-mode Safari and a browser set to block site data both throw here rather
    // than returning null. A sidebar is not worth a blank page.
    return false;
  }
}

/** One place in the product, as a row you can click.
 *
 *  The label stays in the DOM when the rail is collapsed and is hidden by CSS, so the
 *  accessible name of the row is the same either way — a collapsed sidebar is a visual
 *  state, not a different navigation. */
function SideLink({
  to,
  icon,
  label,
  end,
}: {
  to: string;
  icon: IconName;
  label: string;
  end?: boolean;
}) {
  return (
    <NavLink
      to={to}
      end={end}
      title={label}
      className={({ isActive }) => (isActive ? "side-link on" : "side-link")}
    >
      <Icon name={icon} />
      <span className="side-label">{label}</span>
    </NavLink>
  );
}

/** The frame: where you are, who you are, and the way out.
 *
 * **Who you are is not decoration here.** Every screen behind this shows what one
 * specific person may reach, and two of this product's states — an empty agent list, and
 * an agent reachable only through a group — are indistinguishable from a bug unless the
 * reader is certain which account they are looking at. That is not hypothetical: step
 * 9a's verification silently tested the wrong person for a whole pass, because a token
 * is opaque and nothing said whose it was. `dev_token.py` now prints `this token is
 * for:` for the same reason this corner exists.
 *
 * **It is a column rather than a bar** because the administrative sections used to be a
 * second row of navigation drawn inside the page (`AdminNav`), which put two unrelated
 * kinds of "where am I" in two different places. A column has room for a labelled group,
 * so every place in the product is now in one list — and the pages below it stopped
 * having to draw their own navigation.
 */
export default function AppShell({ children }: { children: ReactNode }) {
  const session = useSyncExternalStore(subscribe, current);
  const claims = session.state === "in" ? session.claims : {};
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(readCollapsed);

  function toggle() {
    const next = !collapsed;
    setCollapsed(next);
    try {
      localStorage.setItem(COLLAPSED_KEY, next ? "collapsed" : "open");
    } catch {
      // The preference simply does not persist. Nothing about this screen depends on it.
    }
  }

  /** Whether to offer Administration, from `GET /me`.
   *
   *  **Fetched once here rather than on each administrative screen**, because the thing
   *  it decides is a nav item and the nav item is here. Not polled: a role changes when
   *  somebody runs a CLI command, which is not a rate this needs to keep up with.
   *
   *  **It fails closed and silently.** A `/me` that errors leaves the link absent and
   *  renders nothing about it — the shell is the frame around every other screen, and an
   *  error banner in it would cover the page somebody actually asked for with a failure
   *  about a nav item. Whoever is genuinely an administrator gets it on the next load,
   *  and the deep link still works, because the *server* decides who may read the log. */
  const { data: me, loading: meLoading } = useResource(() => api.me(), []);

  // The one `/me` in the application, shared with the route table (step 042). See
  // `lib/me.ts` for why this is a context rather than a prop from `App`.
  const meState = { me, settled: !meLoading };

  return (
    <MeContext.Provider value={meState}>
    <div className={collapsed ? "shell collapsed" : "shell"}>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="brand" title="carnet">
            carnet
          </span>
          <button
            className="rail-toggle"
            onClick={toggle}
            aria-expanded={!collapsed}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <Icon name={collapsed ? "expand" : "collapse"} />
          </button>
        </div>

        <nav className="sidebar-nav" aria-label="Main">
          <SideLink to="/agents" icon="agents" label="Agents" />
          {/* Last of the four, and it belongs in the navigation rather than under an
              account menu: **it is the only screen here about the person rather than
              about their agents**, and the thing it fixes — an agent that cannot reach
              somebody's data — is discovered while looking at an agent. A person sent
              here from an agent page needs to find their way back to it, which a nav item
              makes obvious and a buried settings page does not. */}
          <SideLink to="/connections" icon="connections" label="Connections" />
          {/* 035c, and **outside the administrative group on purpose**: everybody has
              tokens, or ought to be able to find out that they do not. `GET /me/tokens`
              is deliberately roleless — see `routes_admin.my_tokens` — so unlike the five
              links below, this one is not a courtesy that hides a 403. */}
          <SideLink to="/tokens" icon="tokens" label="Access tokens" />
          {/* **Moved out of the administrative group in 013c**, and the move is the
              feature rather than a tidy-up. The page answers two questions at two
              scopes: *what did my work cost*, which is roleless and everybody's, and
              *what came through the door*, which is the tenant's and stays admin-gated
              on the server. Offering it to everyone is therefore not a courtesy that
              hides a 403 — a non-administrator gets a real page, one section shorter. */}
          <SideLink to="/overview" icon="overview" label="Usage" />

          {/* Offered only to an administrator, and that is `your_role`'s lesson one level
              up: **a control that refuses the person who pressed it reads as a bug**, so a
              link to a page that answers 403 is worse than no link. The routes still exist
              for anybody who types them and still answer 403 with the server's sentence —
              hiding a nav item is a courtesy, and the authorization is on the server.

              The sections are here rather than inside the pages because that is where the
              rest of "where am I" lives. `end` on the first one so that reading the log
              does not light up the ones nested under it. */}
          {me?.admin && (
            <div className="sidebar-group">
              <span className="sidebar-group-label">Admin</span>
              {/* **Three glyphs, where these three shared one.** 035a and 035b each
                  reused `log` on the argument that three logs are three labels and not
                  three glyphs. That reads well and does not survive looking at the rail:
                  stacked, the three rows were identical but for their words, and the
                  glyph is what a person aims at once they have learned the app — it is
                  the only part of the row that survives a collapsed rail at all. So each
                  is drawn as the thing it is: authorization, traffic, refusal. */}
              <SideLink to="/admin" icon="admin" label="Audit log" end />
              <SideLink to="/admin/door-calls" icon="door" label="Request log" />
              <SideLink to="/admin/denials" icon="denied" label="Access denied" />
              <SideLink to="/admin/groups" icon="groups" label="Groups" />
              <SideLink to="/admin/connectors" icon="connectors" label="Connectors" />
            </div>
          )}
        </nav>

        <div className="sidebar-foot">
          {/* `email ?? sub` is right under both claim shapes this product meets: the
              Okta org puts the address in `sub` and the opaque id in `uid` (migration
              010), the local provider is spec-shaped — id in `sub`, address in `email`.
              The tooltip id is what appears in a run's `principal` and in the audit
              log, and somebody comparing the two needs both in front of them. */}
          <span
            className="whoami"
            title={claims.uid ? `user:${claims.uid}` : undefined}
          >
            {claims.email ?? claims.sub ?? "signed in"}
          </span>
          <button
            className="side-link signout"
            onClick={() => signOut("")}
            title="Clears the token held by this page. Your session at your identity provider stays open."
          >
            <Icon name="signout" />
            <span className="side-label">Sign out</span>
          </button>
        </div>
      </aside>

      {/* Keyed by path so a crash does not follow the person to the next page: the
          shell never remounts, so without the key the boundary would keep showing one
          page's wreckage over every page after it. */}
      <main>
        <Boundary key={location.pathname}>{children}</Boundary>
      </main>
    </div>
    </MeContext.Provider>
  );
}
