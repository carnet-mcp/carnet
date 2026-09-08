/** The routes, and the gate in front of them.
 *
 * Sign in, agents, one agent, its versions — and **connections** and **tokens**, which
 * are the routes about the signed-in person rather than about an agent; **administration**,
 * which is about the workspace; and the consent screen an MCP client's OAuth flow lands
 * on. There is no run screen: a door call is not a run, and what it did is an audit row.
 * The gate is the interesting part — see `Gate` below.
 */

import { useEffect, useState, useSyncExternalStore } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from "react-router-dom";

import AppShell from "./components/AppShell";
import { Button, Notice, Spinner } from "./components/ui";
import AdminPage from "./features/admin/AdminPage";
import ConnectorDetailPage from "./features/admin/ConnectorDetailPage";
import ConnectorsPage from "./features/admin/ConnectorsPage";
import DenialsPage from "./features/admin/DenialsPage";
import DoorTrafficPage from "./features/admin/DoorTrafficPage";
import GroupsPage from "./features/admin/GroupsPage";
import OverviewPage from "./features/overview/OverviewPage";
import AgentDetailPage from "./features/agents/AgentDetailPage";
import AgentVersionPage from "./features/agents/AgentVersionPage";
import AgentsPage from "./features/agents/AgentsPage";
import EditAgentPage from "./features/agents/EditAgentPage";
import CreateAgentPage from "./features/agents/create/CreateAgentPage";
import ConnectionsPage from "./features/connections/ConnectionsPage";
import TokenDetailPage from "./features/tokens/TokenDetailPage";
import TokensPage from "./features/tokens/TokensPage";
import AuthorizePage from "./features/oauth/AuthorizePage";
import {
  CALLBACK_PATH,
  boot,
  completeSignIn,
  current,
  signIn,
  subscribe,
} from "./lib/auth";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Outside the gate: this is how somebody gets through it. */}
        <Route path={CALLBACK_PATH} element={<Callback />} />
        <Route
          path="*"
          element={
            <Gate>
              <AppShell>
                <Routes>
                  <Route path="/" element={<Navigate to="/agents" replace />} />
                  <Route path="/agents" element={<AgentsPage />} />
                  {/* Before `/agents/:name`, and it is not merely convention here: React
                      Router would otherwise match `new` as an agent called "new". The
                      server has the mirror of this problem and solves it differently —
                      `validate` is a reserved agent name, so no row can shadow the route.
                      Nothing reserves `new`, because this path never reaches the API. */}
                  <Route path="/agents/new" element={<CreateAgentPage />} />
                  <Route path="/agents/:name" element={<AgentDetailPage />} />
                  {/* After `:name`, unlike `/agents/new`: this one is a suffix rather
                      than a sibling, so no agent name can shadow it. */}
                  <Route path="/agents/:name/edit" element={<EditAgentPage />} />
                  {/* Step 021. A suffix like `/edit`, so no agent name shadows it — and
                      a URL rather than a panel because "look at what this said before you
                      changed it" is a link somebody sends. */}
                  <Route
                    path="/agents/:name/versions/:version"
                    element={<AgentVersionPage />}
                  />
                  <Route path="/connections" element={<ConnectionsPage />} />
                  {/* 035c. **Not admin-gated, and not under `/admin`** — the five routes
                      below are a workspace administrator's and this one is your own.
                      `GET /me/tokens` needs no role on purpose: the person who needs it
                      is a non-administrator picking among their own machines, and a role
                      in front of it would make the surface useless to exactly them. The
                      register's wide `GET /admin/tokens` — everyone's, for an operations
                      team — is a different listing and stays unbuilt. */}
                  <Route path="/tokens" element={<TokensPage />} />
                  {/* 035d. **A URL rather than a panel on the row**, which plan 035
                      wrote as "a section on the token row": what a credential reaches is
                      the thing somebody pastes into a channel during a review, and a
                      disclosure toggle has no address. A suffix like `/edit`, so no token
                      id can shadow it. */}
                  <Route path="/tokens/:tokenId" element={<TokenDetailPage />} />
                  {/* 083. The OAuth consent page — `authorization_endpoint` in the
                      door's `.well-known` document names this path at the origin. Inside
                      the gate on purpose: the person signs in with the provider they
                      already have, `signIn` returns to `pathname + search`, and the page
                      then has a session to consent with. The API has no route here. */}
                  <Route path="/oauth/authorize" element={<AuthorizePage />} />
                  {/* Behind a nav item only administrators see — and reachable by URL
                      for everybody, which is deliberate: the server answers 403 with a
                      sentence, and a route that 404'd for a non-admin would tell an
                      authenticated colleague this product has no administrative log.
                      That holds for all five of these: every one of them is 403 with a
                      sentence rather than a blank page, and `Failure` already says that
                      signing in again will not help. */}
                  {/* 041b. The overview — the door's window, drawn. The only screen
                      here that is not a list of records, and the one somebody arrives at
                      before they know which log they want. Its own URL for the reason
                      `/admin/door-calls` has one: this is what gets sent to a manager. */}
                  {/* `/overview` for everybody, 013c. `/admin/overview` still resolves
                      so a bookmark from before the move does not 404 — the page is the
                      same one and decides for itself what the reader may see. */}
                  <Route path="/overview" element={<OverviewPage />} />
                  <Route path="/admin/overview" element={<OverviewPage />} />
                  <Route path="/admin" element={<AdminPage />} />
                  {/* 035a. The MCP door's traffic — a reader over `audit`, filtered to
                      the rows a run can never have written. Its own route rather than a
                      tab on `/admin`, because an administrator sends this link to a
                      colleague during an incident and a tab index is not a URL. */}
                  <Route path="/admin/door-calls" element={<DoorTrafficPage />} />
                  {/* 035b. The access-denial log, whose route has been live since 015
                      and which nothing in a browser had ever called. Its own URL for
                      `/admin/door-calls`' reason: this is the link somebody sends during
                      an incident. */}
                  <Route path="/admin/denials" element={<DenialsPage />} />
                  {/* 12c. Sections rather than tabs, because an administrator sends these
                      links to each other — "look at what jira is offering" is a URL, and a
                      tab index is not one. */}
                  <Route path="/admin/groups" element={<GroupsPage />} />
                  <Route path="/admin/connectors" element={<ConnectorsPage />} />
                  <Route
                    path="/admin/connectors/:connectorId"
                    element={<ConnectorDetailPage />}
                  />
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </AppShell>
            </Gate>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

/** Nothing renders until there is a principal, and **the first thing tried is not a
 *  login screen.**
 *
 *  The token is in memory, so every reload starts with nothing — and if that meant a
 *  sign-in button, this app would prompt on every refresh and somebody would move the
 *  token to `localStorage` within a week to stop it. So a page load asks the provider
 *  for a token silently first. Somebody who still has a session at their provider — which
 *  is everybody, all day — sees a moment of "signing you in" and then the page.
 *
 *  A sign-in button is what is left when that fails, which is the genuine case: no
 *  session, or a provider that will not answer. */
function Gate({ children }: { children: React.ReactNode }) {
  const session = useSyncExternalStore(subscribe, current);

  useEffect(() => {
    if (session.state === "unknown") void boot();
  }, [session.state]);

  if (session.state === "unknown") {
    return (
      <div className="centered">
        <div className="signin">
          <Spinner label="Signing you in…" />
        </div>
      </div>
    );
  }

  if (session.state === "out") return <SignIn reason={session.reason} />;
  return <>{children}</>;
}

function SignIn({ reason }: { reason: string }) {
  const [going, setGoing] = useState(false);
  return (
    <div className="centered">
      <div className="signin">
        <h1 className="brand">carnet</h1>
        <p className="sentence">
          Sign in with your work account to see the agents that have been shared with
          you.
        </p>
        {reason && (
          <Notice tone="warn" title="You were signed out">
            <p className="sentence">{reason}</p>
          </Notice>
        )}
        <Button
          kind="primary"
          disabled={going}
          onClick={() => {
            setGoing(true);
            // **No argument, so it returns to wherever this gate appeared over.**
            // `signIn` already defaults to the current path, and passing "/agents"
            // threw that away: opening a link to an agent, or reloading its page,
            // signed you in and then dropped you on the list. Observed by reloading
            // `/agents/minimal`, which is the same way 10a's proxy collision was found.
            void signIn();
          }}
        >
          {going ? "Taking you to sign in…" : "Sign in"}
        </Button>
      </div>
    </div>
  );
}

/** The provider has sent somebody back here with a code. Exchange it and get out of the
 *  way — this screen should be visible for a few hundred milliseconds and never again. */
function Callback() {
  const navigate = useNavigate();
  const [failure, setFailure] = useState<string>("");

  useEffect(() => {
    completeSignIn()
      .then((returnTo) => navigate(returnTo, { replace: true }))
      .catch((error: unknown) =>
        setFailure(error instanceof Error ? error.message : String(error)),
      );
  }, [navigate]);

  return (
    <div className="centered">
      <div className="signin">
        {failure ? (
          <>
            <h1>Sign-in did not complete</h1>
            <Notice tone="bad">
              <p className="sentence">{failure}</p>
            </Notice>
            <a className="btn" href="/agents">
              Try again
            </a>
          </>
        ) : (
          <Spinner label="Finishing sign-in…" />
        )}
      </div>
    </div>
  );
}

function NotFound() {
  return (
    <div className="empty">
      <h2>No such page</h2>
      <p>
        <a href="/agents">Back to your agents</a>
      </p>
    </div>
  );
}
