# frontend

The UI. React 19 + TypeScript + Vite, its own project, its own build. It does not import
Python and does not read `var/`; it talks to the API over HTTP and to the customer's
identity provider directly. **No UI library, no CSS framework, no charting dependency** —
hand-written CSS over a design-token layer (`src/styles/`), and that has been declined
on purpose more than once.

What it is a screen for: the door. Agents (permission lists — a named set of tools, each
with a scope), the person's own connected accounts and tokens, the consent screen an MCP
client's OAuth flow lands on, and the administrative reads — the overview, door calls,
denials, groups, connectors. There is no run screen, because a door call is not a run:
what a call did is one audit row, and the door-calls page reads those.

```bash
npm install
npm run dev          # http://localhost:8080
npm run build        # -> dist/, static files anything can serve
npm run typecheck
npm run lint
npx vitest run
```

The whole product on one port, with a local identity provider and nothing to configure,
is `carnet --local` from `backend/` — it serves the built `dist/`. For the dev server
with hot reload, run the API beside it:

```bash
cd ../backend
source .env                 # CARNET_DATABASE_URL, CARNET_SECRET_KEY
uvicorn carnet.api:app    # port 8000
```

## Port 8080 is not a preference

`http://localhost:8080/login/callback` is the redirect URI **registered at the identity
provider**. Vite's default is 5173, and on 5173 the provider refuses the authorize
request with an error about the redirect URI that reads like a bug in this code.

So `vite.config.ts` sets `port: 8080, strictPort: true`. If 8080 is taken it fails to
start rather than quietly moving to 8081 and producing that error at a distance. The
usual culprit is a `dev_token.py` callback server that did not shut down, or a previous
`vite`.

## The API is reached under `/api`, and that is a bug fix

The API's paths are `/agents`, `/connections`, `/tokens`. **So are this app's routes.**
Served from one origin — which is the point of the dev proxy, and how this is deployed —
the server answers first:

```
clicking a link       React Router, never touches the server     the app
reloading the page    a real GET /agents/triage                  {"detail": "an Authorization: Bearer token is required"}
```

So the app worked perfectly until somebody pressed F5. The dev proxy forwards `/api/*`
and strips the prefix; a deployment does the same (`deploy/Caddyfile`, and
`localidp/edge.py` under `--local`). The API's own URLs stay clean for `curl`, the CLI
and any integration — the half that should not pay for the browser's problem.

The two OAuth discovery documents (`/.well-known/oauth-protected-resource` and
`/.well-known/oauth-authorization-server`) are the exception: the RFCs put them at the
origin root, so they are forwarded with the path intact. Without that the SPA fallback
answers them with `index.html` and a 200.

**Found by loading a URL instead of clicking to it**, and no test could have caught it:
every click-through path in the app avoids the server entirely.

## Configuration

The app learns its provider at runtime (`/config.json`, served by both front doors) and
falls back to these variables on the dev server. There is deliberately no hardcoded
default, and none of it is secret — a client id is public by design, and PKCE is what
makes a public client safe. The issuer is the provider's **issuer URL** — the same string
`--add-idp` registers — and the endpoints are resolved from its OIDC discovery document
(`{issuer}/.well-known/openid-configuration`), so any conformant provider works.

| Variable | Example |
| --- | --- |
| `VITE_OIDC_ISSUER` | `https://your-org.okta.com/oauth2/default` |
| `VITE_OIDC_CLIENT_ID` | the SPA client id registered at that provider |
| `VITE_OIDC_SCOPES` | `openid profile email` |
| `VITE_API_ORIGIN` | `http://127.0.0.1:8000` (dev proxy target only) |

The redirect URI is **derived from the origin**, not configured: two places to write a
URL is one place for them to disagree.

## What is where

```
src/lib/api.ts            the only module that calls the API. The 401 rule lives here.
src/lib/auth.ts           PKCE, the callback, silent renewal, sign-out
src/lib/me.ts             who is signed in, and what they may administer
src/lib/draft.ts          the create/edit form's draft, and `toConfig`, which emits a
                          permission list and nothing else
src/lib/types.ts          mirrors backend/src/carnet/api/schemas.py, by hand
src/lib/format.ts         timestamps, sizes, durations
src/lib/csp.ts            the policy the shipped index.html carries, tested
src/components/ui/        the primitives, and the hand-written charts; nothing here
                          knows what an agent is
src/features/agents/      the list, one agent, its versions, the create wizard, the
                          share sheet, the connect card (the snippet in eight dialects)
src/features/tokens/      the person's tokens: reach, simulate, budget
src/features/connections/ the person's connected accounts, and the consent flow
src/features/oauth/       the consent screen an MCP client's sign-in lands on
src/features/admin/       overview, door calls, denials, groups, connectors
```

## Decisions that will look like omissions

- **The access token is held in memory and nowhere else.** Not `localStorage`, not a
  cookie. It does not survive a reload and cannot be read from another tab — and **any
  script running in this page can read it**, which is decision 5's stated cost. The
  mitigation is `script-src 'self'` in `index.html`'s CSP and a refusal to add
  third-party scripts. The rest of the policy — `connect-src` and `frame-src`, which
  name the deployment's identity provider — is served as a header by the front door
  instead, because a bundle cannot know a customer's provider and a header can never
  widen a meta policy (plan 031). The upgrade is an HttpOnly session cookie, deferred
  with a trigger: the first enterprise security questionnaire.
- **A reload does not show a login screen.** It asks the provider for a token silently
  first (`prompt=none`, in a hidden iframe). If that meant a sign-in prompt on every
  refresh, somebody would move the token to `localStorage` within a week.
- **Renewal falls back to a full-page redirect**, because the iframe carries the
  provider's session cookie as a third-party cookie and browsers are in the middle of
  taking that away. The redirect costs the page, which is nearly free only because there
  is no client state to lose — anything typed and not submitted goes.
- **No state library and no cache.** The server is the state. Fetch on mount.
- **These types are hand-written from `schemas.py`.** Two definitions that can drift and
  nothing catches it. Generating them from the OpenAPI document is the fix and is
  deferred because it is a build step in front of the first line of UI.
- **An edit sends only what changed.** `PATCH /agents/{name}` takes a partial config
  merged at the top level, so a field the form does not know about survives an edit —
  `test_a_patch_that_omits_a_field_does_not_delete_it` holds it on the server side.

## Known limits

- **`GET /agents` is unpaginated**, like everything else. 500 agents renders 500 rows.
- **No mobile layout.** The users are staff at a desk. A scope cut, not a claim about the
  future.
- **A person cannot see why they have access** — a direct grant or a team — from the
  list. The share sheet says it for one agent; `--agent-access` says it for the CLI.
