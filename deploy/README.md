# Deploying Carnet

This directory is the deployment: a compose file, the image it builds, and the front
door in front of it. It is written for the platform team running this in their own
cloud — which, for this product, is the normal case, not the exception.

```
                        443 (TLS terminates here)
                          │
                       ┌──▼───┐   /api/* (prefix stripped, body limits enforced)
        the bundle ◄───┤ front ├──────────────► api ──┐
                       └──────┘                       ├──► db (Postgres 16,
                                            migrate ──┘     bundled or yours)
```

Four services. `migrate` and `api` are one image in two roles — an agent here is a
row in the database, not a container, so there is no per-agent artifact and no
pipeline: deploying an agent is giving it a door, and this stack is the door.

## The shape, stated

Four things previous deployments improvised are decided in this file, and changing
them should be a deliberate edit:

- **What this stack is.** The MCP door: `/mcp`, the broker behind it, and the
  administration surface. It runs no agents itself and needs no model key — a
  brokered model call, where a deployment vets one, spends under that connector's own
  credential. The API is deliberately not replicated — its ceilings assume one
  process, and that assumption is written down rather than multiplied.
- **Where `CARNET_SECRET_KEY` comes from, and who holds it.** You generate it
  once (`.env.example` has the command), you hold it — in the same secret store as
  your database passwords — and the platform never keeps a copy. Every delegated
  credential is encrypted with it; losing it is losing all of them.
- **Who runs `--migrate`, and when.** The deployment itself, first, every time it
  comes up: `migrate` is a one-shot service and `api` waits for it to
  complete. Re-running is free (applied migrations are checksummed and skipped) and
  racing is safe (concurrent runners serialize on an advisory lock). The same role
  migrates and serves — `docs/UPGRADING.md` explains why that is a rule, not a
  convenience.

## Day one

```bash
cd deploy
cp .env.example .env
chmod 600 .env   # it is about to hold the master encryption key

# The key first, and NOT through compose: `compose` interpolates this whole file for
# every subcommand, so while the key is unset even `compose build` refuses — the
# remedy would need the thing it is the remedy for. Plain docker has no such loop,
# and it builds the same image compose goes on to use.
docker build -t carnet-api --target api -f Dockerfile ..
docker run --rm carnet-api carnet --generate-key

# put the key in your secret store, set it in .env, set CARNET_DOMAIN — and set
# CARNET_OIDC_ISSUER + CARNET_OIDC_CLIENT_ID to your identity provider
# (.env.example documents them; any OIDC provider, not only Okta).
#
# Set CARNET_BOOTSTRAP_ADMIN here too — the address that becomes this deployment's
# first administrator at their first login. It is read once, when the container starts,
# so it MUST be in .env before the `up` below: set afterwards it is simply not seen, and
# you land on a working sign-in with no administrator and nothing saying why.
docker compose up -d --build

# name the workspace and register the same identity provider with the API. The
# --issuer here and CARNET_OIDC_ISSUER above must name the same provider: the first
# is how the API verifies tokens, the second is how the browser obtains them.
docker compose exec api carnet --add-tenant default "Your Company"
docker compose exec api carnet --add-idp default \
    --issuer https://your-issuer.example.com \
    --jwks-uri https://your-issuer.example.com/oauth2/v1/keys \
    --audience your-client-id
# optionally, the shipped example agent:
docker compose exec api carnet --seed
```

Then open `https://<CARNET_DOMAIN>/` and sign in as the bootstrap-admin address. If
you forgot to set `CARNET_BOOTSTRAP_ADMIN` before the `up` above — or want to appoint
the first administrator by hand — set it in `.env` and `docker compose up -d` to restart
with it read, or grant the role directly:
`docker compose exec api carnet --grant-role admin <email>`.

**Upgrades:** `git pull && docker compose up -d --build`. The dependency graph runs
the migration before new code serves; `docs/UPGRADING.md` is the contract for what a
migration may and may not do to your database.

**What a build contains is pinned.** The image installs `deploy/requirements.lock`
with hashes verified, and every base image is pinned to its digest — so rebuilding a
commit yields the same artifact, byte for byte, which is what makes "what version are
you running" answerable. Upgrading a dependency or a base image is a deliberate edit:
the lock's header carries its own regeneration command, and the digests carry the date
they were taken.

## The other artefact: the same image, from a file

The stack above is the platform — people sign in, connect their own accounts, and
administer in the browser. The same `carnet-api` image is also the **fileborne door**
(step 098, plan 094): one container, one `carnet.yaml`, no database, no sign-in, no
browser, no `CARNET_SECRET_KEY`. Nothing in this directory is involved:

```bash
docker run --rm -p 8000:8000 \
  -v ./carnet.yaml:/carnet.yaml -e CARNET_FILE=/carnet.yaml \
  -e JIRA_TOKEN -e CARNET_TOKEN_LAPTOP \
  carnet-api
```

`CARNET_FILE` is the whole switch: set, the image reads the file into an in-memory
store and serves `/mcp` from it; unset, it is the API this compose file runs. The two
are refused together — a file beside a database is two expressions of the permission
model free to disagree. The repository's `carnet.example.yaml` carries every key, and
`scripts/e2e_file_door.py` drives this artefact the way `e2e_deploy.py` drives the
stack. What it does not have is everything the stack is for: accounts, per-person
credentials, the browser, and a log that outlives the process — its audit is the JSON
line on stdout and nothing else.

## Your Postgres instead of the bundled one

The bundled `db` service exists so the stack is complete on one machine. The intended
production database is yours — RDS, Cloud SQL, Azure, anything Postgres 16+. In
`.env`: delete `COMPOSE_PROFILES=bundled-db`, set `CARNET_DATABASE_URL`. Give
it a dedicated, empty database; the first `--migrate` in a cluster needs `CREATEROLE`
(your managed master user has it).

**A second deployment in the same cluster needs one `GRANT` first, and until it is run
the stack will not come up.** Staging beside production is the normal case here, and
it is the one that stops: migration 037 creates a role that is *cluster-global*, so
the second deployment's role finds it already there and — under PostgreSQL 16's rules —
may not grant itself a role it did not create. `migrate` exits non-zero naming the
remedy, and because everything waits on `migrate`, nothing else starts. Read it with
`docker compose logs migrate`; the fix is one line as your master user:

```sql
GRANT agent_runtime_tenant TO <the role in your CARNET_DATABASE_URL>;
```

Then `docker compose up -d` again. This is a refusal by design, not a bug: the
alternative is a deployment that starts and silently reads nobody's rows.

One property of the bundled database is deliberate and worth keeping if you replace
it: **nothing connects as a superuser.** The app role is `NOSUPERUSER` with
`CREATEROLE` — the same shape as a managed master user — because a superuser silently
bypasses row-level security, which makes an entire class of tenant-isolation defect
invisible until it reaches a customer's ordinary role.

## Your ingress instead of the front door

If TLS already terminates at your load balancer, drop the `front` service and have
your ingress reproduce its contract — the `Caddyfile` is short and is that contract:

1. Terminate TLS; speak plain HTTP only on a network this deployment owns.
2. Enforce the body limit on `/api/hooks/*` (64 KiB, `MAX_DELIVERY_BYTES`): it is the
   unauthenticated door, a chunked request has no Content-Length, and the app can
   only measure what it has already buffered — the refusal must happen in front.
3. Serve `frontend/dist` with an SPA fallback to `index.html`, forward `/api/*` to
   the API with the prefix stripped, and set `CARNET_PUBLIC_ORIGIN` to the
   external origin plus `/api`. **And forward `/.well-known/oauth-*` to the API with
   the path intact** (step 083): the door's OAuth discovery documents live at the
   origin root by RFC, and the SPA fallback answering them with `index.html` is
   the `/config.json` failure below at a new address.
4. Serve the two halves of browser sign-in, and keep them agreeing (plan 031):
   `/config.json` (`{"issuer": …, "client_id": …, "scopes": …}`, content type
   `application/json`, and a **real 404 when unconfigured** — never the SPA
   fallback, which is exactly the masking that once shipped a deployment nobody
   could sign into), and this Content-Security-Policy header on the bundle, with
   your provider's origin in `connect-src` and `frame-src`:

   ```
   default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
   img-src 'self' data:; connect-src 'self' https://<your-issuer-origin>;
   frame-src 'self' https://<your-issuer-origin>; base-uri 'none';
   form-action 'none'; object-src 'none'; frame-ancestors 'self'
   ```

   Three things about that header are load-bearing, and each of them is a way to get
   it subtly wrong:

   - **`<your-issuer-origin>` is an origin, not the issuer.** If your issuer is
     `https://acme.okta.com/oauth2/default`, the CSP source is
     `https://acme.okta.com` — a CSP source with a path means something else.
   - **If your provider's token endpoint is on a different host than its issuer, it
     needs naming too.** Google is the common case: issuer
     `https://accounts.google.com`, token endpoint `https://oauth2.googleapis.com`,
     and both must appear in `connect-src` or sign-in fails at the last step.
   - **Keep `frame-ancestors` at `'self'`, not `'none'`.** The app's silent sign-in
     renders its own `/login/callback` in an iframe; `'none'` blocks that and every
     silent re-entry with it, so people are asked to sign in on every page load.

   The bundle's own `<meta>` CSP deliberately carries only the provider-independent
   directives — a header cannot widen a meta policy (two policies enforce as their
   intersection), so the provider-dependent pair can only live in front.
   `deploy/frontdoor-entrypoint.sh` is the dozen lines that compose all of this from
   `CARNET_OIDC_*`; reproducing it is easier than rederiving it, and
   `scripts/e2e_browser_deploy.py` is what proves a real browser agrees.

5. Point anything that routes traffic at **`/api/health/ready`**, not `/api/health`.
   The first is readiness — one real database round trip, 503 with a sentence when
   the database does not answer — and the second is liveness, which deliberately
   reads nothing and stays green through a database outage. A load balancer draining
   on liveness keeps sending traffic to a deployment that can only refuse it.

The API trusts no forwarded header — `X-Forwarded-Host` does not change what it
builds, and client addresses live in the proxy's access log, not the app's. If your
ingress needs the app to see caller IPs someday, that is a two-file change discussed
in `docs/plans/030-deployment-artifacts.md`, decision 5.

## Deliberately absent

- **Helm and Terraform.** A chart waits for the first deployment that says
  Kubernetes; Terraform for the first that names a cloud. Either would mean guessing
  your ingress class, secret manager and database topology — ask, and it becomes a
  conversation instead of a guess.
- **A registry.** The images build from this checkout; publishing signed images is a
  step that arrives with the first team that cannot build.
- **A backup story beyond Postgres's own.** `db-data` (or your managed instance) is
  the deployment; dump it like any Postgres. `docs/UPGRADING.md` covers what a
  restore is promised to preserve.

`scripts/e2e_deploy.py` drives this stack end to end — TLS on, limits enforced,
prefix rewritten, no superuser serving, `/config.json` and the CSP agreeing — and is
the file to run after changing anything here. `scripts/e2e_browser_deploy.py` goes
the one step further no HTTP client can: a real browser signs into the deployed stack
against a non-Okta identity provider, under the CSP this front door actually serves.
CI runs both on every pull request (the `deploy` job in `tests.yml`, step 054), so a
change that breaks this artifact breaks the build rather than a customer's first
deploy.
