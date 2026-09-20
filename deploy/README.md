# Deploying Carnet

This directory is the deployment: a compose file, the image it builds, and the front
door in front of it. It is written for the platform team running this in their own
cloud or their own datacentre — which, for this product, is the normal case, not the
exception. If that datacentre has a proxy, an intercepting CA, an internal registry or
no internet at all, [`docs/OFFLINE.md`](../docs/OFFLINE.md) is the page for that, one
setting each; this one assumes the open internet and says where it does.

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
migration may and may not do to your database. (A sealed estate upgrades by loading the
next tarball and running `up -d` without `--build` — `docs/OFFLINE.md`.)

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

## Your own certificate

The front door gets its certificate one of three ways, chosen by `CARNET_TLS_MODE` in
`.env` (step 109):

- **`acme`** — the default, and what it has always done: a real `CARNET_DOMAIN` gets a
  public certificate from Let's Encrypt, which needs DNS pointing here and ports 80/443
  reachable from the internet; `localhost` is signed by Caddy's own CA.
- **`internal`** — Caddy's own CA for any name: a trial, or an intranet name Let's
  Encrypt cannot see. Browsers warn until that CA is trusted;
  `docker compose exec front cat /data/caddy/pki/authorities/local/root.crt` is the
  root to distribute.
- **`files`** — a certificate your own CA issued. Put `cert.pem` (the full chain) and
  `key.pem`, both PEM, in `./tls` beside `compose.yaml`, uncomment the `tls` volume on
  the `front` service, set the mode, and `docker compose up -d front`. ACME is never
  attempted. The certificate must name `CARNET_DOMAIN`: a mismatch is not a start-up
  refusal but a handshake failure, which the browser reports and the entrypoint cannot.

A missing file under `files` is refused at start, naming the mount — the same rule as
a half-declared identity provider, and for the same reason: serving anyway would fail
later, quieter, and in a browser.

## Your registry

The base images — node, python, caddy in the Dockerfile, postgres in the compose file —
are pinned to Docker Hub by digest. A policy that says images come from the company's
mirror is one line in `.env`, `CARNET_BASE_REGISTRY=harbor.corp/dockerhub`, and the
digests stay: a mirror preserves them, so the retargeted build pulls **the same bytes
from a different address**, which is both what makes the mirror trustworthy and why the
pins were never meant to be edited to get there. A path after the host is fine; the
`library/` in the image names follows the prefix, because that is where Docker Hub's
official images live in every mirror that proxies it. The published pair,
`ghcr.io/carnet-mcp/carnet` and `ghcr.io/carnet-mcp/carnet-front`, are the `api` and
`front` targets of this same Dockerfile and can be mirrored the same way; the stack
builds from the checkout by default and does not need them (see *Pulling rather than
building* below for when it should).

`CARNET_DB_IMAGE` is the other override and answers a different environment: the sealed
estate, where the images arrived in a tarball and the pinned digest cannot match an
image that has been near no registry. `docs/OFFLINE.md` says when to set it, and it is
never needed where a registry is reachable.

## Pulling rather than building

Everything above builds the two images from this checkout, which is right for a
platform team that reads the Dockerfile before running it. A team whose policy is *we
run what is published and never build* sets two lines in `.env` instead, both to one
version, and drops `--build`:

```bash
CARNET_API_IMAGE=ghcr.io/carnet-mcp/carnet:0.11.0
CARNET_FRONT_IMAGE=ghcr.io/carnet-mcp/carnet-front:0.11.0
```

```bash
docker compose pull
docker compose up -d
```

The images are signed keylessly by the release workflow; the README's *Verifying the
image* section is the command, and it applies to both names. The `build:` blocks stay
in the compose file on purpose — compose builds only when the named image is absent,
so a pulled image is never quietly rebuilt over — and unset, the two variables are the
names the checkout's own build produces, which is why nothing above had to change.
The key-generation line in *Day one* is the one place this matters: with the pair
pulled, it is `docker run --rm ghcr.io/carnet-mcp/carnet:0.11.0 carnet --generate-key`
and no `docker build`.

## Behind a corporate proxy

Set `CARNET_EGRESS_PROXY=http://proxy.corp:3128` (or `http://user:pass@…`) in `.env`
and every dial to the internet goes through it **by name** — the proxy resolves, which
is what a CONNECT proxy is for and why external names that do not resolve inside the
building still work. Your own networks (`CARNET_EGRESS_INTERNAL_HOSTS`) are dialled
direct and keep every check, so the internal Jira never touches the proxy. What the
declaration trades — the door's DNS-rebinding check on the resolved address moves to
the proxy — is stated in `backend/src/carnet/tools/mcp/egress.py`'s docstring, and it
is the right trade only for a proxy that already governs every outbound packet in the
building. `HTTPS_PROXY` and friends are never read; one of them set without this
refuses at start, naming it, because a Docker daemon's proxy config injects them into
every container and an operator who set them expects them to work. If the proxy
re-signs TLS, its root goes in `REQUESTS_CA_BUNDLE` above. And the proxy must not
buffer `text/event-stream`, or streamed completions hang until
`CARNET_MODEL_CHUNK_TIMEOUT` and fail.

## Your ingress instead of the front door

If TLS already terminates at your load balancer — most often because certificates are
issued and rotated somewhere the front door cannot see — drop the `front` service and
have your ingress reproduce its contract. The `Caddyfile` is short and is that
contract; read as one paragraph, it says:

Terminate TLS, and speak plain HTTP to the API only on a network this deployment owns.
Forward `/api/*` to `api:8000` with the `/api` prefix stripped, and forward
`/.well-known/oauth-*` to it with the path intact — the door's OAuth discovery
documents live at the origin root by RFC (step 083), and an SPA fallback answering
them with `index.html` is a JSON parse error about a server that is plainly up. Cap
request bodies on `/api/*` at something like 12 MiB: a backstop against the absurd,
not a boundary — the door's own per-call cap is far lower. Serve `frontend/dist` with
an SPA fallback to `index.html`, but answer a missing `/assets/*` file with a real 404
rather than the fallback, or a stale build reports a MIME type error pointing nowhere
near the cause. Serve the two halves of browser sign-in exactly as the next section
describes, with an unconfigured `/config.json` a real 404. **Do not buffer the
response body** (step 108): `/api/v1/chat/completions` streams a model's answer as
`text/event-stream` while it is still arriving, and an ingress that holds a body to
inspect it turns every streamed completion into a wait for the whole answer — nginx
needs `proxy_buffering off` on that path, and a response timeout shorter than
`CARNET_MODEL_MAX_SECONDS` ends completions early. Set `CARNET_PUBLIC_ORIGIN` to the
external origin plus `/api`, because the API reads no forwarded header. And point
whatever routes traffic at **`/api/health/ready`**, not `/api/health`: the first is
readiness — one real database round trip, 503 with a sentence when the database does
not answer — and the second is liveness, which deliberately reads nothing and stays
green through a database outage, so a load balancer draining on it keeps sending
traffic to a deployment that can only refuse.

The two halves of browser sign-in are the part worth reproducing exactly (plan 031):
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

The API trusts no forwarded header — `X-Forwarded-Host` does not change what it
builds, and client addresses live in the proxy's access log, not the app's. If your
ingress needs the app to see caller IPs someday, that is a two-file change discussed
in `docs/plans/030-deployment-artifacts.md`, decision 5.

## Deliberately absent

- **Helm and Terraform.** A chart waits for the first deployment that says
  Kubernetes; Terraform for the first that names a cloud. Either would mean guessing
  your ingress class, secret manager and database topology — ask, and it becomes a
  conversation instead of a guess.
- **A registry other than GHCR.** Both images are published there, signed and
  multi-architecture (`release.yml`, since step 110 the front door as well as the
  API). Docker Hub, a Helm chart's own registry, an image somebody else builds: none
  of it, until a customer's policy names a registry that cannot proxy GHCR.
- **An air-gapped update channel.** A sealed estate upgrades by carrying the next
  tarball in (`docs/OFFLINE.md`). A delta channel, a mirror of our releases, an update
  server — none of it, until a customer asks in words.
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
