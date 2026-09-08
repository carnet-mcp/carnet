# carnet

[![tests](https://github.com/carnet-mcp/carnet/actions/workflows/tests.yml/badge.svg)](https://github.com/carnet-mcp/carnet/actions/workflows/tests.yml)

**Carnet is an MCP tool.** Connect your own assistant to `/mcp`, and every tool call it
makes goes through a **broker** — scoped to that caller, under a credential the caller
never holds, revocable, metered and audited.

What it displaces is fifty personal tokens on fifty laptops. Distribution, not capability:
one endpoint instead of an unrevocable credential per employee.

`/mcp` serves **tool mode** — `tools/list` returns what a token may call, `tools/call`
runs one through the broker. It is the only mode; agent mode is withdrawn.

A client that speaks OAuth — Claude Desktop, Claude.ai, Cursor — connects with the URL
alone: the door serves the discovery documents, registers the client, sends the person to
sign in with the provider they already have and approve, and mints the token at the end
(step 083). A client that takes a header pastes a token from the tokens page. Either way
the credential is the same `art_` token: on the person's tokens page, revocable there,
dead when they are, and every call it makes is one audit row whose id the result carries
back in `_meta`.

**Governed means routed.** Every call routed through the door is governed, and the
audit log proves it. Calls an agent makes on its own — a direct vendor hit, its own
model call — are outside the door's sight; widening what *can* be routed is plan 045,
and the runtime that would make bypass impossible is registered future work, not an
implied capability.

> **The full premise is [docs/PREMISE.md](docs/PREMISE.md), and it outranks every other
> document here.** Two things it exists to keep straight: an **agent** is a *permission
> list* (a named set of tools and scopes — it is how the door decides what a caller may
> touch, and it cannot be removed), and **a door call is not a run** (it writes one
> `audit` row and nothing else — usage, adoption and governance all read `audit`).
>
> **What you can actually do with it, enumerated:** [docs/CAPABILITIES.md](docs/CAPABILITIES.md)
> — every CLI flag, HTTP route, `carnet.yaml` key, setting and screen, kept complete by a
> test rather than by memory.

## Layout

```
carnet/
├── backend/
│   ├── pyproject.toml              deps, entry point, pytest config
│   ├── src/carnet/
│   │   ├── config.py               paths, ceilings, settings — read once at import
│   │   ├── cli.py                  command-line entry point: onboarding, roles, tokens, connectors
│   │   ├── bootstrap.py            wiring: choose a store, seed the shipped examples
│   │   ├── door.py                 the MCP door: what a token may call, and calling it
│   │   ├── maintenance.py          the log sweep: partitions and retention
│   │   ├── metrics.py              in-process counters for GET /metrics
│   │   ├── rotation.py             finishing a key rotation
│   │   ├── api/                    the HTTP entry point
│   │   │   ├── __init__.py         the app, the lifespan, the def-not-async rule
│   │   │   ├── deps.py             where a request becomes a Principal
│   │   │   ├── errors.py           which failure becomes which status code
│   │   │   ├── schemas.py          the OpenAPI surface
│   │   │   ├── routes_mcp.py       /mcp — the door, speaking MCP
│   │   │   ├── routes_agents.py    permission lists: create, edit, share, history
│   │   │   ├── routes_tools.py     the catalogue
│   │   │   ├── routes_connections.py  a person's own connected accounts
│   │   │   ├── routes_groups.py
│   │   │   ├── routes_admin.py     /me, tokens, the overview, the logs
│   │   │   └── routes_admin_connectors.py  registering and vetting connectors
│   │   ├── access/                 who a caller is: OIDC, users, groups, roles, grants, tokens
│   │   ├── core/                   the broker — knows no tool, no agent
│   │   │   ├── broker.py           the only path from a caller to a tool
│   │   │   ├── permissions.py      may this agent, for this principal, do this?
│   │   │   ├── patterns.py         resource pattern matching
│   │   │   ├── limits.py           has this call already done too much?
│   │   │   ├── credentials.py      the only module that reads secrets
│   │   │   ├── vault.py            a credential resolved from the customer's vault
│   │   │   ├── crypto.py           the only module that holds a key
│   │   │   ├── principal.py        who a call is made for, and for which tenant
│   │   │   ├── context.py          the call: id, principal, budget
│   │   │   ├── usage.py            what a brokered model call cost
│   │   │   ├── audit.py            what happened?
│   │   │   └── audit_query.py      reading it back
│   │   ├── tools/                  one module per tool family
│   │   │   ├── base.py             the Tool and Resource types
│   │   │   ├── validation.py       descriptor rules (used by both registries)
│   │   │   ├── messaging.py
│   │   │   ├── rest/               REST connectors, and the model connector
│   │   │   └── mcp/                connectors: vetted MCP servers
│   │   │       ├── __init__.py     per-tenant connector loading, connect()
│   │   │       ├── transport.py    how messages reach a server (stdio and HTTP)
│   │   │       ├── client.py       the protocol subset + session pool
│   │   │       ├── binding.py      the allowlist: manifest × advertisement
│   │   │       ├── egress.py       which hosts a tenant will let us dial
│   │   │       └── connectors/
│   │   │           └── github.py   the GitHub vetting manifest (seed data)
│   │   ├── agents/
│   │   │   └── __init__.py         the loader: save/get/load + validation
│   │   ├── localidp/               `carnet --local`: a real OIDC provider on your machine
│   │   └── storage/
│   │       ├── __init__.py         configure() / active() — one store per process
│   │       ├── base.py             the Storage protocol
│   │       ├── memory.py           in-memory — what the tests run against
│   │       ├── postgres.py         psycopg3, raw SQL
│   │       ├── migrate.py          numbered SQL, applied in order
│   │       └── migrations/         001_tenants … 052_scim
│   ├── scripts/                    end-to-end checks against real Postgres and real servers
│   └── tests/
│       ├── conftest.py             isolated var dir + a fresh store per test
│       ├── test_door.py            /mcp, end to end through the broker
│       ├── test_broker.py          the enforcement boundary
│       ├── test_tenancy.py         one customer's data is not another's
│       ├── test_storage_contract.py  both implementations, same assertions
│       ├── test_agents.py          validation at write time and load time
│       ├── test_permissions.py     capability and reach
│       ├── test_patterns.py        the matcher
│       ├── test_mcp.py             protocol subset and the allowlist
│       ├── test_transport_http.py  did this maybe happen?
│       ├── test_limits.py          the budget dials
│       ├── test_tools.py           descriptor validation
│       ├── test_credentials.py     lookup key, injected-kwarg contract
│       ├── test_api.py             the entry point, and where the tenant comes from
│       └── test_concurrency.py     what a second thread breaks
├── frontend/                       React 19 + Vite, hand-written CSS
├── deploy/                         compose, the image, the front door
└── var/                            runtime artifacts (gitignored)
```

`tools/__init__.py` is the two-registry module described below, and `core/__init__.py`
re-exports the handful of names entry points need.

**Layering rule.** Each layer imports downward, never upward:

```
cli / (api)   entry points — construct the principal, carry the tenant
agents/       who exists and what they may do   (config only)
core/         the broker                        (knows no tool, no agent)
tools/        what can actually be done         (knows no agent, no policy)
storage/      rows in, rows out                 (knows no agent, no tool, no policy)
config.py     paths, defaults, limits           (knows nothing)
```

Storage sits *below* `tools/` rather than inside `core/`, and the placement is forced:
`core/` is forbidden from knowing what an agent is, while the agent loader needs the
store. Putting it underneath keeps every import pointing downward.

`bootstrap.py` is the exception that proves the rule — it imports across layers
because composing them is exactly what an entry point is for.

The one invariant worth protecting: **nothing outside `core/` may call a tool
implementation directly.** There is no `execute_tool` helper and no public dispatch —
the only route is `core.broker.call`, which is where permissions, credentials, and
audit are enforced. An import of a tool implementation outside `core/` or `tests/` is a bug.

`api/` was an empty growth slot from the first commit and is now the second entry
point. Remaining slots: more modules under `tools/` and `agents/`, and `frontend/` as
its own project with its own build.

## Run

Carnet is one image and two ways to run it. **Free brokers a person's own account
safely; paid is what an organisation needs to administer many of them.** Both of the
free shapes are below, smallest first.

### The fileborne door — a file and `docker run`

No database, no sign-in, no browser. One file is the door's whole administration: the
servers it fronts, the tools it exposes from each, the agents (permission lists) that
bound them, and the tokens that may call them. Every secret is a `${VARIABLE}` pointer
into the environment — a literal is refused — so the file is safe to commit.

```bash
cp carnet.example.yaml carnet.yaml       # edit: your servers, your tools
carnet --new-token                       # prints a token once; put it in a variable
export CARNET_TOKEN_LAPTOP=art_m_…       # the variable carnet.yaml names
export JIRA_TOKEN=…                      # the credential the door presents to Jira

docker run --rm -p 8000:8000 \
  -v ./carnet.yaml:/carnet.yaml -e CARNET_FILE=/carnet.yaml \
  -e JIRA_TOKEN -e CARNET_TOKEN_LAPTOP \
  ghcr.io/carnet-mcp/carnet
```

Then give your assistant `http://localhost:8000/mcp` with `Authorization: Bearer <the
token>` — Claude Code, Cursor, anything that takes a header. `tools/list` is exactly
what the token's agents grant; ask for a tool that is not in the file and the call is
refused with a reason. **Every call and every refusal is one JSON line on the
container's stdout** — who, which tool, which arguments, the decision, the latency —
for whatever already reads your logs.

`carnet --check-file carnet.yaml` validates a file before you run it, naming the key on
every refusal. `carnet --discover <connector>` dials a server and prints the `tools:`
block to paste, with every argument name and a proposed effect. A server on this machine
needs one more line — `-e CARNET_EGRESS_INTERNAL_HOSTS=host.docker.internal` — because
the door refuses plain http and private addresses unless you consent to the host. Until
the first release is published, build the image from the checkout:
`docker build -t ghcr.io/carnet-mcp/carnet --target api -f deploy/Dockerfile .`

The fileborne door speaks for one shared account per server. **Per-person identity —
each person's calls going out as their own account — is free too**, and it is the
platform artefact below: the same image with a database, where people sign in and
connect their own accounts. `CARNET_OPEN_ADMIN=on` there lets every signed-in member
administer it, for a team that trusts itself.

### The whole product, one machine

**The whole product, one command.** Starts Postgres (a private cluster, or
`CARNET_DATABASE_URL` if set), the API, the built frontend and a local
email + password identity provider, then prints a URL. Sign in with an account
you create on the way in; the first account becomes the administrator.

```bash
cd backend
pip install -e ".[dev,postgres,access]"

carnet --local            # then open the URL it prints
```

**The door needs no model key.** A deployment is `/mcp` and the things it scopes by —
agents, connectors, connections, tokens, groups, the administrative reads — and nothing in
it enters a model loop. Where a brokered call reaches a model, it does so through a
connector the tenant vetted, under that connector's own credential.

The identity provider is a real OIDC provider this machine runs — the API verifies
its tokens exactly as it would verify Okta's, same code, same checks. It is not a
bypass: there is no way to a token but a password the provider checked. State lives
in `var/local/`; `--registration closed` shuts the sign-up form once your team is
aboard, and `--host` binds wider than loopback only if you type it (put TLS in
front first). An enterprise IdP is one `--add-idp` away — see **The trust boundary**.

### The CLI alone

With nothing installed and nothing running:

```bash
cd backend
pip install -e ".[dev]"          # installs the `carnet` command

carnet --list             # agents and their grants
carnet --list-tools       # every tool this tenant may grant, with its effect

carnet --admin-log            # who granted, revoked or deleted what
carnet --denials              # who tried, and was refused

carnet --grant-role admin priya@acme.com   # who may administer this tenant
carnet --list-roles                        # ... and who does
```

Agents and connectors are rows, not modules. With no database configured the CLI runs
against an **in-memory store seeded from the shipped modules**, so a fresh clone works
with nothing installed and nothing running — and nothing survives the process.

Against a real database:

```bash
pip install -e ".[dev,postgres]"
export CARNET_DATABASE_URL=postgresql://localhost/carnet

carnet --migrate          # apply pending schema migrations
carnet --seed             # write the shipped agent + connector into the tenant
carnet --list             # now loaded from Postgres
```

`--seed` is explicit and separate on purpose. An in-memory store is seeded on the way
up because otherwise there is nothing to look at; a real database is not, because its
contents are the customer's and overwriting them on every start would be astonishing.
It is safe to re-run, and **never overwrites a configuration a human wrote** — an agent
you have edited, or one of your own that has taken a shipped name, is left alone and
named in the output.

**Upgrading an existing database is [docs/UPGRADING.md](docs/UPGRADING.md)** — what the
migrations promise, the minimum PostgreSQL version, why the database must be a dedicated
one, what to do when a migration fails, and how long the big ones take.

`CARNET_TENANT` picks the tenant the CLI acts for; it defaults to
`default`.

### Bringing your own MCP server

**The platform does not ship integrations.** Customers bring their own MCP servers for
their own systems; the product is the safety layer around arbitrary connectors, not the
connectors. Until step 012 that claim was conditional — a connector was a Python module
in this repository, so adding Jira to a customer's deployment was a change to our source
and a release of our product. It is now four commands their own engineer runs — or, on
the fileborne door, four keys in `carnet.yaml`, which expresses exactly these four acts
(allow the host, register, approve each tool, scope) as one document.

```bash
carnet --allow-host mcp.acme-internal.com   # or nothing will be dialled
carnet --add-connector jira \
    --url https://mcp.acme-internal.com/mcp \
    --credential-env JIRA_TOKEN \
    --description "Jira, issues only"

carnet --connect-account jira priya@acme.com        # a server will not list its
                                                      # tools to an anonymous caller
carnet --discover jira        # what it offers, with each tool's input schema
carnet --vet jira --tool create_issue --effect write \
    --resource jira.project=projectKey \
    --note "Creates a ticket somebody will be paged about."

carnet --list-tools           # it is in the catalogue now, and in the form
```

The order is forced rather than chosen. A credential cannot be sealed against a
connector that does not exist (migration 021), and discovery needs a credential — so
*connect, look, then decide whether to register* is not expressible, and the row comes
first. `--add-connector` therefore **vets nothing**: registering a server and approving
one of its tools are two commands because they are two judgments, made at two times, by
somebody who read a schema in between.

**`--discover` printing the input schema is the part that matters.** The argument names
are the only place anybody can find out what to put in `--resource`, and without them
the flag is a guess that fails at the first run. This is also the step's irreducible
difficulty: somebody has to read that schema and decide which argument carries the
identifier. No interface removes that, which is why 001 made connector onboarding a
different persona from agent creation.

**A registered connector must speak HTTP.** `--seed`'s connectors keep stdio; the
distinction is not transport but provenance — code we ship versus code a customer names.
The reason is that a stdio server takes its credential from the environment at launch
and holds it for the process's life, so it cannot act as two people: every user of every
agent would share one service account, and delegated credentials are what step 7a built.
A customer whose server speaks stdio does not have to rewrite it — they have to host it,
with `mcp-proxy`, `supergateway`, or one line of their MCP SDK.

### A credential we do not hold

`--credential-env` names a variable in **this deployment's** environment. Some customers
would rather the platform did not hold their secret at all, and since step 070 it does not
have to:

```bash
carnet --add-connector jira \
    --url https://mcp.acme-internal.com/mcp \
    --credential-ref 'op://Engineering/Jira Deploy Key/credential'

carnet --check-credential jira      # does it resolve? Never prints the value
```

The connector row stores the **location**, not the secret. Every call resolves it through
the deployment's 1Password Connect service account and forgets it — nothing is written to
disk or to the database, and a referenced credential is not in `--finish-rotation`'s
population because nothing was sealed. The audit row is **identical** to an
environment-variable call: `credential` records whose account a call went out as, and that
is the same organisational account either way.

Set the deployment's vault in `backend/.env`, beside `CARNET_SECRET_KEY`:

```
CARNET_VAULT_URL=https://vault.acme-internal.com
CARNET_VAULT_TOKEN=<1Password Connect service-account token>
CARNET_VAULT_TIMEOUT_SECONDS=3        # a budget for the WHOLE resolution, not per hop
```

**What this buys, said precisely.** Not *we cannot read your keys* — the service-account
token above can read every item behind every pointer, and any vault integration that
resolves at request time has that property. It is: *the secret is not at rest in our
database, and its lifetime in our process is one call* — for a REST connector. For an
HTTP MCP connector it lives as long as the pooled session, up to
`CARNET_MCP_SESSION_IDLE_TTL` idle, because the session is keyed by the credential and
carries it in its headers; a rotation at the vault reaches such a connector when its
session is evicted, not on the next call.

**What it costs.** One to three requests to your vault on **every call**, and there is no
cache — a cached secret is a held secret, and a customer who rotates an item expects the
next call to use it rather than the next minute's. A reference written with **ids** costs
one request; one written with names costs three, because the list endpoints do not return
field values:

```
op://bbbbbbbbbbbbbbbbbbbbbbbbbb/aaaaaaaaaaaaaaaaaaaaaaaaaa/credential   1 request
op://Engineering/Jira Deploy Key/credential                             3 requests
```

Use ids for a connector on a hot path, and for any vault or item whose name contains `"`
or `\` — those cannot be carried in a Connect filter and are refused by name. And a
connector whose credential is a reference
**stops working while your vault is down** — the refusal says so, naming the vault and the
item rather than reading as a broken credential, because *reconnect your account* is the
wrong fix and the expensive one.

`--credential-env` and `--credential-ref` are mutually exclusive: there is no rule for
which would win, and inventing one would decide which secret leaves the building. A field
is matched by its **label**, then its id, then its 1Password purpose — write
`op://vault/item/section/field` when an item carries the same label twice.

A plain-http `CARNET_VAULT_URL` is refused at start-up unless its host is named in
`CARNET_EGRESS_INTERNAL_HOSTS`: the Connect token goes out on every call, and the vault
dial is under the operator's consent rather than a tenant's allowlist.

**Nothing is dialled to a host nobody approved.** The allowlist is per tenant, keyed on
the host and not the URL — a path is not a security boundary — and **an empty allowlist
denies**, which is the state every new customer starts in. Loopback, link-local and
private addresses are refused whatever a tenant approves, because a customer cannot
consent on behalf of a network that is not theirs. The check is in `_transport_for`, the
one place a transport is built.

```bash
carnet --list-hosts           # which hosts, approved by whom, and when
carnet --revoke-host mcp.acme-internal.com
```

### Recipes, for the vendors people ask for

The four commands above are the honest cost of a connector nobody here has ever seen. For
the handful of vendors that come up in every trial, a **recipe** fills them in:

```bash
carnet --list-recipes                    # what this build ships, and when each was checked
carnet --allow-host mcp.atlassian.com    # still yours. A recipe never approves a host
carnet --allow-host auth.atlassian.com
carnet --add-connector jira --from-recipe atlassian-jira
carnet --set-oauth jira --from-recipe atlassian-jira --client-id <yours>
carnet --vet jira --tool <name> --effect read|write ...   # still one at a time
```

**A recipe pre-fills and decides nothing**, and the three things it will not do are the
three worth stating:

- **It vets no tool.** A recipe may *propose* an `effect`, a scope and a binding; a person
  still approves each one. A vendor asserting its own `effect` is exactly what the review
  record exists to refuse.
- **It approves no host.** It *names* the hosts it needs, with a sentence for each, and
  the screen offers them — approving stays a separate act by somebody who can make it.
- **It carries no client id and no client secret.** The one field a recipe cannot fill is
  the one that identifies you to the vendor: the OAuth application is yours, created in
  the vendor's own console.

Recipes are files in this repository, reviewed like code. There is no registry, no upload
and no third-party publishing. **Nothing in the database points back at one** — a
recipe-registered connector is byte-identical to a hand-registered one — which is what
lets a preset that stops being true be deleted rather than carried.

Each says when somebody here last completed a consent flow against that vendor, and the
picker renders it. `not checked` means nobody has: the values are a starting point and
every one of them is editable before you register. See
`docs/plans/068-a-preset-that-fills-and-never-approves.md` for how many we are willing to
carry and why.

Revoking a host leaves its connectors registered and stops them connecting. Deleting
them would destroy the record of which tools somebody approved.

There is **no HTTP route for any of this**, and until step 12b there could not be one:
it needed a tenant-admin role, the same wall group administration (9a) and the
administrative log (11) hit. See `docs/plans/012-connector-registration.md`, decision 1.
The role exists now — a vetting screen is 12c, and these commands stay because a *screen*
was what was missing rather than a route.

### Asking what a token reaches, before it reaches it

A token sees the union of the tools of the agents it is granted, **each tool keeping its
own agent's scope**. So a person holding three grants cannot work out their own reach on
paper, and until step 069 the only way to find out was to make the call and read the
refusal.

Two readers, and neither presents the token, opens a session, resolves a credential or
writes a record anywhere:

```bash
carnet --reach m_1a2b3c            # every tool, the agents that grant it, the patterns
carnet --simulate m_1a2b3c \
    --call github_mcp_search_issues \
    --arg owner=acme --arg repo=web  # allowed or refused, and which rule decided
```

```
REFUSED  github_mcp_search_issues  for API token 'm_1a2b3c'
  arguments: owner=acme, repo=web

  recorded under: security-triage
  rule:          outside_scope
  reason:        github.repo 'acme/web' is outside this agent's 'read' scope. Allowed: acme/secrets

  Every granted agent that carries this tool:
    security-triage — refuses
        github.repo 'acme/web' is outside this agent's 'read' scope. Allowed: acme/secrets
    triage — refuses
        github.repo 'acme/web' is outside this agent's 'read' scope. Allowed: other/*

  Not checked: authentication, binding, acting-for, credential, budget.
```

The list is the answer, not the verdict. A verdict is what you could have got by making
the call; *every one of my grants said no, and here is each one's reason* is what you
could not.

`GET /me/tokens/{id}/reach` and `POST /me/tokens/{id}/simulate` are the same two answers
over HTTP, for the token's owner or an administrator, and the token page renders both.

Three things it will not do:

- **It does not use a second matcher.** Both call `door._granted_agents`,
  `door._candidates` and `door._adjudicate` — the functions `tools/call` runs — with the
  tool never executed. A simulator with its own copy of the rules is a second opinion
  about permission, and the first time they disagree the simulator is believed.
- **It answers about a policy, never about a system.** Every input is a row in this
  database, so it cannot report whether a repository exists, whether an account is
  connected, or whether a server is up. A token you may not aim is refused in the sentence
  a token that does not exist is refused in.
- **It stops at permission and says so.** `Not checked` is part of the answer:
  authentication, binding, the acting-for gate, the credential and the daily budget are
  five other questions with five other places to read them.

See `docs/plans/069-the-same-verdict-without-the-call.md`, which also carries the argument
for why a simulation writes no record of itself.

### Brokering a model, whoever your provider is

An outside agent wired to this door today holds **two** secrets: its Carnet token and
its own model API key. The second is exactly the shape this product exists to displace —
a vendor credential on a laptop, unrevocable, unmetered, unrecorded. A model API is a
REST API, a model name is a resource and token usage is a field in a response, so
brokering one needs no model-specific machinery: it is a `--kind rest` connector, vetted
like anything else.

**The provider is your choice, not ours.** Nothing here ships a provider and none is
special. Two are written out below precisely so neither reads as *the supported one*.

```bash
# OpenAI: Authorization: Bearer, which is the default, so neither flag appears.
carnet --allow-host api.openai.com
carnet --add-connector openai --kind rest \
    --url https://api.openai.com \
    --credential-env OPENAI_BROKERED_KEY \
    --description "OpenAI, chat completions only"
carnet --vet openai --tool chat --effect write \
    --method POST --path /v1/chat/completions \
    --schema ./openai-chat.schema.json \
    --body model --body messages --body max_tokens \
    --resource openai.model=model \
    --redact-arg messages \
    --usage-map '{"model": "model",
                  "input_tokens": "usage.prompt_tokens",
                  "output_tokens": "usage.completion_tokens"}' \
    --tool-description "Think with an OpenAI model."
```

```bash
# Anthropic: its own header, no prefix at all, and a required version header.
carnet --allow-host api.anthropic.com
carnet --add-connector anthropic --kind rest \
    --url https://api.anthropic.com \
    --credential-env ANTHROPIC_BROKERED_KEY \
    --credential-header x-api-key --credential-prefix "" \
    --header anthropic-version=2023-06-01 \
    --description "Anthropic, the Messages API"
carnet --vet anthropic --tool chat --effect write \
    --method POST --path /v1/messages \
    --schema ./anthropic-messages.schema.json \
    --body model --body messages --body max_tokens \
    --resource anthropic.model=model \
    --redact-arg messages --redact-arg system \
    --usage-map '{"model": "model",
                  "input_tokens": "usage.input_tokens",
                  "output_tokens": "usage.output_tokens",
                  "cache_read_tokens": "usage.cache_read_input_tokens",
                  "cache_write_tokens": "usage.cache_creation_input_tokens"}' \
    --tool-description "Think with an Anthropic model."
```

Everything that differs between the two is something the vendor's own documentation
decides: where the credential goes, what the path is, and what the vendor calls its token
counters. The broker, the door, the scope matcher and the audit row never learn what a
model is.

**`ANTHROPIC_BROKERED_KEY`, not `ANTHROPIC_API_KEY`.** A connector may name its own
credential variable, but not the platform's: `core/credentials.PLATFORM_SECRETS` refuses
`ANTHROPIC_API_KEY` when the call goes to fetch it, so a connector registered against it
can be written and can never be called. Nothing in this tree reads that name; it is
reserved so it can never enter connector machinery. Providers with no platform-side counterpart get their own variable
anyway, for symmetry.

**A schema is the contract, and what it omits is refused.** The vetter authors it, so a
caller that sends `stream: true` is refused before the vendor is dialled, and so is any
argument the schema does not carry. That is 045a's rule and it is doing real work here:
this door is JSON-only, and a chat pipe is not what this tool is for.

#### The scope line is a model list, per provider

```json
"permissions": {
  "tools": ["openai_chat", "anthropic_chat"],
  "scope": {
    "openai.model":    {"write": ["gpt-5-mini"]},
    "anthropic.model": {"write": ["*"]}
  }
}
```

Namespaced per provider rather than one shared `llm.model`, and the reason is the
wildcard: `*` matches a single whole segment, so under a shared type `{"write": ["*"]}`
would grant every model on **every** provider the tenant has registered, including one
registered next month. Namespaced, it means *any model from this one vendor*, which is a
sentence somebody can defend in a review. The cost is one scope line per provider.

A model id has no separators, so the matcher's **wildcard** cannot express a *family*:
`claude-haiku-*` is one segment equal to nothing and matches no id. That is the
deliberate refusal behind `core/patterns.py` — a prefix wildcard is how `org/*` comes to
match `org-evil/repo` — and it has not been softened.

**A scope line can name a family, because the identifier answers to one.** The vetter
declares what a vendor's families are called, and a scope may then say either:

```json
"anthropic.model": {"write": ["haiku"]}
```

which admits `claude-haiku-4-5-20251001` and the dated id the vendor ships next quarter,
and still refuses `claude-opus-5`. The families come from the approval, not from a
wildcard:

```
carnet --vet anthropic --tool chat ... \
    --resource anthropic.model=model \
    --resource-family anthropic.model=opus,sonnet,haiku
```

A family matches as a contiguous run of whole `-`-delimited tokens, so `gpt-5` covers
`gpt-5-mini` and does not cover `gpt-4-5`, and `pt-5` covers nothing. **The shipped model
recipes declare their vendors' families**, so a connector registered from one can express
this on the first day. A connector vetted before this existed declares none, and a family
scope against it refuses until it is vetted again — nothing widens a stored policy by
upgrading.

A scope naming an exact dated id still means exactly that id, and still fails closed on
the vendor's next release. That is the right behaviour for a policy that named one; the
family is there so a policy does not have to.

#### Prices are yours, and so is what an unpriced model costs you

`core/usage.RATES` is a dated snapshot of three Anthropic families. There are two ways to
correct it, and the more useful one belongs to whoever registered the vendor's key:

```
carnet --vet openai --tool chat ... --pricing '{"gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0}}'
```

That price rides on the connector's own binding, beside the `usage_map` that says where
the counters are — the same vendor, the same approval, the same person — so a customer
brokering a second provider does not need anybody to edit a file on the server.

Point `CARNET_MODEL_RATES` at your own file and it replaces the built-in table entirely
— **keys included** — and outranks a connector's price where both name the same model:
somebody who set that variable did so because the defaults are wrong for their contract,
which is a statement about the deployment. The keys are matched as substrings of a model
id, longest key first:

```json
{
  "gpt-5":         {"input": 1.25, "output": 10.00, "cache_read": 0.125, "cache_write": 0.00},
  "claude-opus-5": {"input": 15.00, "output": 75.00, "cache_read": 1.50, "cache_write": 18.75}
}
```

All four rates are required per key — a table with three of them prices the fourth kind
of token at nothing and reports a total that looks whole. Refused with a sentence naming
the file: a top level that is not an object, an empty key (it is a substring of every
model id), a rate entry that is not an object, a rate that is not a number (`true` is
not — it would price a million tokens at a dollar), and a **negative** rate, which is the
one nothing else would ever report: spend falls as tokens are used, so a dollar ceiling
is never reached and a deployment that believes it has one does not. A zero rate is
legitimate and an empty table is not an error.

A malformed file is refused on a *report* rather than silently replaced by ours. On the
*ceilings* it degrades to list prices with a loud log line instead, because a typo in a
JSON file must not refuse a customer's whole day.

**A model no key matches is reported as unpriced, never billed at some other model's
rate.** Its tokens are recorded and counted, it costs `$0.00` against
`CARNET_MCP_USD_PER_DAY`, and it is **named** — on `GET /me/tokens/{id}/budget`, on the
Overview, and in the token-ceiling refusal, which is the one such a model will actually
meet — with the remedy, which is to add the id to this file. The call is not refused: a
new model id appearing mid-day must not stop an agent working, and refusing would make
the rate file a release dependency.

So: **a dollar ceiling is only as complete as the rate table, and
`CARNET_MCP_TOKENS_PER_DAY` is the one that bounds an unpriced provider.** It needs no
rates at all, which is why it should be set whenever the dollar ceiling is. Whichever is
met first refuses, and the refusal says which.

#### Four things worth knowing before you wire an agent to this

- **The prompt is hashed in the audit log, not stored.** `--redact-arg messages` is what
  does it, and it is in both recipes on purpose: every brokered call writes one row to an
  append-only table, and without it that row holds the whole conversation forever.
- **Counters gate ceilings and draw dashboards; the invoice is the vendor's.** These are
  the numbers the vendor reported, not a bill, and money is never stored — figures are
  priced at read time, so correcting the rate file reprices the history.
- **Priced by the id that was requested.** A vendor alias that resolves elsewhere is
  recorded under the served id and mispriced until your rate file names it.
- **The door adds a hop to every thought.** A latency-sensitive caller pays it once per
  reasoning step. That is the price of the call being governed, and it is the trade this
  connector kind is: a credential the caller never holds, revocable in one command, with
  a row for every call.

`issue-reporter` reads GitHub through the vetted MCP connector, so it needs Docker
and a read-only GitHub token:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=github_pat_...   # public repos, read-only
```

Without installing: `python -m carnet.cli`. Tests: `pytest` from `backend/`.

No chat account needed — with no webhook configured, `post_message` writes to
`var/outbox.jsonl`. See **Chat delivery** below.

## The HTTP API

```bash
pip install -e ".[dev,api,access]"
uvicorn carnet.api:app

curl localhost:8000/health
curl localhost:8000/agents -H "Authorization: Bearer $TOKEN"
```

Interactive docs at `/docs`; the OpenAPI document at `/openapi.json`.

That command is development. **Deploying it** — TLS, the reverse proxy,
migrations, a real database — is `deploy/`: a compose file and the front door, with a
README written for the platform team that runs it in their own cloud.

| | |
| --- | --- |
| `GET /health` | liveness. No auth, no storage read — it must answer when both are broken |
| `GET /agents` | this tenant's agents, **including broken ones**, each with its reason |
| `GET /agents/{name}` | one agent: capability (`tools`) and reach (`scope`), the whole stored config, **your own role on it**, and an **`ETag`**. A broken agent answers **200 with `valid: false`** — it is the agent you came to fix |
| `GET /tools` | the catalogue: everything this tenant may grant, **and which of it writes**. The one route with no grant filter — see below |
| `POST /agents` | create one. **201**, and the caller becomes its owner **in the same transaction** — never an upsert, so a name somebody else uses is a **409** rather than a silent replacement |
| `POST /agents/validate` | a dry run over the same validator. Writes nothing, needs no grant. `{"valid": true}` or a **422** carrying the validator's own sentence |
| `PATCH /agents/{name}` | **`editor`.** A *partial* config, merged at the top level, and **conditional on `If-Match`** — no precondition is a **428**, a stale one is a **409** naming the keys that differ |
| `DELETE /agents/{name}` | **`owner`**, and a real delete. **204**. Its grants cascade; `audit` and `admin_audit` keep the history |
| `GET /agents/{name}/access` | **`user`.** Who can reach it, at what level, and **through which group** — plus the addresses still waiting for a first sign-in, as a separate list |
| `PUT /agents/{name}/grants/{kind}/{id}` | **`editor`.** Share it. `kind` is `user`, `group` or `email`; the answer says `granted` or `pending`, which is the distinction 006 hid from the sharer |
| `DELETE /agents/{name}/grants/{kind}/{id}` | **`editor`.** **204**. Revoking somebody whose access is inherited is a **400** naming the group, not a silent no-op |
| `GET /me` | who you are here, and **whether you may administer this workspace**. No role required — a non-administrator calls it precisely in order to be told they are not one |
| `GET /admin-audit` | **`admin`.** The administrative log — *who changed who may do what* — oldest first, `limit` capped by the signature. Reading it is deliberately **not** itself recorded |
| `GET /groups` | this tenant's groups: id, name, description. **No grant filter**, like `GET /tools` — it is the menu an `editor` picks from when sharing |
| `POST /groups` | **`admin`.** Create one. **201**, carrying the opaque `group_id` grants will name |
| `GET /groups/{id}` | **`admin`**, because it carries **membership** — "who is in every group" is a directory of the company, where a name only says a team exists |
| `DELETE /groups/{id}` | **`admin`.** **204**, and every access the group carried goes with it, on every agent |
| `PUT`/`DELETE /groups/{id}/members/{kind}/{id}` | **`admin`.** Idempotent, and the body says whether anything **changed** — "added" and "was already there" are different facts |

### One rule: `def`, never `async def`

FastAPI is async-first and this runtime is synchronous end to end. The whole
accommodation is that **every endpoint is a plain `def`**, so FastAPI runs it in a
threadpool and the synchronous broker stays synchronous. An `async def` endpoint calling
`broker.call` blocks the event loop, and the symptom is not a slow request — it is the
server ceasing to answer under load while every individual piece looks correct.

`tests/test_api.py` asserts it by walking the route table, because a rule that lives in
a docstring is one somebody breaks in six months.

Taking FastAPI does not contradict hand-writing the MCP client rather than using the
`mcp` SDK. That rejected four dependencies for a **three-method** protocol subset — a
large dependency for a small surface. This is the opposite trade: a large surface, whose
OpenAPI generation and request validation are exactly what a UI consumes.

### The tenant is never a parameter

```
GET /agents                 ✓   tenant comes off the Principal
GET /tenants/{t}/agents     ✗   never
```

A tenant in a path or a query is the caller asserting *which customer's data to read*,
which is the assertion the trust boundary exists to refuse — and it would be enforced by
remembering to check it on every route, which is the same shape as the missed-`WHERE`
leak already listed under known limits. `api/deps.py` is the one place a `Principal` is
built; everything below takes the tenant off it, exactly as the CLI does.

### Authentication: every customer brings their own SSO

A request carries a bearer token from **the customer's own identity provider** — Okta,
Microsoft Entra, Google Workspace, anything speaking OIDC. Nobody creates a password
here, and access follows the employee record their IT team already maintains.

```
Authorization: Bearer <jwt>
        │
        ▼
peek the issuer (unverified — it only chooses which keys to check against)
        │
        ├─ tenant_idps: issuer (+ a discriminating claim) -> tenant, jwks_uri, audience
        │        └── unregistered ──► 401
        │
        ├─ verify: signature, algorithm, iss, aud, exp, nbf
        │        └── any failure ──► 401
        │
        ├─ users: (issuer, subject) -> principal, created on first login IF the
        │         email domain is one this provider may vouch for
        │        └── unlisted domain, disabled account ──► 403
        ▼
Principal.user(id, tenant_id)      tenant from OUR row, never from a claim
```

**The tenant never comes from the token.** A provider can be configured to put an
organisation id in a claim, and trusting it would make the customer's IdP authoritative
over our tenancy — a mis-mapped claim in someone else's admin console becoming a
cross-tenant read here, in a setting we cannot see or audit. The token proves *who*; a
row we own decides *whose data*.

**All of the above is how a token is *verified*. A browser also has to *obtain* one**,
and that is declared separately, at the deployment: `CARNET_OIDC_ISSUER` and
`CARNET_OIDC_CLIENT_ID` in `deploy/.env`, from which the front door serves both the
runtime config the app fetches and the Content-Security-Policy the browser enforces.
The issuer there must be the same string `--add-idp --issuer` registers — one is how a
token is checked, the other is where it comes from, and a deployment where they
disagree comes up healthy and cannot sign anybody in. `deploy/README.md` is the
narrative; `docs/UPGRADING.md` names it as a required setting.

**One issuer does not always mean one customer.** Okta gives each customer their own
issuer and Entra one per directory, so routing is a lookup. Google Workspace shares
`https://accounts.google.com` across every organisation on it — so a row may also carry
a discriminating claim (`hd`), read from the *verified* claims. A registration without
one claims the whole issuer and cannot coexist with a discriminated one; that rule is
enforced when a provider is registered, because no `UNIQUE` can state it.

**401 and 403 are not interchangeable.** A 401 means authenticate again — expired,
forged, or not ours. A 403 means authenticating again will not help: you are genuinely
who you say and still may not use this. A UI that cannot tell them apart either loops on
a login that cannot succeed or gives up on one that would.

Onboarding a customer is deliberately not self-serve, and there is no admin API — see
the CLI commands under **Run**. Whoever can run them already has the database.

### Sharing: an agent belongs to somebody

Authenticating proves who you are. It does not get you an agent — every agent is shared
with named people, and absence is denial. Three levels, and they are named for the verbs
an agent has rather than a document's:

| | May |
| --- | --- |
| `user` | run it; see its tools and what it may reach |
| `editor` | ... and edit its config, and share it on |
| `owner` | ... and delete it, and hand it to somebody else |

**Every row of that table is now true in code**, which it was not until 10d: `editor`'s
editing half was inert for four steps because `routes_agents.py` was read-only, and
`owner`'s deletion half had never been reachable at all.

Delete is `owner` and not `editor`, and it is the one asymmetry worth arguing. `unshare`
already refuses to revoke the owner on the grounds that *an editor who may orphan an
agent may take it from the person who made it* — and an editor who may **delete** it can
do worse than orphan it.

Each level contains the one below, so a check is one comparison. A Google Doc has two
verbs, view and edit; an agent has a third — **run** — and that is the one that spends
API credits and writes to real systems. Calling that level `viewer` would be a name that
actively misinforms whoever picks it, so it is `user`.

Exactly one owner per agent, enforced by a partial unique index rather than remembered.
Ownership is a role on the grant row rather than a column on `agents`, so one table
answers both "who has access?" and "what may I run?", and a transfer is one statement
instead of two writes that can disagree. A transfer demotes the previous owner to
`editor`: handing an agent over almost never means "and lock me out of it".

```bash
carnet --share-agent triage priya@acme.com --role editor
carnet --unshare-agent triage priya@acme.com
carnet --agent-access triage        # who has access, and who is still waiting
carnet --admin-log                  # ... and who took it away
```

#### Who took it away

`--agent-access` answers *who has access now*. The other question — *who changed it, and
when* — is `admin_audit`, from migration 022, and it exists because the grant table
cannot answer it: `agent_grants.granted_by` records who granted access and is destroyed
by the revocation it should have recorded.

Every write that changes who may do what leaves a record, **in the same transaction as
the write**, so a record cannot be missing from a write that succeeded:

```
when                 who              what                  to                    detail
2026-08-08T03:45:22  system:cli       grant.create          agent:issue-reporter  grantee_kind=group, role=editor
2026-08-08T03:45:23  system:cli       grant.revoke          agent:issue-reporter  grantee_kind=group, role=editor
2026-08-08T03:45:23  system:cli       group.delete          group:g_6f5b10cf      name=oncall, members=1, grants=1
```

Three things worth knowing before relying on it.

**It records changes, not attempts.** Revoking a grant nobody had, deleting an agent that
was never there, adding somebody already in a group — all silent. A log that also
recorded attempts would make *"who took Sam's access away"* ambiguous in exactly the
situation it is asked in.

**`detail` says what changed, never the contents of every field.** No credential, no
token, and no agent system prompt — that last one is free text a person typed, which is
the class the audit log's redaction already exists to keep out of a record kept forever.
The consequence: you cannot reconstruct an agent's configuration at a past date from
this. It says the scope changed and what it changed to, not what the prompt said.

**`GET /admin-audit` exists as of step 12b, and the reasoning that kept it out for two
steps is why it waited rather than why it never arrived.** Reading this needs a
tenant-admin role, which this platform did not have — the same wall group administration
hit — and *a read route retrofitted with authorization later is worse than no route*. So
the authorization went in first and the route second. It was the decision in this design
most worth arguing with, because a log nobody can read is a log nobody notices is broken:
a customer's operations team could not answer *"who gave this person access"* about a
product their staff use all day.

`--admin-log` stays, and not only for symmetry: it is the reader that works when the API
is down, and during the bootstrap, where there is by definition no administrator to sign
in as.

#### Sharing with somebody who has not logged in

An address is what a person knows about a colleague. A **principal** is what
`agent_grants` names — and one does not exist until its owner signs in, because the
`users` row is keyed `(issuer, subject)` and a subject only ever arrives inside a token.
**There is no way to make a user row from an email address.**

So a share resolves one of two ways, and which one is invisible to the person sharing:

```
--share-agent triage priya@acme.com
        │
        ├─ somebody in this tenant already has that address
        │      └──►  a grant, immediately
        │
        └─ nobody by that address has ever logged in
               └──►  pending_grants, claimed at their first login
```

Claiming happens **at a first login and whenever a recorded address changes** — not on
every request, which would put a write in front of every read to catch a case that is
rare by construction. A claim never demotes: shared at `user` while already an editor,
the grant stays `editor`, because a login is the worst possible moment to discover that
access has narrowed.

Two places this deliberately does not behave like a Google Doc, both security:

- **A share to a domain none of this customer's providers may vouch for is refused, at
  share time.** Docs lets you share with any address on earth. Here that address names
  somebody who can never authenticate into this tenant — every login is gated on the
  same domain list — so the grant is either inert forever or the first half of a route
  across the tenant boundary. Refusing when a person is present to be told why is the
  whole value; a pending row that silently never lands looks exactly like one waiting
  patiently.
- **No link sharing**, no public flag, no wildcard row. Absence stays denial.

**Ownership cannot be left waiting on an address.** Ownership is transferred, and an
agent owned by a row that is never claimed is an orphan created on purpose. `--role
owner` against an address that resolves works; against one that does not, it is refused
with the suggestion to share at `editor` instead.

Emails are lowercased on the way in and matched case-insensitively. The local part is
case-sensitive by RFC 5321 and case-insensitive at every provider anybody actually uses,
so being right about the standard would only mean the grant never lands.

An address is the handle a human types. **It is not a credential and not an identity** —
resolving one here establishes nothing about who anybody is, and the person still
arrives with a signed token and is identified by their subject exactly as before.

**An agent nobody shared with you is a 404, not a 403**, and this is the row people want
to change. A 403 is the honest status for "you are who you say and may not have this",
which is exactly why it is wrong here: it confirms the agent exists. In a tenant shared
with colleagues, a 403 sweep over plausible names enumerates the company's agents, and
the enumeration is worth more than the access.

That makes the ordering inside each route load-bearing. **The grant check runs before the
config is loaded**, because an invalid config is a 422 — so checking access second would
answer 404 for an agent that does not exist and 422 for an ungranted one that does, and
the leak reopens through a status code nobody thinks of as an authorization decision.

**This is not the permission model.** Two questions, and collapsing them puts identity
into the policy engine:

```
grants        may this PERSON use this agent?      once, before a run exists
permissions   may this AGENT do this thing?        on every tool call
```

`core/permissions.py` has gone six steps without learning what a user is, and
`tests/test_grants.py` asserts that by reading the module's source — the failure mode is
a helpful import somebody adds without noticing what it costs.

The CLI is checked like anybody else rather than exempt. Migration 011 adopted every
pre-existing agent to `system:cli`, so it works on an existing database and stops working
on one that has been transferred away. Exempting it would mean the operator's path never
exercises the rule every other path is held to — so a sharing bug would be invisible from
the one interface used to investigate it.

### Groups: sharing with the support team

No enterprise shares with individuals. Sharing with forty people was forty rows, and when
somebody joined the team nothing followed them.

```bash
carnet --add-group support "The support team"
carnet --group-add support priya@acme.com
carnet --share-agent triage group:support --role user
carnet --groups support            # who is in it
```

#### A group is a grantee, never a principal

The load-bearing decision, and the seductive wrong answer is a one-line CHECK. Two
vocabularies, and only one of them may act:

```
principal kinds   user, system            who ACTS      runs, audit, connections
grantee kinds     user, system, group     who is GRANTED    agent_grants only
```

Widening the first would make a group able to **hold a delegated credential**, which is
the precise inversion of the credentials work: there, a credential belongs to one person
and is bound to `(tenant, principal, connector)` as GCM additional data. A group
credential is an operator credential wearing a team's name.

Until migration 017, `agent_grants` was the **only** table with a CHECK on that column —
`audit`, `connections` and `runs` declared it `TEXT NOT NULL` and nothing else, so a
Python frozenset was the entire defense on all three. 017 puts the constraint in the
database, because a test written in the same language as the constant does not survive
somebody widening the constant: it fails, and it reads as fallout rather than as a
refusal.

The columns are renamed to `grantee_kind` / `grantee_id` for the same reason the split
exists. After this step some lookups **resolve** a person through their groups and some
operate on a **literal** row, and sharing one parameter name between them is how a
resolving revoke that removes nothing gets written and reviewed without anybody seeing it.

#### The rules, and what each one costs

| | |
| --- | --- |
| **Effective role is the highest of direct and inherited** | you cannot demote somebody below their group |
| **A group may not own an agent** | ownership keeps a person's name on it |
| **Members are principals**, so nesting is refused by `check_principal_kind` | no new rule, no cycle detection |
| **The check stays one query** | a join now, not a point lookup |

Highest-wins rather than direct-overrides-inherited. The alternative reads as more
precise and produces a trap: somebody already granted `user` individually silently does
not gain what the rest of their team has, and the two people differ for a reason invisible
in the grant list and in any UI built on it.

Its cost is stated rather than hidden, and refused loudly rather than quietly obeyed:

```
$ carnet --unshare-agent triage u_sam
error: 'u_sam' has no grant of their own on 'triage' — their access comes from
group:g_c6b1bdd7f6de45ba. Removing a grant that does not exist would report success and
change nothing. Take them out of the group, or unshare the group itself.
```

So `--agent-access` says *how* each person has it, because without that the list is
unactionable in the exact situation it is read in — an owner sees Sam, removes Sam, and
Sam still has access:

```
principal                    role      how                       granted by
group:g_c6b1bdd7f6de45ba     user      direct                    system:cli
system:cli                   owner     direct                    seed
user:u_priya                 user      group:g_c6b1bdd7f6de45ba  <unrecorded>
user:u_sam                   user      group:g_c6b1bdd7f6de45ba  <unrecorded>
```

#### A group is not a wildcard

Absence is denial and there is still no public flag, no share link and no wildcard row.
The test that separates a group from those: *can you answer "who exactly can reach this
agent right now?" with a finite list?* A wildcard cannot — that is what makes it
dangerous, because nobody can enumerate the blast radius after an incident. A group can:
membership is rows, and `--agent-access` expands it. A group is **indirection**, closer to
a mailing list than to `*`.

Directory-backed membership is the next chunk and it is where that stops being free: once
membership comes from a token claim we would know who has logged in and been placed in a
group, not who *would* be.

#### One query, and the index that makes it one

The check runs before every run and filters every list view, so it is a single round trip
by requirement:

```sql
SELECT role FROM agent_grants
 WHERE tenant_id = %s AND agent_name = %s
   AND ( (grantee_kind = %s AND grantee_id = %s)
      OR (grantee_kind = 'group' AND grantee_id IN (
             SELECT group_id FROM group_members
              WHERE tenant_id = %s AND principal_kind = %s AND principal_id = %s)) )
 ORDER BY array_position(%s::text[], role) DESC
 LIMIT 1
```

The ladder is **passed in** rather than written into the SQL. Ordering by `role` itself
would be alphabetical — `editor` < `owner` < `user` — which is the ladder upside down and
would return `user` for somebody who owns the agent. `group_members_by_principal` is what
gets from a person to their groups, and it goes in with the table.

`test_the_permission_check_is_one_statement` counts the store's round trips against real
Postgres with fifty agents, because "one query" is the kind of requirement that is true
when written and false three refactors later.

#### Deleting a group takes the access with it

Membership cascades by foreign key. The **grants** go by a trigger, because
`grantee_id` names a different table depending on the column beside it and a foreign key
cannot be conditional. Without it, `group_members` would still cascade and nobody would
inherit anything — the damage would be quieter: a row in `--agent-access` naming a group
that no longer exists, granting nothing, looking exactly like access.

#### Known limits

- **A person's effective access is a computed thing.** "Why can Sam run this?" needs a
  join where it used to be a row.
- ~~**Group membership is a second thing to revoke**, and revocation is still only as fast
  as token expiry. Nothing tells us when somebody leaves a team — groups make SCIM's
  absence worse, not better, because membership is now load-bearing.~~ Built — step 071,
  and held back from this tree (078): `--disable-user` is the leaver's door here.
- **An empty group grants nothing and looks like access.** The CLI warns at share time;
  it is still a state a UI has to have wording for.
- ~~**There is no HTTP route for group administration and must not be one yet.**~~
  **Step 12b.** Mutating a group required a `system` principal — the CLI — because there
  was no tenant-admin role, and anybody who could add themselves to a group holding an
  `editor` grant would have been promoting themselves. It now requires the `admin`
  platform role, which preserves that restriction exactly rather than relaxing it: what
  changed is that a *person* can hold it, by a row somebody granted. Sharing an agent
  *with* a group is unaffected and always was: that needs `editor` on the agent, so
  filling a group grants nobody anything until somebody who could already share does.
- **Listing groups is open and listing membership is not**, and the line was audited
  rather than assumed. A name discloses that a team exists, which the org chart already
  does, and an `editor` sharing with a group has to pick one — a catalogue that cannot be
  read cannot be shared with. *Who is in every group* is a directory of the company, and
  the one legitimate non-admin need — **who will this share reach** — is already answered
  per agent by `GET /agents/{name}/access`.
- **There is still no group-management UI.** The routes exist; their consumer today is the
  same engineer who runs `--add-group`, and the non-technical one arrives with 12c.

### Offboarding: somebody leaves

Claims are a pull on presence; a person deleted in the customer's IdP never signs in
again, so nothing reconciles, so nothing revokes — until somebody says so:

```
carnet --disable-user their.address@example.com
```

**What it does**, decided rather than inherited: everything that acts *as* the person
stops, and nothing the person *made* is deleted. Their sign-in is refused, every API token
they own is refused at its next call, and an acting-for identity resolving to them is
refused. Their agents, grants, group memberships and connections are untouched. There is
no hard delete — every audit row they ever produced names their id — so a disable is
what there is, and `--enable-user` reverses it. `--list-users` shows who is here.
`docs/runbooks/offboarding.md` is the procedure, run.

### Platform roles: who may administer this tenant

One role, `admin`, from migration 026. It answers a question about the **tenant** where
the sharing ladder answers a question about one agent, and until step 12b it did not exist
— which had stacked four features behind it: group administration (9a), a read route for
the administrative log (11), the vetting screen (12), and consent-flow configuration (7b).

```bash
carnet --grant-role admin priya@acme.com
carnet --list-roles
carnet --revoke-role admin priya@acme.com
```

#### An admin is not a superuser

**Holding `admin` grants access to no agent, no run and no connection.** `access/roles.py`
never consults `agent_grants` and `access/grants.py` never consults `platform_roles`; an
admin with no grant on an agent gets the same 404 as a stranger, and a test says so in
both stores.

The argument is the delegated-credentials work's, one level up. That exists because *an
operator holding everybody's tokens* is the failure it prevents — and an `admin` that
implied agent access would rebuild that operator under a different name, one grant away.
What an admin gets is tenant **configuration**; what they do not get is tenant **data**.

#### `system` is always an administrator, and that is the bootstrap

HTTP structurally cannot mint a `system` principal: every path through `api/deps.py` ends
at `users.resolve`, which returns `Principal.user(...)`. Two things follow, and both are
decisions rather than conveniences.

*Who grants the first admin?* Whoever has the shell — which is this deployment's actual
root of trust, rather than a self-serve ceremony pretending otherwise. And **lockout is
impossible**, so revoking the last administrator is allowed: a "cannot remove the last
admin" rule would guard a failure that cannot occur here, and would become wrong the day
role administration moves to HTTP, where it has to be re-decided rather than inherited.
The CLI warns loudly instead.

#### Granting stays on the CLI

There is no `PUT /roles/...`, deliberately. A role model whose first version lets admins
mint admins over HTTP hands a compromised admin token the one thing it lacks, in the step
whose purpose is containment — and the administrative log recording an escalation is not
preventing one.

A role is granted to a principal that **exists**. An address nobody has logged in with is
refused, which is the connections rule and sharper: *a role is not an invitation*, because
a pending admin grant promotes whoever eventually claims a mistyped or recycled address,
silently, at login, weeks after somebody typed it.

#### Known limits

- **One bit of granularity.** "May vet connectors but not read the log" is not
  expressible. Deliberate — the evidence for the right split does not exist yet, and
  collapsing a wrongly split role is a breaking change where widening one is additive.
- **An admin's 403 does not say who to ask.** A directory of who to phish is not an error
  message's job; the cost is a person asking a colleague instead of reading a screen.
- **The always-admin `system` rule is a convention pinned by tests, not by types.** If a
  future entry point mints `system` principals from network input, that precondition
  breaks — `test_http_can_never_mint_a_system_principal` is the tripwire.

### Editing, and what happens when two editors disagree

`PATCH /agents/{name}` is **conditional**. `GET` returns the agent's `updated_at` as an
`ETag` and as a field; a save sends it back as `If-Match`, and the store compares it
inside the same statement that writes:

```sql
UPDATE agents SET config = %s, updated_at = now()
 WHERE tenant_id = %s AND name = %s AND updated_at = %s
```

**The guard cannot live in the route.** Read-then-write there has a window between the two
in which the other editor commits, and that window is precisely the lost update the
timestamp exists to catch — so it is one statement in storage, next to `create_agent`'s
transaction and for the same reason. A `PATCH` with no `If-Match` is a **428** rather than
a permissive default, because last-write-wins is how one person silently reverts another's
scope narrowing and it fails invisibly by construction.

A stale save is a **409** carrying the current `updated_at` and **the top-level keys the
request disagrees with the stored config about** — not "what the other person did", which
nothing here can answer, but the exact set this save would have overwritten. An empty list
means the save was a no-op and can simply be retried.

**Not a hash of the config.** A hash cannot tell "changed" from "changed and changed
back", and it would be a second answer to a question the schema has had a column for since
migration 002. `updated_at` is also what a UI wants to *show*, which a hash is not.

#### A partial config, merged at the top level

The body is a **patch**, not a config, and that is a decision taken on a confirmed
finding rather than a preference. `frontend/src/lib/draft.ts` has `toConfig` and no
inverse; the shipped `issue-reporter` carries `default_task` and `deny_demo_task`, and no
step of the create form asks about either. An edit screen built from the create form and
saving the whole config **deletes both**, and nothing anywhere reports it.

- **A key that is absent is untouched**, so `default_task` survives because the form never
  sends it rather than because somebody remembered to carry it.
- **`permissions` is replaced as a unit**, never deep-merged. `tools` and `scope` are
  cross-checked in both directions by `_validate_scope_matches_tools`, so a merge that
  updated one and kept the other is the one way to produce a config the validator refuses
  through a route that looks like it is working.
- **`name` is not patchable.** It is the URL, the storage key, the broker's identity and
  the string in every audit record. A body naming a different one is a **400**, never a
  silent ignore.

The cost, stated rather than hidden: **there is no way to *remove* an optional field over
HTTP.** Sending `{"limits": {}}` clears the limits, because whole-value replacement applies
to every top-level key; sending nothing leaves them. Deleting `default_task` entirely needs
the CLI.

#### Deleting

A real delete. The row goes, `agent_grants` and `pending_grants` cascade, and `audit` and
`admin_audit` keep the history because neither has a foreign key that would take it. Soft
delete was refused for the reason this codebase has refused it three times: a disabled
agent still holding grant rows is a row that grants nothing and looks like access.

### Which failure is which status

| Condition | Status |
| --- | --- |
| unknown agent, unknown tenant | 404 |
| an agent nobody shared with you | 404, **the same 404** |
| the agent exists and its config is invalid | **200 with `valid: false`** on the read; 422 on the write that would put it to use |
| a `PATCH` with no `If-Match` | 428 |
| a `PATCH` from a version somebody else has replaced | 409, with `updated_at` and `changed` |
| a `PATCH` whose body names a different agent | 400 — renaming is a different operation |
| a share you may make and that cannot be made | 400 (`ShareRefused`), never the 404 |
| storage unavailable | 503 |

**A brokered denial is not an HTTP error.** The broker refusing a tool call is the system
working as designed: the model is told and carries on. It surfaces as a `denied` count on
a 200, the same way the door log shows it. Mapping it to a 403 would report a successful
enforcement as a server failure, and would make the most important records in the audit
log look like outages.



## Running two of anything at once

A threadpool is the first thing in this project's life to run two of anything, and four
pieces of process-global state were written for a single-threaded loop. None of them is
hard to fix and **all of them fail silently**, which is why they were the substance of
the API step rather than a follow-up to it.

| What | Fix |
| --- | --- |
| One database connection | `psycopg_pool`. The helper had to change shape too — it returned a live cursor, and a connection cannot go back to the pool while a caller holds one onto it |
| A shared MCP session | a lock per session. See below |
| The session pool dict | a lock, plus creation through `get_or_create` so two threads cannot both build a session and orphan one |
| The bound tool registry | a lock. Safe on CPython by accident before, which is not a property to rest a tenant boundary on |
| `InMemoryStorage` | a lock. Its docstring said "not thread-safe, deliberately" — true until this |

### Why a shared session needed a lock, specifically

Two threads sharing one MCP session do not merely race. A session is one pipe with one
id counter, and `_await` **discards** any message whose id is not the one it is waiting
for — correct while a single thread owns the pipe, and how server-initiated
notifications get ignored:

```
thread A  send(id=7) ─┐
thread B  send(id=8) ─┼─►  one pipe, one inbox queue
                      │
          A reads the reply to 8, discards it (not the id it wants), waits on
          B waits for a reply that has already been thrown away → times out
          B raises TransportError(delivered=True) → outcome="unknown"
```

B did nothing wrong and is recorded as a write that **may have taken effect and needs a
person** — the one lie the delivered/ambiguous mapping exists to prevent. Driving the
pre-lock code with eight threads, **seven of the eight** calls came back that way.

The cost is real: two callers sharing a connector *and* a credential take turns at their
tool calls. Acceptable because a call is short, and it stops being a shared key at all
once credentials are delegated. The measurable trigger for moving to several sessions
per key is when waiting on that lock is a material fraction of call duration —
`duration_ms` is already in the audit log for exactly this kind of question.

### Idle eviction stopped being deferrable

Sessions now expire after `MCP_SESSION_IDLE_TTL` and the pool is capped at
`MCP_SESSION_POOL_MAX`, evicting least-recently-used. Both numbers are invented, and
that is a smaller sin than it was: they are bounds where there were none, not tuning.
Deferring them was right while a CLI process exited and took its sessions with it, and
expired the moment the process became long-lived — a connector nobody has used since
Tuesday is a container still running.

Eviction happens opportunistically on every `get` and `put`, which covers a busy server
completely and an idle one not at all — and an idle server is the exact case a TTL
exists for. So the API also runs a background sweep every
`MCP_SESSION_PRUNE_INTERVAL`, started and stopped by the lifespan. The CLI does not
need one; it exits.

`tests/test_concurrency.py` holds all of this in place, driving real threads through the
real objects rather than asserting that a lock exists.

### Verified against the real thing

The suite starts nothing, so the claims above were also checked end to end against real
Postgres and two real MCP servers:

| | |
| --- | --- |
| the Docker connector, bound from a request thread | `github-mcp: bound 3, excluded 6 unvetted` |
| GitHub's **hosted** endpoint, credential per request | `github-remote: bound 1, excluded 43 unvetted` |
| three calls, one bind | the pooled session was reused, not respawned |
| a refusal over HTTP | **200** with `denied: 1`, message byte-identical to the CLI's |

One audit trail, and nothing below the entry point learned that HTTP exists.

## The trust boundary

```
model output ──► runtimes/simple.py ──► broker.call(ctx, config, name, input)
 (untrusted)         (Tier 1)             │
                                          │  BOTH are server-side: the run context
                                          │  (id, principal, budget) is built by the
                                          │  runtime, the agent is loaded from storage
                                          │  for the run's tenant. Neither is
                                          │  model-generated.
                                          ▼
                          1. permissions.check()      ── deny ──► audit + error to model
                          2. budget.reserve()                     (nothing executed,
                          3. credentials.for_tool()                no credential read)
                          4. execute → size cap → audit
```

The model contributes only a tool name and arguments. There is no parameter through
which it can assert *who it is*, *whose authority it acts under*, or *how much budget
it has left* — so it can claim neither another agent's permissions, another user's
access, nor a fresh allowance.

Steps 1 and 2 answer different questions. Scoping bounds what a call may **reach**; the
budget bounds how much it may **do** within that reach.

**Actor vs authority.** The agent is the actor; the principal is the authority it
acts under — the machine token at the door, or the person it says it is acting for.

## Storage and tenancy

Agents, connectors, vetting decisions and the audit trail are rows. Every table
carries a `tenant_id` from the first migration, because retrofitting tenancy means
backfilling a column nobody knows the value of, on tables already being read by code
that does not filter on it.

Two implementations behind one `Storage` protocol: Postgres for real, in-memory for
tests. That seam is what lets the suite keep the property it has always had — it starts
nothing, calls nothing, and finishes in about a second. The risk of a fake is that it
permits what the real thing refuses, so `tests/test_storage_contract.py` runs **one set
of assertions against both**, and every rule Postgres enforces with a constraint is
enforced in Python too: the tenant foreign key, the agent-name check, the refusal to
store a derived field, ordering, and deep-copy on read and write.

### Where the tenant lives

On the **`Principal`**, not on the `RunContext`. A principal belongs to a tenant,
including a system one: the operator's CLI acting for a customer is that customer's
operator. Because the principal is already threaded through the broker, the
audit log, the credential lookup and the permission check, all four got tenancy without
growing a parameter — and `RunContext.tenant_id` derives from it rather than storing a
second copy that could disagree.

`Principal` has **no default tenant**. A defaulted tenant on a frozen security-relevant
dataclass is how a construction site quietly ends up in the wrong customer's data.

### Vetting is per tenant, and that is a security boundary

Two customers can both run the official GitHub MCP server and expose different tools
from it — one vets reads only, the other also vets a write. So the tool registry is
split along a line that is not a filing convenience:

| | Scope | Why |
| --- | --- | --- |
| hand-written tools (`post_message`) | process-global | they are code; every tenant gets the same one |
| connector-bound tools | **per tenant** | vetting is a tenant's decision about a tenant's server |

A single registry keyed by tool name would let one customer's vetting decide what
another customer's agents can call. That is a cross-tenant authorization leak requiring
nothing more exotic than two companies both using GitHub, and `test_tenancy.py` asserts
it directly. Session pooling is keyed by tenant for the same reason: a live session is
bound to the manifest it was bound against.

In the broker this cost **one line** — `tool_registry.get(tool_name, ctx.tenant_id)`.
`permissions.check`, `patterns` and `limits` were not touched, which is what the
resource-type indirection was for.

### Validation moved without weakening

Configs used to be modules, so `validate()` ran at import and a bad grant stopped the
process from starting. Now:

- **write time** — `agents.save()` validates and refuses, so an invalid config never
  becomes a row. A form user gets exactly the errors the import used to raise.
- **load time** — still fail-closed, because a row valid when written can stop being
  valid. Delete a connector and every agent granting its tools is dangling.

One property did change, deliberately: a bad agent no longer stops the process. It
raises when someone tries to run it, and listing skips it and says so. "It cannot start
broken" is a property of a single-tenant process — one customer's bad row must not take
the platform down for everyone else. "It cannot *run* broken" is the property that
mattered, and `get()` raises rather than returning `None`, so a broken agent is never
silently a missing one.

### Schema

Thirty-five migrations, plain SQL, applied in order by a small runner. Not Alembic: its real
value is autogenerating a diff from declarative models, which needs an ORM we
deliberately do not have — without that it is a runner with more machinery, and plain
files mean a reviewer reads the exact DDL that will run.

| Table | Holds |
| --- | --- |
| `tenants` | the customer |
| `agents` | one JSONB config per agent, keyed `(tenant_id, name)` |
| `connectors` | how to reach a vetted server |
| `vetted_tools` | the per-tool review record: effect, resources, who approved it |
| `audit` | one row per brokered call |
| `connections` | delegated credentials: one person's sealed token per connector |
| `agent_grants` | who may use an agent, and at what level. Keyed by **grantee** |
| `groups` / `group_members` | a name and a set of principals. Grantees, never principals |
| `admin_audit` | who changed who may do what — the log the row-shaped design could not hold |
| `connector_oauth` / `pending_authorizations` | a connector's consent flow, and one in progress |
| `tenant_egress_hosts` | what this platform will dial for this customer |
| `platform_roles` | who may administer this tenant. `admin`, and the set is closed |

Three things the database enforces that a dict cannot:

- `CHECK (config->>'name' = name)`. The broker trusts `config["name"]` as identity and
  writes it into every audit record, so a row whose key disagreed with its body would
  misattribute everything that agent ever did. That was an import-time check; this is
  where it went.
- **`audit` is append-only**, via a trigger that refuses UPDATE and DELETE. A JSONL file
  was append-only because of what it is; a table is mutable by default, and an audit log
  somebody can edit is a weaker artifact than the one it replaced. A trigger rather than
  a `REVOKE`, because a revoke does nothing when the app connects as the owner.
  Retention deletion will have to drop it explicitly — that friction is the point.
- **No `ON DELETE CASCADE` from `tenants` to `audit`.** You cannot remove a customer and
  silently erase the record of what their agents did.
- **`principal_kind IN ('user','system')` on `audit` and `connections`**, added by
  017. Until then `agent_grants` was the only table constraining that column, so a Python
  frozenset was the whole defense on the three where a wrong value is a security
  inversion. `audit`'s is `NOT VALID` — it enforces on every future write and declines to
  re-scan the one unbounded table in the schema to re-prove history no code path could
  have written. To finish it where the scan is affordable:
  `ALTER TABLE audit VALIDATE CONSTRAINT audit_principal_kind_check;`

- **`principal_kind IN ('user','system')` on `platform_roles`**, from 026, and it is the
  same CHECK for a sharper reason: a group holding an administrative role would make group
  membership self-service promotion, because anybody who may add a member could then make
  an administrator.

There is deliberately **no `read_only` column**. It stays derived from the vetted
effects — see below — and a stored copy is free to disagree with the allowlist it
defends.

## Permissions — capability and reach

A grant has two dimensions: **which tools** an agent may call, and **which resources**
those calls may touch.

```python
"permissions": {
    "tools": ["github_mcp_list_issues", "post_message"],
    "scope": {
        "github.repo":  {"read":  ["anthropics/*"]},
        "chat.channel": {"write": ["#eng"]},
    },
}
```

Scope is written against **resource types**, not argument names. Each tool declares
which of its arguments are resources of which type, so one `github.repo` grant covers
every tool that touches a repo — including tools we didn't write, whatever each one
calls its arguments. That indirection is what makes the model survive arbitrary MCP
servers (see below).

Rules, all fail-closed:

- A tool not in `tools` is denied. No implicit grants.
- A tool not in the registry is denied — we can't scope what we can't describe.
- A declared resource argument that wasn't supplied is denied.
- A resource type with no grant **at that tool's effect** is denied. Grants are
  per-effect with no implication: `write` does not confer `read`.
- Arguments that aren't declared resources are unconstrained — `limit` is data.
- Any credential-shaped argument (`webhook_url`, `token`, `api_key`, …) is denied
  outright — those come from the broker, so the model supplying one is a red flag.

The `tools` list is also the single source of truth for which schemas the model sees.
That's ergonomics, not security — the broker re-checks every call regardless.

### Composed identifiers

A resource is not always one argument. GitHub's REST API — and so its MCP server —
takes `owner` and `repo` separately, so a tool wrapping it declares:

```python
resources=[Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")]
```

The grant above is unchanged. That is the whole point of writing policy against
resource types: a tool we didn't write, naming its arguments differently and splitting
the identifier across two of them, falls under the same `anthropics/*`.

A list rather than a dict keyed by resource type, because a tool may touch two
resources of the *same* type — a `copy_issue(from_repo, to_repo)` declares two
`github.repo` entries and both are checked.

Composition brings one rule of its own: **a component may not contain `/`**. Given
`{owner}/{repo}` and a grant of `anthropics/**`, a `repo` of `../../torvalds/linux`
composes to a value the matcher admits, and the tool then builds a request path
pointing at a repository nobody granted. This is prefix confusion's composite cousin —
`patterns.py` defends the pattern side, and nothing but this defends the component
side. It applies to composition only: a single argument used whole *is* the
identifier, and the slash in `anthropics/sdk` is its structure.

### Scoping to the caller

```python
"scope": {"tickets.assignee": {"read": ["${principal.id}"]}}
```

Resolved against the principal at check time: one config, any number of users, each
reaching only their own rows. A caller-scoped pattern under a **system** principal is
an explicit denial — a headless run has no user to scope to, so that config is an
error worth surfacing rather than a silent non-match.

### Pattern syntax

Segment-aware, splitting on `/`:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `anthropics/sdk` | exactly that | anything else |
| `anthropics/*` | `anthropics/sdk` | `anthropics/a/b`, `anthropics` |
| `project/**` | `project/42`, `project/42/board/7` | `project` |
| `#eng` | `#eng` | `#random` |

Comparison is always segment-whole, so `org/*` cannot match `org-evil/repo`. Prefix
confusion isn't a case to remember — it isn't expressible. Deliberately **not regex**:
anchoring mistakes and catastrophic backtracking are a poor trade in a check that runs
on every tool call. Matching is case-sensitive; normalizing identifiers is a
connector-vetting concern.

Malformed patterns raise at config load, not at call time — a pattern that can never
match is a policy that denies everything, which is safe but baffling at 3am.

## Tool descriptors, and what MCP does not give you

MCP supplies a **catalog and execution**: a server advertises tools via `tools/list`
and runs them via `tools/call`. It does **not** supply authorization. The protocol has
no per-agent or per-user permission model, and the server sees one client connection —
it cannot tell which of your agents, acting for which user, is calling.

So a `Tool` doesn't disappear once MCP is wired in; it stops being hand-written:

| Field | Source |
| --- | --- |
| `name`, `description`, `input_schema` | copied from the server's advertisement |
| `impl` | generated proxy that calls `tools/call` |
| `effect`, `resources` | **added by us at vetting time** |

The server can't author that last row. Given `create_work_item(project, type, title,
description)` it tells us four argument names; it does not tell us that `project` is
the thing worth scoping on while `title` is data, that this is a write, or that its
"project" maps to our `ado.project`. MCP's `readOnlyHint` is advisory and
self-declared — an enterprise boundary can't rest on a claim made by the component
being constrained.

Per connector this is roughly two annotations per tool, once. That's what "vetted and
scoped" concretely means.

### Vetting is an allowlist, not a filter

A connector manifest names the tools we expose. Binding intersects it with what the
server actually advertises, and each of the three outcomes is deliberate:

| | |
| --- | --- |
| advertised, not vetted | **excluded and reported.** A server that adds `delete_repository` in v1.4 does not become callable because nobody remembered to exclude it. |
| vetted, not advertised | **raise.** A vetted tool that vanished is drift; guessing which of the rest replaced it isn't this layer's call. |
| vetted, schema moved | **raise**, via `tools/validation.py`. If `repo` became `repository`, our resource declaration names an argument that never arrives — enforced in review, absent in fact. |

The shipped GitHub connector vets **three** tools out of the hundred-odd the server
advertises — `list_issues`, `issue_read`, and one write, `add_issue_comment`. That
ratio is the point: you don't vet a server, you vet the tools you want, and the rest
stay invisible to every agent on the platform.

`search_issues` is deliberately unvetted, and the reason is the interesting one. It
*does* take `owner` and `repo` — but both are optional, and `query` is not. The query
is GitHub's own search syntax and may carry its own `repo:` qualifier, so two arguments
can disagree about what the call reaches and the server decides which wins. Scoping the
pair we can see would be a constraint that reads as enforced while the query goes
wherever it likes, and parsing a vendor's query grammar to work out what a call will
touch is exactly the guess a permission check must not make. Unscopeable, therefore
unvetted.

### Adding a connector

A connector is a `Connector` object saved for a tenant, and nothing in `core/` changes:

```python
tools.save_connector(tenant_id, Connector(
    id="jira",
    launch=Launch(command=(...), credential_env="JIRA_TOKEN"),
    vetted=[
        Vetted("search_issues", effect="read",
               resources=[Resource("jira.project", "projectKey")]),
    ],
))
```

`save_connector` validates the manifest and refuses one whose namespaced tool names
would shadow a hand-written tool — a check that used to run at import and now runs at
the moment the data arrives, which is when somebody can still do something about it.

Still deliberately not self-serve. The two-persona split is unchanged: a **connector
admin** decides which of a server's tools to expose and annotates each one's effect and
resources; an **agent creator** picks from what has already been vetted. Only the
mechanism moved — vetting is a reviewed decision recorded as data (`vetted_by`,
`vetted_at`) rather than a code change, which is what makes a connector-admin UI
possible without touching the policy engine.

Tool names are namespaced by connector id — `github_mcp_list_issues` — so two servers
may both offer `list_issues`, a connector can't shadow a hand-written tool (refused
when the connector is saved), and an audit record says which path a call took without
a cross-reference.

Connecting is lazy and per-agent: a connector is a container, and an agent that
touches no GitHub tool shouldn't pay for a GitHub server. `run_agent` connects only
what the agent's granted tools need, before the model sees a schema list. Failure
**raises** — a tool missing from that list is a gap the model improvises around, which
is a silent degrade in the one place a loud failure costs nothing. If a connector
somehow isn't bound, `tools.get(name, tenant)` returns None and the broker refuses a
tool it cannot describe; that's the backstop, not the plan.

### What the connector actually cost

The reason GitHub was the first connector: a hand-written `get_github_issues` already
existed, so the same agent could run the same task down each path and the audit log
could answer what changed. Same prompt, same grants, same repo — only the tool differs.
(The hand-written tool has since been retired; this is the run that decided it.)

```
                  issue-reporter            issue-reporter-mcp
tool calls        2                         3      <-- differs
denied            0                         0
writes            1                         1
oversize          0                         0
response bytes    2812                      25384  <-- differs
tool time (ms)    531                       1953   <-- differs

  A: get_github_issues[ok] -> post_message[ok]
  B: github_mcp_list_issues[ok] -> github_mcp_list_issues[ok] -> post_message[ok]
```

**The security abstraction holds.** Asked to overstep, both refuse with a
byte-identical message:

```
github.repo 'torvalds/linux' is outside this agent's 'read' scope.
Allowed: anthropics/anthropic-sdk-python
```

— even though the MCP tool supplied `owner: "torvalds"` and `repo: "linux"` as two
separate arguments. One grant, written before the connector existed, constrains a tool
that names its arguments differently and splits the identifier across two of them.
Same decision, same audit shape, same wording.

**The cost is real.** 9× the bytes and 3.7× the time. Two calls instead of one,
because the server paginates and the model followed the cursor. An earlier run against
the unfiltered response returned **77,710 bytes** and blew `MAX_RESPONSE_BYTES` — the
cap working exactly as designed, including telling the caller how to recover. The
model then found the server's `fields` parameter on its own and narrowed the request,
which is why the run above passes. Byte ceilings for connector tools should be set
from this data rather than guessed; logging `response_bytes` on passing calls is what
makes that possible.

**The semantics do not carry, and that is the finding worth having.** The two paths
gave different answers to the same question:

| | reported |
| --- | --- |
| `get_github_issues` | 12 open issues |
| `github_mcp_list_issues` | 146 open issues |
| GitHub search API (truth) | **146** |

The hand-written tool is the one that is wrong. It requests 30 items, filters out pull
requests, and returns `{"count": 12}` — a number that looks complete and isn't, with
nothing in the payload saying so. The connector paginated and got all 146.

Nothing in the broker could have caught this. Permissions bound what a tool may
*reach*; budgets bound how much it may *do*. Neither has an opinion about whether a
tool answers the question correctly. **Vetting a connector is a security review, not a
correctness review** — a scoped, audited, budgeted tool can still be wrong, and swapping
one for another can silently change what an agent tells someone.

### Two transports, and why there are two

| | Credential | Sessions |
| --- | --- | --- |
| **stdio** | env var at process launch, held for the process's life | one subprocess |
| **Streamable HTTP** | a header, **per request** — no long-lived process holds it | one endpoint |

That difference is not a deployment preference. Per-user credentials over stdio would
mean one long-lived subprocess per user, each sitting on a plaintext secret readable by
anything that can read the process table. HTTP is what makes delegated credentials
possible at all, which is why it was built before the access layer rather than after.

A connector says which it speaks, and there is **no fallback between them.** Quietly
substituting one for the other because the first would not start would be substituting
a security posture.

```python
StdioLaunch(command=("docker", "run", ...), credential_env="GITHUB_PERSONAL_ACCESS_TOKEN")

HttpLaunch(url="https://api.example.com/mcp/", credential_env="EXAMPLE_TOKEN",
           credential_header="Authorization", credential_prefix="Bearer ")
```

Either way the row names *where* the secret comes from and never the secret itself.
Adding the second shape needed no migration — `connectors.launch` is JSONB, and a row
without a `kind` is stdio, so anything written before this existed keeps working.

One thing is lost over HTTP and worth stating: **read-only mode is a launch-time
switch, and there is no launch.** `Connector.read_only` is still derived and still
correct, it simply has nothing to act on. That costs a layer of defence in depth and no
more — the allowlist was always the actual control, and pointing this at GitHub's
hosted endpoint shows exactly what that means:

```
[mcp] github-remote: bound 1, excluded 43 unvetted
      (add_comment_to_pending_review, add_issue_comment, create_branch,
       create_or_update_file, delete_file, merge_pull_request, push_files, ...)
```

44 tools advertised, including every destructive one, because nothing asked the server
to be read-only and nothing could. One is callable. That ratio is the argument for
allowlisting rather than filtering, made by a real server rather than by assertion.

**The subset stays a subset.** POST for every message; both content types accepted
because the server chooses which to answer with; `Mcp-Session-Id` carried once
assigned; re-initialize on a 404. No client→server GET stream (we handle no
server-initiated requests), no resumability, no cancellation, and **no OAuth** — that
is a per-user consent flow, so it belongs with the access layer, and servers requiring
it cannot be used yet.

Verified against GitHub's hosted endpoint, and the interesting part is what the server
chose: it answers every request with `text/event-stream`, never `application/json`. A
client that had treated SSE as the optional half would not have worked at all.

A connector's manifest names the environment variable its credential lives in, and
that is deliberate rather than convenient. A map in `credentials.py` keyed by connector
id could only answer for connectors somebody had edited that file for, so every new one
would authenticate as nobody — which is exactly what the first real run did, with a
401. A connector admin already supplies `StdioLaunch.command`, which the platform
executes; naming an environment variable grants strictly less. The platform's own
secrets are refused regardless.

### Ambiguous writes

A write that reaches an external system and never answers may or may not have taken
effect. From inside the process that looks identical to a write that never left — and
the two call for opposite responses. One is safe to retry; the other is how one
comment becomes five.

So the transport records which it was. Failing to write to a pipe is a different event
from writing successfully and hearing nothing, and it is knowable at the moment it
happens and unreconstructable afterwards:

| | the model is told | audited as |
| --- | --- | --- |
| never delivered | "nothing happened" | `error` |
| delivered, no reply | "this MAY have taken effect; do not repeat it" | `unknown` |

`unknown` only applies to writes — an unanswered read changed nothing either way. It
is its own outcome in the audit log and on the door log because it is the one outcome
that needs a person: nobody can tell from here whether the thing happened.

Any tool may claim this, not just MCP ones — a hand-written HTTP POST that times out
has exactly the same problem. It sets `may_have_completed` on its error result and
the broker does the rest.

**Over HTTP there are more ways to be ambiguous**, and this table is the whole of the
mapping. Getting a row wrong does not fail loudly — it silently turns "this might have
happened" into "this definitely did not", which is the one lie the audit log must never
tell.

| What happened | delivered | Why |
| --- | --- | --- |
| DNS failure, connection refused, TLS failure | no | Never reached the server. |
| Timeout before the request was written | no | Same. |
| Read timeout after it was written | **yes** | It is on the wire. The server may be acting on it. |
| 5xx | **yes** | It reached the server; partial processing is possible. |
| 4xx | no | Rejected before dispatch. The tool did not run. |
| 404 for an expired session | no | The server does not know the session, so it cannot have executed under it. |
| **SSE stream drops before the response** | **yes** | The spec says explicitly this is not cancellation. Maximally ambiguous. |

Two of those are load-bearing in opposite directions. The **404** row is what makes
re-initializing and retrying once safe — even for a write, because nothing ran. The
**dropped stream** row is why such a retry is never automatic: there, the server may
well still be working.

The bias where it is genuinely unclear — a connection that broke for reasons the client
cannot classify — is **say delivered**. A false "delivered" costs a person a glance at a
run that was fine; a false "not delivered" costs the truth. But the common cases are
mapped exactly rather than biased, because if every outage produced ambiguous writes
then `unknown` would stop meaning anything, and it is valuable precisely because it is
rare.

### Read-only mode is derived, never written down

A server's read-only switch is defence in depth — the allowlist decides which tools
exist — but as a constant it drifts. Vet a write and someone has to remember to turn
it off; remove that write later and nobody remembers to turn it back on. Either way
the flag stops describing intent while still looking like it does.

So `Connector.read_only` is computed from the vetted effects, and the shipped connector
demonstrates the mechanism in both directions. While only reads were vetted, GitHub's
server was launched read-only and did not advertise `issue_write`, `add_issue_comment`
or `sub_issue_write` at all — 6 tools instead of 9. Vetting `add_issue_comment` took
the mode off **by itself**, with no flag to remember; un-vet it and read-only comes
back the same way, for exactly as long as no write is vetted.

That is the property: nobody ever edits the switch, so it cannot describe an intent
that stopped being true.

This survived the move to a database, which is where the argument for deriving it gets
tested rather than asserted: there is **no `read_only` column**, the storage layer
refuses a manifest carrying one rather than dropping it quietly, and the value is
recomputed when a row becomes a `Connector`. Two tenants vetting the same server
differently get different modes, from the same code, with nothing written down.

### Two registries

| | |
| --- | --- |
| `get(name, tenant)` | tools callable right now. Hand-written always; connector tools once bound for that tenant. |
| `known_names(tenant)` | every name that tenant recognises, including vetted-but-unconnected. |

Agent configs validate against `known_names`, so granting an MCP tool is checked when
the config is saved rather than failing at the first run. The broker looks in `get`.
Both fail closed, and both are tenant-scoped — a tenant that has vetted nothing knows
only the hand-written tools, which is where every new customer starts.

Agent validation also cross-checks reach against capability in both directions: a
granted tool whose resource type has no grant at its effect (every call would be
denied), and a grant no granted tool can use (a leftover, or the visible half of a
misspelling). Resource types are bare strings with no registry, so `github.repos` for
`github.repo` is a policy that denies everything — safe, and baffling at 3am.

**Descriptors are validated whenever a `Tool` is built** — at import for hand-written
tools, at bind time for connector ones — because each failure is a policy that would
look enforced in review and not be:

- A `Resource` naming an argument the schema lacks — a constraint that can never fire.
- A resource composed from several arguments with no template — joining values into an
  identifier without a stated shape is a guess.
- A template naming an argument the resource doesn't declare, or ignoring one it does.
- A `write` tool declaring no resources — unscopeable by construction.
- An `effect` that isn't `read` or `write`.
- An agent granting a tool name that isn't registered, or a malformed scope pattern.

The first rule was written for hand-authored tools, where such a failure is a typo.
Against an MCP server it does more: it is what catches a connector renaming `repo` to
`repository` in a later version and silently unhooking our scoping from the argument
it was written against.

These run at **bind** time and not earlier, and they have to: checking a `Resource`
against the schema it names requires the server's advertisement, which does not exist
until something connects. Saving a connector validates what *is* knowable without a
server — legal tool names, no duplicates, no collision with a hand-written tool — and
the rest waits for the advertisement it is checked against.

### Coverage

1313 tests by default; 1677 with a Postgres DSN set; and 225 in `frontend/` via
`npm test`. The weight is on
`tests/test_patterns.py` (the matcher, including the prefix-confusion set),
`tests/test_permissions.py` (capability, reach, per-effect grants, composed
identifiers, caller substitution), and `tests/test_mcp.py` (the protocol subset, result
normalization, and — carrying most of the weight — the allowlist).
`tests/test_tenancy.py` covers where the tenant lives and the cross-tenant leak the
per-tenant registry closes; `tests/test_storage_contract.py` runs one set of assertions
against both storage implementations; `tests/test_agents.py` covers validation at write
time and load time; `tests/test_transport_http.py` covers the delivered/ambiguity
mapping above, one test per row. `tests/test_limits.py` covers each budget dial and the ordering
rules above; `tests/test_tools.py` covers descriptor validation;
`tests/test_credentials.py` covers the lookup key, the injected-kwarg contract and the
three outcomes of the delegated read path;
`tests/test_broker.py` covers enforcement, redaction, principal, run correlation, and
the size cap; `tests/test_runtimes.py` covers tier dispatch and the turn limit.

Three carry the credentials step, and the weight in each is on a refusal rather than on
the feature. `tests/test_crypto.py` is mostly about what must *not* decrypt — a row moved
to another user, tenant or connector; a flipped byte; an unknown key — plus the refusal
to start without one and the refusal to invent one. `tests/test_connections.py` covers
the write half: sealed before it is a row, nothing returning it afterwards, reconnecting
replacing rather than accumulating. `tests/test_delegation.py` is the separation
property, and it is the file to read first — its central test failed against the code as
it stood, with one user's call going out under another user's credential.

`tests/test_groups.py` carries the groups step, and its weight is on the two things
somebody would quietly undo: that a group cannot hold a credential, own a run or appear in
an audit record, and that `core/permissions.py` still does not know what a user — or a
group — is, asserted by reading its source. Both are also constrained in migration 017,
because a test written in the same language as a constant does not survive somebody
widening the constant. `test_the_permission_check_is_one_statement` in the contract suite
counts the store's round trips against real Postgres with a person in a group holding
grants on fifty agents; it was mutation-checked, and breaking it the obvious way fails
with "the permission check took 2 round trips".

Two carry the API step. `tests/test_api.py` covers the entry point — the `def`-not-`async`
rule, asserted by walking the route table; that no route accepts a tenant from the
caller; the error table one test per row; and the dev-auth hole, asserted **because** it
is a hole, so closing it is a test change somebody makes on purpose.
`tests/test_concurrency.py` drives real threads through the real objects, and its first
test is the one the step exists for: eight threads, one pooled session, and every reply
reaching the caller that asked for it.

`tests/test_roles.py` carries platform roles, and its weight is on one assertion:
`test_holding_admin_grants_access_to_no_agent_run_or_connection`. **An admin is not a
superuser** — the ladder still answers who may use an agent, `for_connector` still answers
whose credential a call acts with, and a role row changes neither. The argument is step
7b's, one level up: delegated credentials exist so that no operator holds everybody's
tokens, and an `admin` that implied agent access would rebuild that operator under a new
name. Two more are about rules that fail *silently* rather than loudly:
`test_every_admin_route_carries_the_dependency` walks the route table against a written-down
list, because an administrative route missing its dependency **works** — for the wrong
person; and `test_http_can_never_mint_a_system_principal` pins the precondition the
always-admin rule for `system` rests on.

**And one property no test can hold**, which is why the route-table walk exists rather
than being decoration: on the group routes the dependency is *redundant* with
`access/groups.py`'s own `require_admin`, so removing either one alone changes no
observable behaviour. Only `GET /admin-audit` — which reads storage directly — fails
visibly without it. Driving the product cannot tell you the dependency is still on a
group route; walking the route table can.

The suite makes no network calls, starts no subprocess, and **connects to no
database** — every MCP test drives a fake transport, and storage is in-memory. Set
`CARNET_TEST_DSN` to run the storage contract against real Postgres as well:

```bash
CARNET_TEST_DSN=postgresql://localhost/carnet_test pytest -q
```

That database is **dropped and rebuilt at the start of the session**, so point it at a
throwaway. It has to be rebuilt rather than cleaned between tests, because the audit
table refuses DELETE by design.

`frontend/` has a suite as of 10b, and it exists because of two bugs rather than a
policy. `src/lib/api.test.ts` asserts the **URLs the app puts on the wire** — the class
of assertion that would have caught the dev proxy claiming `/agents` and `/runs`, paths
the app also owns, so a *reload* returned the API's 401 JSON where the app should be.
`src/features/agents/AgentDetailPage.test.tsx` asserts the permissions screen says which
tools write, and the singular sentence that shipped reading "One tool that alter a
system". Both were mutation-checked by reintroducing the original bug.

`jsdom` is pinned to `^26`: version 30 needs Node ≥ 22, and on 20 the suite does not
fail, it fails to *collect*, with `ERR_REQUIRE_ESM` from a transitive dependency. CI
pins Node 22 so it is not the more permissive of the two.

`src/lib/auth.test.ts` drives the real `silentSignIn` on fake timers, because what it
asserts is *when* it gives up: a provider refusing `prompt=none` answers with a page
rather than a redirect, so nothing posts back and the wait used to run to the 20s
timeout. Getting that file stable took one real fix — `authorizeUrl` awaits a genuine
`crypto.subtle.digest`, which fake timers do not control, so the tests raced the module
and the *failure count varied run to run*. The harness now waits for the iframe to be in
the document before driving it.

That was the suite at 10b; it has grown with every screen since, has lint since 035m,
and CI drives the built app through a real browser since 035j.

## Response size cap

Every tool response is measured after execution and before it reaches the model.
Over the limit, the payload is **discarded** and replaced with an error stating the
size and the ceiling.

- Default `config.MAX_RESPONSE_BYTES` = 64 KiB; `Tool.max_response_bytes` overrides
  per tool.
- Enforced in the broker, never in a tool — a cap inside an implementation would only
  protect tools we wrote, which is the opposite of the point once MCP-backed tools
  arrive.
- **Refused, not truncated.** A clipped JSON payload is malformed JSON the model has
  to guess at; a clean refusal is something it can act on by narrowing its request.
- Sizes are logged even when they pass (`response_bytes`), so future caps can be set
  from data rather than guessed. For reference, 12 GitHub issues serialize to ~2.7 KB.

This is a security control, not a performance one: unbounded tool output is how
injected instructions reach the model from content an agent reads.

## What bounds a call, and what an agent's `limits` block does here

The broker consumes a `Spending` at step 2 of every call — it checks a ceiling and, on
success, consumes against it. **There is one implementation, and it is the door's.**

**`TokenBudget` is what a door call gets**, and it is the ceiling that is real here: per
token, per UTC day, counted in Postgres so it holds across replicas. Three environment
variables, and the next section is about them — see **A daily allowance**. It ignores
which tool was called, deliberately: a door caller makes one call per request under its
own credential, so the dial that matters is how much that credential may spend in total.

**There was a second implementation, `Budget`, and step 084 deleted it.** It counted four
per-run dials — `max_calls`, `max_calls_per_tool`, `max_writes`, `max_response_bytes` —
overridable per agent by a `limits` block, and *nothing in this tree ever constructed
one*: its only caller was `RunContext.start`, which belonged to the model loop step 078
deleted. Correct code that enforced nothing is worse than absent code, because somebody
greps for where a ceiling is applied and finds it. So on this deployment:

```python
"limits": {"max_writes": 0}     # accepted, validated, stored — and read by nothing
```

An agent's `limits` block is still checked when it is written — an unknown key or a
negative number is refused, with a sentence — and still stored untouched through an edit,
because a config written for a tree that *does* run agents must stay valid and stay
intact. The four key names live in `agents.KNOWN_LIMITS` now, which is the whole of what
084 kept: a vocabulary, so a typo is refused rather than stored as a ceiling nobody can
read back. It bounds nothing at the door. The agent's own page says so, under **Stored,
and not read here**; step 081 removed the controls that used to author it, because a tick
box promising *every write is refused before it reaches a system* over a dial nothing
reads is worse than no tick box.

The ordering is still load-bearing for whoever builds the second implementation, and
`TokenBudget` follows it:

- **The budget runs after the permission check**, so a call refused on scope costs
  nothing. A denial must not push a caller toward exhaustion.
- **Counters are consumed before execution**, because the point is to bound calls that
  reach an external system, and a call that fails still hit it.
- **Money is checked before the call count**, because the count *consumes*: checking it
  first would charge a call to a caller about to be refused for spend.

Two ceilings do still apply to every brokered call and are not part of any of this: the
per-response size cap above (`MAX_RESPONSE_BYTES`, and a tool's own lower one), and the
egress rules on what a connector may dial.

## A daily allowance

Two ceilings at the door, both per token, both counted in Postgres so they are the same
ceiling however many API replicas serve:

```
CARNET_MCP_CALLS_PER_DAY=1000      # calls one token may make in a UTC day
CARNET_MCP_USD_PER_DAY=300         # what one token may spend at a brokered model
CARNET_MCP_TOKENS_PER_DAY=50000000 # the net underneath it
```

The spend dials exist because a brokered call may reach a model (045c) and the
connector reports what it cost; an unpriced model costs `$0.00` against the dollar
ceiling, so the token ceiling is the net that catches it. Whichever is met first
refuses, with a sentence naming the figure and the dial. A refused call spends nothing.
The **Overview** renders the door's traffic, spend and refusals for an administrator,
and every token's own page shows what it has spent against its allowance.

## Credentials

`core/credentials.py` is the only module that reads secrets. The broker fetches them
*after* authorizing a call and injects them as keyword-only arguments the tool schema
does not contain. They never appear in the agent config, the tool arguments, the
model's context, or the audit log.

Channels map to *per-channel* webhook URLs, making the lookup a second enforcement
point: a channel with no mapping has no secret to send with.

Lookups are keyed by **(tool, principal)**, because there are two kinds of credential
and only one is a property of the tool alone:

| Kind | Example | Varies by caller? |
| --- | --- | --- |
| **shared** | the `#eng` webhook — one organisational secret | no |
| **delegated** | each user connects their own account; the vendor enforces what it can see | yes |

A ticket agent run by two people must reach two different sets of tickets, and no
policy of ours produces that — it is the credential that differs. The principal sat in
that signature for four steps before anything read it, so that delegation would be a
lookup rather than a change to this signature, the broker's call site and every
connector at once.

### Delegated credentials: the agent acts on *your* data

Each person connects their own account. The credential is encrypted at rest and
decrypted only at the moment a tool call has already been authorized.

```bash
carnet --connect-account github-remote priya@acme.com --label "@priya-acme"
carnet --list-connections          # who is connected, and as whom
carnet --disconnect-account github-remote priya@acme.com
```

**The credential is never an argument.** It arrives on a hidden prompt, or piped —
because a token in `argv` is a token in shell history and in the process table, on the
one command whose entire subject is a secret.

```bash
echo "$TOKEN" | carnet --connect-account github-remote priya@acme.com
```

### …and, as of step 7b, the credential a person gives themselves

Every command above is one an **operator** runs, which means the operator obtains and
sees each person's third-party token — precisely the thing delegated credentials exist to
avoid. The agent is meant to act as Priya rather than as the operator, and until 7b the
only way to arrange that required the operator to hold Priya's secret.

An administrator configures the consent flow once per connector:

```bash
carnet --allow-host auth.atlassian.com               # the TOKEN endpoint's host
carnet --set-oauth jira \
    --auth-server https://auth.atlassian.com \
    --client-id <id> \
    --scope read:jira-work --scope offline_access      # offline_access → a refresh token
# reads the client secret from a hidden prompt, or piped. Never from argv.
```

and then it is self-serve. A person opens **Connections**, clicks Connect, approves at
*Atlassian's* consent screen, and lands back on a row that says `Connected as
priya@acme.com` — a label the provider supplied rather than one anybody typed.

```
browser: click Connect Jira
   │  an authenticated API call, so we know whose connection this is
   ▼
POST /connectors/jira/connect   → mint `state`, return the provider's authorize URL
   │  a TOP-LEVEL navigation, not a fetch
   ▼
Atlassian's consent screen → approve
   │  Atlassian redirects the browser to us
   ▼
GET /connect/callback?code=…&state=…   ← a plain navigation, NO bearer token on it
   │  look up `state` → the principal, the connector, the PKCE verifier
   │  POST the token endpoint (client secret + PKCE) → access + refresh
   │  connect_account(...)                            ← 7a's function, unchanged
   ▼
browser lands on "jira is connected"   ← and never saw a token
```

**The token never touches the browser**, which is the decision the whole shape follows
from. Login's token is for us and the SPA holds it to call our own API; a connector token
is for *Atlassian* and is used server-side, so a browser holding it is an exfiltration
surface for zero benefit.

**The callback trusts `state`, not the request**, which is the security crux. A
provider's redirect is a top-level navigation carrying no bearer token, so "whose
connection is this" cannot come from the request — it rides in an opaque, single-use,
short-lived row minted while the person *was* authenticated. That is also the CSRF
defence: a `state` we never issued finds nothing, and a replayed one finds nothing
because the row is consumed atomically.

**The access token is refreshed before each run that needs it.** Without that, a
connection dies in about an hour and the person re-consents hourly — a consent flow whose
output expires before anybody notices it worked. Most providers *rotate* refresh tokens
and invalidate the old one on every use, so two runs refreshing at once is a lost update
that stores a token the provider has already killed and breaks the connection permanently
with nothing saying why. Two mechanisms: a compare-and-set on the row's own version, and
a single-flight lock so eight concurrent runs make **one** token-endpoint call rather
than eight. A refresh that loses the race re-reads and uses the winner's token; it never
retries the exchange, because the token it holds is spent and reuse is what trips a
provider's breach detection.

A `400 invalid_grant` is terminal: the connection is marked as needing re-consent, the
person is told in the provider's own words, and the run is refused rather than falling
back to the shared credential — which would mean the agent acting as the *operator* while
the log reported it as them.

**Disconnecting revokes upstream, and deletes locally regardless.** Deleting our row
alone leaves a live token at the provider; for an OAuth connection RFC 7009 gives us a
revocation endpoint and having obtained the token on somebody's behalf we are the right
party to hand it back. Revoke *then* delete, because delete-then-revoke loses the token
needed to revoke — and the delete is unconditional, because a provider that is down must
not leave somebody unable to end a connection they have asked to end. Whether revocation
succeeded is reported and recorded, so *"is that token still live at Atlassian"* has an
answer.

What 7b deliberately does **not** change: `--connect-account` still works on an
OAuth-configured connector and writes a `static` row. A person with a personal access
token should not be blocked because an administrator later added a consent flow, and
refusing would make configuring OAuth a destructive act for everyone already connected.

Three outcomes at read time, and the third is the reason this is written out rather
than being a one-line lookup:

```
for_connector(connector, principal, env_var)
        │
        ├─ no row                      ──►  the environment variable, exactly as before
        ├─ a row that decrypts         ──►  that person's own credential
        └─ a row that will not decrypt ──►  raise. Never the environment variable.
```

Falling back on the third would mean the agent acting as the **operator** while the
person believes it is acting as them — reaching data they have no access to, and
attributing it to them in a log kept forever. A broken credential has to look broken.
An expired row gets its own message, which is why `connections.expires_at` is nullable
rather than absent: never connected and connected-but-expired send a person to two
different places.

#### The key

**AES-256-GCM, and the key is supplied or the process refuses to start.** It is never
auto-generated. A key that regenerates makes every stored credential silently
unreadable — not at write time, not at boot, but the first time somebody's agent runs,
on a row that looks perfectly fine.

```bash
carnet --generate-key            # prints one; storing it is your job
export CARNET_SECRET_KEY=<key>
```

Required whenever there is a durable store, and by the HTTP server regardless. Without
a database the store is a dict that dies with the process, so no connection can
pre-exist or outlive it and a key would protect nothing — which is what keeps the
property that a fresh clone runs an agent with nothing installed and nothing running.

**The ciphertext is bound to its row.** GCM authenticates additional data for free, so
encrypting against `(tenant, principal, connector)` means a row lifted into another
user's row — or another tenant's — *fails to decrypt* rather than working. The database
cannot express that; a primary key stops two rows colliding and has no opinion about a
value moved between them. It is the cheapest cross-tenant defence available in a system
whose stated known limit is that tenant isolation is enforced by the application.

That binding is length-prefixed rather than joined on a separator, because
`"|".join(parts)` lets two different rows produce one string as soon as a value can
contain the separator. Free to prevent now, and impossible to fix later without
re-encrypting every row.

**`key_id` is derived from the key, never assigned** — the same argument as
`Connector.read_only` being derived: a value somebody maintains by hand is free to stop
being true. Rotation is therefore a list: `CARNET_SECRET_KEY` encrypts,
`CARNET_SECRET_KEYS_OLD` is a comma-separated decrypt-only set, and each row says
which key it still needs.

`core/crypto.py` is the only module that holds a key, the same containment
`credentials.py` has for secrets. The interface is seal/open rather than "give me the
key bytes", because with a KMS the key never leaves the service — an interface handing
out keys would have foreclosed the upgrade it exists to allow. `tenant_id` is a
parameter on both operations for the same shape-before-the-thing reason `principal` was:
every tenant resolves to the same key today, and per-customer keys later are a new class
rather than a re-encryption of every row.

#### Where this cannot be used

**A stdio connector cannot carry a per-user credential, and says so.** It takes its
credential from the environment at launch and holds it for the process's life, so one
server cannot act as two people. A `connections` row for one is refused at connect time,
loudly — ignoring it and using the environment variable would be the same untruth as the
third outcome above, arriving by a different route. The check lives in `tools/mcp`, where
the transport is known; `core/credentials.py` is told a variable *name* and deliberately
never learns what an MCP server is.

The shipped GitHub connector is stdio, so delegation there needs the one-row switch to
the hosted HTTP endpoint.

#### Two people, two sessions

The session pool is keyed `(tenant, connector, credential-fingerprint)`, which
anticipated this — two users never share a session bound with somebody else's token.

What did **not** survive contact was `ensure_available`. Binding is a fact about a
*tenant's* vetting; a session is a fact about the *caller's* credential, and the two were
welded together: once anybody had run an agent its tools were registered, so the check
"are the tools bound?" returned early and the second user of the day never got a session
at all. Their calls then fell through to a proxy fallback that borrowed whichever session
was to hand — the first user's. Priya connects her own account, runs the agent, and
reaches Sam's data because Sam ran it first that morning. No error, and the audit record
says Priya.

Both halves are fixed: a session is ensured for every run's credential, and a missing
session is **created under the right credential, never borrowed**. That is what makes
the pool cap and the idle TTL latency decisions rather than correctness ones.
`tests/test_delegation.py` asserts the separation rather than the fix.

A connector's credential is keyed by **connector, not tool** — one GitHub token serves
every GitHub tool, so keying by tool would be twenty copies of one fact. The broker
passes `tool.connector` so `credentials.py` never learns what an MCP server is.

**Where the vendor's enforcement stops.** Once a delegated credential is in play it's
tempting to think the vendor is doing the security. It isn't doing *ours*. A user's
token is strictly more powerful than the agent should be — she can see fifty repos;
the agent may touch one. Two bounds, neither substituting for the other:

- the vendor bounds what **the user** can reach
- our grants bound what **the agent** may reach on that user's behalf

## Chat delivery

`post_message` picks its transport from the webhook URL shape, so the same tool and
the same permission model work for all three:

| Backend | Setup | Env var |
| --- | --- | --- |
| **Local outbox** (default) | none | none — appends to `var/outbox.jsonl` |
| **Discord** | create a channel webhook (~1 min) | `WEBHOOK_URL_ENG` |
| **Slack** | create an incoming webhook | `WEBHOOK_URL_ENG` |

```bash
export WEBHOOK_URL_ENG="https://discord.com/api/webhooks/..."
```

That's the only change — no code edit. Add channels in `CHANNEL_WEBHOOK_ENV`
(`core/credentials.py`) and grant them in an agent's permissions.

## Audit log

One row per brokered call — allowed, denied, or failed. Denials are the most important
records, so they're never skipped.

```json
{"v":6,"ts":"2026-08-02T20:08:23.074+00:00","tenant_id":"default",
 "run_id":"e1ddbff6585d",
 "principal_kind":"system","principal_id":"cli",
 "agent":"issue-reporter","tool":"post_message","effect":"write",
 "args":{"channel":"#eng","text":"sha256:d3872206522a (len=2147)"},
 "decision":"allow","reason":"","outcome":"ok","credential":"shared",
 "duration_ms":0,"response_bytes":147}
```

`credential` is `delegated`, `shared`, or absent when the tool needed no secret or
nothing ran. It was added **with** delegated credentials rather than after, and the
reason is the whole argument for having a schema version at all: a record says who a run
acted *for* and said nothing about whose credential it *used*. Those two facts could not
disagree while there was one credential and it was the operator's. They disagree the
moment delegation ships — somebody with no connection falls back to the environment
variable, and the record reads as though the call went out as them. Whoever audits that
write six months later is wrong about the account it was made from, and the account is
what decides what the write could reach.

Deliberately *which kind*, never *whose*. A second person's identifier in a table that
is append-only by trigger, with retention still undesigned, to answer a question
`principal_id` mostly answers already — what was missing is the one bit that column
cannot carry: whether those two are the same person.

`run_id` correlates every record from one run — without it you can only ask "what did
this agent ever do?", never "what did that run do?". `outcome` is one of `ok`,
`error`, `oversize`, `unknown`, or empty when the call was denied and nothing ran. `effect` makes
"show me every write last quarter" a filter rather than an archaeology project. `v` is
the schema version — present from the first record, which is what made the move to
Postgres a filter on a field rather than a guess from which keys exist. It is now `6`;
`5` marked `tenant_id` and `6` marks `credential`.

The table is **append-only** and enforced as such; see the schema section above.

Redaction is two-layered: the tool's own `redact_args` hashes free text, and
credential-shaped names are hashed *always* — a denied call is still logged, and a
smuggled secret must not land in a log we keep forever. Policy-relevant arguments
(`repo`, `channel`) are stored in the clear; they're the point of the log.

`audit.py` depends on nothing but `config`, `credentials` and `storage` — the per-tool
policy is passed in by the broker, so audit has no knowledge of the tool registry.
That is what made swapping the JSONL writer for a database a change to this one file,
and `audit_query.py` — deliberately built as its reading half — a change to one more.

## Adding a tool

Everything about a tool lives on one `Tool` object in one module — schema, impl, and
redaction policy — so a tool can't half-exist.

1. In `tools/<family>.py`, write the function and append a `Tool(...)` to `TOOLS`.
   Credentials arrive as keyword-only args; never read `os.environ` in a tool.
2. Declare its descriptor: `effect` (`read`/`write`) and `resources`, a list of
   `Resource(type, args, template=None)`. Validated at import.
3. New family? Add one import line to `tools/__init__.py`.
4. Needs a secret? Add the lookup to `core/credentials.for_tool`.
5. Returns unusually large or unusually untrusted output? Set `max_response_bytes`.
6. Grant it in an agent's `permissions` — add the name to `tools`, and the resource
   type to `scope` if it declares one.

New *constraint kinds* (regex, numeric ceiling, time window) go in
`core/permissions._check_resource`, which is shaped to accept them; the broker doesn't
change.

## Adding an agent

`agents.save(tenant_id, config)`. It validates first, so an invalid config never
becomes a row, and the errors are the ones a person has to read at 3am.

A config's `name` is the key it is stored under — the broker trusts it as identity, so
a mismatch would misattribute audit records. Enforced by a `CHECK` constraint as well
as by the loader.

`bootstrap.py` carries the shipped example — a permission list granting two tools with
a scope each. It is what `--seed` writes, and it is the worked example of a real grant.

## Notes and limits

- Tool names can't contain dots (`^[a-zA-Z0-9_-]{1,64}$` per the Messages API), so
  `github.list_issues` isn't expressible — hence `github_mcp_list_issues`.
- **`effect` is per-tool, not per-argument.** A hypothetical `copy_issue(from, to)`
  would check both arguments against `write`. Per-argument effects are a later
  refinement.
- **Grants are allow-only.** No explicit denies, so no precedence rules to reason
  about — adding them later is a design decision of its own.
- Scope patterns are strings. An identifier **composed** from several arguments is
  handled (`Resource(..., template=...)`), but one with genuine internal structure —
  an opaque GUID whose bytes carry meaning, a key that isn't segment-shaped — will
  need a new constraint kind, which `_check_resource` is shaped to accept.
- A composed identifier's components may not contain `/`. A resource whose component
  is legitimately path-shaped needs that new constraint kind rather than a template.
- **Tenant isolation is enforced by the application, not the database.** Every query
  filters on `tenant_id` and the contract suite checks it, but a missed `WHERE` is a
  leak. Row-level security is the belt to these braces and belongs with the access
  layer, when there is a per-tenant database role to attach it to.
- The in-memory store is a second implementation that can drift. The contract suite is
  the mitigation, and it only runs against Postgres when a DSN is set — so a developer
  who never sets one can write a passing test for behaviour Postgres does not have.
- Connectors are loaded from storage per run, with no cache. A cache would have to be
  tenant-keyed and invalidated on write, and the failure mode of getting that wrong is
  not a stale read but one tenant serving another tenant's allowlist.
- `audit_query` still loads records into memory to group them into runs. Fine at CLI
  scale; the aggregation belongs in SQL once there is a fleet to report on.
- Migrations are forward-only. No `down`, which is right at this stage and will not
  stay right.
- **The identity provider is a hard dependency of every request.** A JWKS fetch failure
  would be an outage, so keys are cached for `JWKS_CACHE_TTL` and a stale set is served
  rather than failing when a refresh dies. That is not failing open — a stale key still
  has to verify the signature.
- **Revocation is only as fast as token expiry.** No introspection, no revocation list:
  a departed employee's token works until it expires. Keep lifetimes short; `users.status`
  is the only thing that cuts somebody off immediately.
- **Key rotation is tested against a synthetic provider, not a real one.** Providers
  replace their signing keys every few months, and a token then arrives signed by a key
  we have never seen. Handled — an unknown `kid` triggers exactly one refetch, and there
  is a test that publishes a second key and checks a token signed by it verifies — but
  the test provider is one we generate, not Okta.

  Getting this wrong locks out **every user** on the day a customer's provider rotates,
  months after deployment, with no code change to blame. So it is worth saying why it
  was not verified against the real thing: Okta *can* be made to rotate on demand
  through its API, but that needs an admin API token — a long-lived secret, unlike the
  public client id and short-lived access tokens everything else here uses. The
  incremental confidence did not seem worth introducing one. Revisit if a rotation ever
  causes an incident, at which point it will be worth the token.
- **The audit log is personal data now.** `principal_id` stopped being `cli`. It is an
  opaque id rather than an email precisely so that a table which is append-only *by
  trigger* does not accumulate addresses nobody can remove — but the linkage exists in
  `users`, and retention is still undesigned.
- **`CARNET_TENANT` for the CLI is a typo guard, not a boundary.** Whoever runs
  the CLI holds the database URL and can read any tenant directly, so checking which one
  they name protects nothing from them. It catches a misspelling before it becomes a run
  against a customer who does not exist.
- **No SCIM in this tree** (built in step 071 and held back in 078), and **no SAML** —
  some regulated buyers federate only that way, and Okta and Entra can bridge it.
- **Sharing has no groups.** `agent_grants` names principals, so sharing with forty
  people is forty rows. A claims-to-roles mapping is a second indirection and wants its
  own reason.
- **A pending grant to an address somebody's account never carries waits forever.**
  Share with `priya@acme.com` when her directory address is `p.sharma@acme.com` and the
  row sits there. `--agent-access` lists what is waiting for exactly this reason, and
  nothing expires them. Nobody is notified either — sharing writes a row, and the person
  finds out by looking.
- **A claim runs at a first login and on an address change, not on every request.** A
  grant created between those two moments applies at the next one. The alternative is an
  indexed query per authenticated request to catch a case that is rare by construction.
- **Two users in one tenant can share an address**, since `users` is unique on
  `(issuer, subject)` and a customer may have two providers. The lookup resolves to the
  lowest id, deterministically, and the other never receives what was shared.
- **A share survives its sharer.** An invitation sent by an editor who has since been
  revoked still lands at the recipient's first login — the same way a grant they made
  directly would still stand. Consistent, and worth knowing before reading an access
  list and wondering who authorised what.
- **Revoking somebody's access hides their own past runs from them.** Visibility follows
  the *agent*, not the runner: if you may use an agent you may see what it has done,
  including runs other people started, which is what an owner needs in order to know what
  their agent is being used for. The cost is the mirror image — lose access and you lose
  sight of work you did yourself. The audit trail still holds it and the CLI can still
  read it; the person cannot. Observed by doing it, not reasoned about.
- **The model is chosen from a three-entry menu, and the field is not validated.** The
  form offers Fast / Balanced / Most capable with relative cost; `POST /agents` accepts
  any model string. That asymmetry is deliberate — a tool is a tenant's own vetting
  decision and is refused if unknown, while a model is the provider's set and changes
  without anybody here acting, so an allowlist would refuse configs the API accepts. The
  cost: a typo'd model stores happily and fails at run with the provider's error.
- **Nothing reports what a run cost.** The form shows relative cost before the fact and
  no figure exists after it. Distinct from the cross-run budget gap: that one bounds
  spend, this one merely shows it.
- **An `editor` still cannot edit.** The level exists and only its re-sharing half does
  anything: `routes_agents.py` gained a create and no update, so `PATCH` is the first
  caller of the level and it does not exist yet. Deliberate, and the same
  shape-before-the-thing bet as `Principal.user()` and the `connections` table — a write
  route should be a route, not a route plus a permission model.
- **Creating an agent is not audited.** A tool call is; a configuration change is not.
  Until there was a create route only `--seed` wrote agents, so there was nobody to have
  a record of. There is now, and "who made this agent, and what did they grant it?" has
  no answer beyond the owner grant's `granted_by`.
- **A refused grant check writes no audit record.** Nothing was brokered, so there is
  nothing for the audit log to hold: "who tried to run an agent they may not?" is
  unanswerable, and it is the question asked after an incident. An access log is a
  different artifact from a tool-call log and deserves its own decision.
- **Session locking serializes tool calls** per (tenant, connector, credential). The
  session TTL and pool cap are still invented numbers, but the cap was **re-derived**
  rather than inherited: the key space became tenants × connectors × *users*, so 32 meant
  roughly thirty-two concurrently active people platform-wide. It is 256, settable with
  `CARNET_MCP_SESSION_POOL_MAX`, and `SessionPool.overflow_evictions` counts what
  it would take to stop guessing — an eviction raises no error, so a pool a tenth the
  size it should be otherwise looks exactly like a slow MCP server.
- **Every ceiling here is per process, so `uvicorn --workers N` multiplies it.** Four
  processes means four session pools, four bound-tool registries and four connection
  pools. Nothing breaks — the locks are per process and so is the state they guard — but
  the numbers stop meaning what they say, and a connector container is started per
  process rather than per host. The door's daily ceilings are the exception: they are
  counted in Postgres and hold across replicas. Run one process until the rest is shared.
- **A denied read does not make a permitted write suspect.** Observed, not theorised:
  asked for a repository outside its scope, the broker refused — correctly, and the
  refusal is in the audit log — and the model then **invented** plausible issue titles
  and posted them through its *other* grant. The audit record reads `post_message[ok]`,
  because as a call it was entirely legitimate.

  Nothing was breached; the reach boundary held exactly as designed. But it shows the
  boundary's shape: a denial is returned to the model as information, and the model is
  free to fabricate and then act through a different, permitted tool. Permissions bound
  what a call may *reach* and budgets bound how much it may *do*; **neither has any
  opinion about whether what it writes is true.** `max_writes` was the only dial that
  touched this, and it was a blunt one — and it does not apply at the door at all, which
  makes the gap wider here than the sentence above implies: what bounds a door caller is
  a count and a spend per day, neither of which distinguishes a write from a read. The
  narrower answer is per-call checks on what a call carries, which is registered work and
  not built. Connecting "that read was refused" to "this write is now suspect" is a real
  design question and nothing in the system does it.
- **A call's correlation id is 48 bits** (`uuid4().hex[:12]`), which collides at around
  a billion calls, and nothing in `audit` enforces uniqueness on it. Widening it changes
  every id already written down.
- An existing `var/audit.jsonl` is **not** backfilled into Postgres. Records carry `v`
  from the first line so a backfill stays possible; it wasn't worth doing now.
- Cumulative byte overruns are detected on the call *after* the one that crossed.
- `credentials.for_tool()` is still an `if tool_name == ...` chain for hand-written
  tools. Connector tools no longer go through it, so it stops growing — but it should
  become a per-tool declaration before more hand-written tools arrive.
- **The encryption key lives in an environment variable**, readable by anything that can
  read the process environment. Better than plaintext in a database by a wide margin, and
  short of a KMS. `key_id` is what makes moving to KMS-wrapped or per-customer keys a
  change to `crypto.py` rather than to every row.
- **One key serves every tenant.** One compromised key is therefore every customer. Real
  isolation needs somewhere per-tenant to keep a key, which is the KMS question again —
  and the seam is in: `seal`/`open_` already take a `tenant_id` that the local cipher
  ignores.
- **Rotation is manual.** Set a new key, list the old one in
  `CARNET_SECRET_KEYS_OLD`, re-encrypt by hand, drop the old one. The old-key list
  makes rotation possible; a background re-encrypt job would make it finishable, and
  wants the job model.
- **Revoking a connection does not stop a call already holding the credential.** The fetch
  happened at the tool call, and Python cannot interrupt a thread — the same constraint
  as the request timeout and the grant check.
- **Deleting a user leaves their connections behind**, encrypted and openable by nobody
  — the same orphan shape as their grants.
- **A connection cannot wait for somebody the way a share can.** `--share-agent` to an
  address nobody holds becomes a pending grant; `--connect-account` refuses. A share is
  an invitation, which is a reasonable thing to leave waiting; a credential would be a
  secret sitting encrypted at rest for an account that may never exist.
- **`account_label` is not verified.** The platform ships no integrations, so it cannot
  ask an arbitrary MCP server whose token this is. **7b's OAuth flow now gets it from the
  token response, verified**, so an `oauth` connection's label is the provider's answer —
  but a `static` one is still whatever somebody typed, and the two look identical on the
  page except for the `credential_kind` beside them.
- **Tool descriptions are not pinned.** The allowlist controls *which* tools appear;
  it says nothing about what their descriptions say, and a model reads a description
  as authoritative rather than as content. A compromised or careless server can put
  instructions there. The size cap and byte budgets defend tool *results*; nothing
  defends this. The fix is a lockfile — hash description and schema at vetting time,
  fail the bind on change — which is correct and noisy, since every upstream release
  then breaks the build on purpose. Deferred deliberately at one connector.
- **The MCP subset is deliberate**: `initialize`, `notifications/initialized`,
  `tools/list` (paginated), `tools/call`, over either transport. No resources, prompts,
  sampling, roots, completions, server-initiated requests, or cancellation — and on the
  HTTP side, no client→server GET stream, which the spec makes optional for exactly
  that reason. Hand-written rather than taken from the `mcp` SDK, which is async-first
  against a synchronous runtime and brings pydantic/httpx/anyio/starlette for three
  methods. If we need more of the protocol, take the SDK and put an adapter behind the
  same `Session` interface.
- **Stdio holds credentials for a process lifetime**, so a stdio connector cannot carry
  per-user credentials — see the transports section. This is now **refused rather than
  documented**: a `connections` row on a stdio connector fails the run before anything is
  launched. The shipped GitHub connector stays stdio because that is what the local
  Docker image speaks and what the comparison baseline was measured against, so
  delegating it needs the one-row switch to the hosted endpoint.
- **No OAuth.** MCP's authorization spec is a per-user consent flow and needs a
  signed-in user, which does not exist yet. Servers that refuse static credentials
  cannot be used until the access layer lands.
- **No SSE resumability.** We do not send `Last-Event-ID`, so a stream dropped
  mid-`tools/call` is an ambiguous write needing a person rather than something the
  client recovers from. Correct, and more annoying than it sounds the first time a
  proxy times out.
- **A connector row now causes an outbound request.** An HTTP connector's URL is
  supplied by a connector admin — a reviewed role, but this is the first time data in
  the database reaches the network. An egress allowlist belongs here before this is
  multi-tenant in production.
- SSE lines are split with `requests.iter_lines`, which splits on more separators than
  SSE defines. A `data:` payload containing a raw U+2028 could be split wrongly. Remote
  in practice, and the fix is a hand-rolled chunk reader.
- Sessions are process-global. A stale one is retired when `tools/list` reveals it and
  replaced once, and an expired HTTP session re-initializes. Idle eviction and a pool
  cap now exist — see **Running two of anything at once** — with invented numbers,
  because there is still no real traffic to size them against.
- `Tool.max_response_bytes` is per-tool. A whole server being verbose wants a
  connector-level default.
- Unauthenticated GitHub is capped at 60 req/hour per IP.
- `get_github_issues` has been **retired**. The connector replaced it, and keeping two
  paths to one system meant maintaining the one with the bug. The registry now holds a
  single hand-written tool, `post_message`, which exists because no vendor publishes
  it — picking Slack, Discord or a local file from the URL shape is our logic.
- `var/` is gitignored, and `outbox.jsonl` is the only thing still written
  there — the audit log moved to a table. An existing `audit.jsonl` from before that
  move is now inert. Override the location with `CARNET_VAR_DIR` in a container.
