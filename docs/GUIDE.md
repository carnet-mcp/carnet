# Guide

What you do after Carnet is running: reach a server of your own, hand it a credential
without holding one, ask what a token can do before it does it, and broker a model call.

The two ways to start it are in the [README](../README.md). Everything here assumes one
of them is already up.

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

**Upgrading an existing database is [docs/UPGRADING.md](UPGRADING.md)** — what the
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
every one of them is editable before you register. Recipes are deliberately few — each
one is a claim about somebody else's API that goes stale on their schedule, so the set
stays small enough to re-check by hand.

Revoking a host leaves its connectors registered and stops them connecting. Deleting
them would destroy the record of which tools somebody approved.

These began as command-line only, and the reason is worth keeping: registering a
connector and approving a tool needed an administrator role to sit behind, and until that
role existed there was nowhere safe to put a route. The role exists now and so does the
vetting screen — see [the administration routes](CAPABILITIES.md#administration). The commands stay
because some people would rather script it than click it.

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

A simulation deliberately writes no record of itself. It is a question about a
permission, asked by somebody who already holds it; recording every question would fill
the log a real refusal needs to stand out in.

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

**A schema is the contract, and what it omits is refused.** The vetter authors it, so
any argument the schema does not carry is refused before the vendor is dialled, with a
sentence naming it — never dropped, so a caller is not told a value applied when it did
not. That is 045a's rule. Through `/mcp` the two schemas above refuse `stream: true` as
well, because that door is JSON-only; the OpenAI-compatible surface below is where a
model call streams, and its recipe declares `stream` for exactly that reason.

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

### Put Carnet in front of Azure OpenAI

A company has built its own coding agent. It runs on every engineer's machine, calls
Azure AI Foundry's OpenAI-compatible endpoint with the Azure OpenAI SDK, and every
engineer already signs in with `az login`. The company wants per-engineer usage and
spend, a daily ceiling per engineer, and the Azure key off every laptop — and the
engineer to change nothing: same `az login`, same agent, no token to mint, no page to
visit. This is step 108, and it is what the OpenAI-compatible surface exists for.

#### What the agent's author changes, once

Two values in the client, and a fifteen-line function that supplies the second:

```python
# before
client = AzureOpenAI(azure_endpoint=FOUNDRY_URL, api_key=os.environ["AZURE_OPENAI_KEY"],
                     api_version="2024-10-21")

# after
client = AzureOpenAI(azure_endpoint=CARNET, api_key=carnet_token(),
                     api_version="2024-10-21")
```

`CARNET` is the deployment's API address — `https://carnet.acme.com/api` behind the
shipped front door. Every `resp.choices[0].message.content`, every stream loop and every
tool-call delta is untouched: what comes back is Azure's answer, byte for byte, streamed
chunk for chunk when the agent asked for a stream. The Azure key is deleted from the
agent's configuration. `carnet_token()` is this, and it is run as written by
`scripts/e2e_openai_surface.py` so it cannot rot:

```python
# carnet_token.py — the silent first-run exchange. Standard library only.
import json, os, pathlib, socket, subprocess, urllib.error, urllib.request

CARNET = os.environ.get("CARNET", "https://carnet.acme.com/api")
CARNET_APP_ID = os.environ.get("CARNET_APP_ID", "<carnet-app-id>")   # the Entra app registration
CACHE = pathlib.Path(os.environ.get("CARNET_TOKEN_FILE", "~/.config/carnet/token")).expanduser()


def entra_token() -> str:
    """The signed-in engineer's Entra token *for Carnet's app*, from the `az login` session."""
    if os.environ.get("CARNET_ENTRA_TOKEN"):          # a test or a CI job supplies its own
        return os.environ["CARNET_ENTRA_TOKEN"]
    return subprocess.check_output(
        ["az", "account", "get-access-token", "--scope", f"api://{CARNET_APP_ID}/.default",
         "--query", "accessToken", "-o", "tsv"], text=True,
    ).strip()


def mint() -> str:
    """One personal token, owned by the engineer, cached 0600. Refused loudly when the
    engineer has been offboarded — never retried, because re-minting is refused too."""
    body = json.dumps({"name": f"coding-agent · {socket.gethostname()}"}).encode()
    request = urllib.request.Request(f"{CARNET}/me/tokens", data=body, method="POST",
        headers={"Authorization": f"Bearer {entra_token()}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            token = json.load(response)["token"]
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Carnet refused to mint a token ({exc.code}): {exc.read().decode()[:300]}") from exc
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(token)
    CACHE.chmod(0o600)
    return token


def carnet_token() -> str:
    """The cached token, or a freshly minted one. The two error rules the agent needs:
    on 401 `invalid_api_key` (revoked or expired) delete the cache and mint once more;
    on 403 `account_deactivated` stop — surface the sentence and do not re-mint."""
    if CACHE.exists():
        return CACHE.read_text().strip()
    return mint()


def refreshed_after(error) -> str | None:
    """Call from the agent's error handler with the SDK's exception. Returns a new token
    to retry with, or None when the agent should stop and show `error`."""
    body = getattr(error, "body", None)          # the SDK's parsed `error` object
    code = body.get("code") if isinstance(body, dict) else None
    if getattr(error, "status_code", None) == 401 and code == "invalid_api_key":
        CACHE.unlink(missing_ok=True)
        return mint()
    return None
```

The agent calls `refreshed_after(exc)` once when the SDK raises `AuthenticationError`,
retries with the token it returns, and stops when it returns `None`. A `403
account_deactivated` is the person having been disabled; the sentence says so and the
right move is to stop rather than mint all night.

**What the exchange depends on, said out loud.** The token the agent presents must have
*Carnet* as its audience: `az login`'s default token is for Azure Resource Manager and
Carnet refuses it, correctly. Somebody with Entra admin rights creates **one app
registration** for Carnet, exposes an API scope on it, and sets
`accessTokenAcceptedVersion: 2`; its application id is `CARNET_APP_ID` above and the
`--audience` below. This is the one step neither Carnet nor the agent's author can do
for the company, and it is the one most likely to stall a rollout.

#### The admin's hour, in the container, once

```bash
# 1. The identity provider, spelled for Entra: the stable id is `oid`, the email is the UPN.
#    `acme` is your tenant id — the customer the provider signs people into.
carnet --add-idp acme \
    --issuer   https://login.microsoftonline.com/<tenant-id>/v2.0 \
    --jwks-uri https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys \
    --audience api://<carnet-app-id> \
    --subject-claim oid \
    --email-claim preferred_username \
    --domain acme.com                      # --groups-claim groups lights up directory groups

# 2. The resource, and the connector from the recipe. Your resource, not the recipe's placeholder.
carnet --allow-host acme-foundry.openai.azure.com
carnet --add-connector foundry --from-recipe azure-openai \
    --url https://acme-foundry.openai.azure.com \
    --credential-env AZURE_OPENAI_KEY      # the one key, in .env, held here and nowhere else

# 3. The three tools, each from the recipe: binding, schema, usage map, redaction, cap, prices.
carnet --vet foundry --tool chat_completions --from-recipe azure-openai
carnet --vet foundry --tool embeddings      --from-recipe azure-openai
carnet --vet foundry --tool list_models     --from-recipe azure-openai
```

Then one permission list, shared with the group that owns the agent (or linked to a
directory group, so membership follows Entra):

```json
{
  "name": "coding-agent",
  "permissions": {
    "tools": ["foundry_chat_completions", "foundry_embeddings"],
    "scope": {"azure.deployment": {"write": ["*"]}}
  }
}
```

**The first week's scope is `write: ["*"]` with a generous ceiling.** Nothing is
refused, everything is recorded, and the admin reads a week of the overview before
deciding what to tighten. A governance product that begins by refusing things on day one
is one that gets removed on day two; the value on day one is the log, and the log needs
traffic. After the week: name the deployments (`write: ["gpt-4o-prod", "gpt-4o-mini-prod"]`),
set `CARNET_MCP_USD_PER_DAY` and `CARNET_MCP_CALLS_PER_DAY` — per engineer, across every
machine they hold — and read the refusals on the door log.

**Prices.** The recipe carries OpenAI's list prices as of its date, which Azure matches
for the same models. When yours differ — a reservation, a region, next quarter — set
`CARNET_MODEL_RATES` or re-vet with `--pricing`; the overview says *estimated, priced at
read time*, so a corrected table reprices the history.

#### What it looks like from each seat

- **The engineer** sees nothing new. On first run the agent mints a personal token
  from the `az login` session and caches it; a second machine mints a second token under
  the same name, and both draw on one daily allowance. Ctrl-C mid-completion closes the
  upstream request too, so Azure stops generating, and the row says `aborted`.
- **The admin** reads the door log with the person's email on every row and a filter by
  it, and an overview where an engineer with two machines is one bar. `--simulate` for a
  token and a deployment gives the same verdict and the same sentence the route would.
- **The SDK** raises its own classes with Carnet's sentences inside them: a deployment
  outside the scope is `PermissionDeniedError` with `insufficient_scope`, a ceiling is
  `RateLimitError` with `daily_limit_reached`, a prompt over 4 MiB is a 413. Azure's own
  429 arrives whole, with its `Retry-After`, so the SDK's backoff works as before.
- **A CI pipeline** that runs the same agent unattended holds a **service** token minted
  by the admin, with its own grant and its own budget; its rows say *nobody named*.

#### Two network shapes, and the trade

A public Foundry endpoint needs only `--allow-host`. A **private endpoint** resolves to a
`10.x` address inside the VNet, which egress refuses unless the operator consents:
`CARNET_EGRESS_INTERNAL_HOSTS=acme-foundry.openai.azure.com`, and Carnet itself deployed
inside the VNet or peered to it, or the call cannot leave.

**This makes Carnet an inline dependency of every model call the company makes.** Before
it, a Carnet outage stopped tool calls; after it, it stops the agent. There is
deliberately no fallback to calling Foundry directly, because that is a path around the
door with the key on the laptop again — the state this exists to end. Availability is the
deployment's problem, and `deploy/` is where it is solved. Every open stream holds one
thread for the life of the completion; `CARNET_THREADS` (default 200) is the ceiling on
engineers mid-completion per process, and the compose file's comment says when to add
`--workers`.

The agent's own tool calls — to GitHub, to Jira — go through `/mcp` as they do today.
That is the moment the two halves meet on one audit trail: the model call and the tool
call it led to, under the same person, on the same page.

`issue-reporter` reads GitHub through the vetted MCP connector, so it needs Docker
and a read-only GitHub token:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=github_pat_...   # public repos, read-only
```

Without installing: `python -m carnet.cli`. Tests: `pytest` from `backend/`.

No chat account needed — with no webhook configured, `post_message` writes to
`var/outbox.jsonl`. See **Chat delivery** below.

