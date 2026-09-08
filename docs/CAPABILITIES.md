# What you can do with Carnet

The complete user-facing surface of this repository, enumerated rather than remembered.
`backend/tests/test_capabilities.py` reads the code and refuses to pass if a CLI flag, an
HTTP route, a `carnet.yaml` key, a `CARNET_*` setting or a screen exists that this
document does not name. It can prove the list is complete; whether each sentence is
*true* was checked by a person on 2026-09-07, against an acceptance pass that ran every
end-to-end harness in this repository in one sitting — forty of them, 2,921 assertions,
against real Postgres, real sockets, the real command line, real Chromium and the real
image. `backend/scripts/acceptance.py` is that pass, and it is one command.

**Everything here is in this repository, under its licence.** Carnet is one image and two
ways to run it. Free brokers a person's own account safely; paid is what an organisation
needs to administer many of them. The line that positioning draws is not a line through
this code: groups, platform roles, ceilings, retention and tenant isolation are all here.
What is *not* here is the enterprise plane around it — an Entra or Okta connector, SCIM
offboarding, teams, support and a release promise.

The two artefacts, in one sentence each:

- **The fileborne door** — one container, one `carnet.yaml`, no database, no sign-in.
  Tokens, connectors and agents are declared in the file; secrets are `${VARIABLE}`
  pointers into the environment; every call and refusal is one JSON line on stdout.
- **The platform** — the same image with Postgres behind it. People sign in, connect
  their own accounts, mint their own tokens; an administrator registers connectors and
  vets tools in a browser; the audit trail is a table as well as a stream.

Both serve the same `/mcp`: `tools/list` returns what a token may call, `tools/call` runs
one through the broker, and every call writes exactly one audit record.

---

## 1. The fileborne door: `carnet.yaml`

Every key the file accepts. An unknown key anywhere is refused rather than ignored, so a
misspelling cannot silently mean the default. Names are lowercase letters, digits and
hyphens. `carnet --check-file` reports the first refusal by key.

### Top level

| Key | What it declares |
| --- | --- |
| `connectors` | the MCP servers and REST APIs this door can reach, by id |
| `agents` | permission lists: which tools a token may call and the scope on each |
| `tokens` | the tokens people paste into their clients, each granted one or more agents |

### `connectors.<id>`

| Key | What it does |
| --- | --- |
| `kind` | `http` (a Streamable HTTP MCP server, the default) or `rest` (a plain HTTP API whose tools you author). `stdio` is refused: a fileborne door has no accounts, and a stdio server holds one credential for everybody |
| `url` | the endpoint. Plain `http://` and private addresses are refused unless the operator consents to the host in `CARNET_EGRESS_INTERNAL_HOSTS` |
| `credential` | the shared credential presented to the server, as a `${VARIABLE}` pointer. A literal is refused. Omit for a server that takes none |
| `credential_header` | the header the credential travels in. Default `Authorization` |
| `credential_prefix` | what precedes it in that header. Default `Bearer `; `""` for a vendor that wants the bare token |
| `headers` | non-secret headers sent on every request, e.g. a vendor's version header |
| `description` | what this connector is, for whoever reads the catalogue |
| `tools` | the tools this door exposes from that server — and only these; everything else the server advertises stays invisible |

### `connectors.<id>.tools[]`

Every tool, of either kind:

| Key | What it does |
| --- | --- |
| `name` | the tool's name as the server advertises it (or, for `rest`, the name you give it) |
| `effect` | `read` or `write`, required. The one judgment a server cannot make for you: it decides which scope line applies |
| `resources` | what the tool touches, so an agent's scope can bound it (see below). A `write` with none is refused |
| `identity` | accepted only as `service`. `user` is refused in a file — nobody signs in to a fileborne door, so every call to such a tool would be refused |
| `local_name` | the name agents grant, when the generated `<connector>_<tool>` is too long or too ugly |
| `description` | what the tool does, in your words; shown to the model |
| `note` | what somebody here should know before granting it |
| `max_response_bytes` | a per-tool response cap, for a tool whose output is genuinely large |
| `redact_args` | arguments the audit line hashes rather than stores — a prompt, a message body |

A `rest` tool, additionally — a REST API does not describe itself, so these are what
discovery would have supplied:

| Key | What it does |
| --- | --- |
| `method` | `GET`, `POST`, `PUT`, `PATCH` or `DELETE` |
| `path` | the path template joined to the connector's `url`; `{argument}` segments name arguments from the schema |
| `schema` | the tool's input schema, a JSON Schema object — what the model sees and what `resources` validates against |
| `query` | schema arguments that travel as query parameters |
| `body` | schema arguments that travel in the JSON request body |
| `usage_map` | where token usage lives in this API's answers, for the spend metering |
| `pricing` | what this vendor's models cost, in USD per million tokens, keyed as `CARNET_MODEL_RATES` is |

### `resources[]` on a tool

| Key | What it does |
| --- | --- |
| `type` | the resource type a scope line names, e.g. `jira.project` |
| `args` | the tool argument(s) that carry the identifier |
| `template` | how several arguments compose into one identifier, e.g. `{owner}/{repo}` |
| `families` | the families this type's ids divide into, so a scope can say `haiku` instead of a dated model id |

### `agents.<name>`

| Key | What it does |
| --- | --- |
| `tools` | the local tool names this agent grants |
| `scope` | `<resource type>: {read: [patterns], write: [patterns]}`. `*` is a whole segment, never a prefix |

### `tokens.<name>`

| Key | What it does |
| --- | --- |
| `secret` | a `${VARIABLE}` holding what `carnet --new-token` printed. The door stores a hash and re-reads the token's grants on every call |
| `agents` | the agents this token is granted; it sees the union of their tools, each keeping its own agent's scope |

The two commands that need no store: `carnet --new-token` mints a token offline, and
`carnet --check-file PATH` applies the file to a throwaway store and reports what it
declares or the first refusal. `carnet --discover ID` with `CARNET_FILE` set dials a
connector and prints the `tools:` block to paste.

---

## 2. The command line: every flag

`carnet --help` groups these the same way. The CLI acts as the `system:cli` principal, a
principal with grants like any other; it is how an engineer at a terminal does what the
browser also does, plus the operator's commands the browser deliberately does not offer.

### General

| Flag | What it does |
| --- | --- |
| `--version` | print the version and exit |
| `--list` | list this tenant's agents |
| `--list-tools` | every tool this tenant may grant, with its effect |
| `--quiet` | log warnings only |
| `--admin-log [N]` | the last N administrative changes — who granted, revoked or deleted what |
| `--denials [N]` | the last N refused access attempts |
| `--migrate` | apply pending schema migrations to `CARNET_DATABASE_URL`. Runs before the store is configured, so a database from any released version can be brought up to date |
| `--seed` | write the shipped example agent and connector into this tenant, once and deliberately; never overwrites a configuration a person wrote |
| `--generate-key` | print a fresh encryption key for stored credentials. Never generated automatically |
| `--new-token` | print a fresh machine token for a `carnet.yaml` |
| `--check-file PATH` | validate a `carnet.yaml` and report what it declares, or the first refusal by key |
| `--finish-rotation` | re-encrypt every stored secret under the current key and report whether the old keys can be dropped. Exit 0 when they can, 1 while any row still needs one |

### Sharing an agent

| Flag | What it does |
| --- | --- |
| `--share-agent AGENT WHO` | give somebody access to an agent, at `--role` |
| `--role {user,editor,owner}` | user calls through it, editor also shares it on, owner also deletes and transfers |
| `--unshare-agent AGENT WHO` | take somebody's access away |
| `--agent-access AGENT` | who may use this agent and at what level |
| `--rename-agent OLD NEW` | change an agent's name, keeping its grants and history |

### Groups

| Flag | What it does |
| --- | --- |
| `--add-group NAME [DESCRIPTION]` | create a group |
| `--delete-group GROUP` | delete a group, its membership and its grants |
| `--group-add GROUP WHO` | put somebody in a group |
| `--group-remove GROUP WHO` | take somebody out |
| `--group-link GROUP DIRECTORY_ID` | hand a group's membership to the customer's directory: its members become whoever the groups claim names, at each person's next sign-in |
| `--group-unlink GROUP` | stop following the directory; removes nobody |
| `--groups [GROUP]` | list groups, or one group's members |

### Platform roles

| Flag | What it does |
| --- | --- |
| `--grant-role ROLE WHO` | make somebody an administrator of this tenant (`admin`). Refused for an address nobody has signed in with — a role is not an invitation |
| `--revoke-role ROLE WHO` | take a platform role away; warns when the tenant is left with no administrator |
| `--list-roles` | who may administer this tenant |

### API tokens

| Flag | What it does |
| --- | --- |
| `--mint-token NAME WHO` | create an API token owned by a person and print it once |
| `--expires-days N` | with `--mint-token`: expire after N days (default never) |
| `--as-owner` | with `--mint-token`: a personal token — it resolves its owner's access and may hold no grant of its own |
| `--revoke-token TOKEN_ID` | close a token; the row stays so old records still name it |
| `--list-tokens` | this tenant's tokens and what happened to each |
| `--reach TOKEN_ID` | what this token may call, tool by tool, with the agents that grant each — without presenting it |
| `--simulate TOKEN_ID` | with `--call`: would this call be admitted, and which rule decided. Dials nothing, records nothing |
| `--call TOOL` | with `--simulate`: the tool to ask about |
| `--arg NAME=VALUE` | with `--simulate`: one argument of the hypothetical call, repeatable |

### People

| Flag | What it does |
| --- | --- |
| `--list-users` | who is in this tenant, their status, whether they have signed in |
| `--disable-user WHO` | cut somebody off now: sign-in refused, every token they own refused at its next call. Nothing they made is deleted |
| `--enable-user WHO` | let a disabled person back in |

### Registering a connector

| Flag | What it does |
| --- | --- |
| `--add-connector ID` | register an MCP server or a REST API. Vets nothing |
| `--url URL` | its endpoint: a Streamable HTTP MCP server, or with `--kind rest` a base URL |
| `--kind {http,rest}` | what the URL is |
| `--credential-env NAME` | the environment variable holding the shared credential. A name, never a value |
| `--check-credential CONNECTOR` | resolve the shared credential now and say whether it worked. Never prints it |
| `--credential-ref op://VAULT/ITEM/FIELD` | hold the shared credential in your own 1Password vault, read at call time and never stored here |
| `--credential-header NAME` | the header the credential is presented in |
| `--credential-prefix TEXT` | what precedes it; `''` for the bare token |
| `--header NAME=VALUE` | a non-secret header sent on every request, repeatable |
| `--description DESCRIPTION` | what this connector is |
| `--list-recipes` | the connector presets this build ships, and when each was last checked against its vendor |
| `--from-recipe ID` | with `--add-connector` or `--set-oauth`: take a recipe's values as defaults. Vets nothing, approves no host |
| `--allow-asserted-identity` | with `--add-connector`: believe an asserted acting-for through the door for this server's tools. Off by default |
| `--set-asserted-identity ID ON\|OFF` | turn that on or off for a registered connector |
| `--allow-host HOST [NOTE]` | let this tenant dial a host. Nothing is dialled without one; an empty allowlist denies |
| `--revoke-host HOST` | withdraw a host; connectors using it stay and stop connecting |
| `--list-hosts` | which hosts this tenant will dial, and who approved each |
| `--discover ID` | connect and print what the server advertises, with input schemas — and the block to paste into a `carnet.yaml` |
| `--vet ID` | approve one of a connector's tools. Needs `--tool` and `--effect` |
| `--tool TOOL` | the tool name the server advertises |
| `--effect {read,write}` | does this tool observe, or change something |
| `--identity {service,user}` | whose account it acts as: the connector's shared credential, or the caller's own connected account — refused when they have none, never the shared fallback |
| `--resource TYPE=ARG` | what this tool touches and which argument names it; `TYPE={a}/{b}:a,b` for a composed identifier. A write with none is refused |
| `--note NOTE` | what somebody here should know before granting it |
| `--local-name LOCAL_NAME` | override the generated name |
| `--max-response-bytes N` | a per-tool response cap |
| `--redact-arg ARG` | an argument the audit rows hash rather than store, repeatable |
| `--method {GET,POST,PUT,PATCH,DELETE}` | REST: this tool's HTTP method |
| `--path PATH` | REST: the path template, `{argument}` segments naming schema arguments |
| `--schema SCHEMA` | REST: the input schema, inline JSON or a file |
| `--query ARG` | REST: a schema argument that travels as a query parameter |
| `--body ARG` | REST: a schema argument that travels in the JSON body |
| `--resource-family TYPE=A,B,C` | the families a resource type's ids divide into |
| `--usage-map JSON` | REST: where token usage lives in this API's answers |
| `--pricing JSON` | REST: what this vendor's models cost, per million tokens |
| `--tool-description TEXT` | REST: what this tool does, in your words |
| `--who WHO` | whose credential to discover or vet with. Defaults to the CLI's own |

### Connecting an account

| Flag | What it does |
| --- | --- |
| `--connect-account CONNECTOR WHO` | store somebody's own credential for a connector, so their calls act as them. Read from a hidden prompt or piped stdin — never from argv |
| `--disconnect-account CONNECTOR WHO` | remove it |
| `--list-connections` | who has connected an account, and as whom. Never shows a credential |
| `--label ACCOUNT` | which vendor account a pasted credential is, e.g. `@priya-acme`. Not verified |

### Configuring a consent flow

| Flag | What it does |
| --- | --- |
| `--set-oauth CONNECTOR` | record the OAuth application a connector's consent flow uses, so people connect their own accounts from a browser. Reads the client secret from a hidden prompt or stdin |
| `--clear-oauth CONNECTOR` | remove it; credentials people already connected keep working |
| `--auth-server URL` | the authorization server's base; `/authorize` and `/token` assumed |
| `--authorize-endpoint URL` | where the browser is sent |
| `--token-endpoint URL` | where the code is exchanged, with the client secret |
| `--revoke-endpoint URL` | RFC 7009; without it, disconnecting deletes locally and leaves the token live at the provider |
| `--client-id CLIENT_ID` | the application's public id |
| `--authorize-param NAME=VALUE` | a provider-specific parameter on the sign-in link, repeatable. The ones the flow builds itself are refused |
| `--scope SCOPE` | repeatable. Include the provider's spelling of `offline_access` or the connection dies in an hour |
| `--scope-notes JSON\|FILE` | what each scope permits, in words the person granting it can read |

### Onboarding a customer

| Flag | What it does |
| --- | --- |
| `--add-tenant TENANT_ID NAME` | create a customer |
| `--tenant-status TENANT_ID STATUS` | `active` or `suspended`. Suspending stops sign-ins and refuses every door call; nothing is deleted |
| `--prune-logs` | run one retention sweep now and report what went. Needs `CARNET_RETENTION_DAYS` |
| `--delete-tenant TENANT_ID` | erase a customer and everything of theirs, permanently. Must be suspended first; prompts for the id as confirmation |
| `--add-idp TENANT_ID` | register an identity provider (needs `--issuer`, `--jwks-uri`, `--audience`) |
| `--issuer ISSUER` | the provider's `iss` claim, exactly as it emits it |
| `--jwks-uri JWKS_URI` | where it publishes its signing keys |
| `--audience AUDIENCE` | what a token's `aud` must be |
| `--discriminator CLAIM=VALUE` | for a shared issuer (Google Workspace): the claim identifying this customer, e.g. `hd=acme.com` |
| `--domain DOMAIN` | an email domain this provider may vouch for, repeatable |
| `--email-claim CLAIM` | which claim carries the email |
| `--subject-claim CLAIM` | which claim carries the stable identity (`sub`, or `uid` for Okta access tokens) |
| `--groups-claim CLAIM` | which claim carries the groups a person is in; unset means the directory decides nothing |
| `--list-idps [TENANT_ID]` | show registered identity providers |

### Running the whole product locally

| Flag | What it does |
| --- | --- |
| `--local` | start everything — database, API, frontend and a local email-and-password identity provider — and print a URL. State persists in `var/local/` |
| `--admin EMAIL` | with `--local`: who becomes the first administrator |
| `--port PORT` | with `--local`: the one port everything is served on (default 8080) |
| `--host HOST` | with `--local`: the bind address; anything but `127.0.0.1` is plain HTTP on a network and the banner says so |
| `--public-url URL` | with `--local`: the public address this deployment is reached at, added to the sign-in redirects |
| `--registration {open,closed}` | with `--local`: whether the sign-in screen offers *Create account* |
| `--fresh` | with `--local`: drop the local database and accounts after a typed confirmation |

---

## 3. The HTTP API: every route

Every route takes the tenant from the caller's identity, never from a parameter. A person
authenticates with their identity provider's token; a machine with an `art_` token. The
administrative routes need the `admin` platform role (or `CARNET_OPEN_ADMIN=on`).

### Health

| Route | What it answers |
| --- | --- |
| `GET /health` | the process is up |
| `GET /health/ready` | and can reach its database — one `SELECT 1` through the same pool the door uses |
| `GET /metrics` | operational numbers in Prometheus text format |

### Who I am, and my tokens

| Route | What it answers |
| --- | --- |
| `GET /me` | who you are, whether you may administer, and the door's address |
| `GET /me/tokens` | the API tokens you own, hash-free |
| `POST /me/tokens` | mint a personal token; the secret is shown once |
| `DELETE /me/tokens/{token_id}` | revoke one of yours, idempotently |
| `GET /me/tokens/{token_id}/reach` | what this token is granted — the door's own answer, without the door |
| `POST /me/tokens/{token_id}/simulate` | would this call be admitted, and which rule decided. Executes nothing |
| `GET /me/tokens/{token_id}/budget` | what this token has spent through the door today, against what ceiling |

### The door

| Route | What it answers |
| --- | --- |
| `POST /mcp` | one JSON-RPC message in, one answer out: `initialize`, `tools/list`, `tools/call`. Every call is one audit record whose id comes back in `_meta` |

### The door's own OAuth server, for clients that speak it

| Route | What it answers |
| --- | --- |
| `GET /.well-known/oauth-protected-resource` | RFC 9728: where this resource's authorization server is |
| `GET /.well-known/oauth-protected-resource/{rest:path}` | the same, for a client that asks about a sub-path |
| `GET /.well-known/oauth-authorization-server` | RFC 8414: the server's endpoints and capabilities |
| `POST /oauth/register` | RFC 7591 dynamic client registration — the one unauthenticated write, bounded |
| `GET /oauth/clients/{client_id}` | what the consent page shows before the person decides |
| `POST /oauth/consent` | the person's decision; answers with where the browser goes next |
| `POST /oauth/token` | RFC 6749 §4.1.3: code plus PKCE verifier for an `art_` token |

### Agents (permission lists)

| Route | What it answers |
| --- | --- |
| `GET /agents` | the agents shared with this caller, including the broken ones |
| `POST /agents` | create one, owned by whoever asked |
| `POST /agents/validate` | a dry run over the same validator; writes nothing |
| `GET /agents/{name}` | one agent, with its grants split into capability and reach |
| `GET /agents/{name}/door-activity` | has anyone knocked on this agent through the door |
| `PATCH /agents/{name}` | edit it, with an `If-Match` on its version so two editors cannot silently overwrite each other |
| `POST /agents/{name}/rename` | give it a different name, keeping grants and history (owner) |
| `DELETE /agents/{name}` | delete it (owner) |
| `GET /agents/{name}/versions` | every configuration it has had, newest first |
| `GET /agents/{name}/versions/{version}` | one stored configuration, whole |
| `POST /agents/{name}/versions/{version}/restore` | make that one current again |
| `GET /agents/{name}/access` | everyone who can reach it and how, plus who is still waiting |
| `PUT /agents/{name}/grants/{kind}/{grantee}` | share it with a user, a group or an email address (editor) |
| `DELETE /agents/{name}/grants/{kind}/{grantee}` | take access away; nobody may revoke the owner |

### Tools and connections, as a person sees them

| Route | What it answers |
| --- | --- |
| `GET /tools` | everything this tenant may grant, grouped by where it came from |
| `GET /connections` | every vetted connector, and this person's own state for each |
| `POST /connectors/{connector_id}/connect` | start the consent flow: a URL at the provider, carrying PKCE and never the secret |
| `GET /connect/callback` | where the provider sends the browser back; exchanges the code and redirects to the Connections page |
| `DELETE /connectors/{connector_id}/connection` | disconnect this person's own account, revoking upstream where it can |

### Groups

| Route | What it answers |
| --- | --- |
| `GET /groups` | every group: id, name, description |
| `POST /groups` | make one |
| `GET /groups/{group_id}` | one group and who is in it |
| `PATCH /groups/{group_id}` | point it at a directory group, or let it go |
| `DELETE /groups/{group_id}` | delete it, and every access it carried |
| `PUT /groups/{group_id}/members/{member_kind}/{member_id}` | put a principal in, idempotently |
| `DELETE /groups/{group_id}/members/{member_kind}/{member_id}` | take one out |

### Administration

| Route | What it answers |
| --- | --- |
| `GET /admin/overview` | the numbers the Overview page draws: calls per day, latency, refusals by control, who called, what it cost |
| `GET /admin-audit` | the administrative log: who granted, revoked, vetted or deleted what |
| `GET /admin/denials` | the access-denial log |
| `GET /admin/door-calls` | the door log: who called what, as whom, and what was refused |
| `GET /admin/hosts` | every host this tenant will dial, and who approved each |
| `POST /admin/hosts` | approve one; a host that can never be dialled is recorded with a warning |
| `DELETE /admin/hosts/{host}` | withdraw one; connectors are not touched, and the answer names what is stranded |
| `GET /admin/recipes` | the connector presets this build ships |
| `GET /admin/connectors` | every registered connector, what is vetted on it, and whether people can self-serve it |
| `POST /admin/connectors` | register one; it vets nothing |
| `GET /admin/connectors/{connector_id}` | one connector and what was approved on it, by whom, against what server version |
| `POST /admin/connectors/{connector_id}/discovery` | ask the server what it offers right now, with each tool's arguments and whether it is vetted |
| `PUT /admin/connectors/{connector_id}/tools/{remote_name}` | approve one tool; re-vetting restamps the row |
| `PUT /admin/connectors/{connector_id}/asserted-identity` | turn asserted acting-for on or off for one connector |
| `PUT /admin/connectors/{connector_id}/oauth` | configure its consent flow; the secret goes in and never comes back |
| `DELETE /admin/connectors/{connector_id}/oauth` | remove it; credentials people already gave are untouched |

---

## 4. The screens

React, served by the front door beside the API. The sidebar offers four pages to everyone
and five more to an administrator.

| Page | Path | What is on it |
| --- | --- | --- |
| Create MCP | `/agents` | the agents shared with you, each with what it reaches and whether anyone has knocked |
| Create wizard | `/agents/new` | four steps — name, tools, reach, review — that build a permission list and validate it before saving |
| Agent detail | `/agents/:name` | the connect card with the door's URL and a paste-ready token, the share sheet, effective reach, version history, rename and delete |
| Edit | `/agents/:name/edit` | the same form over an existing agent, refusing to overwrite an edit somebody else made meanwhile |
| A version | `/agents/:name/versions/:version` | one stored configuration and a Restore button |
| Connections | `/connections` | every vetted connector and your own state for each: a Connect button that starts consent, what it will ask for, who you are connected as, Disconnect |
| Tokens | `/tokens` | your tokens: mint one, see its secret once, revoke it |
| A token | `/tokens/:tokenId` | its four stamps, effective reach, the simulator (*would this call be allowed*), and today's spend against the ceiling |
| Overview | `/overview` (also `/admin/overview`) | a month of door traffic drawn: calls per day, how long they took, how big the answers were, who called, under which permission list, what was refused and by which control, what it cost |
| Approve a client | `/oauth/authorize` | the consent page a Claude Desktop or Cursor lands on: which client, what it will reach, Approve or Deny |
| Sign-in callback | `/login/callback` | where the identity provider sends the browser back |
| Administration | `/admin` | the administrative log |
| Door traffic | `/admin/door-calls` | the door log, row by row, with each refusal's own sentence |
| Access denials | `/admin/denials` | who tried what, and was refused |
| Groups | `/admin/groups` | groups, their members, and whether a directory owns the membership |
| Connectors | `/admin/connectors` | approve a host, register a connector, from a recipe or by hand |
| A connector | `/admin/connectors/:connectorId` | discovery against the live server, vet each tool with its effect and resources, configure the consent flow |

`/` redirects to the agents page; anything unrouted is a Not found page.

---

## 5. The settings: every `CARNET_*` variable

The environment is a user interface too. Every setting is read at startup unless it says
otherwise; a misspelt value is refused rather than defaulted.

### Which artefact, and where its state is

| Setting | What it does |
| --- | --- |
| `CARNET_FILE` | the `carnet.yaml` a fileborne door runs from. Refused beside `CARNET_DATABASE_URL`: one artefact or the other |
| `CARNET_DATABASE_URL` | the Postgres DSN. Without it, an in-memory store seeded from the shipped examples |
| `CARNET_SECRET_KEY` | the key stored credentials are sealed under. Required whenever there is a database; not needed under a file |
| `CARNET_SECRET_KEYS_OLD` | retired keys, comma-separated, while `--finish-rotation` re-encrypts rows written under them |
| `CARNET_TENANT` | the tenant the CLI acts on (default `default`) |
| `CARNET_VAR_DIR` | where runtime artefacts go; set by the image and by `--local` |
| `CARNET_LOCAL_STATE` | where `--local` keeps its database and accounts (default `var/local`) |

### The door

| Setting | What it does |
| --- | --- |
| `CARNET_PUBLIC_ORIGIN` | the address this deployment is reached at, which the consent flows and `/me` hand out |
| `CARNET_OAUTH_TOKEN_DAYS` | how long a token the door's own OAuth server mints lives (default 30) |
| `CARNET_REQUEST_TIMEOUT` | seconds to wait on a connector's answer (default 15) |
| `CARNET_MCP_SESSION_POOL_MAX` | how many upstream sessions the door keeps open at once |
| `CARNET_MCP_MAX_CALL_BYTES` | the largest `tools/call` the door accepts (default 64 KiB) |
| `CARNET_MCP_MAX_ACTING_FOR_BYTES` | the largest acting-for claim a call may carry |
| `CARNET_MCP_CALLS_PER_DAY` | a per-token daily call ceiling, counted in the database so replicas agree (default 1000) |
| `CARNET_MCP_TOKENS_PER_DAY` | a per-token daily model-token ceiling; zero disables |
| `CARNET_MCP_USD_PER_DAY` | a per-token daily spend ceiling in dollars; zero disables. Read fresh per call, so it can be turned mid-incident |
| `CARNET_MODEL_RATES` | a file of what each model costs, so spend is priced in your figures rather than the built-in list |
| `CARNET_EGRESS_INTERNAL_HOSTS` | hosts on the deployment's own network the door may dial over plain http or at private addresses — the operator's consent |

### People and administration

| Setting | What it does |
| --- | --- |
| `CARNET_BOOTSTRAP_ADMIN` | the address whose first sign-in becomes the first administrator; inert after that |
| `CARNET_OPEN_ADMIN` | `on` lets every signed-in person administer, writing no role row; `off` (default) restores the gate |

### The log and the audit stream

| Setting | What it does |
| --- | --- |
| `CARNET_AUDIT_STDOUT` | `on` (default) prints one JSON object per brokered call and per refusal on stdout; `off` silences the stream, the table still counts |
| `CARNET_LOG_LEVEL` | the application log's level (default `info`) |
| `CARNET_LOG_FORMAT` | `text` (default) or `json` |
| `CARNET_RETENTION_DAYS` | how long log rows are kept; a monthly partition older than this is dropped |
| `CARNET_RETENTION_SWEEP` | seconds between sweeps (default 3600) |

### Credentials held elsewhere

| Setting | What it does |
| --- | --- |
| `CARNET_VAULT_URL` | the 1Password Connect server an `op://` credential reference is read from |
| `CARNET_VAULT_TOKEN` | its token |
| `CARNET_VAULT_TIMEOUT_SECONDS` | how long to wait on the vault before refusing the call |

### Reserved prefixes, for the file

| Prefix | What it is for |
| --- | --- |
| `CARNET_TOKEN_` | variables holding a `carnet.yaml` token's secret — `${CARNET_TOKEN_LAPTOP}`. Yours by construction; never one of Carnet's own settings |
| `CARNET_CONNECTOR_` | variables holding a connector's shared credential, the same way |

### Set on the compose stack, read by the front door rather than the application

| Setting | What it does |
| --- | --- |
| `CARNET_DOMAIN` | the hostname the front door terminates TLS for |
| `CARNET_HTTP_PORT` / `CARNET_HTTPS_PORT` | the only published ports (default 80 and 443) |
| `CARNET_DB_PASSWORD` | the bundled database's password |
| `CARNET_OIDC_ISSUER` / `CARNET_OIDC_CLIENT_ID` / `CARNET_OIDC_SCOPES` | the browser's identity provider, declared once and served to the SPA and its CSP |
| `CARNET_OIDC_EXTRA_ORIGINS` | further origins the CSP must allow for that provider |

---

## Names that are not a user surface

The completeness check finds these in the code too. Each is here so its absence from the
sections above is a decision rather than an omission.

| Name | Why it is not above |
| --- | --- |
| `CARNET_INSECURE_DEV_AUTH` | named in a comment as something that has never existed; the dev-auth bypass was deleted rather than disabled |
| `CARNET_TOKEN_ALICE` | the example variable in a comment explaining the `CARNET_TOKEN_` prefix |
| `/` and `*` in the router | a redirect to the agents page, and the Not found page |
