# carnet

[![tests](https://github.com/carnet-mcp/carnet/actions/workflows/tests.yml/badge.svg)](https://github.com/carnet-mcp/carnet/actions/workflows/tests.yml)

**Carnet is an MCP tool.** Connect your assistant to `/mcp`, and every tool call it makes
goes through a broker — scoped to that caller, under a credential the caller never holds,
revocable, metered and audited.

What it displaces is fifty personal tokens on fifty laptops. Each engineer installs the
GitHub or Jira MCP server locally, under a credential nobody can revoke and nothing
records. Carnet is one endpoint instead: per-caller scope, a budget, an audit trail, and a
token you can kill without moving the URL.

**Distribution, not capability.** Every call it admits was already possible in the
assistant's own chat. The door is not a new power; it is the same power, brokered.

> **Read [docs/PREMISE.md](docs/PREMISE.md) before filing anything.** It outranks every
> other document here, and it exists to keep two things straight: an **agent** is a
> *permission list* — a named set of tools and scopes, not something that runs — and
> Carnet **executes no agents**. It brokers the calls your assistant makes.

## Run

One image, two shapes. Start with the first.

### A file and `docker run`

No database, no sign-in, no browser. One `carnet.yaml` is the whole configuration: the
servers you front, the tools you expose from each, the permission lists that bound them,
and the tokens that may call them. Every secret is a `${VARIABLE}` pointer into the
environment — a literal is refused — so the file is safe to commit.

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

Give your assistant `http://localhost:8000/mcp` with `Authorization: Bearer <the token>`
— Claude Code, Cursor, anything that takes a header. `tools/list` returns exactly what
that token's permission lists grant. Ask for anything else and the call is refused with a
reason.

**Every call and every refusal is one JSON line on stdout** — who, which tool, which
arguments, the decision, the latency — for whatever already reads your logs.

Three commands worth knowing before you run it:

```bash
carnet --check-file carnet.yaml    # validate it; every refusal names the key
carnet --discover jira             # dial a server, print the tools: block to paste
carnet --new-token                 # mint a token, offline, no database
```

A server on your own machine needs one more line, because the door refuses plain HTTP and
private addresses unless you say so:
`-e CARNET_EGRESS_INTERNAL_HOSTS=host.docker.internal`.

Until the first image is published, build it from the checkout:

```bash
docker build -t ghcr.io/carnet-mcp/carnet --target api -f deploy/Dockerfile .
```

### The whole product, one machine

The file above speaks for one shared account per server. This is the other shape: the
same image with a database, where people sign in and connect **their own** accounts, so
each person's calls go out as them.

```bash
cd backend
pip install -e ".[dev,postgres,access]"

carnet --local            # then open the URL it prints
```

That starts Postgres, the API, the built frontend and a local email-and-password identity
provider. The first account you create becomes the administrator. The provider is a real
OIDC provider running on your machine — the API verifies its tokens with the same code
and the same checks it would use on Okta, so it is not a bypass. State lives in
`var/local/`. An enterprise identity provider is one `carnet --add-idp` away.

For a real deployment, `deploy/` holds a compose stack with TLS, a front door, and a
migration step that runs before the API starts. See [deploy/README.md](deploy/README.md).

## What you can do with it

[**docs/CAPABILITIES.md**](docs/CAPABILITIES.md) is the complete list — every command-line
flag, HTTP route, `carnet.yaml` key, setting and screen, with a test that fails if the
code grows one the document does not name. The short version:

- **Front several MCP servers and REST APIs behind one endpoint**, with one token per
  person instead of one credential per laptop.
- **Vet tools one at a time.** Registering a connector approves nothing. You approve each
  tool, mark it read or write, and say which arguments carry the resources a scope can
  bound.
- **Scope by resource.** A permission list says `jira.project: {read: [ACME]}`, and a call
  outside it is refused by the broker before the server is dialled.
- **Let people connect their own accounts**, by pasting a token or through an OAuth
  consent flow you configure once. Their calls then go out as them rather than as a
  shared service account.
- **See what happened.** Every brokered call is one audit row and one JSON line: who,
  what, under which permission list, the decision, and the reason when it was refused.
- **Ask before you act.** `carnet --simulate` gives the verdict the door would give,
  without dialling anything or recording anything.
- **Bound the spend.** Daily ceilings per token on calls, on model tokens and in dollars,
  counted in the database so replicas agree.

## How it works

```
your assistant  ──►  /mcp  ──►  the broker  ──►  the server or API you vetted
                      │            │
                      │            ├── is this token granted this tool?
                      │            ├── does its scope admit these arguments?
                      │            ├── which credential — the shared one, or this
                      │            │   person's own connected account?
                      │            └── has it spent past its ceiling today?
                      │
                      └── one audit row per call, whose id comes back in _meta
```

The broker is the only path from a caller to a tool. There is no dispatch helper and no
way around it, which is what makes *every call routed through the door is governed* a
sentence the audit log can prove.

**Governed means routed.** Calls your assistant makes on its own — a direct vendor hit,
its own model call — are outside the door's sight. Making that impossible would mean
running the agent inside infrastructure that blocks its egress, which Carnet does not do
and does not claim to.

## Where to go next

| Document | What it is for |
| --- | --- |
| [docs/PREMISE.md](docs/PREMISE.md) | what Carnet is and is not. Outranks everything else here |
| [docs/CAPABILITIES.md](docs/CAPABILITIES.md) | the complete surface: flags, routes, file keys, settings, screens |
| [docs/GUIDE.md](docs/GUIDE.md) | reaching your own server, credentials you do not hold, brokering a model |
| [docs/API.md](docs/API.md) | the HTTP API, and the reasoning behind it |
| [docs/DESIGN.md](docs/DESIGN.md) | why it is shaped this way: layering, tenancy, permissions, the audit log |
| [docs/LIMITS.md](docs/LIMITS.md) | what is not done, and what is known to be wrong |
| [docs/UPGRADING.md](docs/UPGRADING.md) | what an upgrade preserves, and how far back it works from |
| [docs/runbooks/](docs/runbooks/) | offboarding, key rotation and tenant deletion, each run at least once |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), and the
[code of conduct](CODE_OF_CONDUCT.md) that goes with it. Every commit needs a
[DCO](DCO) sign-off (`git commit -s`); there is no CLA. The gates are `pytest`, `ruff`,
`mypy` and the frontend build, and every one of them runs locally with no secrets and no
network.

What changed between releases is in the [changelog](CHANGELOG.md), and what an upgrade
preserves is in [docs/UPGRADING.md](docs/UPGRADING.md).

Security issues go through GitHub's private vulnerability reporting rather than a public
issue — see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Free brokers a person's own account safely; a paid tier is what an organisation needs to
administer many of them. Everything described in this repository is in this repository.
