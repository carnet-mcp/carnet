"""`carnet.yaml`: the whole administration of a fileborne door. Step 095.

Plan 094's artefact A is a door with no database, no sign-in and no browser — one
container and one file. This module is the file: it is read once at startup, checked,
and written into the in-memory store through **the same two functions `--seed` uses**
(`tools.save_connector`, `agents.save`) plus the token and grant writes the CLI makes.
The broker then reads back what any other writer would have written, which is the whole
of the claim that the file is a second door into one model and not a second model.

## What the file replaces, and what it keeps

The four administrative stages a stranger meets on the platform artefact — allow the
host, register the connector, approve each tool, scope them — are, in a team that trusts
itself, four role separations buying nothing. Here they are four keys in one document.
What is **kept** is every reason each stage exists: the egress rules still refuse a
link-local address and a plain-http URL, a vetted tool still carries an effect somebody
chose, a grant is still written against a named permission list, and a token is still a
digest with a live owner. What is removed is the ceremony of doing them one at a time.

## Secrets: pointers, and a literal is refused

The file is meant to be committed, so it holds no secret and cannot: a connector's
`credential` and a token's `secret` accept exactly one shape, `${NAME}`, and anything
else is refused with a sentence. A warning would make "safe to commit" a habit; a
refusal makes it a property. The variable is checked at load — set, not one of ours,
and for a token the right shape — because startup is where a one-line fix is cheap and
the first call is where it reads as an outage.

## This module is an entry-point concern

It sits beside `bootstrap.py`, and for the same reason: it composes layers — `tools`,
`agents`, `access.tokens`, `storage` — which is what an entry point does and what
nothing below `cli.py` may do. `load` needs no store and `apply` needs no file, so a
refusal can be asserted without rows and a row without a path.
"""

import logging
import os
import re
from dataclasses import dataclass
from typing import NoReturn

import yaml

from . import agents, config, storage, tools
from .access import tokens
from .access.oidc import TokenError
from .tools import mcp
from .tools.base import Resource
from .tools.mcp.binding import Connector, HttpLaunch, RestLaunch, Vetted

log = logging.getLogger(__name__)

# Who the file is when it writes. A `system` principal, like `--seed`'s `system:cli`,
# and deliberately a different id: an administrative record that says `system:file`
# names the document a row came from, which is the one fact a reader of the log wants.
FILE_ACTOR = "system:file"

# The issuer on the `users` row a token's owner is. See `apply`: the owner check in
# `access/tokens.py` is kept rather than bypassed, so every token needs an active
# person to answer to, and here that person is a line of this file.
FILE_ISSUER = "carnet.yaml"

# `${NAME}`, and nothing else. Upper-case with digits and underscores — an environment
# variable's own grammar — so a `${jira_token}` is refused rather than looked up under a
# name nothing exports.
POINTER_RE = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)\}$")

# Connector ids and token names share one rule — lowercase, digits, hyphens — because
# both become identifiers: a connector id is a tool-name prefix and a token name is the
# suffix of its owner row's id. `Connector.__post_init__` enforces the first already;
# this is the same pattern so the two refusals read alike.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

TOP_KEYS = frozenset({"connectors", "agents", "tokens"})
CONNECTOR_KEYS = frozenset(
    {
        "kind",
        "url",
        "credential",
        "credential_header",
        "credential_prefix",
        "headers",
        "description",
        "tools",
    }
)
TOOL_KEYS = frozenset(
    {
        "name",
        "effect",
        "identity",
        "resources",
        "note",
        "description",
        "local_name",
        "max_response_bytes",
        "redact_args",
    }
)
# The binding a `rest` tool carries, spelled with `--vet`'s flag names so a person who
# has read one has read the other. `schema` rather than `input_schema` for that reason.
REST_TOOL_KEYS = frozenset(
    {"method", "path", "query", "body", "schema", "usage_map", "pricing"}
)
RESOURCE_KEYS = frozenset({"type", "args", "template", "families"})
AGENT_KEYS = frozenset({"tools", "scope"})
TOKEN_KEYS = frozenset({"secret", "agents"})


class CarnetFileError(ValueError):
    """The file cannot be used, and the sentence says where.

    Every message begins with the path and the key — `carnet.yaml: connectors.jira.
    tools[1].effect — …` — because the file is edited by a person who cannot see a stack
    trace, and a sentence that names the key is the difference between a fix and a search.
    """


@dataclass(frozen=True)
class FileToken:
    """One `tokens:` entry, resolved: the id and digest, never the secret."""

    name: str
    token_id: str
    secret_hash: str
    agents: tuple


@dataclass(frozen=True)
class Declaration:
    """What a file declares, checked and resolved, before any row exists."""

    path: str
    connectors: tuple
    agents: tuple
    tokens: tuple


@dataclass(frozen=True)
class Summary:
    """What `apply` wrote, for the startup line."""

    connectors: int
    tools: int
    agents: int
    tokens: int

    def __str__(self) -> str:
        return (
            f"{self.connectors} connector(s), {self.tools} tool(s), "
            f"{self.agents} agent(s), {self.tokens} token(s)"
        )


# --- reading ------------------------------------------------------------------------


def load(path: str, environ=None) -> Declaration:
    """Read, parse, check and resolve one file. Touches no store.

    `environ` is injectable so a test can assert a refusal about a variable without
    setting one; production passes nothing and reads the process environment.
    """
    environ = os.environ if environ is None else environ
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except FileNotFoundError:
        raise CarnetFileError(
            f"{path}: no such file. CARNET_FILE names the carnet.yaml this door runs "
            "from; a container needs it mounted (-v ./carnet.yaml:/carnet.yaml)."
        ) from None
    except IsADirectoryError:
        # Found by the artefact e2e (098): Docker creates an empty *directory* at a
        # bind-mount target when the host path does not exist or is not shared with
        # the engine, and a stranger's first `docker run` meets exactly this.
        raise CarnetFileError(
            f"{path}: is a directory, not a file. Docker creates an empty directory at "
            "a -v target when the host path does not exist (or, on Docker Desktop, "
            "is outside the folders shared with the engine). Check the host path in "
            "-v ./carnet.yaml:/carnet.yaml, and remove the directory the container "
            "left behind."
        ) from None
    except yaml.YAMLError as exc:
        raise CarnetFileError(f"{path}: not valid YAML — {exc}") from exc

    reader = _Reader(path, environ)
    return reader.declaration(raw)


class _Reader:
    """The schema, as a walk that names where it is."""

    def __init__(self, path: str, environ):
        self.path = path
        self.environ = environ

    def refuse(self, where: str, sentence: str) -> NoReturn:
        raise CarnetFileError(f"{self.path}: {where} — {sentence}")

    # -- shapes ----------------------------------------------------------------

    def mapping(self, value, where: str) -> dict:
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.refuse(where, f"expected a mapping, got {type(value).__name__}")
        return value

    def only_keys(self, value: dict, allowed, where: str) -> None:
        unknown = sorted(str(k) for k in value if k not in allowed)
        if unknown:
            self.refuse(
                where,
                f"unknown key(s) {', '.join(unknown)}. Known: "
                f"{', '.join(sorted(allowed))}. A misspelt key is refused rather "
                "than ignored, because ignored is how a setting silently means its "
                "default.",
            )

    def string(self, value, where: str, *, required: bool = False, default: str = "") -> str:
        if value is None:
            if required:
                self.refuse(where, "is required")
            return default
        if not isinstance(value, str):
            self.refuse(where, f"expected a string, got {type(value).__name__}")
        return value

    def strings(self, value, where: str, *, required: bool = False) -> tuple:
        if value is None:
            if required:
                self.refuse(where, "is required")
            return ()
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            self.refuse(where, "expected a list of strings")
        return tuple(value)

    def name(self, value, where: str) -> str:
        if not isinstance(value, str) or not NAME_RE.fullmatch(value):
            self.refuse(
                where,
                f"'{value}' is not a legal name: lowercase letters, digits and hyphens, "
                "starting with a letter or digit.",
            )
        return value

    def pointer(self, value, where: str) -> tuple:
        """`${NAME}` -> `(NAME, its value)`, or a refusal. The whole of decision 3."""
        if not isinstance(value, str):
            self.refuse(where, "expected ${VARIABLE}")
        match = POINTER_RE.fullmatch(value)
        if match is None:
            self.refuse(
                where,
                "must be a pointer into the environment, written ${VARIABLE}. This "
                "file is meant to be committed; a value here would commit a "
                "credential. Put the secret in the environment and name the variable.",
            )
        name = match.group(1)
        if config.is_platform_env(name):
            self.refuse(
                where,
                f"${{{name}}} names one of Carnet's own settings, which may not be "
                "handed to a vendor or presented as a token. Use a variable of your "
                "own; CARNET_CONNECTOR_* and CARNET_TOKEN_* are reserved for exactly "
                "this.",
            )
        value = self.environ.get(name)
        if not value:
            self.refuse(
                where,
                f"${{{name}}} is not set in this environment. The door reads it at "
                "startup so a missing secret is a one-line fix now rather than a "
                "refused call later — export it, or pass it to the container.",
            )
        return name, value

    # -- the document ------------------------------------------------------------

    def declaration(self, raw) -> Declaration:
        doc = self.mapping(raw, "the document")
        self.only_keys(doc, TOP_KEYS, "the document")

        connectors = tuple(
            self.connector(connector_id, spec)
            for connector_id, spec in self.mapping(
                doc.get("connectors"), "connectors"
            ).items()
        )
        declared = set()
        for connector in connectors:
            declared |= connector.declared_names()

        agent_configs = tuple(
            self.agent(name, spec, declared)
            for name, spec in self.mapping(doc.get("agents"), "agents").items()
        )
        agent_names = {a["name"] for a in agent_configs}

        file_tokens = tuple(
            self.token(name, spec, agent_names)
            for name, spec in self.mapping(doc.get("tokens"), "tokens").items()
        )
        ids = {}
        for token in file_tokens:
            if token.token_id in ids:
                self.refuse(
                    f"tokens.{token.name}.secret",
                    f"is the same token as tokens.{ids[token.token_id]}. Each token "
                    "is one credential with one owner; mint another with "
                    "`carnet --new-token`.",
                )
            ids[token.token_id] = token.name

        return Declaration(
            path=self.path,
            connectors=connectors,
            agents=agent_configs,
            tokens=file_tokens,
        )

    # -- connectors --------------------------------------------------------------

    def connector(self, connector_id, spec) -> Connector:
        where = f"connectors.{connector_id}"
        connector_id = self.name(connector_id, where)
        spec = self.mapping(spec, where)
        self.only_keys(spec, CONNECTOR_KEYS, where)

        kind = self.string(spec.get("kind"), f"{where}.kind", default=HttpLaunch.KIND)
        if kind == "stdio":
            self.refuse(f"{where}.kind", tools.STDIO_REFUSED)
        if kind not in (HttpLaunch.KIND, RestLaunch.KIND):
            self.refuse(
                f"{where}.kind",
                f"'{kind}' is not a kind this file knows. `http` is an MCP server "
                "(the default); `rest` is a plain HTTP API whose tools you describe.",
            )

        url = self.string(spec.get("url"), f"{where}.url", required=True)
        if not url.strip():
            self.refuse(f"{where}.url", "is required")

        credential_env = None
        if "credential" in spec:
            credential_env, _ = self.pointer(spec["credential"], f"{where}.credential")

        headers = self.mapping(spec.get("headers"), f"{where}.headers")
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                self.refuse(f"{where}.headers", "expected a mapping of string to string")

        # `None` means the launch's own default; `""` is a real value (an `x-api-key`
        # vendor wants the bare token) and must survive — `register_connector`'s rule.
        header = spec.get("credential_header")
        prefix = spec.get("credential_prefix")
        launch_cls = HttpLaunch if kind == HttpLaunch.KIND else RestLaunch
        launch = launch_cls(
            url=url,
            credential_env=credential_env,
            credential_header=(
                "Authorization"
                if header is None
                else self.string(header, f"{where}.credential_header")
            ),
            credential_prefix=(
                "Bearer "
                if prefix is None
                else self.string(prefix, f"{where}.credential_prefix")
            ),
            headers=dict(headers),
        )

        raw_tools = spec.get("tools")
        if raw_tools is not None and not isinstance(raw_tools, list):
            self.refuse(f"{where}.tools", "expected a list")
        vetted = tuple(
            self.tool(f"{where}.tools[{i}]", tool, rest=kind == RestLaunch.KIND)
            for i, tool in enumerate(raw_tools or ())
        )

        try:
            return Connector(
                id=connector_id,
                description=self.string(spec.get("description"), f"{where}.description"),
                launch=launch,
                vetted=vetted,
            )
        except RuntimeError as exc:
            # `Connector.__post_init__` and `validate()` refuse with sentences that name
            # the connector; the path is what this module adds.
            self.refuse(where, str(exc))

    def tool(self, where: str, spec, *, rest: bool) -> Vetted:
        spec = self.mapping(spec, where)
        allowed = TOOL_KEYS | REST_TOOL_KEYS if rest else TOOL_KEYS
        self.only_keys(spec, allowed, where)

        name = self.string(spec.get("name"), f"{where}.name", required=True)

        effect = self.string(spec.get("effect"), f"{where}.effect", required=True)
        if effect not in tools.VALID_EFFECTS:
            self.refuse(
                f"{where}.effect",
                f"'{effect}' is not an effect; it is `read` or `write`. This is the "
                "one judgment a server cannot make for you — `carnet --discover` "
                "proposes one and says where it came from.",
            )

        identity = self.string(spec.get("identity"), f"{where}.identity", default="service")
        if identity == "user":
            self.refuse(
                f"{where}.identity",
                "`user` means the call goes out as the caller's own connected account, "
                "and is refused when they have none. A fileborne door has no accounts "
                "— nobody signs in — so every call to this tool would be refused. "
                "Per-person identity is the platform artefact: the same image with a "
                "database, where each person connects their own account.",
            )
        if identity != "service":
            self.refuse(
                f"{where}.identity", f"'{identity}' is not an identity; use `service`."
            )

        raw_resources = spec.get("resources")
        if raw_resources is not None and not isinstance(raw_resources, list):
            self.refuse(f"{where}.resources", "expected a list")
        resources = tuple(
            self.resource(f"{where}.resources[{i}]", ref)
            for i, ref in enumerate(raw_resources or ())
        )

        max_bytes = spec.get("max_response_bytes")
        if max_bytes is not None and (
            isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1
        ):
            self.refuse(f"{where}.max_response_bytes", "expected a positive integer")

        binding = self.binding(where, spec) if rest else None

        return Vetted(
            remote_name=name,
            effect=effect,
            identity=identity,
            resources=resources,
            note=self.string(spec.get("note"), f"{where}.note"),
            description=self.string(spec.get("description"), f"{where}.description"),
            local_name=(
                self.string(spec["local_name"], f"{where}.local_name")
                if spec.get("local_name") is not None
                else None
            ),
            max_response_bytes=max_bytes,
            redact_args=self.strings(spec.get("redact_args"), f"{where}.redact_args"),
            binding=binding,
        )

    def resource(self, where: str, spec) -> Resource:
        spec = self.mapping(spec, where)
        self.only_keys(spec, RESOURCE_KEYS, where)
        args = spec.get("args")
        if isinstance(args, str):
            args = [args]
        return Resource(
            type=self.string(spec.get("type"), f"{where}.type", required=True),
            args=self.strings(args, f"{where}.args", required=True),
            template=(
                self.string(spec["template"], f"{where}.template")
                if spec.get("template") is not None
                else None
            ),
            families=self.strings(spec.get("families"), f"{where}.families"),
        )

    def binding(self, where: str, spec: dict) -> dict:
        """A `rest` tool's request binding, spelled as `--vet` spells it."""
        missing = [key for key in ("method", "path", "schema") if not spec.get(key)]
        if missing:
            self.refuse(
                where,
                f"a rest tool needs {', '.join(missing)}. A REST API does not "
                "describe itself, so the method, the path template and the input "
                "schema are authored here — they are what discovery would have "
                "supplied.",
            )
        schema = spec["schema"]
        if not isinstance(schema, dict):
            self.refuse(f"{where}.schema", "expected a mapping (a JSON Schema object)")
        for key in ("usage_map", "pricing"):
            if spec.get(key) is not None and not isinstance(spec[key], dict):
                self.refuse(f"{where}.{key}", "expected a mapping")
        return {
            "method": self.string(spec["method"], f"{where}.method"),
            "path": self.string(spec["path"], f"{where}.path"),
            "query": list(self.strings(spec.get("query"), f"{where}.query")),
            "body": list(self.strings(spec.get("body"), f"{where}.body")),
            "input_schema": schema,
            "usage_map": spec.get("usage_map"),
            "pricing": spec.get("pricing"),
        }

    # -- agents and tokens -------------------------------------------------------

    def agent(self, name, spec, declared: set) -> dict:
        where = f"agents.{name}"
        if not isinstance(name, str):
            self.refuse(where, "an agent's name must be a string")
        spec = self.mapping(spec, where)
        self.only_keys(spec, AGENT_KEYS, where)

        granted = self.strings(spec.get("tools"), f"{where}.tools", required=True)
        # Checked here, against what this file declares, rather than left to
        # `agents.validate` — which checks against the store and would say the same
        # thing without the hint that matters: the *local* name is what a grant names.
        for i, tool_name in enumerate(granted):
            if tool_name not in declared and tool_name not in tools.REGISTRY:
                self.refuse(
                    f"{where}.tools[{i}]",
                    f"'{tool_name}' is not a tool this file declares. A grant names the "
                    "local name: the connector id with hyphens as underscores, an "
                    f"underscore, then the tool — `jira_searchJiraIssuesUsingJql`. "
                    f"Declared: {', '.join(sorted(declared)) or '<none>'}.",
                )

        scope = self.mapping(spec.get("scope"), f"{where}.scope")
        for type_, effects in scope.items():
            effects = self.mapping(effects, f"{where}.scope.{type_}")
            self.only_keys(effects, tools.VALID_EFFECTS, f"{where}.scope.{type_}")
            for effect, patterns in effects.items():
                self.strings(patterns, f"{where}.scope.{type_}.{effect}", required=True)

        return {
            "name": name,
            "permissions": {
                "tools": list(granted),
                "scope": {
                    type_: {effect: list(patterns) for effect, patterns in effects.items()}
                    for type_, effects in scope.items()
                },
            },
        }

    def token(self, name, spec, agent_names: set) -> FileToken:
        where = f"tokens.{name}"
        name = self.name(name, where)
        spec = self.mapping(spec, where)
        self.only_keys(spec, TOKEN_KEYS, where)

        if "secret" not in spec:
            self.refuse(
                f"{where}.secret",
                "is required: ${VARIABLE} holding a token from `carnet --new-token`",
            )
        variable, presented = self.pointer(spec["secret"], f"{where}.secret")
        try:
            token_id, secret_hash = tokens.digest_presented(presented)
        except TokenError:
            self.refuse(
                f"{where}.secret",
                f"${{{variable}}} does not hold a token. It should be the whole line "
                "`carnet --new-token` printed — `art_m_<hex>.<secret>` — not a "
                "password of your own.",
            )

        granted = self.strings(spec.get("agents"), f"{where}.agents", required=True)
        if not granted:
            self.refuse(
                f"{where}.agents",
                "a token granted nothing can call nothing; name at least one agent.",
            )
        for i, agent_name in enumerate(granted):
            if agent_name not in agent_names:
                self.refuse(
                    f"{where}.agents[{i}]",
                    f"'{agent_name}' is not an agent this file declares. Declared: "
                    f"{', '.join(sorted(agent_names)) or '<none>'}.",
                )

        return FileToken(
            name=name, token_id=token_id, secret_hash=secret_hash, agents=granted
        )


# --- writing ------------------------------------------------------------------------


def apply(tenant_id: str, declaration: Declaration) -> Summary:
    """Write a declaration into the active store. The rows, and nothing the browser
    would not write.

    **The active store, not a parameter.** `tools.save_connector`, `agents.save` and
    `egress.check` all read `storage.active()` — a store handed in here would receive
    the hosts and tokens while the connectors and agents went elsewhere, which is the
    exact split the first draft of this function had. `check` below swaps a scratch
    store in for the duration rather than pretending otherwise.

    Order is the dependency made visible, as in `bootstrap.seed_tenant`: hosts before
    connectors (the egress check reads the allowlist), connectors before agents (a
    grant validates against tools that exist), agents before tokens (a token's grant
    names an agent).
    """
    store = storage.active()
    store.create_tenant(tenant_id, "Default")

    tool_count = 0
    for connector in declaration.connectors:
        where = f"connectors.{connector.id}"
        url = connector.launch.url
        # Allowing the host IS the administrative act the URL performs here — decision
        # 5 — and every other egress rule stands: `check` still refuses link-local,
        # private-without-consent and plain http, after the row is written, so a
        # refused host leaves an allowlist row and no connector, which is the state
        # `--allow-host` followed by a refused `--add-connector` leaves too.
        try:
            store.allow_host(
                tenant_id, mcp.egress.host_of(url), actor=FILE_ACTOR, note="carnet.yaml"
            )
            mcp.egress.check(tenant_id, url)
            tools.save_connector(tenant_id, connector, actor=FILE_ACTOR)
        except (mcp.EgressRefused, storage.StorageError, RuntimeError) as exc:
            raise CarnetFileError(f"{declaration.path}: {where} — {exc}") from exc
        tool_count += len(connector.vetted)

    for agent in declaration.agents:
        where = f"agents.{agent['name']}"
        try:
            agents.save(tenant_id, agent, actor=FILE_ACTOR)
        except (agents.InvalidAgentError, storage.StorageError) as exc:
            raise CarnetFileError(f"{declaration.path}: {where} — {exc}") from exc
        # An owner, on `bootstrap._adopt`'s reasoning: absence is denial, and an agent
        # nobody owns is one nothing administrative can touch. The file owns it.
        store.grant_agent(
            tenant_id,
            agent["name"],
            "system",
            "file",
            role=storage.OWNER_ROLE,
            granted_by="carnet.yaml",
            actor=FILE_ACTOR,
        )

    for token in declaration.tokens:
        where = f"tokens.{token.name}"
        # **The owner check is kept, not bypassed.** `check_row_is_live` re-reads a
        # token's owner on every request and the offboarding story rests on it. The
        # fileborne door has no people, so the owner is a row that says exactly what
        # is true: this token answers to this line of this file.
        owner_id = f"u-file-{token.name}"
        try:
            store.create_user(
                tenant_id,
                {
                    "id": owner_id,
                    "issuer": FILE_ISSUER,
                    "subject": token.name,
                    "display_name": f"carnet.yaml: {token.name}",
                    "status": "active",
                },
            )
            store.create_api_token(
                tenant_id,
                {
                    "id": token.token_id,
                    "name": token.name,
                    "owner_id": owner_id,
                    "acts_as_owner": False,
                    "secret_hash": token.secret_hash,
                    "expires_at": None,
                    "via": "carnet.yaml",
                },
                actor=FILE_ACTOR,
            )
            for agent_name in token.agents:
                store.grant_agent(
                    tenant_id,
                    agent_name,
                    "machine",
                    token.token_id,
                    role="user",
                    granted_by="carnet.yaml",
                    actor=FILE_ACTOR,
                )
        except storage.StorageError as exc:
            raise CarnetFileError(f"{declaration.path}: {where} — {exc}") from exc

    summary = Summary(
        connectors=len(declaration.connectors),
        tools=tool_count,
        agents=len(declaration.agents),
        tokens=len(declaration.tokens),
    )
    log.info("%s: %s", declaration.path, summary)
    return summary


def check(path: str, tenant_id: str | None = None) -> Summary:
    """`carnet --check-file`: load, then apply to a throwaway store. Decision 8.

    Applying is the point — `tools.save_connector` and `agents.save` have refusals of
    their own (a name collision, a scope naming a resource type no granted tool
    touches) that only a write produces. The store is discarded; the process-wide
    one is untouched.
    """
    declaration = load(path)
    try:
        previous = storage.active()
    except storage.StorageError:
        previous = None
    storage.configure(storage.InMemoryStorage())
    try:
        return apply(tenant_id or config.DEFAULT_TENANT_ID, declaration)
    finally:
        if previous is None:
            storage.reset()
        else:
            storage.configure(previous)


# --- what `--discover` prints ---------------------------------------------------------


def tools_block(advertised: list, indent: int = 4) -> str:
    """A `tools:` block to paste under a connector, one entry per advertised tool.

    Decision 7. `effect` is the vendor's `readOnlyHint` when they gave one, and
    **`write` when they did not**: `read` would be the convenient default and the wrong
    direction, because a write vetted as `read` is checked against the read scope —
    the wider one — while the server goes on executing writes. The comment beside each
    says where the proposal came from, and the argument names are printed where the
    person deciding on `resources` will need them.
    """
    pad = " " * indent
    lines = [f"{pad}tools:"]
    for tool in sorted(advertised, key=lambda t: t.get("name") or ""):
        name = tool.get("name") or ""
        hint = (tool.get("annotations") or {}).get("readOnlyHint")
        if hint is True:
            effect, why = "read", "the server says read-only"
        elif hint is False:
            effect, why = "write", "the server says it writes"
        else:
            effect, why = "write", "no hint from the server; write is the cautious default"
        lines.append(f"{pad}  - name: {name}")
        lines.append(f"{pad}    effect: {effect:<6}  # {why}")
        arguments = _argument_summary(tool.get("inputSchema") or {})
        lines.append(f"{pad}    # arguments: {arguments}")
    return "\n".join(lines)


def _argument_summary(schema: dict) -> str:
    properties = schema.get("properties") or {}
    if not properties:
        return "none"
    required = set(schema.get("required") or ())
    parts = []
    for name in sorted(properties):
        spec = properties[name] if isinstance(properties[name], dict) else {}
        kind = spec.get("type") or "any"
        if isinstance(kind, list):
            kind = "|".join(str(k) for k in kind)
        parts.append(f"{name} ({kind}, {'required' if name in required else 'optional'})")
    return ", ".join(parts)


__all__ = [
    "CarnetFileError",
    "Declaration",
    "FILE_ACTOR",
    "FILE_ISSUER",
    "FileToken",
    "Summary",
    "apply",
    "check",
    "load",
    "tools_block",
]
