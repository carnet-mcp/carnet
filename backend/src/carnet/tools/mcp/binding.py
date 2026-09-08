"""Vetting, and the moment it meets what a server actually advertises.

Two phases, deliberately separate, matching the two people involved:

  VETTING   offline, by a connector admin, checked into source. A `Connector` names
            the server, how to reach it, and — per tool — its effect and what it
            touches. Nothing else. This file is the allowlist.

  BINDING   at startup. Connect, ask `tools/list`, and intersect the advertisement
            with the manifest. What comes out is ordinary `Tool` objects that the
            broker cannot distinguish from hand-written ones, which is the point.

The intersection is an **allowlist, not a filter**, and the difference is the whole
security argument:

  advertised, not vetted   excluded and reported. A server that adds
                           `delete_repository` in v1.4 does not quietly appear in the
                           registry because nobody remembered to exclude it.
  vetted, not advertised   raise. A vetted tool that vanished is drift, and guessing
                           which of the remaining ones replaced it is not our call.
  vetted, schema moved     raise, via tools.validation. If `repo` became `repository`,
                           our scoping constraint now names an argument that never
                           arrives — enforced in review, absent in fact.

What the server cannot tell us, and why a Tool doesn't disappear once MCP is wired in:
given `list_issues(owner, repo, state, perPage)` it supplies four argument names. It
does not say that `owner` and `repo` together identify the thing worth scoping while
`perPage` is data, nor whether the call mutates anything. MCP's `readOnlyHint` is
advisory and self-declared, and an enterprise boundary cannot rest on a claim made by
the component being constrained.
"""

import re
from dataclasses import dataclass, field, replace

from ..base import NO_SCHEMA, Resource, Tool, uncallable
from ..validation import VALID_IDENTITIES, validate

# Per the Messages API. No dots, which is why connector tools are namespaced with
# underscores rather than `github.list_issues`.
TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@dataclass(frozen=True)
class Vetted:
    """One tool a connector admin has looked at and is willing to expose.

    `effect` and `resources` are the annotation the server cannot make for us. Both
    are judgments about consequence and identity, not facts about a schema.

    `description` and `note` are the annotation nobody could read. They are here
    rather than fetched from the server at the moment somebody is choosing a tool,
    for two reasons that are the same reason twice: a page about *choosing* must not
    depend on servers being *up*, and text that can change after approval was not part
    of the approval. See migration 018.
    """

    remote_name: str
    effect: str = "read"
    resources: tuple = field(default_factory=tuple)

    # Whose account this tool acts as when it runs — step 033a, and the third judgment
    # beside `effect` and `resources` that the server cannot make for us. `service` is
    # the connector's shared credential, always; `user` is the caller's own connected
    # account, always, refused when they have none. There is deliberately no third
    # value meaning "whichever exists": that fallback is the defect this field retires
    # — which account a call went out as depended on whether the caller happened to
    # have connected one, a condition nobody stated at approval time.
    identity: str = "service"

    # Override the generated local name. Needed when prefix + remote name would run
    # past 64 characters, and useful when a server's naming is unbearable.
    local_name: str | None = None

    # A whole server may be verbose. Set per tool where it matters; see the response
    # size cap in the README.
    max_response_bytes: int | None = None

    # Step 045a: the request binding of a `rest` connector's tool — method, path,
    # where each argument travels, and the authored input schema. What discovery would
    # have supplied, written down by the vetter, because a REST API describes nothing.
    # None on every MCP row: the field and the connector's launch kind imply each
    # other, and `Connector.validate()` refuses the mismatch in both directions.
    binding: dict | None = None

    # What the server said this tool does, copied at vetting time — the vendor's words,
    # not ours. Deliberately **not** taken from `spec["description"]` during `bind()`:
    # binding needs a live server, and the whole point is that the catalogue does not.
    description: str = ""

    # What somebody here should know before granting it. Ours, optional, and separate
    # from `description` because "the vendor says this lists issues" and "scope this to
    # the repos a team owns" are different claims with different authors.
    note: str = ""

    # Which of this tool's arguments the **audit log** hashes rather than stores. Step
    # 045c, and the fourth judgment a vetter makes that no server can make for them:
    # `effect` says what a call changes, `resources` says what it touches, `identity`
    # says whose account it goes out as, and this says what of it may be written down.
    #
    # `Tool.redact_args` has been the audit's policy since the first shipped tool
    # (`post_message` hashes `text`), and until this step **only a hand-written tool
    # could set it** — a vetted connector tool's arguments landed in `audit.args`
    # verbatim, forever, in a table with no UPDATE. Harmless while an argument is a repo
    # name. Not harmless when it is `messages`, which is the whole conversation: the
    # brokered model call 045c exists for sends a prompt through this door on every
    # call, and a governed model call whose prompts accumulate in the log is a privacy
    # position nobody chose.
    #
    # A tuple of argument names, checked against the tool's own input schema by
    # `validation.validate` — a redaction naming an argument that never arrives is a
    # policy that reads as applied and is not, which is the same failure `Resource`'s
    # argument-existence rule exists for and is caught in the same place.
    redact_args: tuple = field(default_factory=tuple)

    def __post_init__(self):
        object.__setattr__(self, "resources", tuple(self.resources))
        object.__setattr__(self, "redact_args", tuple(self.redact_args))


@dataclass(frozen=True)
class StdioLaunch:
    """How to start a server as a child process, and where it expects its credential.

    The credential is injected into the child's environment at spawn, because that is
    what a stdio server accepts — and it therefore lives in that process's environment
    for the process's whole life. See transport.py for why that is a limitation rather
    than a design, and HttpLaunch for the shape that does not have it.
    """

    KIND = "stdio"

    command: tuple
    credential_env: str | None = None

    # **There is deliberately no `credential_ref` here — step 070.** A stdio server takes
    # its credential from the environment at spawn and holds it for the process's whole
    # life, so a pointer resolved once at spawn and held for hours is exactly the thing a
    # pointer exists not to be: it would let the strongest claim in the product be made
    # about the weakest shape. Customers cannot register stdio connectors anyway
    # (`STDIO_REFUSED`); the shipped ones keep the variable.

    # Non-secret settings the server reads from its environment — toolset selection
    # and the like. Separate from the credential so it is obvious at a glance which
    # of these is a secret.
    env: dict = field(default_factory=dict)

    # The env var that puts this server in read-only mode, if it has one. Set from
    # the manifest rather than written here: see Connector.read_only.
    read_only_env: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "command", tuple(self.command))
        if not self.command:
            raise RuntimeError("a stdio launch needs a command to run")

    def env_for(self, credential: str | None, read_only: bool = False) -> dict:
        """The child's environment. Deliberately not `os.environ` plus extras —
        a server should receive the secret it needs and nothing else we happen to hold.
        """
        env = dict(self.env)
        if self.credential_env and credential:
            env[self.credential_env] = credential
        if self.read_only_env and read_only:
            env[self.read_only_env] = "1"
        return env


@dataclass(frozen=True)
class HttpLaunch:
    """Where to reach a Streamable HTTP server, and how to present a credential.

    The point of this shape: the credential travels **per request**, in a header, and
    no long-lived process holds it. That is what makes per-user credentials possible
    at all — see transport.py.

    Note what is missing: there is no `read_only_env`. A server's read-only mode is a
    launch-time switch, and over HTTP there is no launch to switch. `Connector.read_only`
    is still derived and still correct; it simply has nothing to act on here. That costs
    a layer of defence in depth and no more, because the allowlist was always the actual
    control — the mode only ever narrowed what the server bothered to offer.
    """

    KIND = "http"

    url: str
    credential_env: str | None = None

    # Where the connector's shared credential lives when it is **not** ours to hold —
    # `op://vault/item/field`, resolved at call time through the deployment's 1Password
    # Connect service account (step 070, `core/vault.py`). Mutually exclusive with
    # `credential_env`, refused at registration and again at the read.
    #
    # Two fields rather than one sniffed field: an environment variable's name can never
    # contain `:` or `/`, so one field would in fact be unambiguous, and it would make
    # every reader of this manifest wrong about what the row says. `access_token`'s
    # sentence — *told, never inferred* — one layer out.
    credential_ref: str | None = None

    # Where the credential goes. `Authorization: Bearer <token>` is what most servers
    # want; the pair is configurable because some vendors insist on their own header.
    credential_header: str = "Authorization"
    credential_prefix: str = "Bearer "

    # Non-secret headers, the counterpart of StdioLaunch.env. Separate from the
    # credential for the same reason: which one is the secret should be obvious.
    headers: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.url:
            raise RuntimeError("an http launch needs a url")
        if not self.url.startswith(("http://", "https://")):
            raise RuntimeError(
                f"connector url must be http(s): got {self.url!r}. This value causes an "
                "outbound request, so it is checked rather than assumed."
            )

    def headers_for(self, credential: str | None) -> dict:
        """The headers for one request. Mirrors StdioLaunch.env_for — the credential
        is applied here and nowhere else, so there is one place it can leak from."""
        headers = dict(self.headers)
        if self.credential_header and credential:
            headers[self.credential_header] = f"{self.credential_prefix}{credential}"
        return headers


@dataclass(frozen=True)
class RestLaunch:
    """Where a plain REST API lives, and how to present a credential. Step 045a.

    Not an MCP server: there is no session, no handshake and no discovery — the base
    URL plus each vetted tool's stored `binding` is the whole contract. The attribute
    names are `HttpLaunch`'s **on purpose**: `_summary`'s `getattr(launch, "url", "")`,
    `ensure_available`'s `connector.launch.credential_env`, and
    `egress.host_of(connector.launch.url)` all keep working with no edit, which is most
    of the argument that this is a connector kind rather than a new subsystem.

    The credential travels per request, in a header, exactly as it does for an HTTP MCP
    server — which is why `carries_per_user_credentials` includes this kind and
    `identity: "user"` REST tools are legitimate.
    """

    KIND = "rest"

    url: str
    credential_env: str | None = None

    # Where the connector's shared credential lives when it is **not** ours to hold —
    # `op://vault/item/field`, resolved at call time through the deployment's 1Password
    # Connect service account (step 070, `core/vault.py`). Mutually exclusive with
    # `credential_env`, refused at registration and again at the read.
    #
    # Two fields rather than one sniffed field: an environment variable's name can never
    # contain `:` or `/`, so one field would in fact be unambiguous, and it would make
    # every reader of this manifest wrong about what the row says. `access_token`'s
    # sentence — *told, never inferred* — one layer out.
    credential_ref: str | None = None

    # Where the credential goes. `Authorization: Bearer <token>` is what most APIs
    # want; the pair is configurable because some vendors insist on their own header —
    # `x-api-key` with no prefix is the first named customer (plan 045c).
    credential_header: str = "Authorization"
    credential_prefix: str = "Bearer "

    # Non-secret headers, the counterpart of StdioLaunch.env. Separate from the
    # credential for the same reason: which one is the secret should be obvious.
    headers: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.url:
            raise RuntimeError("a rest launch needs a url")
        if not self.url.startswith(("http://", "https://")):
            raise RuntimeError(
                f"connector url must be http(s): got {self.url!r}. This value causes an "
                "outbound request, so it is checked rather than assumed."
            )

    def headers_for(self, credential: str | None) -> dict:
        """The headers for one request. The credential is applied here and nowhere
        else, so there is one place it can leak from — HttpLaunch's rule, kept."""
        headers = dict(self.headers)
        if self.credential_header and credential:
            headers[self.credential_header] = f"{self.credential_prefix}{credential}"
        return headers


# Deliberately no `Launch` alias for any of these. A generic-sounding name that is
# concretely one of the shapes is how someone writes `Launch(url=...)` and gets a
# confusing error about an unexpected keyword — and the whole point of splitting them
# is that which transport a connector uses should be impossible to be vague about.
_LAUNCH_KINDS = {cls.KIND: cls for cls in (StdioLaunch, HttpLaunch, RestLaunch)}


@dataclass(frozen=True)
class Connector:
    """A vetted MCP server: how to reach it, and exactly which tools we expose."""

    id: str
    launch: StdioLaunch | HttpLaunch | RestLaunch
    vetted: tuple = field(default_factory=tuple)
    description: str = ""
    # Step 033c: whether an *asserted* acting-for through the MCP door is believed for
    # this server's tools. False is the posture — verified or nothing — and turning it
    # on is an administrative act with the actor recorded (`set_asserted_identity`).
    # A fact about trust in a caller, not about the transport, which is why it sits
    # beside `description` rather than on the launch.
    allow_asserted_identity: bool = False

    def __post_init__(self):
        object.__setattr__(self, "vetted", tuple(self.vetted))
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.id):
            raise RuntimeError(
                f"connector id '{self.id}' must be lowercase letters, digits and hyphens"
            )

    @property
    def read_only(self) -> bool:
        """Should the server be launched in read-only mode?

        **Derived, never written down.** A server's read-only switch is defence in
        depth — the allowlist is what decides which tools exist — but a hardcoded
        constant drifts: vet a write and someone has to remember to turn it off, and
        when that write is later removed nobody remembers to turn it back on. Either
        way the flag stops describing our intent while still looking like it does.

        Deriving it means the two can never disagree. Vet only reads and the server
        is not even offered the ability to mutate; vet a write and it is, for exactly
        as long as that write stays vetted.
        """
        return all(vetted.effect == "read" for vetted in self.vetted)

    @property
    def transport_kind(self) -> str:
        """Which transport this connector speaks. Never inferred, never defaulted at
        the point of use — `connect()` dispatches on this and does not fall back."""
        return self.launch.KIND

    @property
    def carries_per_user_credentials(self) -> bool:
        """Whether this connector's transport can act as more than one person.

        HTTP sends the credential per request; stdio takes it from the environment at
        launch and holds it for the process's life. `mcp.supports_delegation` is this
        property under a name the access layer reads better, and calls it rather than
        restating it — one rule, because 021's lesson was a rule written twice and
        enforced once.

        `rest` is included (step 045a): a REST API over HTTPS takes a per-request
        header exactly the way an HTTP MCP server does, so `identity: "user"` REST
        tools resolve the acting-for person's own connection unchanged. Without this,
        `validate()` below would wrongly refuse them — plan 045a, finding 5.
        """
        return self.transport_kind in (HttpLaunch.KIND, RestLaunch.KIND)

    def launch_env(self, credential: str | None) -> dict:
        """The child process's environment. stdio only."""
        return self.launch.env_for(credential, read_only=self.read_only)

    def launch_headers(self, credential: str | None) -> dict:
        """The headers for one request. HTTP only.

        No `read_only` here, and nothing to pass it to: a read-only *mode* is a
        launch-time switch and there is no launch. The allowlist is unaffected, and
        the allowlist was always the control.
        """
        return self.launch.headers_for(credential)

    @property
    def prefix(self) -> str:
        """`github-mcp` -> `github_mcp_`. Hyphens are legal in a tool name, but mixing
        them with the underscores in a remote name reads as noise."""
        return self.id.replace("-", "_") + "_"

    def local_name(self, vetted: Vetted) -> str:
        """The name this tool has in our registry, and in the audit log.

        Namespaced so two connectors may both offer `list_issues`, and so a glance at
        an audit record says which path a call took.
        """
        return vetted.local_name or f"{self.prefix}{vetted.remote_name}"

    def declared_names(self) -> set:
        """Local names this connector will contribute once bound.

        Known without connecting, which is what lets an agent config granting an MCP
        tool be validated at import rather than at the first run.
        """
        return {self.local_name(v) for v in self.vetted}

    def declared_resource_types(self) -> dict:
        """local name -> {(resource type, effect)}, again without connecting."""
        return {
            self.local_name(v): {(ref.type, v.effect) for ref in v.resources}
            for v in self.vetted
        }

    def validate(self) -> None:
        """Checked at import. Everything here is knowable without a server."""
        seen = set()
        for vetted in self.vetted:
            name = self.local_name(vetted)

            # Checked at load as well as at bind, so a manifest row carrying an
            # identity nobody defined fails when the connector is read rather than at
            # the first run — the same fail-closed moment an unknown launch kind gets.
            if vetted.identity not in VALID_IDENTITIES:
                raise RuntimeError(
                    f"connector '{self.id}': '{vetted.remote_name}' declares identity "
                    f"'{vetted.identity}'; expected one of {sorted(VALID_IDENTITIES)}. "
                    "Whose account a tool acts as is not something to guess."
                )

            # **The impossible combination, refused where every path meets it.**
            # `tools.vet_tool` refuses this earlier and with a longer sentence, which
            # is the message somebody filling in a form should get — but that guard
            # covers one writer, and `save_connector` writes the allowlist wholesale
            # without passing through it. This runs inside `from_manifest`, so it is
            # reached by every write *and* every read: a row that somehow got stored
            # cannot bind, rather than binding into a tool the broker would resolve a
            # per-user credential for and hand to a server that can only hold one.
            if vetted.identity == "user" and not self.carries_per_user_credentials:
                raise RuntimeError(
                    f"connector '{self.id}': '{vetted.remote_name}' is vetted to act "
                    f"as the person calling it, but this connector speaks "
                    f"{self.transport_kind}, which takes its credential from the "
                    "environment at launch and holds it for as long as it runs — so "
                    "it cannot act as two people. Move the connector to HTTP, or vet "
                    "the tool as 'service'."
                )

            # **The kind and the binding imply each other, refused where every path
            # meets it** — the same placement argument as the identity check above.
            # A `rest` tool without a binding is a tool nobody can call: there is no
            # advertisement to fall back on, so binding it would mean guessing a
            # request shape. A binding on any other kind is a claim about a request
            # this connector will never make, stored where it reads as honoured.
            is_rest = self.transport_kind == RestLaunch.KIND
            if is_rest and vetted.binding is None:
                raise RuntimeError(
                    f"connector '{self.id}': '{vetted.remote_name}' is vetted on a "
                    "REST connector but carries no request binding. A REST API does "
                    "not describe itself, so the method, path, argument mapping and "
                    "input schema must be authored at vetting time."
                )
            if not is_rest and vetted.binding is not None:
                raise RuntimeError(
                    f"connector '{self.id}': '{vetted.remote_name}' carries a request "
                    f"binding, but this connector speaks {self.transport_kind}. A "
                    "binding describes a plain REST request; an MCP server describes "
                    "its own tools, and a stored binding it would never use reads as "
                    "honoured. The field and the 'rest' kind imply each other."
                )

            if not TOOL_NAME_RE.fullmatch(name):
                raise RuntimeError(
                    f"connector '{self.id}': '{vetted.remote_name}' becomes '{name}', "
                    f"which is not a legal tool name ({TOOL_NAME_RE.pattern}). "
                    "Set local_name to something shorter."
                )
            if name in seen:
                raise RuntimeError(f"connector '{self.id}' declares '{name}' twice")
            seen.add(name)


# --- manifests: a Connector as a row ---------------------------------------------
#
# Vetting used to be a Python module checked into source. It is now a row, and these
# two functions are the whole of that translation. Everything else about binding is
# unchanged, which is the point: a connector loaded from the database is the same
# object a connector loaded from an import was.


def _launch_to_dict(launch) -> dict:
    """A launch as a storable dict, tagged with which shape it is."""
    if isinstance(launch, (HttpLaunch, RestLaunch)):
        # The two shapes share their field names on purpose (see RestLaunch), so one
        # serializer body covers both — the `kind` tag is what keeps them distinct.
        return {
            "kind": launch.KIND,
            "url": launch.url,
            "credential_env": launch.credential_env,
            "credential_ref": launch.credential_ref,
            "credential_header": launch.credential_header,
            "credential_prefix": launch.credential_prefix,
            "headers": dict(launch.headers),
        }

    return {
        "kind": StdioLaunch.KIND,
        "command": list(launch.command),
        "credential_env": launch.credential_env,
        "env": dict(launch.env),
        "read_only_env": launch.read_only_env,
    }


def _launch_from_dict(row: dict):
    """Rebuild a launch from a stored row.

    A missing `kind` means stdio. Rows written before the HTTP transport existed have
    no such key, and defaulting is what lets them keep working without a migration —
    `connectors.launch` is JSONB precisely so the shape can grow.
    """
    kind = row.get("kind") or StdioLaunch.KIND

    if kind not in _LAUNCH_KINDS:
        # Fail closed and loudly. Guessing which transport a connector meant would be
        # guessing at its security properties: stdio holds a credential for a process
        # lifetime and HTTP does not, so the two are not interchangeable.
        raise RuntimeError(
            f"connector launch has unknown kind {kind!r}; "
            f"expected one of {', '.join(sorted(_LAUNCH_KINDS))}"
        )

    if kind in (HttpLaunch.KIND, RestLaunch.KIND):
        # `credential_prefix` distinguishes absent from empty: `""` is a legitimate
        # stored value (an API that wants the bare token in its header, `x-api-key`
        # style), and `or "Bearer "` would silently rewrite it on every load.
        prefix = row.get("credential_prefix")
        launch_cls = HttpLaunch if kind == HttpLaunch.KIND else RestLaunch
        return launch_cls(
            url=row.get("url") or "",
            credential_env=row.get("credential_env"),
            credential_ref=row.get("credential_ref"),
            credential_header=row.get("credential_header") or "Authorization",
            credential_prefix="Bearer " if prefix is None else prefix,
            headers=dict(row.get("headers") or {}),
        )

    return StdioLaunch(
        command=tuple(row.get("command") or ()),
        credential_env=row.get("credential_env"),
        env=dict(row.get("env") or {}),
        read_only_env=row.get("read_only_env"),
    )


def vetted_to_dict(vetted: Vetted) -> dict:
    """One `Vetted` as a storable row.

    Extracted from `to_manifest` in step 012, because vetting gained a second writer:
    `--vet` stores one tool at a time through `storage.vet_tool`, and a second inline
    serializer for the same shape is how a `template` written wholesale by `--seed` and a
    `template` written one-at-a-time by `--vet` quietly stop being the same row.

    Note what is deliberately absent: `vetted_by`, `vetted_at`, `server_name`,
    `server_version`. All four are the review record, which is the database's to own —
    see `Storage.load_vetting_record`. A `Vetted` cannot carry them because a caller
    would then be able to assert them, and a `vetted_by` asserted by a caller is a claim
    that Alice approved this made by code that is not Alice.
    """
    return {
        "remote_name": vetted.remote_name,
        "effect": vetted.effect,
        # Written even when it is the default, so a row's answer to "whose account?"
        # is on the row rather than in this file's history.
        "identity": vetted.identity,
        "resources": [
            {
                "type": ref.type,
                "args": list(ref.args),
                "template": ref.template,
                # Written even when empty, on `identity`'s reasoning above: a row's
                # answer to "what may a scope line name here" belongs on the row rather
                # than in this file's history. Step 086.
                "families": list(ref.families),
            }
            for ref in vetted.resources
        ],
        "local_name": vetted.local_name,
        "max_response_bytes": vetted.max_response_bytes,
        "description": vetted.description,
        "note": vetted.note,
        # Written even when empty, on `identity`'s reasoning: a row's answer to "what of
        # this call is not written down" belongs on the row rather than in this file's
        # history. Step 045c.
        "redact_args": list(vetted.redact_args),
        # None on every MCP row — "not applicable", the `response_bytes` precedent.
        "binding": dict(vetted.binding) if vetted.binding is not None else None,
    }


def to_manifest(connector: Connector) -> dict:
    """A `Connector` as a storable dict.

    Note what is **not** here: `read_only`. It is derived from the vetted effects
    (see `Connector.read_only`) and writing it down would create a stored copy free
    to disagree with the allowlist it defends. The storage layer refuses a manifest
    carrying it, rather than dropping it quietly.
    """
    return {
        "id": connector.id,
        "description": connector.description,
        "launch": _launch_to_dict(connector.launch),
        "vetted": [vetted_to_dict(vetted) for vetted in connector.vetted],
        # Written even when it is the default, on `identity`'s reasoning above: the
        # row's answer to "is an asserted caller believed here" belongs on the row.
        "allow_asserted_identity": connector.allow_asserted_identity,
    }


def from_manifest(manifest: dict) -> Connector:
    """Rebuild a `Connector` from a stored row, and validate it.

    `validate()` used to run at import, so a malformed manifest stopped the process
    from starting. It runs here instead — at load — which keeps the fail-closed
    property while letting one tenant's bad row be one tenant's problem.
    """
    connector = Connector(
        id=manifest["id"],
        description=manifest.get("description", ""),
        # A row written before 033c has no key, and False is what its tenant's posture
        # was: nothing could be asserted at all. The closed direction, like `identity`.
        allow_asserted_identity=bool(manifest.get("allow_asserted_identity", False)),
        launch=_launch_from_dict(manifest.get("launch") or {}),
        vetted=[
            Vetted(
                remote_name=row["remote_name"],
                effect=row.get("effect", "read"),
                # A row written before 033a has no key, and reading it as `service`
                # is the stated break in docs/UPGRADING.md: the shared credential is
                # what a headless caller always got, and the one it stops meaning —
                # try-delegated-first — was never part of any approval. An unknown
                # value is refused downstream by `validate()`, like a launch kind.
                identity=row.get("identity") or "service",
                resources=tuple(
                    Resource(
                        type=ref["type"],
                        args=tuple(ref["args"]),
                        template=ref.get("template"),
                        # A row written before 086 has no key, and `()` is what its
                        # approval meant: no family was declared, so no scope line can
                        # name one and a family scope against this tool refuses — which
                        # is exactly the state it is in today. `redact_args`' rule, and
                        # the closed direction is the empty one for the same reason:
                        # inventing a vocabulary nobody approved would widen a stored
                        # policy by upgrading.
                        families=tuple(ref.get("families") or ()),
                    )
                    for ref in row.get("resources") or ()
                ),
                local_name=row.get("local_name"),
                max_response_bytes=row.get("max_response_bytes"),
                description=row.get("description") or "",
                note=row.get("note") or "",
                # A row written before 045c has no key, and `()` is what its approval
                # meant: nothing was redacted, because nothing could be. The closed
                # direction here is the empty one — inventing a redaction somebody did
                # not approve would make the log quieter than the review that produced it.
                redact_args=tuple(row.get("redact_args") or ()),
                binding=row.get("binding"),
            )
            for row in manifest.get("vetted") or ()
        ],
    )
    connector.validate()
    return connector


def described(connector: Connector, vetted: Vetted) -> Tool:
    """The half of a bound tool that came from the **vetting**, and nothing else.

    Step 069, and the one construction site for a fact three callers need. `bind` below
    and `tools/rest.bind` build a callable tool by replacing the three fields that come
    from outside this database; `tools.describe` hands this straight to
    `permissions.check`, which reads `name`, `effect` and `resources` and touches
    nothing else.

    **Every field here is a row.** `_descriptor` above already states the same
    separation for a different purpose — it is the list of fields `bind` copies off the
    manifest, which is what lets a bound tool compare equal to its vetting — and the
    reason this function exists is that stating it twice is how the two drift. What
    comes off the wire is exactly `description`, `input_schema` and `impl`.

    That separation is what makes a simulator possible at all. A page answering *would
    this call be admitted* must not open a session to a customer's server, and it does
    not have to: whether a call is **permitted** is settled by the vetting, and only
    whether it is **available** needs a handshake.

    The impl is `uncallable` and the schema is empty, which is why `validate(tool)` is
    not called here: it checks a resource argument against the schema it was vetted
    against, and there is no schema until `bind` supplies one. See known limits of 069.
    """
    return Tool(
        name=connector.local_name(vetted),
        description="",
        input_schema=NO_SCHEMA,
        impl=uncallable,
        effect=vetted.effect,
        resources=vetted.resources,
        max_response_bytes=vetted.max_response_bytes,
        connector=connector.id,
        identity=vetted.identity,
        credential_env=connector.launch.credential_env,
        credential_ref=getattr(connector.launch, "credential_ref", None),
        binding=vetted.binding,
        redact_args=frozenset(vetted.redact_args),
    )


def bind(connector: Connector, advertised: list, call) -> tuple:
    """Intersect a manifest with an advertisement. Returns (tools, excluded_names).

    `call(remote_name, arguments)` executes a tool; binding stays ignorant of sessions
    and credentials so it can be tested against a list of dicts.
    """
    by_name = {tool.get("name"): tool for tool in advertised}
    tools = []

    for vetted in connector.vetted:
        spec = by_name.get(vetted.remote_name)
        if spec is None:
            raise RuntimeError(
                f"connector '{connector.id}' vets '{vetted.remote_name}', which this "
                f"server does not advertise. Advertised: "
                f"{', '.join(sorted(by_name)) or '<none>'}. A vetted tool that vanished "
                "is a change worth looking at, not one to route around."
            )

        # The vetting's half, then the server's. Built by `described` rather than
        # listed again here, so a field added to the descriptor cannot arrive at the
        # simulator and miss the broker, or the other way round (069).
        tool = replace(
            described(connector, vetted),
            # Description and schema come from the server. We copy them rather than
            # restate them: a description we wrote would drift from what the tool does.
            description=spec.get("description") or spec.get("title") or "",
            input_schema=spec.get("inputSchema") or {"type": "object", "properties": {}},
            impl=_proxy(call, vetted.remote_name),
        )

        # The drift check. `resources` was written against the schema as vetted; this
        # is where a renamed argument stops being a silent hole and becomes a crash.
        validate(tool)
        tools.append(tool)

    vetted_remote = {v.remote_name for v in connector.vetted}
    excluded = sorted(name for name in by_name if name not in vetted_remote)
    return tools, excluded


def _proxy(call, remote_name: str):
    """The generated implementation. Everything interesting already happened.

    By the time this runs the broker has authorized the call, charged the budget, and
    fetched the credential. `token` arrives as a keyword-only argument the tool's
    schema does not contain — it is in credentials.RESERVED_KWARGS, so the permission
    check refuses a model that tries to supply one and the audit log hashes it.
    """

    def proxy(*, token=None, **arguments):
        return call(remote_name, arguments, token)

    return proxy
