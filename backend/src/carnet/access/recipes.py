"""Checked-in presets that pre-fill connector registration. Step 068.

A **recipe** is a JSON file in `recipes/` carrying what somebody would otherwise type at
a shell to register one vendor: the connector row, the OAuth application's endpoints and
scopes, the hosts it needs allowed, and a set of *proposed* tools.

## What a recipe is not, stated first because every shortcut here erodes one of them

**It never vets.** A recipe's `tools` are proposals that arrive in the vetting form
pre-filled and unsubmitted. There is no bulk-apply anywhere in this module and adding one
would undo 012's judgment that a tool is approved one at a time by somebody who read its
schema. `DEFERRED.md`'s OpenAPI row says it in the same words: *import must not mean
bulk-vet*. A vendor proposing an `effect` is precisely what `vetted_tools.effect` exists
to refuse.

**It never allows a host.** It *names* the hosts it needs, each with a sentence saying
why, and the screen puts the approve control beside them. Approving stays a separate act
by a tenant admin with its own `admin_audit` record. A recipe carrying its own consent
would be 023's back-fill objection one layer up: this deployment inventing a consent
nobody gave.

**It carries no client id and no client secret.** The one field a recipe cannot fill is
the one that identifies you to the vendor. The OAuth application is the customer's,
created in the customer's console, and `oauth.configure` already refuses a missing
`client_id`.

**It is not a marketplace.** These files are in this repository and are reviewed like
code. There is no upload, no per-tenant recipe and no third-party publishing; that is the
community-catalogue row in `DEFERRED.md`, a different product with a different threat
model.

## The rule the rest of the design rests on

**Nothing in the database points back at a recipe.** No `recipe_id` column, no foreign
key, no join. Registering from a recipe produces byte-identical rows to registering by
hand — `connector.create`'s `admin_audit.detail` carries the recipe's name as a log line,
which nothing indexes and nothing joins on.

That is what makes a bounded catalogue possible. A wrong recipe costs one form's worth of
wrong defaults, because every field it fills is editable before submit. A **deleted**
recipe costs nothing at all, because nothing references it. So the catalogue can shrink,
and a preset that stops being true can be removed in the commit that finds out rather
than carried, half-true, until somebody has time.

The price is real and is paid on purpose: nothing can answer *which connectors came from
the recipe that just broke*. See plan 068's known limits.

## Why these are data files and not Python modules

`tools/mcp/connectors/github.py` is a Python `Connector` and stays one — it is code we
ship and run. A recipe is neither. It is a form's defaults, and a form's defaults must not
be able to compute anything, dial anything or import anything.

JSON rather than TOML, and the reason is better than the Python floor (`>=3.10`, so no
`tomllib`). A TOML comment is read by a code reviewer. A JSON `"why"` field is read by
**the administrator standing at the form** — the same sentence, in front of the person
whose judgment it informs. Prose only the reviewer sees is prose in the wrong place, so
the explanations here are fields.

## Staleness is displayed, never prevented

`verified_on` is the date somebody here created the OAuth application at that vendor,
registered our redirect URI and completed one consent flow end to end. `null` means
nobody has. We are not in the call path of a consent flow after handing over a URL, so we
learn a vendor moved an endpoint when a customer tells us — there is no signal to build a
freshness check on. What is achievable is refusing to look authoritative, which is
`staleness()` and the sentence the screen renders from it.
"""

from __future__ import annotations

import datetime
import inspect
import json
import pathlib
import re

from .. import storage, tools
from ..storage import base as storage_base
from ..tools.mcp import binding, egress
from . import oauth

RECIPES_DIR = pathlib.Path(__file__).parent / "recipes"

# **The ceiling, and it is a policy rather than a limit of anything.**
#
# Plan 068 rule 3: the number of recipes we are willing to carry is the number one person
# can re-verify against the vendors in one sitting. Today that is eight. It bounds
# *recipes*, never connectors — a customer registers whatever they like and always could.
#
# `test_the_catalogue_stays_under_its_ceiling` fails when a ninth file lands, and its
# message is the argument rather than the number. That is the whole mechanism: raising
# this is a visible act with plan 068 attached, instead of a directory quietly reaching
# forty and nobody being able to say when it stopped being maintained.
CEILING = 8

# Past this, the screen stops presenting a recipe as checked. Six months is not derived
# from anything about vendors — it is how long it takes for "somebody looked at this" to
# stop being a useful claim.
STALE_AFTER_DAYS = 183

# Every key a recipe file may carry. Unknown keys are refused rather than ignored, which
# is `Vetted`'s rule and `pydantic`'s `extra="ignore"` lesson from 044: a field that is
# silently dropped looks exactly like a field that works. A recipe is edited by hand by
# somebody reading a vendor's documentation, which is precisely the writer who will invent
# a plausible key.
RECIPE_FIELDS = frozenset(
    {
        "id",
        "name",
        "description",
        "verified_on",
        "verified_by",
        "verified_against",
        "hosts",
        "connector",
        "oauth",
        "tools",
    }
)

HOST_FIELDS = frozenset({"host", "why"})

# The connector half. `connector_id` is the id a recipe *suggests* and an admin may
# change; the rest are `register_connector`'s own keyword parameters, checked against its
# signature by `check_field_sets`.
CONNECTOR_FIELDS = frozenset(
    {
        "connector_id",
        "url",
        "kind",
        "credential_env",
        # **`credential_ref` is deliberately absent** (step 070), and the drift check
        # above is one-directional precisely so an omission like this is legal: a recipe
        # is a subset of what the code takes. A checked-in file can carry a vendor's
        # endpoints and scopes; it cannot know where in *your* vault your token is, and
        # a recipe that guessed would be filling in the one field that decides which
        # secret leaves the building. Typed by the administrator, at the moment
        # `credential_env` would have been.
        "credential_header",
        "credential_prefix",
        "headers",
        "description",
    }
)

# The OAuth half of a recipe. Deliberately **not** the full parameter set of
# `oauth.configure`: `client_id`, `client_secret` and `actor` are absent because a recipe
# may not carry them, and `connector_id` comes from the connector half.
OAUTH_FIELDS = frozenset(
    {
        "authorize_endpoint",
        "token_endpoint",
        "revoke_endpoint",
        "scopes",
        "authorize_params",
        "scope_notes",
    }
)

# What a proposed tool may carry. `remote_name` plus the vetter's four judgments, plus the
# REST binding. Checked against `binding.Vetted`'s own fields below rather than restated,
# so this set cannot drift from the dataclass the proposals become.
TOOL_FIELDS = frozenset(
    {
        "remote_name",
        "effect",
        "identity",
        "resources",
        "local_name",
        "max_response_bytes",
        "description",
        "note",
        "redact_args",
        "binding",
    }
)


class RecipeRefused(Exception):
    """A recipe file this platform will not serve. Raised at load, never at use."""


def _connector_fields() -> frozenset:
    """The keyword parameters `tools.register_connector` actually takes.

    Read from the function rather than written down, which is the check plan 068's rule 5
    calls the one that earns its keep. The failure it prevents is **ours**: somebody
    renames `credential_env` and six recipe files keep setting a key nothing reads, with
    every test green because nothing compares the two. Introspection makes that rename a
    red load instead of a silent no-op.

    `tenant_id`, `connector_id` and `actor` are excluded — the first two are positional
    and the third is the person doing the registering, which is never a file's to assert.
    """
    taken = set(inspect.signature(tools.register_connector).parameters)
    return frozenset(taken - {"tenant_id", "connector_id", "actor"}) | {"connector_id"}


def _oauth_fields() -> frozenset:
    """The keyword parameters `oauth.configure` takes, less the ones a recipe may not."""
    taken = set(inspect.signature(oauth.configure).parameters)
    return frozenset(
        taken - {"tenant_id", "connector_id", "actor", "client_id", "client_secret"}
    )


def _refuse(recipe_id: str, sentence: str) -> None:
    raise RecipeRefused(f"recipe '{recipe_id}': {sentence}")


def check_field_sets() -> None:
    """**The check plan 068's rule 5 calls the one that earns its keep.**

    The failure it prevents is *ours*. Somebody renames `credential_env` on
    `register_connector`, or drops `authorize_params` from `oauth.configure`, and six
    recipe files keep setting a key nothing reads — with every test green, because nothing
    compares the two. The recipes would go on registering connectors that are subtly
    wrong, and the first symptom would be a customer's consent flow failing.

    Raised rather than returned, and called from `validate` so it runs on every load
    rather than only under test. A catalogue that cannot be trusted to fill the form is
    worse than no catalogue: it is a blank form somebody believes.
    """
    for what, declared, available in (
        ("a connector", CONNECTOR_FIELDS, _connector_fields()),
        ("an oauth application", OAUTH_FIELDS, _oauth_fields()),
        ("a proposed tool", TOOL_FIELDS, frozenset(binding.Vetted.__dataclass_fields__)),
    ):
        drifted = declared - available
        if drifted:
            raise RecipeRefused(
                f"the recipe catalogue describes {sorted(drifted)} on {what}, and the "
                f"code it fills no longer takes {'it' if len(drifted) == 1 else 'them'}. "
                f"A recipe cannot be served until the two agree: every recipe setting "
                f"that field is silently filling nothing.\n"
                f"  recipes offer:  {sorted(declared)}\n"
                f"  the code takes: {sorted(available)}"
            )


def validate(recipe: dict, *, source: str = "") -> dict:
    """Check one recipe against the parameter sets it pre-fills. Returns it, normalized.

    Runs at **load** rather than at import, on `binding.from_manifest`'s precedent: one
    malformed file should be one refused recipe, not a process that will not start.
    """
    if not isinstance(recipe, dict):
        raise RecipeRefused(
            f"recipe '{source or '<unnamed>'}': a recipe file must contain one JSON "
            f"object"
        )
    recipe_id = str(recipe.get("id") or source or "<unnamed>")

    # Before any field of any recipe is read, so a renamed parameter is a refusal about
    # the code rather than a confusing refusal about a file nobody edited.
    check_field_sets()

    unknown = set(recipe) - RECIPE_FIELDS
    if unknown:
        _refuse(
            recipe_id,
            f"carries {sorted(unknown)}, which is not part of a recipe. Known keys are "
            f"{sorted(RECIPE_FIELDS)}. Unknown keys are refused rather than ignored: a "
            f"field that is silently dropped looks exactly like one that works.",
        )

    for required in ("id", "name", "connector"):
        if not recipe.get(required):
            _refuse(recipe_id, f"needs a {required}")

    if source and recipe["id"] != source:
        _refuse(
            recipe_id,
            f"is in a file named '{source}.json'. The id and the filename must match, so "
            f"that the id in an `admin_audit` record names a file somebody can open.",
        )

    # --- the connector half ------------------------------------------------------------
    connector = recipe["connector"]
    if not isinstance(connector, dict):
        _refuse(recipe_id, "its connector must be an object")
    unknown = set(connector) - CONNECTOR_FIELDS
    if unknown:
        _refuse(
            recipe_id,
            f"its connector sets {sorted(unknown)}, which a recipe does not carry. "
            f"`register_connector` takes {sorted(_connector_fields())}; a recipe offers "
            f"{sorted(CONNECTOR_FIELDS)}, and `allow_asserted_identity` is deliberately "
            f"not among them — believing an asserted caller is a security posture a "
            f"tenant adopts on purpose, with the actor recorded, not a default a vendor "
            f"preset arrives holding.",
        )
    suggested = connector.get("connector_id") or ""
    if not suggested:
        _refuse(recipe_id, "its connector needs a connector_id to suggest")
    # `Connector.__post_init__`'s rule, checked here so a recipe cannot pre-fill a form
    # with a value that is then refused at submit. That refusal would be about a string
    # the person did not type, at the end of a flow they had no reason to doubt — which
    # is the worst place in the arc to discover a defect in this repository's own files.
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", suggested):
        _refuse(
            recipe_id,
            f"suggests the connector id '{suggested}', which `Connector` refuses: it "
            f"must be lowercase letters, digits and hyphens. A recipe may only pre-fill "
            f"a value that would be accepted.",
        )
    url = connector.get("url") or ""
    if not url.startswith("https://"):
        # http:// is legal for `register_connector` — a customer's internal MCP server on
        # a private network is a real deployment — but a recipe is a preset for a public
        # vendor, and a checked-in default that downgrades somebody's transport is not a
        # default anybody chose.
        _refuse(
            recipe_id,
            f"its connector url is {url!r}. A recipe names a public vendor and must use "
            f"https. Plain http stays available to somebody registering their own "
            f"server by hand, where it is a decision rather than an inherited default.",
        )

    # --- the hosts it needs ------------------------------------------------------------
    hosts = recipe.get("hosts") or []
    if not isinstance(hosts, list) or not hosts:
        _refuse(
            recipe_id,
            "names no hosts. A connector nothing may dial is a registration that cannot "
            "work, and the hosts are what the screen offers for approval.",
        )
    for entry in hosts:
        if not isinstance(entry, dict) or set(entry) - HOST_FIELDS:
            _refuse(recipe_id, f"a host entry must be {sorted(HOST_FIELDS)}")
        host = entry.get("host") or ""
        # The same normalization the allowlist applies, run here so a recipe cannot
        # propose a host the approve control would then refuse or silently rewrite.
        #
        # `normalize_host` **raises** on a host it cannot normalize rather than returning
        # something different, so the comparison alone is not the whole check — without
        # this catch a recipe with `https://` in a host field escapes as a raw
        # `ValueRefused` from the storage layer, which names no recipe and no file. Its
        # sentence is the right one to show, so it is quoted rather than replaced.
        try:
            normalized = storage.normalize_host(host)
        except storage.ValueRefused as exc:
            _refuse(recipe_id, f"host '{host}' is not storable: {exc}")
        if host != normalized:
            _refuse(
                recipe_id,
                f"host '{host}' is stored as '{normalized}'. Write it in the form the "
                f"allowlist keeps, so the string in this file is the one an "
                f"administrator sees on the approve control.",
            )
        if not (entry.get("why") or "").strip():
            _refuse(
                recipe_id,
                f"host '{host}' has no `why`. The sentence is the point: somebody is "
                f"being asked to widen where this tenant may dial, which is the sharpest "
                f"administrative act in the product, and 'the recipe said so' is not a "
                f"reason anybody can weigh.",
            )

    # Every host the recipe's own URLs dial must be one it names. Without this a recipe
    # can point at a vendor whose token endpoint is on a host the screen never offers,
    # and the failure lands at somebody's first Connect rather than here.
    named = {entry["host"] for entry in hosts}
    dialled = {_host_of(url)}
    if recipe.get("oauth"):
        # The authorize endpoint is deliberately not included: nothing of ours dials it,
        # it is a redirect the browser follows, and `oauth.configure` does not check it
        # either. Naming it as required would describe a connection we never make.
        dialled.add(_host_of(recipe["oauth"].get("token_endpoint") or ""))
    missing = {host for host in dialled if host} - named
    if missing:
        _refuse(
            recipe_id,
            f"dials {sorted(missing)} and does not name it in `hosts`, so the screen "
            f"would never offer it for approval and the registration would fail at the "
            f"first call instead of here.",
        )

    # --- the oauth half ----------------------------------------------------------------
    app = recipe.get("oauth")
    if app is not None:
        if not isinstance(app, dict):
            _refuse(recipe_id, "its oauth must be an object or null")
        unknown = set(app) - OAUTH_FIELDS
        if unknown:
            forbidden = unknown & {"client_id", "client_secret"}
            if forbidden:
                _refuse(
                    recipe_id,
                    f"carries {sorted(forbidden)}. A recipe may never hold either: the "
                    f"OAuth application belongs to the customer, created in the "
                    f"customer's console, and a client secret in this repository would "
                    f"be a credential in a git history shared by every deployment.",
                )
            _refuse(
                recipe_id,
                f"its oauth sets {sorted(unknown)}, which `oauth.configure` does not "
                f"take.",
            )
        for required in ("authorize_endpoint", "token_endpoint"):
            if not (app.get(required) or "").startswith("https://"):
                _refuse(recipe_id, f"its oauth needs an https {required}")
        # The refusal `normalize_scope_notes` would give, given here so a broken recipe is
        # caught at load rather than at the moment an admin submits the form. Same
        # redundancy as `oauth.configure` checking egress at configure time *and* at use.
        try:
            storage_base.normalize_scope_notes(
                app.get("scope_notes"), scopes=app.get("scopes") or ()
            )
        except storage.ValueRefused as exc:
            _refuse(recipe_id, str(exc))

    # --- the proposed tools ------------------------------------------------------------
    proposals = recipe.get("tools") or []
    if not isinstance(proposals, list):
        _refuse(recipe_id, "its tools must be a list")
    for proposal in proposals:
        if not isinstance(proposal, dict):
            _refuse(recipe_id, "each proposed tool must be an object")
        unknown = set(proposal) - TOOL_FIELDS
        if unknown:
            _refuse(
                recipe_id,
                f"tool '{proposal.get('remote_name', '?')}' sets {sorted(unknown)}, "
                f"which `Vetted` does not carry.",
            )
        if not proposal.get("remote_name"):
            _refuse(recipe_id, "a proposed tool needs the name the vendor advertises")
        # **A redaction naming an argument the schema does not carry is refused here as
        # well as at vet time**, and this check was written because the shipped Anthropic
        # recipe failed it: it marked `system` as redacted and its authored schema did not
        # have a `system` property.
        #
        # `validation.validate` caught it — 045c's guard, and it is the load-bearing half
        # of that step, because the failure is silent in the reassuring direction: a
        # policy that reads as applied and is not. But it caught it at the moment an
        # administrator ran `--vet`, which is a refusal about a file they did not write
        # at the end of a flow they had no reason to doubt. A recipe's own defects belong
        # to us and should surface when the catalogue loads.
        binding = proposal.get("binding") or {}
        schema = (binding.get("input_schema") or {}).get("properties") or {}
        if schema:
            unknown = set(proposal.get("redact_args") or ()) - set(schema)
            if unknown:
                _refuse(
                    recipe_id,
                    f"tool '{proposal['remote_name']}' redacts {sorted(unknown)}, which "
                    f"its authored schema does not carry ({sorted(schema)}). A redaction "
                    f"for an argument that never arrives never applies, and the review "
                    f"record would say a value is hidden while the log holds it in the "
                    f"clear.",
                )
        # **A family a scope line could never name is refused where the catalogue
        # loads**, on the redaction check's reasoning directly above: it is our file's
        # defect, and the alternative is an administrator meeting it as a refusal about
        # something they did not write. The failure is the same silent-in-the-reassuring-
        # direction shape — a blank family is a token run inside every identifier, so one
        # scope line naming it would admit every model on the connector, and a family
        # carrying a `/` is a name a single-segment value can never match, so a scope
        # written against it refuses everything.
        for ref in proposal.get("resources") or ():
            if not isinstance(ref, dict):
                _refuse(recipe_id, "each proposed resource must be an object")
            for family in ref.get("families") or ():
                if not isinstance(family, str) or not family.strip():
                    _refuse(
                        recipe_id,
                        f"tool '{proposal['remote_name']}' proposes an empty family on "
                        f"'{ref.get('type')}'. An empty family is a run of tokens inside "
                        f"every identifier, so one scope line naming it would admit every "
                        f"one of them.",
                    )
                if "/" in family:
                    _refuse(
                        recipe_id,
                        f"tool '{proposal['remote_name']}' proposes family '{family}' on "
                        f"'{ref.get('type')}', which contains '/'. A family is matched as "
                        f"one whole segment, so a scope line naming it would match "
                        f"nothing at all.",
                    )

        if proposal.get("effect") not in ("read", "write"):
            _refuse(
                recipe_id,
                f"tool '{proposal['remote_name']}' proposes effect "
                f"{proposal.get('effect')!r}; it must be read or write. A recipe may "
                f"*propose* an effect and a person still approves it — but a proposal "
                f"with no effect is a form field somebody will leave as it lands.",
            )

    _check_verification(recipe, recipe_id)
    return recipe


def _check_verification(recipe: dict, recipe_id: str) -> None:
    """`verified_on` is a date or null, and a date brings its evidence with it.

    A stamp with no `verified_by` is a claim nobody signed, which is the same defect
    `admin_audit.actor_id` refuses with a CHECK: a record that says nobody did it looks
    like an answer.
    """
    stamped = recipe.get("verified_on")
    if stamped is None:
        return
    try:
        datetime.date.fromisoformat(str(stamped))
    except ValueError:
        _refuse(recipe_id, f"verified_on is {stamped!r}; it must be YYYY-MM-DD or null")
    if not (recipe.get("verified_by") or "").strip():
        _refuse(
            recipe_id,
            "is stamped verified_on with no verified_by. A verification nobody signed is "
            "a claim with no author, and the whole value of the stamp is that somebody "
            "put their name to having completed a consent flow against the vendor.",
        )


def _host_of(url: str) -> str:
    """The host of a URL, or `''`. `mcp.egress.host_of` under a local name so this module
    does not grow a second opinion about what a host is."""
    return egress.host_of(url) if url else ""


def staleness(recipe: dict, *, today: datetime.date | None = None) -> str:
    """`"verified"`, `"stale"` or `"unverified"` — what the screen renders a sentence from.

    Computed rather than stored, on `HostEntry.warning`'s precedent: the rule about when a
    check stops counting is code, and a copy of it in a file goes stale the first time the
    rule changes.
    """
    stamped = recipe.get("verified_on")
    if not stamped:
        return "unverified"
    today = today or datetime.date.today()
    age = (today - datetime.date.fromisoformat(str(stamped))).days
    return "stale" if age > STALE_AFTER_DAYS else "verified"


def catalogue(*, directory: pathlib.Path | None = None) -> list[dict]:
    """Every recipe this deployment ships, by id. Reads the disk; caches nothing.

    Uncached on `mcp.connectors_for`'s precedent and for a duller reason than the door's:
    this is read by a form and by a CLI listing, neither of which is a hot path, and a
    cache would be a second place a deleted file could still exist.
    """
    directory = directory or RECIPES_DIR
    if not directory.is_dir():
        return []
    return [_read(path) for path in sorted(directory.glob("*.json"))]


def _read(path: pathlib.Path) -> dict:
    """One file as a validated recipe, or a `RecipeRefused` naming it.

    **Every way this can fail is a `RecipeRefused`**, which is the module's stated
    contract — *raised at load, never at use* — and it was not true until this function
    existed. `validate` refused cleanly and `json.loads` and `read_text` did not, so a
    file with a stray comma left as a bare `JSONDecodeError` and a file saved in the wrong
    encoding as a `UnicodeDecodeError`. Both reached `GET /admin/recipes` unmapped and
    became an unhandled 500 with no sentence and no filename — found by driving the route
    with a broken file rather than by reading it, which is how 7b found the same shape
    twice and how 011's `NoSuchGroupError` shipped as a 503.

    The filename is in every message because the reader is whoever has to open it.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RecipeRefused(
            f"recipe file '{path.name}' is not valid UTF-8 ({exc.reason} at byte "
            f"{exc.start}). A recipe is JSON, and JSON is UTF-8."
        ) from None
    except OSError as exc:
        raise RecipeRefused(f"recipe file '{path.name}' cannot be read: {exc}") from None

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecipeRefused(
            f"recipe file '{path.name}' is not valid JSON: {exc.msg} at line "
            f"{exc.lineno} column {exc.colno}."
        ) from None

    return validate(parsed, source=path.stem)


def load(recipe_id: str, *, directory: pathlib.Path | None = None) -> dict | None:
    """One recipe by id, or None.

    The id is used as a filename, so it is checked against the same shape a connector id
    must have — which incidentally makes `../` unrepresentable rather than filtered.
    """
    directory = directory or RECIPES_DIR
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", recipe_id or ""):
        return None
    path = directory / f"{recipe_id}.json"
    if not path.is_file():
        return None
    return _read(path)
