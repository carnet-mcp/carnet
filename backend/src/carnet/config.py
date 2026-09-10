"""Paths and runtime settings. No secrets here — those live in core/credentials.py.

Everything that touches the filesystem resolves through this module, so there is one
place to change when this moves behind a server or into a container.
"""

import os
from pathlib import Path


def _refuse_retired_prefix(environ) -> None:
    """This package has been renamed twice — agent-runtime, then shipyard, now carnet —
    and each rename retired an environment prefix with it. See docs/UPGRADING.md.

    Refused rather than ignored, and refused rather than read as a fallback. A retired
    variable that is silently skipped is a deployment that silently loses its
    configuration — a database URL that stops being durable, a retention policy that
    stops deleting — which is the exact failure `CARNET_RETENTION_DAYS` below refuses
    in miniature. And a dual-prefix release would preserve the two-prefixes-in-one-file
    confusion the rename exists to end, then need removing anyway. Nothing was deployed
    at either rename, so both breaks are clean and the remedy is a rename in place.

    The refusal names every offending variable and its replacement, because the whole
    point of failing loudly is to be actionable in one read: a message saying only
    *that* prefix is retired sends somebody to grep their own deployment.
    """
    for retired_prefix in ("AGENT_RUNTIME_", "SHIPYARD_"):
        retired = sorted(k for k in environ if k.startswith(retired_prefix))
        if not retired:
            continue
        remedies = ", ".join(
            f"{k} is now CARNET_{k[len(retired_prefix):]}" for k in retired
        )
        raise ValueError(
            f"The {retired_prefix} prefix is retired — the package is named carnet now. "
            f"Rename in your environment: {remedies}. See docs/UPGRADING.md."
        )


_refuse_retired_prefix(os.environ)

# .../carnet/backend/src/carnet/config.py -> .../carnet
REPO_ROOT = Path(__file__).resolve().parents[3]

# Runtime artifacts (audit trail, message outbox). Not source, not committed.
# Override with CARNET_VAR_DIR when running in a container or on a server.
VAR_DIR = Path(os.environ.get("CARNET_VAR_DIR", REPO_ROOT / "var"))

# The outbox is the last thing in var/ that is still a file: `post_message` with no
# webhook configured appends here, so the runtime is fully exercisable without signing
# up for anything. The audit log used to live beside it and is now a table.
OUTBOX_PATH = VAR_DIR / "outbox.jsonl"
# Where a post-execution audit record lands when the database append fails (step 060)
# — the outbox's pattern: a durable local file on the volume the shipped compose
# already mounts, flagged CRITICAL at birth, awaiting an operator. Rare by
# construction; `api.LogMaintainer` keeps the partitions that made it reachable ahead
# of the writes.
AUDIT_FALLBACK_PATH = VAR_DIR / "audit-fallback.jsonl"

# --- Storage -----------------------------------------------------------------
# Where agents, connectors and the audit trail live. Unset means the CLI runs
# against an in-memory store seeded from the shipped modules — enough to try the
# runtime without standing up a database, and explicitly not durable.
DATABASE_URL = os.environ.get("CARNET_DATABASE_URL") or None

# The fileborne door — step 095, plan 094's artefact A. Set, this names a `carnet.yaml`
# that *is* the door's whole administration: connectors, agents and tokens, parsed at
# startup into the same rows the browser would write, in an in-memory store that dies
# with the process. No database, no sign-in, no browser.
#
# **Refused beside a database rather than layered over it.** A file applied over rows
# the browser also writes is two expressions of the permission model free to disagree —
# the next restart quietly puts the file's version back over somebody's screen edit —
# and which one wins is a design with its own plan, not a default. One image, either
# artefact, never both at once. Refused at import, on `_retention_days`' precedent: this
# is a setting somebody types once, and finding out at the first call is three days late.
CARNET_FILE = os.environ.get("CARNET_FILE") or None

if CARNET_FILE and DATABASE_URL:
    raise ValueError(
        "CARNET_FILE and CARNET_DATABASE_URL are both set, and the door runs from one "
        "or the other. A carnet.yaml is the whole administration of a fileborne door — "
        "no database, no sign-in — while a database is administered in the browser. "
        "Unset one of them."
    )

# The tenant a headless caller acts for when nothing else says otherwise. Every
# row in the database carries a tenant from the first migration; a single-tenant
# CLI still needs a name for the one it is using.
#
# This is a *default for the entry point*, not a fallback inside the call path.
# Principal requires a tenant with no default precisely so that a construction
# site cannot quietly land here by forgetting.
DEFAULT_TENANT_ID = os.environ.get("CARNET_TENANT") or "default"

# Where a browser reaches this deployment, origin only. Step 7b's OAuth redirect URI is
# built from it: `<PUBLIC_ORIGIN>/connect/callback`, which is the value an administrator
# registers at each provider.
#
# **Configuration rather than anything derived from the request**, which is decision 3
# and is the part somebody will want to skip. Building a redirect URI out of the `Host`
# or `X-Forwarded-Host` header means it is whatever a header says — and the only thing
# standing between that and an authorization code delivered to an attacker is the
# provider validating it strictly on their side. They do, so in practice the failure is
# an `invalid_grant` that shows up only behind a proxy and reads like a code bug; the
# reason to refuse anyway is that *"safe because somebody else checks"* is not a
# property to build on.
#
# The default is the dev server rather than the API's own port, and that is not a typo:
# the browser talks to Vite on 8080, which proxies `/api` onward — so `localhost:8000` is
# an origin no browser in this project ever visits. See `vite.config.ts`, and note that
# the callback is therefore reached at `/api/connect/callback` in development, which is
# what has to be registered at the provider.
PUBLIC_ORIGIN = (
    os.environ.get("CARNET_PUBLIC_ORIGIN") or "http://localhost:8080/api"
)


def public_origin_parts() -> tuple[str, str]:
    """`PUBLIC_ORIGIN` as the browser's origin and the path the API is mounted under.

    `("https://carnet.acme.com", "/api")` for the shipped deployment. Step 083 reads
    it for the three OAuth documents: the `.well-known` documents live at the origin
    root (RFC 9728, RFC 8414), the consent page is the SPA at the origin, and the token
    and registration endpoints are under the API path. **No second setting**: the one
    this deployment already registers at every OAuth provider is the one that decides
    where a client is sent, and a deployment whose value is wrong already cannot
    complete a connector consent.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(PUBLIC_ORIGIN.rstrip("/"))
    return f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")


# --- The door as an OAuth resource server (step 083) ---------------------------
#
# How long a token minted by an OAuth consent lives, in days. `0` means no expiry —
# the CLI's default. 30 because the flow issues no refresh token (the plan says why),
# so an expiry is a re-consent, which for a person still signed in at their identity
# provider is one click; and because a desktop client's token is standing authority
# on a laptop, which is the case an expiry exists for.
OAUTH_TOKEN_DAYS = int(os.environ.get("CARNET_OAUTH_TOKEN_DAYS") or 30)

# An authorization code lives this long. RFC 6749 recommends at most ten minutes; five
# is the SDK's own expectation and covers a person reading the consent page.
OAUTH_CODE_TTL_SECONDS = 300

# A code row outlives its expiry by this much before the sweep takes it, so a replayed
# code is recognised as one (and revokes what it minted) rather than read as unknown.
OAUTH_CODE_SWEEP_SECONDS = 3600

# A client that registered and was never consented to is swept after this many days.
# Registration is unauthenticated, so this is the bound on what a stranger's script
# can leave behind.
OAUTH_CLIENT_UNUSED_DAYS = 30

# Outbound HTTP timeout for tool implementations, in seconds.
#
# **Overridable since 065**, and the reason is a vendor rather than a preference: a
# public documentation server answered in 1.9s all afternoon and then took longer than
# this, which the caller sees as `no reply from the server in time` on a call that may
# well have taken effect. Fifteen seconds is right for a chat-shaped tool and wrong for
# a search-shaped one, and which a deployment has is not something this file knows.
# The default is unchanged; a deployment that brokers a slow vendor raises it.
REQUEST_TIMEOUT = int(os.environ.get("CARNET_REQUEST_TIMEOUT") or 15)

# --- model calls through the OpenAI-compatible surface -----------------------------
#
# Step 108, decision 4. A model call is not a tool call, and the two dials above and
# the door's 64 KiB body cap are right for what they guard and wrong here. A coding
# agent's prompt carries file context and is routinely 200 KiB; a completion routinely
# takes forty seconds and streams the whole way. So `/v1/*` has its own four, read at
# startup like every other setting here:
#
#   MODEL_MAX_REQUEST_BYTES   the request body. 4 MiB: under the front door's 12 MiB
#                             backstop, far past any prompt that is not a document.
#   MODEL_CHUNK_TIMEOUT       seconds between two chunks of a streamed answer. A stream
#                             that is still producing is healthy however long it has
#                             run; one that has produced nothing for a minute is not.
#                             Also the read timeout for a non-streamed model call, since
#                             the whole body is its one chunk.
#   MODEL_MAX_SECONDS         wall clock for one call, streamed or not. Ten minutes: a
#                             stream that has produced *anything* for ten minutes is
#                             not a completion, it is a leak holding a thread.
#   THREADS                   the API's threadpool. Every route here is sync `def` by
#                             house rule, so one open stream is one thread for the life
#                             of the completion; uvicorn's default of 40 would cap a
#                             company at forty engineers mid-completion. Two hundred is
#                             a guess sized to a company, not a measurement, and the
#                             plan says so.
MODEL_MAX_REQUEST_BYTES = int(os.environ.get("CARNET_MODEL_MAX_REQUEST_BYTES") or 4 * 1024 * 1024)
MODEL_CHUNK_TIMEOUT = int(os.environ.get("CARNET_MODEL_CHUNK_TIMEOUT") or 60)
MODEL_MAX_SECONDS = int(os.environ.get("CARNET_MODEL_MAX_SECONDS") or 600)
THREADS = int(os.environ.get("CARNET_THREADS") or 200)

# --- MCP session pool --------------------------------------------------------
# Sessions outlive runs, which is right: a connector is a subprocess or a container,
# and re-spawning one per run would be absurd. Behind a CLI the process exited and
# took its sessions with it. A server does not, so a pool with no expiry and no
# ceiling is a leak with a subprocess attached.
#
# Both numbers are invented, and that is a smaller sin than it was: they are bounds
# where there were none, not tuning. Step 003 deferred idle eviction on the grounds
# that a TTL without traffic is fiction — correct then, expired now that the process
# is long-lived. Size them from real traffic when there is some.
MCP_SESSION_IDLE_TTL = 900  # seconds; an idle server is retired after 15 minutes

# Live sessions across all tenants.
#
# **Re-derived for delegated credentials, and still invented.** The pool is keyed
# (tenant, connector, credential-fingerprint), which already anticipated delegation —
# two users never share a session bound with somebody else's token. What did not
# survive is the *capacity*: while every user in a tenant shared one credential the key
# space was tenants x connectors, and 32 was generous. It is now tenants x connectors x
# **users**, where 32 means roughly "thirty-two concurrently active people on the whole
# platform" before least-recently-used eviction starts thrashing.
#
# 256 is a bound, not tuning, and saying so is the point. What must not happen is a
# number surviving unexamined into the step that invalidates it.
#
# Overridable without a deploy, because the first customer to hit this should not be
# waiting on a release — and because the honest way to size it is to watch
# `SessionPool.overflow_evictions` and `duration_ms` under real traffic and set it from
# what they say.
#
# Being wrong here costs a re-handshake, never correctness: a caller whose session has
# been evicted rebuilds one under its own credential. That was not true until step 007
# removed a fallback that silently borrowed whichever session was lying around, which
# is what made an undersized pool a cross-user leak rather than a latency problem.
MCP_SESSION_POOL_MAX = int(os.environ.get("CARNET_MCP_SESSION_POOL_MAX") or 256)

# How often a long-running process sweeps for expired sessions.
#
# The pool also evicts opportunistically, on every get and put — which covers a busy
# server completely and an idle one not at all, and an idle server is the exact case
# the TTL exists for. A connector nobody has touched since Tuesday is only noticed by
# something that goes looking. The CLI does not need this; it exits.
MCP_SESSION_PRUNE_INTERVAL = 60

# --- Identity ----------------------------------------------------------------
# Read by access/ only.

# The email address that becomes this deployment's **first administrator**, granted at
# that person's next login into a tenant whose `platform_roles` table is empty.
#
# Step 12b made `admin` a row and left granting it on the CLI, which was the right call
# and left one hole it could not fill: **appointing the first administrator needs a
# shell**. In one working session the operator hit that twice — once asking where the CLI
# runs from, once asking how a customer configures a consent flow "if I keep doing it
# through you". The person the product is *for* could not do the thing without the person
# the product is *by*.
#
# **This is not the pending-grant landmine 12b refused**, and two things distinguish it.
# *Who sets it*: deployment configuration, held by exactly the person who could run
# `--grant-role`, present and inspectable at every boot rather than typed into a row weeks
# ago by an admin who has since left. *When it fires*: only into a tenant with no
# administrator at all. A mistyped address is armed only while that table is empty, on a
# deployment somebody is actively setting up, and it disarms the moment anyone is
# appointed by any means.
#
# It is **trust-equivalent to the shell**, which is the honest limit: a platform that
# shows environment variables to more people than it would give a terminal to has widened
# who can appoint the first admin. Not solvable below the deployment, and stated rather
# than left for somebody to discover.
#
# Captured at import like every other setting here, so changing it is a restart. That is
# the right cost for a value that answers *who is first*: a deployment that has to
# restart to change it is one where the change is a deploy somebody reviewed.
#
# The cost on the login path is a module attribute read and a string comparison for
# everybody who is not this address — see `users._bootstrap_admin`, which reaches storage
# only after both.
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("CARNET_BOOTSTRAP_ADMIN") or ""

# How long a provider's signing keys are held before refetching. Keys rotate on the
# order of months and the old set stays valid across a rotation, so this is about
# noticing a rotation eventually rather than about security. Long, because every
# authenticated request depends on having them and each fetch is somebody else's
# endpoint.
JWKS_CACHE_TTL = 3600

# Floor on how often an unknown `kid` may trigger a refetch. Rotation shows up as a
# key we have not seen, so refetching is right — but `kid` is attacker-controlled, and
# without a floor a stream of junk tokens becomes a stream of requests at a customer's
# identity provider, with our name on them.
JWKS_MIN_REFRESH_INTERVAL = 60

# Tolerance for clock difference when checking `exp` and `nbf`, in seconds.
#
# Not padding for the sake of it. A server a minute out of sync rejects every valid
# token with a message about expiry, which reads as the product being broken rather
# than as NTP being broken. Small enough that it does not meaningfully extend the life
# of a token somebody wanted revoked.
CLOCK_SKEW_LEEWAY = 60

# --- Observability (step 057) ------------------------------------------------
# Read by `api.configure_logging` and nowhere else; here because this module is where
# every setting lives. Both validated with `_retention_days()`'s treatment — a typo'd
# level that silently means `info` is the "does nothing, silently" shape `the_knobs`
# exists to kill.


def _log_level() -> str:
    raw = (os.environ.get("CARNET_LOG_LEVEL") or "info").strip().lower()
    if raw in ("debug", "info", "warning", "error"):
        return raw
    raise ValueError(
        f"CARNET_LOG_LEVEL must be one of debug, info, warning, error — not "
        f"'{raw}'. It sets the carnet logger's threshold; unset means info."
    )


def _log_format() -> str:
    raw = (os.environ.get("CARNET_LOG_FORMAT") or "text").strip().lower()
    if raw in ("text", "json"):
        return raw
    raise ValueError(
        f"CARNET_LOG_FORMAT must be 'text' or 'json', not '{raw}'. 'text' is the "
        "human-readable line a terminal wants; 'json' is one object per line for a "
        "log pipeline."
    )


def _audit_stdout() -> bool:
    """Step 096: one JSON line per brokered call and per refusal, on stdout.

    `on` in both artefacts — plan 094 decision 6 — because a team's log pipeline is the
    honest free half of *stored, queryable, tied to identities*, and on the fileborne
    door it is the only copy there is. `off` for a deployment whose pipeline reads the
    table. Validated on `_log_format`'s precedent: an operator who typed `off` and
    misspelt it must not silently get `on`.
    """
    raw = (os.environ.get("CARNET_AUDIT_STDOUT") or "on").strip().lower()
    if raw in ("on", "off"):
        return raw == "on"
    raise ValueError(
        f"CARNET_AUDIT_STDOUT must be 'on' or 'off', not '{raw}'. 'on' prints one JSON "
        "object per brokered call and per refusal on stdout, for a log pipeline; unset "
        "means on."
    )


def _open_admin() -> bool:
    """Step 097, plan 094 decision 5: every signed-in person administers this tenant.

    `on` makes `roles.is_admin` answer yes for every `user` principal — never a machine
    token — while it is set, and writes no row: unset it and the gate is back in front
    of whoever holds a real `platform_roles` row. Off by default in both artefacts. A
    typo refuses rather than silently meaning *closed*, because the person who typed it
    meant *open*.
    """
    raw = (os.environ.get("CARNET_OPEN_ADMIN") or "off").strip().lower()
    if raw in ("on", "off"):
        return raw == "on"
    raise ValueError(
        f"CARNET_OPEN_ADMIN must be 'on' or 'off', not '{raw}'. 'on' lets every "
        "signed-in member of the tenant administer it — allow hosts, register "
        "connectors, approve tools, configure consent flows, manage groups — with "
        "every act still recorded against them; unset means off."
    )


LOG_LEVEL = _log_level()
LOG_FORMAT = _log_format()
AUDIT_STDOUT = _audit_stdout()
OPEN_ADMIN = _open_admin()

# --- The MCP door's ceilings ---------------------------------------------------
# Here rather than beside the door because this module is where every setting lives,
# and a second settings file is how two of them start disagreeing.

# How many tool-mode calls one machine token may make through the MCP door in a UTC day.
# Step 033b, decision 4 of plan 033.
#
# The door is the one entry point to this system, and without this it would have no
# bound on volume at all.
#
# A thousand is invented, in the same tradition, and it is a thousand because that is
# roughly a day of one busy agent working continuously — high enough that no legitimate
# editor session reaches it and low enough that a loop is stopped inside an afternoon.
# Zero or less disables it entirely — the convention every dial here uses, and an
# operator's explicit decision to run unmetered.
#
# **Counted in Postgres rather than in the process, and that is the load-bearing half.**
# See migration 040: the door exists to sit in front of somebody's production agents, so
# the API has to be able to run replicated — and N replicas each holding an in-memory
# copy of this number would enforce N times it while still printing this one.
MCP_CALLS_PER_DAY = int(os.environ.get("CARNET_MCP_CALLS_PER_DAY") or 1000)

# What one **principal** may spend at a model through the MCP door in a UTC day.
# Step 045b.
#
# These two bound the product. `MCP_CALLS_PER_DAY`
# has bounded the door since 040 and counts *calls* — which was the right unit while
# every brokered call was a vetted tool whose token cost is a vendor's problem. 045c ends
# that: a brokered model call spends real money per call, under a key this platform
# holds, and a thousand-call allowance says nothing about whether that is ten dollars or
# ten thousand.
#
# **The subject is the calling principal, which at this door *is* the token** —
# `api/deps.py` resolves a machine credential to `Principal.machine(token_id, tenant_id)`
# and `door.require_machine` refuses every other kind, so `machine:<token id>` is the only
# thing that ever reaches the gate. So this keys on the same subject `MCP_CALLS_PER_DAY`
# does, without either dial having to know that: the ceiling is written against the
# principal, and the door supplies a principal that happens
# to be one-to-one with a credential.
#
# That is worth stating because it is the field somebody will want to change. A ceiling
# whose subject were the token's *owner* — one allowance across every credential a person
# holds — is a different product decision, and it would make the figure on
# `GET /me/tokens/{id}/budget` stop being the figure in that token's refusal.
#
# **A gate on the next call, not a reservation**, and migration 046's header already
# argued the shape: *"`mcp_budget` reserves before execution because a door call is one
# unit known in advance; a run's cost is unknown until it finishes."* A door call whose
# cost is tokens is in the run's position — the cost exists only after the call — so the
# call that crosses the line completes and the one after it is refused. Two replicas can
# each admit near the line; that is bounded by one call's cost per replica and stated in
# `door.TokenBudget.reserve` rather than discovered.
#
# Off by default, both, because deployments differ by
# orders of magnitude, and a ceiling invented before any data is a ceiling sized from
# nothing. Zero or less disables, the convention every sibling here uses. Read fresh per
# call by the door, never captured, so an operator can turn the knob mid-incident.
MCP_USD_PER_DAY = float(os.environ.get("CARNET_MCP_USD_PER_DAY") or 0)

# The net under the dollar ceiling at the door, in tokens.
#
# A dollar ceiling cannot see an unpriced model: `estimate_cost` returns None for a model
# with no rate, and that usage costs `$0.00` against the ceiling however much of it there
# is. **At the door that is the ordinary case** — a customer brokers whichever provider they
# run, and `core/usage.RATES` ships a snapshot of three Anthropic families. Until 045c
# makes the rate table extensible, a deployment brokering anything else is bounded by
# this number and by nothing else, which is why it should be set whenever the dollar
# ceiling is.
MCP_TOKENS_PER_DAY = int(os.environ.get("CARNET_MCP_TOKENS_PER_DAY") or 0)

# The most bytes one `tools/call` may carry as arguments through the MCP door.
#
# **Bounded because it lands in an append-only table.** Every brokered call writes its arguments to the
# audit log, and through the door those arguments are composed directly by somebody else's
# agent rather than by a model inside our own loop.
#
# Without a cap that is an unmetered write, and the ceiling above does not close it: a
# *denied* call spends no budget — deliberately, so an agent fixing its own scope mistakes
# cannot exhaust its day doing so — while still writing a row. So a token granted a single
# tool could put megabytes per request into the one table an operator reads during an
# incident, degrading the evidence as much as the disk.
#
# Refused before anything is recorded, so an oversized call costs a sentence rather than a
# row. 64 KiB is far past any real tool call and far short of a problem; the front door's
# 12 MiB backstop on `/api/*` is what stops the *body* before this ever sees it.
MCP_MAX_CALL_BYTES = int(os.environ.get("CARNET_MCP_MAX_CALL_BYTES") or 65536)

# The most bytes an acting-for identity may carry through the MCP door. Step 033c.
#
# The acting-for value rides in `_meta`, **beside** the arguments the cap above
# measures — so without its own bound it would be the third unmetered write this door
# has had to close, arriving in the same release that closed the second. Refused with a
# sentence before anything reads it, exactly as an oversized call is.
#
# A config value rather than a constant because the verified form is a real IdP token
# and those vary by customer: Entra access tokens carrying group claims run to several
# KB. 16 KiB clears every real token while refusing a payload; an asserted email is
# additionally bounded to an address's wire maximum in `access/acting.py`, and
# migration 041 bounds what any producer can put in the audit column behind both.
MCP_MAX_ACTING_FOR_BYTES = int(
    os.environ.get("CARNET_MCP_MAX_ACTING_FOR_BYTES") or 16384
)

# Environment variables that belong to the platform, never to a connector — step 050,
# blocker B1 of plan 049.
#
# A connector row names the variable its credential lives in (`credential_env`), and that
# value is presented to a vetted server in an `Authorization: Bearer` header. Naming the
# deployment's own secret — its master encryption key, its database DSN, a cloud
# credential — would exfiltrate it to whatever host the same admin approved. The rule that
# stops it lives here, in the one module both check sites may import downward: `core`
# imports `tools` (`core/broker.py`), so `tools/` may not import `core`, and `config` is
# the leaf beneath both. `tools.register_connector` asks at registration and
# `core.credentials._shared_credential` asks again at the credential read — the two-place
# check `mcp.egress` already makes for a host.
#
# A denylist by shape rather than an allowlist by prefix, because legitimate connector
# variables share no prefix (`GITHUB_PERSONAL_ACCESS_TOKEN`, `TRACKER_TOKEN`, a brokered
# `ANTHROPIC_BROKERED_KEY` are each a connector's own and stay legal). What is refused is
# the platform's surface: its whole `CARNET_` namespace — save `CARNET_CONNECTOR_`,
# reserved back for connectors — the model key it holds, cloud credentials, and any
# database URL. Compared upper-cased so a lower-case spelling that would not resolve on the
# host cannot smuggle the same secret past the check; refusing a borderline name is the
# safe direction.
_PLATFORM_ENV_EXACT = frozenset({"ANTHROPIC_API_KEY", "DATABASE_URL"})
_PLATFORM_ENV_PREFIXES = ("CARNET_", "AWS_")
_CONNECTOR_ENV_PREFIX = "CARNET_CONNECTOR_"
# Step 095. A `carnet.yaml` names the variable holding each token it declares, and the
# natural spelling — `${CARNET_TOKEN_ALICE}` — sat inside the platform prefix and was
# refused as one of ours. Reserved for the operator on `CARNET_CONNECTOR_`'s exact
# reasoning: a name in this family is theirs by construction and can never collide with
# a setting this module reads.
_TOKEN_ENV_PREFIX = "CARNET_TOKEN_"


# --- Egress: the operator's own networks (step 058) ---------------------------
#
# The tenant consents to HOSTS (the per-tenant allowlist `mcp.egress` checks); the
# operator consents to NETWORKS. A name listed here may resolve to loopback or private
# addresses and still be dialled — the operator's sidecar, their internal MCP and REST
# services, addresses that are actually theirs. It is deliberately not a tenant setting
# and not a row: a tenant cannot consent to an address on somebody else's network
# (`egress.forbidden_reason`'s standing argument), and the operator's `.env` is where
# the operator's own topology is already declared. Link-local — where cloud metadata
# lives — is refused for every name, listed or not.
#
# Empty by default, which is the fail-closed reading: with nothing listed, every name
# must resolve to public addresses only.
def _internal_hosts() -> frozenset:
    raw = os.environ.get("CARNET_EGRESS_INTERNAL_HOSTS") or ""
    return frozenset(
        host.strip().rstrip(".").lower() for host in raw.split(",") if host.strip()
    )


EGRESS_INTERNAL_HOSTS = _internal_hosts()


def is_platform_env(name: str) -> bool:
    """True if `name` is one of the platform's own environment variables, which a
    connector's `credential_env` may never name. See the block above for the rule."""
    upper = (name or "").strip().upper()
    if not upper:
        return False
    if upper.startswith((_CONNECTOR_ENV_PREFIX, _TOKEN_ENV_PREFIX)):
        return False
    if upper in _PLATFORM_ENV_EXACT or upper.endswith("_DATABASE_URL"):
        return True
    return any(upper.startswith(prefix) for prefix in _PLATFORM_ENV_PREFIXES)


# --- The customer's own vault (step 070) --------------------------------------
#
# A connector's shared credential may be held as an `op://vault/item/field` reference
# instead of an environment variable, resolved at call time through a 1Password Connect
# service account. See `core/vault.py` for the whole of it, including the asterisk: the
# token below can read every item behind every pointer, so the claim this buys is *the
# secret is not at rest in our database*, not *we cannot read it*.
#
# **Deployment configuration, not a row**, and the reason is that the alternative argues
# with itself: a `tenant_vaults` table would hold the credential that opens every other
# credential, sealed under the platform key this feature exists to stop mattering. BYOC
# is the settled shape (027), so the deployment is the customer's and `backend/.env` —
# beside CARNET_SECRET_KEY — is where a deployment's own secrets are already declared.
#
# The dial is under **operator** consent and against no tenant allowlist — the address
# is the operator's, written here, and a pointer contributes path segments only, so no
# row decides where it goes. `core/vault`'s module docstring has the argument, which
# reverses what plan 070 wrote. What that skips is `egress.check`, the one place the
# https rule lives, so the rule is applied here instead, at load: a plain-http vault
# URL would put CARNET_VAULT_TOKEN on the wire in clear on every door call, and a
# vault on the operator's own network is what `EGRESS_INTERNAL_HOSTS` — defined above,
# which is why this block sits below it — already exists to admit.
#
# Refused at load rather than at the first pointer, on `_retention_days`' precedent: every one
# of these is a setting somebody types once and finds out about three days later, during
# a tool call, as a credential error about a vault that was never going to answer.


def _vault() -> tuple:
    """`(url, token, timeout_seconds)`, coherent or refused. Both unset is the norm.

    Coherence is the part a bare `os.environ.get` cannot say: a URL without a token is a
    vault that will refuse every request with a 401 the refusal blames on the token, and
    a token without a URL is a secret in the environment that nothing reads. Either is
    a half-configured deployment, and `vault.configured()` — which the admin form and
    `--credential-ref` consult before accepting a pointer — would read both as *no vault*
    and refuse the pointer with a sentence about setting two variables one of which is
    set. Named here, once, where somebody can fix it.
    """
    from urllib.parse import urlsplit

    url = (os.environ.get("CARNET_VAULT_URL") or "").strip()
    token = (os.environ.get("CARNET_VAULT_TOKEN") or "").strip()

    if url and not token:
        raise ValueError(
            "CARNET_VAULT_URL is set but CARNET_VAULT_TOKEN is not. A vault needs "
            "both: the URL says where 1Password Connect is and the token is the "
            "service account that opens it. Put both in backend/.env, beside "
            "CARNET_SECRET_KEY, or unset the URL."
        )
    if token and not url:
        raise ValueError(
            "CARNET_VAULT_TOKEN is set but CARNET_VAULT_URL is not. A vault needs "
            "both: the token is the service account and the URL says where 1Password "
            "Connect is. Put both in backend/.env, beside CARNET_SECRET_KEY, or unset "
            "the token."
        )

    if url:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        if parts.scheme not in ("http", "https") or not host:
            raise ValueError(
                f"CARNET_VAULT_URL must be a URL with a scheme and a host, like "
                f"https://vault.example.internal — not '{url}'. It is the base address "
                "of this deployment's 1Password Connect server; the pointer supplies "
                "the rest of the path."
            )
        # Mirrors `egress.check`'s sentence, because it is the same rule made by the same
        # person: "TLS optional here" and "this is my own network" are one claim.
        if parts.scheme != "https" and host not in EGRESS_INTERNAL_HOSTS:
            raise ValueError(
                f"CARNET_VAULT_URL '{url}' is not https, which would put the 1Password "
                "Connect token in CARNET_VAULT_TOKEN on the wire in clear on every "
                "door call. Use https — or, if this host is on the deployment's own "
                "network, name it in CARNET_EGRESS_INTERNAL_HOSTS."
            )

    raw = (os.environ.get("CARNET_VAULT_TIMEOUT_SECONDS") or "").strip()
    if not raw:
        timeout = 3.0
    else:
        try:
            timeout = float(raw)
        except ValueError:
            timeout = float("nan")
        # `nan` fails both comparisons, so it lands here with the bad-number cases
        # rather than becoming a budget `_Deadline` can never spend.
        if not (timeout > 0) or timeout == float("inf"):
            raise ValueError(
                f"CARNET_VAULT_TIMEOUT_SECONDS must be a positive number of seconds, "
                f"not '{raw}'. It is the whole budget for resolving one credential "
                "reference across every request it takes; unset means 3."
            )
    return url, token, timeout


# A budget for resolving ONE pointer, across every hop it takes — not a per-request
# timeout. A name-addressed reference costs three round trips, and three requests at
# three seconds each is a nine-second door call; somebody who sets this means *this must
# not hang*, and honouring it per hop would make the setting mean a third of what it
# says. The door's own overhead is ~430ms, so this is the number that decides whether a
# vault-backed connector is usable.
#
# **Exact for a vault that is down, that stalls, or that never stops answering; within
# one byte's read of exact for one that is merely slow.** No synchronous read can bound
# wall time exactly — the read timeout fires only on *no* data — so `core/vault
# ._read_bounded` reads the body a byte at a time and consults the clock between bytes,
# and says why that granularity is the bound. Before it existed, a 0.4s setting here
# produced a measured 5.92s hold.
VAULT_URL, VAULT_TOKEN, VAULT_TIMEOUT_SECONDS = _vault()


def _retention_days() -> int | None:
    """How long the three append-only log tables keep a record, in days.

    **Unset or empty means keep everything, forever** — which is what every deployment
    does today, so upgrading to 018 changes nothing until somebody decides it should.
    A retention policy that arrived switched on would silently destroy the history of
    every existing customer at the first sweep, and the whole subject here is
    that erasing records must be deliberate.

    **Zero and negative are refused rather than accepted as "off"**, and that is the
    one input worth being strict about: `RETENTION_DAYS=0` reads to a person as
    "disabled" and means "everything older than right now", which is every record in
    the table. Two plausible readings of one value, one of them catastrophic and
    irreversible — so it is neither, and the operator is told to unset it instead.

    Read at import like everything else here, so changing it is a restart.
    """
    raw = (os.environ.get("CARNET_RETENTION_DAYS") or "").strip()
    if not raw:
        return None

    try:
        days = int(raw)
    except ValueError:
        raise ValueError(
            f"CARNET_RETENTION_DAYS must be a whole number of days, not '{raw}'. "
            "Unset it to keep records forever."
        ) from None

    if days <= 0:
        raise ValueError(
            f"CARNET_RETENTION_DAYS must be at least 1, not {days}. "
            "Unset it to keep records forever — 0 would mean 'delete everything', "
            "which is not what a disabled policy should look like."
        )
    return days


RETENTION_DAYS = _retention_days()

# How often the maintenance sweep checks whether anything has aged out, in seconds.
#
# An hour, and it is an invented number that says so. Retention is measured in days, so
# the only thing this interval decides is how far past its window a record may briefly
# live — an hour of slack on a thirty-day promise is nothing, and sweeping more often
# would spend a transaction per process per interval to delete nothing at all.
#
# Tracked in-process rather than as a row, which is what makes two processes running this
# harmless: the delete is idempotent by `ts`, so a second sweep finds what the first
# already removed to be gone.
RETENTION_SWEEP_INTERVAL = int(os.environ.get("CARNET_RETENTION_SWEEP") or 3600)

# `RETENTION_BATCH` lived here and is gone with migration 030. It bounded how many rows
# one retention transaction deleted before committing, because "one statement deleting
# ten million rows" was a transaction holding locks on an append-only table for minutes,
# on the path every tool call writes to. A prune is now a partition drop: it writes no
# per-row WAL and takes no per-row lock, so there is nothing left for a batch size to
# bound. What replaced it is a `lock_timeout` on the drop itself, in `prune_log_records`,
# which bounds the one wait that is still real.

# `AGENT_RUNTIME_INSECURE_DEV_AUTH` and the `X-Dev-Principal` header it enabled are
# **gone**, not disabled. They were the whole authentication story for exactly one
# step, and the API now validates real tokens against each customer's identity
# provider — see `access/`.
#
# Deleted rather than left behind a flag, deliberately. A bypass that survives the
# thing it stood in for is the one somebody leaves switched on, and a setting that
# still exists is a setting that can still be set.
#
# **Spelled with the retired prefix on purpose, and it is the one place in this file
# that is.** This is a grave marker: its whole function is to record the exact string
# so nobody reintroduces it, and the variable was deleted long before the rename, so
# `CARNET_INSECURE_DEV_AUTH` would name something that has never existed anywhere.
# `_refuse_retired_prefix` now seals it twice over — this spelling is refused at
# import by the prefix rule, whatever anybody sets it to.

# Ceiling on a single tool response, measured as the serialized bytes that would
# enter model context. Enforced in the broker so it covers every tool, including
# MCP-backed ones we don't own. A Tool may raise or lower it for itself.
#
# This is a security control, not a performance one: unbounded tool output is how
# injected instructions reach the model from content an agent reads.
MAX_RESPONSE_BYTES = 65_536  # 64 KiB

# --- Per-run budgets, and where they went ------------------------------------
# Four dials lived here — total calls, calls per tool, writes, and cumulative response
# bytes under one run — as the defaults an agent's `limits` block overrode. **Step 084
# deleted all four**, because the only thing that read them was `core.limits.Budget`, and
# the only thing that built a `Budget` was `RunContext.start`, which nothing in this tree
# has called since 078 took the runtime out. A default for a dial nobody turns is a number
# an operator can find, read, and believe.
#
# What is *not* gone: the four **key names** an agent config may set. They are
# `agents.KNOWN_LIMITS` now, and `agents.validate` still refuses anything else, because a
# stored `limits` block is read back by a person and by a tree that does have a runtime.
# See that constant for the whole argument.
#
# The live ceilings on this deployment are per token per day and are set below and by the
# operator: `MCP_CALLS_PER_DAY`, `MCP_USD_PER_DAY`, `MCP_TOKENS_PER_DAY`, enforced by
# `door.TokenBudget` — not per agent, and not from a config.
#
# `MAX_RESPONSE_BYTES` above is a different dial and it is live: it bounds one response,
# in the broker, on every call the door admits.


# --- Model rates -------------------------------------------------------------
# What a token costs, for the one report that turns counts into an estimate. Step 013.
#
# **A path, not a table**, and the indirection is the decision. Plan 013 refused to put a
# cost anywhere on the grounds that *"turning tokens into money needs a price list per
# model that changes without warning, and a wrong number on a screen labelled cost is
# worse than no screen"* — and then said where the arithmetic does belong: *"where prices
# are maintained"*. This is that sentence with a filename on it. Unset, `--usage` prices
# against the dated snapshot in `core/usage.py` and says which one it used; set, it prices
# against the operator's own contract and says that instead.
#
# Nothing on the run path reads this and nothing persists what it produces. A rate list is
# a thing that changes, so a figure computed from one is only ever correct as of the
# moment it was printed — which is exactly why it is printed rather than stored.
MODEL_RATES_PATH = os.environ.get("CARNET_MODEL_RATES") or ""


def model_rates() -> dict | None:
    """The rate table `--usage` prices against, or None for the built-in snapshot.

    Read at call time rather than at import, for the reason `credentials.py` reads its
    key at call time: a long-lived API process should pick up a corrected price list on
    the next report rather than at the next restart, and a report is not a hot path.

    **A malformed or missing file raises**, and that is deliberate against the tempting
    alternative of falling back to the snapshot with a warning. Somebody who set this
    variable did so precisely because the built-in numbers are wrong for them; quietly
    using those numbers anyway produces a plausible figure computed from the table they
    explicitly rejected, which is the failure mode this whole feature is arranged to
    avoid. The shape is `{"opus": {"input": .., "output": .., "cache_read": ..,
    "cache_write": ..}, ...}`, in USD per million tokens.

    ## Every check below is a `ValueError` naming the file, and step 045c is why

    Until 045c the keys of this table were decorative: `core/usage.model_family` matched
    three built-in literals, so this file could correct a *number* and could not add a
    *model*. It is now the vocabulary — the only way a customer brokering any provider
    but Anthropic reaches a price at all — which means the population editing it goes
    from "operators with a bespoke contract" to "everyone who registers a model
    connector", and the failure they meet has to be a sentence rather than a traceback.

    Five malformed shapes used to escape as a bare `AttributeError` from `.items()` or
    `.get()` — a top-level list, a top-level string, and a rate entry that is a list, a
    string or null. Each one reached a report as an unhandled exception naming a Python
    method, about a file the reader could have fixed in ten seconds.

    Two more were **accepted**, which is worse than either:

      - `"input": true` — `isinstance(True, int)` is true in Python, so a JSON `true`
        priced a million tokens at one dollar. This codebase refuses a bool where a
        number goes in three other places for exactly this reason (`VetRequest.
        max_response_bytes` says so at length, `agents.validate`'s limits, and
        `storage.check_limit`); this is the file's rule, not a new one.
      - a **negative** rate, which is the quiet one. Spend then *falls* as tokens are
        used, so `MCP_USD_PER_DAY` can never be reached and a deployment that believes
        it has a dollar ceiling has none. An unpriced model at least gets named in
        `unpriced_models`; a negative rate is invisible everywhere.

    An empty key is refused too: `""` is a substring of every model id including the
    `''` a usage report with no model produces, so it would price everything at one
    rate. `model_family` skips it defensively; this refuses it where somebody can fix it.

    **A third shape was accepted until step 086's edge pass, and it is the worst of the
    three**: a rate that is not a *finite* number. `json.load` reads bare `NaN` and
    `Infinity`, and neither the missing-counter test (`isinstance(nan, float)` is true)
    nor the sign test (`nan < 0` is false) sees them. An infinite rate refuses every call
    forever; a NaN is silent, because `nan > ceiling` is `False` — so a dollar ceiling
    over NaN spend never fires — and the figure serializes as `{"usd": NaN}`, which no
    parser outside Python reads.

    **Every rule above now lives in `storage.base.check_rate_table`**, because a rate
    table gained a second home on `vetted_tools.binding` and a checker above the storage
    boundary is one a wholesale write does not run. See `check_rate_table` below.
    """
    if not MODEL_RATES_PATH:
        return None

    import json

    with open(MODEL_RATES_PATH, encoding="utf-8") as handle:
        table = json.load(handle)

    check_rate_table(table, MODEL_RATES_PATH)
    return table


def check_rate_table(table, where: str) -> None:
    """Refuse a malformed rate table. Raises `ValueError` naming `where`.

    **The implementation is `storage.base.check_rate_table` and this is the name the rest
    of the tree calls it by.** It lives down there rather than here because step 086's
    edge pass found it had to: a rate table has a second home on `vetted_tools.binding`,
    every write into that column funnels through the storage boundary, and a checker
    above the boundary is one a wholesale write does not run. It was not run — a seeded
    manifest carrying `{"gpt-5": {}}` stored fine and made **every** metered door call in
    that tenant raise `KeyError: 'input'` out of `estimate_cost`.

    Imported inside the function, like `model_rates_label`'s `RATES_CHECKED`, so this
    module keeps its import surface.
    """
    from .storage.base import check_rate_table as check

    check(table, where)


def model_rates_label() -> str:
    """Which price list a report was computed against, for the report to say out loud.

    A number whose provenance is not on the page is a number somebody will quote in a
    meeting. This is the sentence that stops that.
    """
    if MODEL_RATES_PATH:
        return MODEL_RATES_PATH
    from .core.usage import RATES_CHECKED

    return f"built-in list prices, last checked {RATES_CHECKED}"


def ensure_var_dir() -> Path:
    """Create the var directory on demand. Safe to call repeatedly."""
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    return VAR_DIR
