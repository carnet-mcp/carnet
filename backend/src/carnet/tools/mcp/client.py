"""A deliberately small MCP client: handshake, list tools, call a tool.

Hand-written rather than taken from the `mcp` SDK, for reasons worth stating because
they may stop being true:

  - The SDK is async-first and this runtime is synchronous end to end. Every brokered
    call would become an `asyncio.run` or a loop thread living beside the broker.
  - It brings pydantic, httpx, anyio and starlette for a three-method subset.
  - It offers no transport seam of the kind transport.py exists to provide.

What we implement: `initialize`, `notifications/initialized`, `tools/list` (paginated),
`tools/call`. What we do not: resources, prompts, sampling, roots, completions,
server-initiated requests, cancellation. If we start needing those, take the SDK and
put an adapter behind the same Session interface rather than growing this file.

Note the division of labour with the rest of the platform. This module knows how to
*talk* to a server. It has no idea which tools are allowed, what they touch, or whose
credential it is using — all of that is binding.py and the broker.
"""

import hashlib
import json
import logging
import threading
import time

from ...config import MCP_SESSION_IDLE_TTL, MCP_SESSION_POOL_MAX
from ..base import MAY_HAVE_COMPLETED, REPORTED_USAGE
from .transport import SessionExpired, TransportError

log = logging.getLogger(__name__)

# The version we implement. A server may negotiate down; we accept whatever it
# answers with rather than insisting, since our subset is stable across these.
PROTOCOL_VERSION = "2025-06-18"

CLIENT_INFO = {"name": "carnet", "version": "0.3.0"}

# A server with an enormous tool list is either misconfigured or hostile; either way
# we should stop rather than page forever.
MAX_LIST_PAGES = 20


class McpError(RuntimeError):
    """The server answered, and the answer was an error."""


class Session:
    """One live conversation with one MCP server.

    **Serialized by a lock, and that lock is load-bearing.** A session is one pipe or
    one endpoint with one id counter, and it is shared: the pool hands the same object
    to every run using the same (tenant, connector, credential). Behind a CLI only one
    thread ever held it. Behind a server, two threads sharing it unlocked is not a
    performance problem, it is a correctness one — and it corrupts the audit trail
    rather than failing:

        thread A  send(id=7) ─┐
        thread B  send(id=8) ─┼─►  one pipe, one inbox queue
                              │
                  A reads the reply to 8, discards it (not the id it wants), waits on
                  B waits for a reply that has already been thrown away → times out
                  B raises TransportError(delivered=True) → outcome="unknown"

    B did nothing wrong and is recorded as a write that *may have taken effect and
    needs a person* — the one lie the delivered/ambiguous mapping exists to prevent.
    `_next_id` is an unguarded increment on top of that, so the two can collide outright.

    Reentrant, because `initialize()` holds it across a handshake that is itself two
    requests and a notification, and `_request` re-enters on an expired session.

    The cost: two runs sharing a connector *and* a credential take turns at their tool
    calls. Acceptable because a call is short and a run is long — and it stops being
    a shared key at all once credentials are delegated. When waiting on this lock
    becomes a material fraction of run duration (measurable: `duration_ms` is already
    in the audit log), the answer is several sessions per key, not a finer lock.
    """

    def __init__(self, transport):
        self._transport = transport
        self._next_id = 0
        self._lock = threading.RLock()
        self.server_info: dict = {}

    # --- plumbing ---------------------------------------------------------------

    def _request(self, method: str, params: dict | None = None, _retrying: bool = False) -> dict:
        with self._lock:
            return self._request_locked(method, params, _retrying)

    def _request_locked(self, method: str, params: dict | None, _retrying: bool) -> dict:
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params

        try:
            reply = self._transport.send(message)
        except SessionExpired:
            # The server has forgotten our session and the spec says to start a new
            # one rather than treat this as a failure.
            #
            # **This retries a write, and that is safe.** It looks alarming, so: the
            # server told us it does not recognise the session, which means it cannot
            # have executed anything under it. Nothing ran, so nothing can run twice.
            # Contrast a dropped response stream, which is the opposite case and is
            # never retried — see HttpTransport._read_sse.
            #
            # Once only. A server that expires every session immediately is broken,
            # and looping on it would turn one bad server into an infinite one.
            if _retrying:
                raise
            self.initialize()
            return self._request(method, params, _retrying=True)

        if reply is None:
            raise McpError(f"no reply to {method}")

        if "error" in reply:
            error = reply["error"] or {}
            raise McpError(f"{method} failed: {error.get('message', error)}")

        return reply.get("result") or {}

    def _notify(self, method: str, params: dict | None = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        with self._lock:
            self._transport.send(message)

    # --- the subset -------------------------------------------------------------

    def initialize(self) -> dict:
        """Handshake. Must complete before anything else is legal.

        Called again when a session expires, so it must be safe to repeat: it resets
        the negotiated version and re-announces, and holds no state that accumulates.

        Held across the whole handshake, not per message. The spec forbids requests
        before `notifications/initialized`, so another thread slipping a `tools/call`
        into the gap between the initialize response and that notification is a protocol
        violation the server is entitled to refuse.
        """
        with self._lock:
            return self._initialize_locked()

    def _initialize_locked(self) -> dict:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
            # An expired session cannot be recovered by re-initializing *during* an
            # initialize; that would be a loop.
            _retrying=True,
        )
        self.server_info = result.get("serverInfo") or {}

        # Later requests carry the version the server actually agreed to, which is
        # only knowable now. A no-op on stdio, which negotiates in-band.
        self._transport.set_protocol_version(
            result.get("protocolVersion") or PROTOCOL_VERSION
        )

        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        """Everything the server advertises, following `nextCursor` to the end.

        Returned raw. Deciding which of these we are willing to expose is vetting,
        and vetting is not this module's job — see binding.py.
        """
        tools: list[dict] = []
        cursor = None

        for _page in range(MAX_LIST_PAGES):
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params)
            tools.extend(result.get("tools") or [])

            cursor = result.get("nextCursor")
            if not cursor:
                return tools

        raise McpError(
            f"server advertised more than {MAX_LIST_PAGES} pages of tools; refusing to page further"
        )

    def call_tool(self, name: str, arguments: dict) -> dict:
        """Run one tool and return something the broker can size-cap and audit."""
        try:
            result = self._request("tools/call", {"name": name, "arguments": arguments})
        except TransportError as exc:
            # The broker turns a dict with "error" into outcome="error" and hands it
            # to the model. Raising instead would work — the broker catches — but the
            # message would arrive wrapped in a class name nobody needs to see.
            if exc.delivered:
                return {
                    "error": f"{exc} The request reached the server, so it MAY have "
                    "taken effect. Do not repeat it; report what happened instead.",
                    MAY_HAVE_COMPLETED: True,
                }
            return {"error": f"{exc} The request never reached the server, so nothing happened."}
        except McpError as exc:
            # The server answered and the answer was a refusal — it decided, so this
            # is unambiguous however it failed.
            return {"error": str(exc)}

        return normalize(result)

    def close(self) -> None:
        """Deliberately **not** under the lock.

        Closing is how a broken or evicted session is torn down, and a session is most
        worth tearing down exactly when a thread is stuck inside a `send` that will not
        return. Taking the lock here would make the pool's idle eviction wait out a
        60-second read timeout on an unrelated connector before it could reclaim
        anything — a teardown path that blocks on the thing it is tearing down.
        """
        self._transport.close()


def normalize(result: dict) -> dict:
    """Turn an MCP tool result into a plain dict.

    MCP returns a list of content blocks; the Messages API wants one JSON value, and
    the broker measures whatever we return against the size cap. Order of preference:

      structuredContent   the server already did this properly
      text that is JSON   the common case — a JSON document sent as a text block
      text                fall back to handing the model the prose

    Non-text blocks are counted, not inlined. An embedded image is base64 that would
    consume the whole size budget to say nothing the model asked for.

    **Token usage rides out on `REPORTED_USAGE`, lifted from `_meta`.** Step 045b, and
    `_meta` is the right carrier for the reason 033c already used it inbound: it is the
    protocol's own extension point, so a server that wants to say what a call cost has
    somewhere sanctioned to say it, and a server that does not is unaffected. The broker
    pops the key before the result reaches anyone; `core.usage.parse_report` decides
    whether to believe it.
    """
    if result.get("isError"):
        # An errored call may still have spent money — a model proxy that charged and
        # then failed is the case 045b's edge table calls "money spent is money
        # recorded" — so the report is lifted here too rather than only on the happy
        # path.
        return _with_usage(
            {"error": _text_of(result) or "the tool reported an error"}, result
        )

    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return _with_usage(structured, result)

    blocks = result.get("content") or []
    other = sum(1 for block in blocks if block.get("type") != "text")
    text = _text_of(result)

    payload = _as_json(text)
    if other:
        payload = {**payload, "non_text_blocks": other}
    return _with_usage(payload, result)


# Where a server puts what a call spent, inside `CallToolResult._meta`. Step 045b.
#
# Namespaced with a reverse-DNS-ish prefix because `_meta` is a shared bag every
# extension writes into, and MCP's own spec reserves bare and `modelcontextprotocol`-
# prefixed keys for the protocol. A server that speaks to two brokers must be able to
# answer both without either reading the other's number.
USAGE_META_KEY = "io.carnet/usage"


def _with_usage(payload: dict, result: dict) -> dict:
    """`payload` plus this call's usage report, when the server sent one.

    **The key is cleared unconditionally first**, and that is the load-bearing line
    rather than a tidy one. `payload` can be `structuredContent` — a mapping the *server*
    composed — so without this a server could report its own spend by putting our
    reserved key in its result body and skipping `_meta` entirely, and the broker would
    believe it. Clearing first means the only route to the meter is `_meta`, which is the
    one place this function reads.

    A missing or non-mapping `_meta` leaves the payload with no key at all, so the broker
    records NULL usage — *not applicable*, which is the truth about every MCP tool built
    before this existed and most of them after.
    """
    payload.pop(REPORTED_USAGE, None)

    meta = result.get("_meta")
    if not isinstance(meta, dict):
        return payload

    report = meta.get(USAGE_META_KEY)
    if report is None:
        return payload

    # Passed through unexamined: `parse_report` in the broker is the one validator, and
    # a second opinion here would be a second place for the rules to drift.
    return {**payload, REPORTED_USAGE: report}


def _text_of(result: dict) -> str:
    return "\n".join(
        block.get("text", "")
        for block in (result.get("content") or [])
        if block.get("type") == "text"
    ).strip()


def _as_json(text: str) -> dict:
    if not text:
        return {"result": None}
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {"text": text}

    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"items": parsed}
    return {"result": parsed}


def _close_quietly(session) -> None:
    try:
        session.close()
    except Exception:  # noqa: BLE001 - it is already going away; that is the point
        pass


class _Entry:
    """A pooled session, when it was last used, and in what order.

    Two clocks, deliberately. `last_used` answers "has this been idle too long?" and
    has to be a real duration. `seq` answers "which of these was used least recently?"
    and must not depend on clock resolution — `time.monotonic()` is coarse enough on
    Windows that two touches microseconds apart read as identical, which silently turns
    least-recently-used eviction into insertion-order eviction.
    """

    __slots__ = ("session", "last_used", "seq")

    def __init__(self, session, last_used: float, seq: int):
        self.session = session
        self.last_used = last_used
        self.seq = seq


class SessionPool:
    """Live sessions, keyed by (tenant, connector, credential).

    Keyed by the **credential**, not the principal, because the credential is what
    the vendor sees. Two users sharing a service account should share one session;
    two users with their own tokens must not, or the second would silently act with
    the first one's authority — the exact failure the principal exists to prevent.

    Keyed by **tenant** as well, and that is not redundant with the credential. A live
    session is bound to the manifest it was bound against: the same server, vetted
    differently by two customers, is two different allowlists. Sharing one session
    between them because they happened to configure the same token would serve one
    customer an allowlist they never approved.

    Process-global, unlike Budget: a subprocess outlives a run and re-spawning a
    container per run would be absurd. `reset()` exists for tests, which must not
    inherit each other's sessions.

    ## What a server changed

    Three things, all of which were fine while one thread owned this dict:

    **Creation must happen once.** Two threads missing the cache for the same key both
    build a session; one wins the dict and the other is orphaned — still holding a live
    subprocess that nothing will ever close. So creation goes through `get_or_create`,
    which double-checks under a per-key lock. Per-key rather than global: building a
    session spawns a container and does a handshake, and holding one lock across that
    would serialize startup for every tenant behind whichever connector was slowest.

    **Idle sessions must expire.** A CLI process exited and took its sessions with it.
    A server does not, and a connector nobody has used since Tuesday is a container
    still running.

    **The pool must be bounded.** With delegated credentials the key space is per user,
    so an unbounded pool is one subprocess per user who ever ran anything.

    Both numbers come from `config.py` and are invented; see the note there.

    Sessions are closed **outside** the lock. `close()` on a stdio transport terminates
    a subprocess and waits for it, and doing that while holding the pool lock would
    block every other tenant's lookup behind an unrelated teardown.
    """

    def __init__(
        self,
        idle_ttl: float = MCP_SESSION_IDLE_TTL,
        max_size: int = MCP_SESSION_POOL_MAX,
    ):
        self._lock = threading.RLock()
        self._sessions: dict = {}
        # One creation lock per key. Bounded by the same key space as the sessions
        # themselves and holding nothing but a Lock, so these are not pruned — the
        # expensive thing a key owns is the session, and that is what expires.
        self._building: dict = {}
        self._idle_ttl = idle_ttl
        self._max_size = max_size
        self._tick = 0
        # How many sessions have been dropped for being over the cap. Read by whoever
        # is deciding what the cap should actually be; see `_take_overflow_locked`.
        self.overflow_evictions = 0

    def _next_seq(self) -> int:
        """Use order, independent of the clock. Caller holds the lock."""
        self._tick += 1
        return self._tick

    def stats(self) -> dict:
        """Size, cap and evictions, for `/metrics` (step 057).

        These are the numbers `MCP_SESSION_POOL_MAX`'s comment says to size the cap
        from, exposed at last. The lock is held for three reads and nothing else.
        """
        with self._lock:
            return {
                "size": len(self._sessions),
                "max": self._max_size,
                "overflow_evictions": self.overflow_evictions,
            }

    @staticmethod
    def fingerprint(credential: str | None) -> str:
        """Identify a credential without holding it as a dict key or logging it."""
        if not credential:
            return "anonymous"
        return hashlib.sha256(credential.encode("utf-8")).hexdigest()[:12]

    def _key(self, tenant_id: str, connector_id: str, credential: str | None) -> tuple:
        return (tenant_id, connector_id, self.fingerprint(credential))

    # --- lookup -----------------------------------------------------------------

    def get(self, tenant_id: str, connector_id: str, credential: str | None):
        """A live session for this key, or None. Touches it, so use keeps it alive."""
        key = self._key(tenant_id, connector_id, credential)

        with self._lock:
            stale = self._take_expired_locked()
            entry = self._sessions.get(key)
            if entry is not None:
                entry.last_used = time.monotonic()
                entry.seq = self._next_seq()
            session = entry.session if entry is not None else None

        for victim in stale:
            _close_quietly(victim)
        return session

    def get_or_create(
        self, tenant_id: str, connector_id: str, credential: str | None, factory
    ) -> tuple:
        """`(session, created)` — building at most one session per key, ever.

        `factory` runs outside the pool lock and under a per-key lock, because it
        spawns a process and performs a handshake. The second thread through waits for
        the first rather than building a duplicate it would then leak.
        """
        existing = self.get(tenant_id, connector_id, credential)
        if existing is not None:
            return existing, False

        key = self._key(tenant_id, connector_id, credential)
        with self._lock:
            building = self._building.get(key)
            if building is None:
                building = self._building[key] = threading.Lock()

        with building:
            # Re-checked: another thread may have finished building while we queued.
            existing = self.get(tenant_id, connector_id, credential)
            if existing is not None:
                return existing, False

            session = factory()
            self.put(tenant_id, connector_id, credential, session)
            return session, True

    def put(
        self, tenant_id: str, connector_id: str, credential: str | None, session: Session
    ) -> None:
        key = self._key(tenant_id, connector_id, credential)

        with self._lock:
            self._sessions[key] = _Entry(session, time.monotonic(), self._next_seq())
            stale = self._take_expired_locked()
            stale += self._take_overflow_locked()

        for victim in stale:
            _close_quietly(victim)

    # --- retirement -------------------------------------------------------------

    def evict(self, tenant_id: str, connector_id: str, credential: str | None) -> None:
        """Drop a session that has stopped working, closing it if we can.

        Pooled sessions outlive runs, so a subprocess that died or an endpoint that
        recycled its session leaves a handle behind that looks live and is not. This
        is how it gets retired — see `connect`, where the failure surfaces.
        """
        key = self._key(tenant_id, connector_id, credential)
        with self._lock:
            entry = self._sessions.pop(key, None)
        if entry is not None:
            _close_quietly(entry.session)

    def prune(self) -> int:
        """Close sessions idle past the TTL. Returns how many. Safe to call anytime."""
        with self._lock:
            stale = self._take_expired_locked()
        for victim in stale:
            _close_quietly(victim)
        return len(stale)

    def _take_expired_locked(self) -> list:
        """Remove and return sessions idle past the TTL. Caller holds the lock."""
        if not self._idle_ttl:
            return []
        cutoff = time.monotonic() - self._idle_ttl
        expired = [k for k, entry in self._sessions.items() if entry.last_used < cutoff]
        return [self._sessions.pop(k).session for k in expired]

    def _take_overflow_locked(self) -> list:
        """Remove and return the least recently used sessions above the cap.

        Least-recently-used rather than oldest: a connector in constant use should not
        be retired because it was the first one started.

        **Counted, because the cap is an invented number and this is the evidence that
        would size it.** An eviction here is not an error — the caller rebuilds under
        its own credential — so nothing else would ever record that it happened, and a
        pool one tenth the size it should be looks exactly like a slow MCP server. A
        counter is what turns "the number is invented" into "the number is invented and
        here is what it would take to stop inventing it".
        """
        if not self._max_size or len(self._sessions) <= self._max_size:
            return []

        ordered = sorted(self._sessions.items(), key=lambda kv: kv[1].seq)
        overflow = len(self._sessions) - self._max_size
        self.overflow_evictions += overflow
        if self.overflow_evictions in (1, 10, 100) or self.overflow_evictions % 1000 == 0:
            # Logged on a curve rather than every time: a pool at capacity evicts
            # constantly, and a line per eviction would bury the first one — which is
            # the only one anybody needs to see to know the cap wants raising.
            log.info(
                "mcp session pool at capacity (%d): %d evictions so far. Raise "
                "CARNET_MCP_SESSION_POOL_MAX if this keeps climbing — each "
                "eviction costs the next caller a handshake.",
                self._max_size,
                self.overflow_evictions,
            )
        return [self._sessions.pop(k).session for k, _ in ordered[:overflow]]

    def reset(self) -> None:
        with self._lock:
            entries = list(self._sessions.values())
            self._sessions.clear()
            self._building.clear()
        for entry in entries:
            _close_quietly(entry.session)
