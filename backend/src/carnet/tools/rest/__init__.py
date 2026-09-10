"""The REST connector: a connector that is not an MCP server. Step 045a.

A registered base URL plus per-tool request bindings, producing the same `Tool`
objects MCP vetting produces — brokered, scoped, credentialed and audited
identically. Deliberately small, and the smallness is the design: no session, no
pool, no handshake, no transport seam. A REST call is one bounded `requests` round
trip, so the whole module is a pure `bind()` and the closure it generates.

Two things this module does NOT get that `tools/mcp` does, both stated in the plan
rather than glossed:

  **No discovery.** A REST API self-describes nothing, so the input schema, the
  description and the request mapping are authored by the vetter. The
  argument-existence rule survives, but it degrades from a drift detector into a
  self-consistency check — the schema and the mapping come from the same person.

  **No drift probe.** A changed vendor API fails at call time, not at review. The
  first symptom of vendor drift is a tool error in some agent's transcript.

What it keeps, without exception: the egress allowlist is enforced **at dial time**,
per request (`egress.check` is the first thing the impl does), and the credential
arrives from the broker as the keyword-only `token` the schema never contains —
exactly the way MCP's proxy receives it.
"""

import json
import logging
import time
from dataclasses import replace
from string import Formatter
from urllib.parse import quote

from ... import config
from ..base import MAY_HAVE_COMPLETED, REPORTED_USAGE
from ..mcp import egress
from ..mcp.binding import described
from ..validation import validate

# The methods a binding may name. Bounded on purpose: HEAD and OPTIONS observe
# transport facts rather than resources, and anything more exotic has no customer.
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# Every key a binding may carry. `usage_map` is stored and validated here and
# consumed by 045c; `pricing` is step 086's, beside it because it is the same kind of
# fact about the same vendor written by the same person — one says where the counters
# are, the other says what they cost; the rest are what discovery would have supplied.
BINDING_KEYS = frozenset(
    {"method", "path", "query", "body", "input_schema", "usage_map", "pricing"}
)

# The counters a `usage_map` may name, and `model` beside them. Step 045b.
#
# `core/usage.TokenUsage`'s four fields plus the model that produced them — the same
# vocabulary the audit columns, `spend_since` and `price_buckets` use, so a REST binding
# describes its vendor's response in the words the rest of the system already speaks and
# nothing translates between two spellings of *input tokens*.
#
# `model` is here rather than a separate binding key because it comes from the same place
# by the same mechanism: a dotted path into the response body. A model connector's reply
# names the model that served it, which is not always the one the caller asked for, and
# 045's Amendment 3 already settled that the served id is the one worth recording.
USAGE_COUNTER_NAMES = (
    "model",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
)

# How much of a vendor's answer a tool error may quote. A bound fragment, because an
# error body can be as attacker-sized as a success body and the broker's response cap
# only measures what we return — this keeps the quote small before that.
ERROR_FRAGMENT_BYTES = 500

# The two response headers a streamed answer carries back to the caller verbatim. The
# content type because the caller's SDK branches on it (SSE or JSON); `Retry-After`
# because a vendor's 429 is only actionable with it. Nothing else — a vendor's request
# ids, rate-limit accounting and server banner are facts about *our* call to the
# vendor, and the caller's relationship is with this door.
RELAYED_HEADERS = ("Content-Type", "Retry-After")

log = logging.getLogger("carnet.tools.rest")


def path_arguments(path: str) -> tuple:
    """The argument names a path template consumes, in order of appearance."""
    return tuple(
        field_name
        for _, field_name, _, _ in Formatter().parse(path)
        if field_name is not None
    )


def check_binding(name: str, binding) -> None:
    """Refuse a malformed or self-inconsistent binding. Raises RuntimeError.

    Run at vet time — where the person deciding is still at the form — and again by
    `bind()`, so a stored row that somehow went bad fails at bind rather than at the
    first call. Every rule here catches a binding that would read as complete in
    review and not be:

      - a path placeholder naming an argument absent from the schema is a call that
        can never be built
      - a schema property mapped nowhere is an argument the model can set that goes
        nowhere — a lie in the schema
      - a property mapped twice is a request whose shape depends on which mapping wins

    The storage boundary (`storage.check_vetted_tool`) refuses the *shape* — wrong
    types, an unknown method, an unknown key — so a row written around this function
    still cannot be stored malformed. The cross-checks live here, one layer up, on
    `tools/validation.py`'s precedent: they compare the mapping against the schema.
    """
    if not isinstance(binding, dict):
        raise RuntimeError(
            f"tool '{name}': a REST binding must be a mapping, not "
            f"{type(binding).__name__}"
        )

    unknown = set(binding) - BINDING_KEYS
    if unknown:
        raise RuntimeError(
            f"tool '{name}': binding carries unknown keys {sorted(unknown)}; "
            f"expected only {sorted(BINDING_KEYS)}"
        )

    method = binding.get("method")
    if method not in METHODS:
        raise RuntimeError(
            f"tool '{name}': binding method {method!r} is not one of "
            f"{', '.join(METHODS)}"
        )

    path = binding.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise RuntimeError(
            f"tool '{name}': binding path must be a string starting with '/', "
            f"got {path!r}. It is joined to the connector's base URL."
        )

    schema = binding.get("input_schema")
    if not isinstance(schema, dict):
        raise RuntimeError(
            f"tool '{name}': binding must carry 'input_schema', the object schema "
            "the model sees. A REST API does not describe itself, so the vetter "
            "authors it."
        )
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise RuntimeError(
            f"tool '{name}': input_schema must be an object schema with a "
            "'properties' mapping (empty is legal; absent is not)."
        )

    # The path template, held to `validation._validate_template`'s standard: plain
    # argument names, no conversions, no format specs — a path segment must be its
    # argument verbatim.
    in_path = []
    try:
        parsed = list(Formatter().parse(path))
    except ValueError as exc:
        raise RuntimeError(
            f"tool '{name}': binding path {path!r} is not a valid template: {exc}"
        ) from exc
    for _literal, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if conversion is not None or format_spec:
            raise RuntimeError(
                f"tool '{name}': path {path!r} uses a conversion or format spec on "
                f"'{field_name}'. A path segment must be its argument verbatim."
            )
        if not field_name.isidentifier():
            raise RuntimeError(
                f"tool '{name}': path {path!r} has placeholder '{field_name}'; "
                "only plain argument names are allowed."
            )
        in_path.append(field_name)

    for where in ("query", "body"):
        names = binding.get(where) or []
        if not isinstance(names, list) or not all(
            isinstance(entry, str) and entry for entry in names
        ):
            raise RuntimeError(
                f"tool '{name}': binding '{where}' must be a list of argument "
                f"names, got {names!r}"
            )

    # Every argument must exist, and every property must travel in exactly one
    # place. Everything unmapped refuses at vet time rather than guessing.
    placements: dict[str, str] = {}
    for where, names in (
        ("path", in_path),
        ("query", binding.get("query") or []),
        ("body", binding.get("body") or []),
    ):
        for arg in names:
            if arg not in properties:
                raise RuntimeError(
                    f"tool '{name}': binding maps argument '{arg}' into the "
                    f"{where}, but '{arg}' is not in its input_schema. A mapping "
                    "for an argument that never arrives silently never applies."
                )
            if arg in placements:
                raise RuntimeError(
                    f"tool '{name}': argument '{arg}' is mapped into both the "
                    f"{placements[arg]} and the {where}. One argument travels in "
                    "one place, or the request's shape is a guess."
                )
            placements[arg] = where

    unmapped = sorted(set(properties) - set(placements))
    if unmapped:
        raise RuntimeError(
            f"tool '{name}': input_schema declares {unmapped} but the binding maps "
            "them nowhere. An argument the model can set that goes nowhere is a lie "
            "in the schema — map it into the path, query or body, or remove it."
        )

    usage_map = binding.get("usage_map")
    if usage_map is not None:
        if not isinstance(usage_map, dict) or not all(
            isinstance(k, str) and k and isinstance(v, str) and v
            for k, v in usage_map.items()
        ):
            raise RuntimeError(
                f"tool '{name}': usage_map must map counter names to response "
                f"paths, both non-empty strings, got {usage_map!r}"
            )
        # The counter names are a closed set, checked here rather than at call time.
        # Step 045b: 045a stored this mapping and nothing read it, so a typo
        # (`imput_tokens`, `prompt_tokens`) was inert. Now it is a counter that silently
        # never arrives — a tool that looks metered, reports nothing, and leaves a money
        # ceiling bounding a number that is always short. Refused where the vetter is
        # still at the form, which is `check_binding`'s whole reason for existing.
        unknown = sorted(set(usage_map) - set(USAGE_COUNTER_NAMES))
        if unknown:
            raise RuntimeError(
                f"tool '{name}': usage_map names {unknown}, which are not token "
                f"counters. Expected any of {sorted(USAGE_COUNTER_NAMES)} — a name "
                "this list does not hold would never be read, and the tool would look "
                "metered while reporting nothing."
            )

    # Step 086, 080's E5. What this vendor's models cost, keyed the way
    # `CARNET_MODEL_RATES` is keyed, so the price lives on the row written by whoever
    # registered the key rather than in a JSON file on the server that a different
    # person maintains.
    #
    # **Checked by `config.check_rate_table`, which is the one checker a rate table has**,
    # rather than a copy of its rules. Two implementations of *what is a legal price*
    # would diverge as a number rather than as an error: one writer accepting a negative
    # rate the other refuses is a deployment that believes it has a dollar ceiling and
    # has none, invisibly.
    #
    # **The rules themselves live at the storage boundary** (`storage.base.check_rate_table`)
    # and this call is the earlier, better refusal — here the person is still at the form.
    # 086's edge pass is why they are down there and not here: this function is not on the
    # wholesale write path, so a seeded manifest never crossed it.
    #
    # Re-raised as `RuntimeError` because that is the class every refusal in this function
    # raises and `_vet_rest_tool` turns into a sentence for the person at the form.
    pricing = binding.get("pricing")
    if pricing is not None:
        try:
            config.check_rate_table(pricing, f"tool '{name}'")
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc


def bind(tenant_id: str, connector, http=None) -> list:
    """Bind a REST connector's vetted tools. A pure function — nothing is dialled.

    Takes the connector alone: there is no advertisement to intersect with, which is
    the honest cost decision 2 of the plan states. Produces the identical shape
    `mcp.bind` produces, then `validate(tool)` — same as MCP — so a binding whose
    resource args drift from its own schema fails at bind rather than at the first
    call.

    `http` is injectable so tests drive status codes, content types and connection
    failures without a socket — the same seam `HttpTransport(post=...)` keeps, one
    call wide because a REST call is one request. Nothing else passes it.
    """
    tools = []
    for vetted in connector.vetted:
        name = connector.local_name(vetted)
        # `Connector.validate()` already refused a rest row with no binding; this
        # re-checks the binding's own consistency so a row written wholesale (--seed,
        # save_connector) fails closed here rather than improvising a request.
        check_binding(name, vetted.binding)

        # The vetting's half, then the three fields that are not it — the same
        # composition `mcp.bind` makes, off the same `described` (069). A REST tool's
        # "not it" half is authored rather than advertised, which changes where the
        # three values come from and not that there are three.
        tool = replace(
            described(connector, vetted),
            # Authored, both of them — the vetter's words, because there is no vendor
            # advertisement to copy from. Stated as known limit 1 of the plan.
            description=vetted.description,
            input_schema=vetted.binding["input_schema"],
            impl=_impl(tenant_id, connector, vetted.binding, http=http),
            # Every REST tool can be read as it arrives — step 108. Same binding, same
            # checks, same credential; the difference is that the bytes are handed on
            # while the vendor is still sending them. `broker.stream` is the one reader.
            stream_impl=_stream_impl(tenant_id, connector, vetted.binding, http=http),
        )
        validate(tool)
        tools.append(tool)
    return tools


class _RefusedArgument(RuntimeError):
    """An argument value that cannot travel where its binding sends it.

    Caught inside the impl and returned as a tool error the model can read — never
    an exception, because a value problem is the model's to fix by calling again.
    """


class _Prepared:
    """One request, rendered from a binding and a call's arguments. Step 108.

    The half of `impl` that is not the network: argument vetting, the URL, the query,
    the body and the headers. Pulled out so the streamed closure and the buffered one
    build *the same request* from the same checks — a second copy of the preamble is a
    place for the two to disagree about which argument is refused.
    """

    __slots__ = ("url", "params", "body", "headers", "method", "has_body")

    def __init__(self, method, url, params, body, headers, has_body):
        self.method = method
        self.url = url
        self.params = params
        self.body = body
        self.headers = headers
        self.has_body = has_body


def _prepare(tenant_id: str, connector, binding: dict):
    """The closure both implementations share: arguments in, `_Prepared` or a tool error out."""
    launch = connector.launch
    method = binding["method"]
    path = binding["path"]
    in_path = path_arguments(path)
    in_query = tuple(binding.get("query") or ())
    in_body = tuple(binding.get("body") or ())
    # Every argument the vetter mapped somewhere, which — because `check_binding`
    # refuses a schema property that travels nowhere — is exactly the schema's
    # properties. Computed once at bind rather than per call.
    mapped = frozenset(in_path) | frozenset(in_query) | frozenset(in_body)

    def prepare(token, arguments, *, accept: str):
        # **An argument nobody vetted is refused, not dropped.** Step 045c, and it is
        # the fail-closed half of 045a's vet-time rule: there, a schema property mapped
        # nowhere is a lie in the schema; here, an argument arriving that the schema
        # does not declare would have been silently discarded — the caller believes it
        # applied and the request goes out without it.
        #
        # A model connector is where that stops being cosmetic. `stream: true` is not in
        # any authored schema, so a caller asking for a streamed answer used to get a
        # buffered one with nothing saying the flag was ignored; this door is JSON-only
        # (033b) and the honest answer is that the tool does not offer it. The same
        # applies to a `temperature` or a `tools` array the vetter deliberately left out
        # — the schema is the contract, and an argument outside it is outside the
        # approval.
        #
        # A tool error rather than an exception, like every other value problem here:
        # this is the model's to fix by calling again with what the schema advertises.
        unvetted = sorted(set(arguments) - mapped)
        if unvetted:
            return {
                "error": f"this tool does not accept {', '.join(unvetted)}. Its "
                f"arguments are {', '.join(sorted(mapped)) or 'none'} — an argument "
                "outside the approved schema is not sent to the connector, and it is "
                "refused rather than dropped so a caller is never told a value applied "
                "when it did not."
            }

        try:
            url = _render_url(launch.url, path, in_path, arguments)
        except _RefusedArgument as exc:
            return {"error": str(exc)}

        # Dial-time, per request — the load-bearing site (plan finding 6). The
        # registration-time check is the convenience; a stored row outlives the
        # moment it was written, and a host revoked later must refuse here.
        egress.check(tenant_id, url)

        params = {
            name: arguments[name]
            for name in in_query
            if name in arguments and arguments[name] is not None
        }
        body = {name: arguments[name] for name in in_body if name in arguments}
        headers = {"Accept": accept, **launch.headers_for(token)}
        return _Prepared(method, url, params, body, headers, bool(in_body))

    return prepare


def _impl(tenant_id: str, connector, binding: dict, http=None):
    """The generated implementation: one bounded request, JSON in, JSON out.

    By the time this runs the broker has authorized the call, charged the budget and
    fetched the credential; `token` arrives keyword-only, reserved, never in the
    schema. The response is size-bounded by the broker's `_bound_response` — not
    duplicated here.
    """
    prepare = _prepare(tenant_id, connector, binding)
    usage_map = binding.get("usage_map") or {}

    def impl(*, token=None, **arguments):
        prepared = prepare(token, arguments, accept="application/json")
        if isinstance(prepared, dict):
            return prepared

        # Resolved per call rather than closed over, so the module-level seam is
        # still the one in force for a tool bound before a test (or a future
        # change) replaced it — the same late-binding `config` gets in the broker.
        send = http or _request
        try:
            response = send(
                method=prepared.method,
                url=prepared.url,
                params=prepared.params,
                json=prepared.body if prepared.has_body else None,
                headers=prepared.headers,
                timeout=config.REQUEST_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 - a network failure is the model's answer
            return _failure(connector.id, exc)

        return _lift_usage(_result(connector.id, response), usage_map)

    return impl


# --- the answer while it arrives -----------------------------------------------------
#
# Step 108, decisions 2 and 3. A model call is the one REST call whose caller wants the
# first byte before the last one exists, and the buffered `impl` above cannot give it:
# `requests` reads the body whole, the broker bounds it whole, the route returns it
# whole. What follows is the same request read as it arrives, with three things the
# buffered path does at the end done on the way past — the usage counters lifted from
# whichever chunk carries them, the failure noticed mid-body, and the bytes counted so
# the broker's cap can close the upstream rather than measure a completed download.
#
# **Nothing here parses the answer for the caller.** The bytes are handed on unmodified,
# chunk for chunk, and the only reading done is a scan for the `usage_map`'s paths. That
# is what keeps tool-call deltas, content-filter annotations and whatever a vendor adds
# next year working without a release here.


class _UsageScanner:
    """Reads a vendor's usage counters off a response as it passes. Step 108.

    Two body shapes, decided by the content type on arrival. **`text/event-stream`**:
    each event's `data:` lines are joined, decoded as JSON and the `usage_map`'s paths
    read from the object — the last value seen per counter wins, which is where OpenAI
    and Azure put theirs: one usage object in the final chunk, on every earlier chunk
    `null`. **Anything else**: the body is kept and decoded once at the end, which is the
    buffered path's `_lift_usage` done late — a non-streamed model call through the
    streamed broker is the ordinary case for a client that did not ask to stream.

    A chunk that will not decode, an event with no `data:`, the `[DONE]` sentinel — all
    skipped. Nothing here validates a number; `core.usage.parse_report` in the broker is
    the one place that decides what to believe, exactly as for the buffered path.

    Bounded by the broker rather than here: the broker closes the stream at the tool's
    byte cap, so the buffer this holds is never more than that plus one chunk.
    """

    def __init__(self, usage_map: dict, content_type: str):
        self._map = usage_map
        self._sse = content_type.split(";")[0].strip().lower() == "text/event-stream"
        self._buffer = b""
        self._found: dict = {}

    def feed(self, chunk: bytes) -> None:
        if not self._map:
            return
        self._buffer += chunk
        if not self._sse:
            return
        # Events end at a blank line; either line ending, because a proxy in the path
        # may normalise one into the other.
        while True:
            cut = _event_end(self._buffer)
            if cut is None:
                return
            event, self._buffer = self._buffer[: cut[0]], self._buffer[cut[1] :]
            self._scan_event(event)

    def _scan_event(self, event: bytes) -> None:
        data = b"\n".join(
            line[5:].lstrip(b" ")
            for line in event.replace(b"\r\n", b"\n").split(b"\n")
            if line.startswith(b"data:")
        )
        if not data or data.strip() == b"[DONE]":
            return
        try:
            decoded = json.loads(data)
        except ValueError:
            return
        self._lift(decoded)

    def _lift(self, body) -> None:
        for counter, path in self._map.items():
            found = _at_path(body, path)
            if found is not None:
                self._found[counter] = found

    def report(self) -> "dict | None":
        """What was seen, in `REPORTED_USAGE`'s shape — or None for nothing."""
        if not self._map:
            return None
        if not self._sse and self._buffer:
            try:
                self._lift(json.loads(self._buffer))
            except ValueError:
                pass
            self._buffer = b""
        return dict(self._found) or None


def _event_end(buffer: bytes):
    """Where the first complete SSE event ends: `(event_end, next_start)` or None."""
    candidates = [
        (buffer.find(b"\n\n"), 2),
        (buffer.find(b"\r\n\r\n"), 4),
    ]
    found = [(at, width) for at, width in candidates if at >= 0]
    if not found:
        return None
    at, width = min(found)
    return at, at + width


class Upstream:
    """One vendor response being read as it arrives. What `stream_impl` returns.

    The broker iterates `chunks()` and reads the rest afterwards: `status` and
    `headers` to relay, `error` for the audit row's reason when the call did not
    succeed, `report()` for what it spent. **The broker never parses the bytes**; this
    object never bounds them — the cap is the broker's, applied as they pass, exactly
    where `_bound_response` applies it to a whole body.

    `relay_body` is False for a 401 or 403, on `_result`'s rule: a vendor's refusal of
    *our* credential tends to quote the URL and the header, and neither belongs in a
    caller's hands. The status still travels so the route can say *upstream refused the
    connector's credential* in the caller's dialect; the body does not.

    `may_have_completed` carries `_failure`'s bias for the broker's `unknown` outcome
    when the request failed before a byte arrived. A failure *after* bytes arrived is an
    `error` with a sentence naming where it stopped — the request plainly reached the
    vendor, and what a mid-answer stall means for a completion is *it was cut short*,
    which the caller already knows from the bytes stopping.
    """

    def __init__(
        self,
        connector_id: str,
        response=None,
        usage_map: "dict | None" = None,
        *,
        error: "str | None" = None,
        may_have_completed: bool = False,
    ):
        self.connector_id = connector_id
        self._response = response
        self.status = response.status_code if response is not None else None
        self.headers = {}
        if response is not None:
            for name in RELAYED_HEADERS:
                value = response.headers.get(name)
                if value:
                    self.headers[name] = value
        self.error = error
        self.may_have_completed = may_have_completed
        self.relay_body = True
        self.closed = False
        self._started = time.monotonic()
        self._scanner = _UsageScanner(
            usage_map or {}, self.headers.get("Content-Type", "")
        )

        if response is not None and error is None:
            status = int(self.status or 0)
            if status in (401, 403):
                self.error = (
                    f"'{connector_id}' did not accept this call's credential "
                    f"(HTTP {self.status}). The connector's credential may be missing, "
                    "expired or short a permission — an administrator can rotate it."
                )
                self.relay_body = False
            elif not 200 <= status < 300:
                # No fragment: the body is the caller's to read, chunk by chunk, and
                # quoting it here would mean buffering what is about to be relayed.
                self.error = f"'{connector_id}' answered HTTP {self.status}."

    def chunks(self):
        """The body, as it arrives. Empty when there is nothing to relay.

        The read timeout on the socket is per chunk (`config.MODEL_CHUNK_TIMEOUT`), so a
        stream that is still producing is healthy however long it has run; the wall
        clock (`config.MODEL_MAX_SECONDS`) is checked between chunks so a stream that
        has produced *anything* for ten minutes is closed rather than held. Either
        failure sets `error` and stops — the broker reads `error` after the last chunk.
        """
        if self.closed or self._response is None or not self.relay_body:
            self.close()
            return
        try:
            for chunk in self._response.iter_content(chunk_size=None):
                if not chunk:
                    continue
                if time.monotonic() - self._started > config.MODEL_MAX_SECONDS:
                    self.error = (
                        f"'{self.connector_id}' was still answering after "
                        f"{config.MODEL_MAX_SECONDS}s, which is the ceiling on one call "
                        "(CARNET_MODEL_MAX_SECONDS); the stream was closed."
                    )
                    return
                self._scanner.feed(chunk)
                yield chunk
        except Exception as exc:  # noqa: BLE001 - a broken stream is the caller's answer
            self.error = _mid_stream_failure(self.connector_id, exc)
        finally:
            self.close()

    def report(self) -> "dict | None":
        return self._scanner.report()

    def close(self) -> None:
        """Close the upstream request. Idempotent, and the one thing a caller that stops
        early must do — an open response is a completion Azure keeps generating and
        billing for a listener that has gone."""
        if self.closed:
            return
        self.closed = True
        if self._response is None:
            return
        try:
            self._response.close()
        except Exception:  # noqa: BLE001 - closing is best-effort by definition
            log.debug("closing the response from %s raised", self.connector_id, exc_info=True)
        session = getattr(self._response, "carnet_session", None)
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                log.debug("closing the session to %s raised", self.connector_id, exc_info=True)


def _mid_stream_failure(connector_id: str, exc: Exception) -> str:
    """A sentence for a stream that broke after it began.

    A read timeout *before* the first byte is `requests.ReadTimeout`; one *during*
    `iter_content` surfaces as `requests.ConnectionError` wrapping urllib3's
    `ReadTimeoutError` — found by the e2e, whose stalled fake produced the second and
    was reported as a generic break. The chain is walked for the urllib3 class.
    """
    import requests

    def timed_out(err) -> bool:
        try:
            from urllib3.exceptions import ReadTimeoutError
        except ImportError:  # pragma: no cover - urllib3 ships with requests
            return False
        seen = set()
        while err is not None and id(err) not in seen:
            seen.add(id(err))
            if isinstance(err, ReadTimeoutError):
                return True
            for inner in getattr(err, "args", ()):
                if isinstance(inner, BaseException) and timed_out(inner):
                    return True
            err = err.__cause__ or err.__context__
        return False

    if isinstance(exc, requests.exceptions.ReadTimeout) or timed_out(exc):
        return (
            f"'{connector_id}' stopped sending for {config.MODEL_CHUNK_TIMEOUT}s "
            "mid-answer (CARNET_MODEL_CHUNK_TIMEOUT); the stream was closed."
        )
    return f"the stream from '{connector_id}' broke mid-answer: {type(exc).__name__}."


def _stream_impl(tenant_id: str, connector, binding: dict, http=None):
    """The generated streamed implementation. Returns an `Upstream`, never raises for
    a network failure — a failure is an `Upstream` with `error` set and no chunks, so
    the broker writes the same row it would for the buffered path."""
    prepare = _prepare(tenant_id, connector, binding)
    usage_map = binding.get("usage_map") or {}

    def stream_impl(*, token=None, **arguments):
        # Both, in preference order: a vendor asked to stream answers SSE, one that was
        # not answers JSON, and the caller's SDK reads the content type to know which.
        prepared = prepare(token, arguments, accept="text/event-stream, application/json")
        if isinstance(prepared, dict):
            return Upstream(connector.id, error=prepared["error"])

        send = http or _request
        try:
            response = send(
                method=prepared.method,
                url=prepared.url,
                params=prepared.params,
                json=prepared.body if prepared.has_body else None,
                headers=prepared.headers,
                timeout=config.MODEL_CHUNK_TIMEOUT,
                stream=True,
            )
        except Exception as exc:  # noqa: BLE001 - a network failure is the caller's answer
            failure = _failure(connector.id, exc)
            return Upstream(
                connector.id,
                error=failure["error"],
                may_have_completed=bool(failure.get(MAY_HAVE_COMPLETED)),
            )

        return Upstream(connector.id, response, usage_map)

    return stream_impl


def _render_url(base: str, path: str, in_path: tuple, arguments: dict) -> str:
    """Join the base URL and the rendered path template.

    Path segments are URL-encoded, and an argument that renders into a path may not
    contain `/` — the same whole-segment discipline `core/patterns.py` keeps, at the
    other end. A value that could splice its own segments would widen the call past
    what the vetter bound.
    """
    rendered = []
    for literal, field_name, _spec, _conv in Formatter().parse(path):
        rendered.append(literal)
        if field_name is None:
            continue
        if field_name not in arguments or arguments[field_name] is None:
            raise _RefusedArgument(
                f"argument '{field_name}' is needed to build this call's path and "
                "was not supplied."
            )
        value = arguments[field_name]
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise _RefusedArgument(
                f"argument '{field_name}' travels in the path and must be a string "
                f"or integer, not {type(value).__name__}."
            )
        text = value if isinstance(value, str) else str(value)
        if not text:
            raise _RefusedArgument(
                f"argument '{field_name}' is empty, and an empty path segment "
                "changes which resource the URL names."
            )
        if "/" in text:
            raise _RefusedArgument(
                f"argument '{field_name}' contains '/', which would splice extra "
                "path segments into the URL. One argument is one segment."
            )
        rendered.append(quote(text, safe=""))
    return base.rstrip("/") + "".join(rendered)


def _result(connector_id: str, response):
    """A response as data the model can read. Never the URL — it may embed secrets
    (the `post_message` precedent), so failures name the connector instead."""
    status = response.status_code

    if status in (401, 403):
        # The broker's generic-credential-message rule, kept: not the URL, not the
        # credential, and not the vendor's body, which tends to quote both.
        return {
            "error": f"'{connector_id}' did not accept this call's credential "
            f"(HTTP {status}). The connector's credential may be missing, expired "
            "or short a permission — an administrator can rotate it."
        }

    if not 200 <= status < 300:
        return {
            "error": f"'{connector_id}' answered HTTP {status}: "
            f"{_fragment(response)}"
        }

    if not (response.content or b"").strip():
        # A 204, or an empty 200. Legal, and "it worked and said nothing" is the
        # honest answer rather than a JSON error about a body that was never owed.
        return {"status": status}

    try:
        parsed = response.json()
    except ValueError:
        content_type = (response.headers.get("Content-Type") or "").split(";")[0]
        return {
            "error": f"'{connector_id}' answered "
            f"{content_type.strip() or 'an unnamed content type'} where JSON was "
            f"expected: {_fragment(response)}"
        }

    # The vendor's JSON, verbatim, when it is an object — the broker's size cap is
    # what bounds it. Anything else is wrapped so the caller always gets a mapping.
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def _lift_usage(result: dict, usage_map: dict) -> dict:
    """`result` with what the call spent attached under `REPORTED_USAGE`. Step 045b.

    The vendor's own body is where the counters live — the Messages API answers
    `{"usage": {"input_tokens": ...}}` and every provider does something like it — so a
    `usage_map` of `{"input_tokens": "usage.input_tokens"}` says where to look, and this
    reads them out. **The body itself is not modified**: 045a's contract is that a
    vendor's JSON comes back verbatim, and the broker pops this key before anything sees
    the result, so what the caller receives is what the vendor sent.

    **The key is cleared unconditionally first**, which is the load-bearing line rather
    than a tidy one. `_result` returns the vendor's object as the result, so without this
    a vendor could report its own spend simply by putting our reserved key in its
    response body — and on a binding with no `usage_map` at all, nothing else would ever
    remove it. Clearing first means the only route to the meter is a path a vetter
    authored.

    A binding with no `usage_map` — every REST tool that is not a model — leaves no key,
    so the broker records NULL usage: *not applicable*, which is the truth about it.

    Nothing here validates. A path that resolves to a string, a negative, or nothing at
    all is passed on as it was found, and `core.usage.parse_report` in the broker is the
    single place that decides what to believe. Two validators would be two sets of rules
    free to disagree about the same number.
    """
    result.pop(REPORTED_USAGE, None)
    if not usage_map:
        return result

    report = {}
    for counter, path in usage_map.items():
        found = _at_path(result, path)
        if found is not None:
            report[counter] = found

    # Nothing found is nothing reported, rather than a report of zeros: a vendor that
    # changed its response shape should show up as *unmeasured*, not as a free call.
    # Same distinction `Meter.unmeasured_replies` draws one layer over.
    if not report:
        return result

    return {**result, REPORTED_USAGE: report}


def _at_path(body, path: str):
    """The value at a dotted path in a decoded JSON body, or None.

    Deliberately the smallest thing that works: dotted keys into mappings, nothing else.
    No array indices, no wildcards, no JSONPath — every one of those is a small query
    language that has to be specified, tested and refused safely, and a token counter is
    never behind one. A path that does not resolve is None, which is `usage_map`'s way of
    saying this vendor did not send that counter.
    """
    current = body
    for segment in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
        if current is None:
            return None
    return current


def _fragment(response) -> str:
    """The first bounded piece of a response body, for a tool error."""
    text = response.text or ""
    if len(text) > ERROR_FRAGMENT_BYTES:
        return f"{text[:ERROR_FRAGMENT_BYTES]}…"
    return text


def _failure(connector_id: str, exc: Exception) -> dict:
    """A client-side failure as a tool error, with `transport._classify`'s bias.

    A request that verifiably never went out is a plain error — safe to retry. One
    that may have reached the server carries MAY_HAVE_COMPLETED, so the broker marks
    a write's outcome `unknown` rather than `error`: "it failed" and "it might have
    worked" call for opposite responses, and only the audit log will remember which.
    """
    import requests

    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return {"error": f"'{connector_id}' did not accept a connection in time."}

    if isinstance(exc, requests.exceptions.ConnectionError) and _never_sent(exc):
        return {"error": f"'{connector_id}' could not be reached."}

    if isinstance(exc, requests.exceptions.ReadTimeout):
        return {
            "error": f"'{connector_id}' accepted the request and did not answer "
            "in time.",
            MAY_HAVE_COMPLETED: True,
        }

    if isinstance(exc, requests.exceptions.RequestException):
        return {
            "error": f"the call to '{connector_id}' failed: "
            f"{type(exc).__name__}.",
            MAY_HAVE_COMPLETED: True,
        }

    raise exc


def _never_sent(exc: BaseException) -> bool:
    """Did this fail before anything was sent? `transport._is_connect_failure`'s
    heuristic: urllib3 marks DNS failure and connection-refused with
    NewConnectionError, and when the marker is absent we fall back to ambiguous —
    the safe direction for a write."""
    try:
        from urllib3.exceptions import NewConnectionError
    except ImportError:  # pragma: no cover - urllib3 ships with requests
        return False

    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, NewConnectionError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _request(**kwargs):
    """The real network call, the only one in this module.

    `allow_redirects=False`, and that is an egress decision rather than a nicety:
    the allowlist was checked against the URL this module built, and a 3xx pointing
    anywhere else would be a dial the check never saw. A redirect therefore comes
    back as a non-2xx tool error naming its status.

    **The dial is pinned (step 058, through `egress.dial` since 064).** The host is
    resolved here, at dial time, every answer refused if it is an address nobody may
    consent to, and the request goes out to the checked address with the `Host` header
    and TLS name kept — the rebinding close, per call, which is this path's existing
    `egress.check` cadence. Inside this seam so an injected `http` fake never resolves
    anything. The per-call `Session` is what `requests.request` itself does under the
    hood; nothing about connection reuse changes.
    """
    import requests

    from ..mcp import egress

    timeout = kwargs.pop("timeout")
    method = kwargs.pop("method")
    url = kwargs.pop("url")
    headers = kwargs.pop("headers")
    session = requests.Session()
    try:
        response = egress.dial(
            session,
            method,
            url,
            headers=headers,
            timeout=(timeout, timeout),
            **kwargs,
        )
    except BaseException:
        session.close()
        raise
    if kwargs.get("stream"):
        # The body is still on the wire, so the session lives as long as the response
        # does — `Upstream.close` closes both. Closing it here would be closing the
        # pool the connection belongs to under a read that has not happened yet.
        response.carnet_session = session
        return response
    session.close()
    return response
