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
        )
        validate(tool)
        tools.append(tool)
    return tools


class _RefusedArgument(RuntimeError):
    """An argument value that cannot travel where its binding sends it.

    Caught inside the impl and returned as a tool error the model can read — never
    an exception, because a value problem is the model's to fix by calling again.
    """


def _impl(tenant_id: str, connector, binding: dict, http=None):
    """The generated implementation: one bounded request, JSON in, JSON out.

    By the time this runs the broker has authorized the call, charged the budget and
    fetched the credential; `token` arrives keyword-only, reserved, never in the
    schema. The response is size-bounded by the broker's `_bound_response` — not
    duplicated here.
    """
    launch = connector.launch
    method = binding["method"]
    path = binding["path"]
    in_path = path_arguments(path)
    in_query = tuple(binding.get("query") or ())
    in_body = tuple(binding.get("body") or ())
    usage_map = binding.get("usage_map") or {}
    # Every argument the vetter mapped somewhere, which — because `check_binding`
    # refuses a schema property that travels nowhere — is exactly the schema's
    # properties. Computed once at bind rather than per call.
    mapped = frozenset(in_path) | frozenset(in_query) | frozenset(in_body)

    def impl(*, token=None, **arguments):
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
        headers = {"Accept": "application/json", **launch.headers_for(token)}

        # Resolved per call rather than closed over, so the module-level seam is
        # still the one in force for a tool bound before a test (or a future
        # change) replaced it — the same late-binding `config` gets in the broker.
        send = http or _request
        try:
            response = send(
                method=method,
                url=url,
                params=params,
                json=body if in_body else None,
                headers=headers,
                timeout=config.REQUEST_TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001 - a network failure is the model's answer
            return _failure(connector.id, exc)

        return _lift_usage(_result(connector.id, response), usage_map)

    return impl


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
    with requests.Session() as session:
        return egress.dial(
            session,
            method,
            url,
            headers=headers,
            timeout=(timeout, timeout),
            **kwargs,
        )
