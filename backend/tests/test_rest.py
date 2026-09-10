"""The REST connector — step 045a. A connector that is not an MCP server.

The weight here is on the two places REST genuinely differs from MCP, because
everything downstream of `Tool` is connector-kind-blind and the door tests already
prove that half:

    vetting is AUTHORING   there is no advertisement, so the schema, the mapping and
                           the description are the vetter's words — and every way the
                           mapping can disagree with its own schema is a refusal at
                           vet time, not a surprise at call time
    the impl is ONE REQUEST rendered from the binding, egress-checked at dial time,
                           credential injected per call, tool errors never exceptions

Nothing here opens a socket. The impl's one network call is a seam (`rest._request`),
resolved per call so a monkeypatched module attribute reaches tools that were bound
before the patch — the same trick the MCP tests play with `_transport_for`. The real
socket is `scripts/e2e_rest_connector.py`'s job.
"""

import json

import pytest
from fastapi.testclient import TestClient

from carnet import agents, config, storage, tools
from carnet.access import tokens
from carnet.api import create_app
from carnet.core import Principal
from carnet.core.context import RunContext
from carnet.core import broker
from carnet.tools import mcp, rest
from carnet.tools.base import MAY_HAVE_COMPLETED, REPORTED_USAGE, Resource

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT, Unmetered, read_audit

BASE_URL = f"https://{TEST_HOST}/v1"
OWNER = "u-priya"

SCHEMA = {
    "type": "object",
    "properties": {
        "owner": {"type": "string"},
        "repo": {"type": "string"},
        "state": {"type": "string"},
    },
    "required": ["owner", "repo"],
}

WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "owner": {"type": "string"},
        "repo": {"type": "string"},
        "title": {"type": "string"},
    },
    "required": ["owner", "repo", "title"],
}

READ_BINDING = {
    "method": "GET",
    "path": "/repos/{owner}/{repo}/issues",
    "query": ["state"],
    "input_schema": SCHEMA,
}

WRITE_BINDING = {
    "method": "POST",
    "path": "/repos/{owner}/{repo}/issues",
    "body": ["title"],
    "input_schema": WRITE_SCHEMA,
}

REPO = Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")


class FakeResponse:
    def __init__(self, status=200, payload=None, body=None, content_type="application/json"):
        self.status_code = status
        if body is None:
            body = json.dumps(payload if payload is not None else {})
        self.text = body
        self.content = body.encode()
        self.headers = {"Content-Type": content_type}

    def json(self):
        return json.loads(self.text)


class FakeHttp:
    """The network seam, as a recorder. Returns queued responses, last one sticky."""

    def __init__(self, *responses):
        self.calls = []
        self.responses = list(responses) or [FakeResponse(payload={"issues": []})]

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        answer = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def http(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(rest, "_request", fake)
    return fake


@pytest.fixture
def registered(isolated_storage, monkeypatch):
    """A REST connector, registered through the production path, credential set."""
    monkeypatch.setenv("TRACKER_TOKEN", "service-secret")
    tools.register_connector(
        TEST_TENANT,
        "tracker",
        url=BASE_URL,
        kind="rest",
        credential_env="TRACKER_TOKEN",
        description="Acme's issue tracker, plain REST.",
        actor=TEST_ACTOR,
    )
    return mcp.get_connector(TEST_TENANT, "tracker")


def vet(remote_name="list_issues", *, effect="read", resources=(REPO,), binding=READ_BINDING,
        description="List issues in a repository.", identity="service", **kwargs):
    return tools.vet_tool(
        TEST_TENANT,
        "tracker",
        remote_name,
        effect=effect,
        identity=identity,
        resources=resources,
        actor=TEST_ACTOR,
        binding=binding,
        description=description,
        **kwargs,
    )


@pytest.fixture
def vetted(registered):
    vet()
    vet("create_issue", effect="write", binding=WRITE_BINDING,
        description="Open an issue.")
    return mcp.get_connector(TEST_TENANT, "tracker")


# --- registration ------------------------------------------------------------------


def test_a_rest_registration_stores_a_rest_launch(registered):
    assert registered.transport_kind == "rest"
    assert isinstance(registered.launch, mcp.RestLaunch)
    assert registered.launch.credential_env == "TRACKER_TOKEN"
    assert registered.vetted == ()


def test_registration_checks_egress_like_any_other_kind(isolated_storage):
    with pytest.raises(mcp.EgressRefused, match="has not approved the host"):
        tools.register_connector(
            TEST_TENANT, "elsewhere", url="https://api.unapproved.example/v1",
            kind="rest", actor=TEST_ACTOR,
        )


def test_an_unknown_kind_is_refused_with_the_vocabulary(isolated_storage):
    with pytest.raises(tools.RegistrationRefused, match="'http'.*'rest'"):
        tools.register_connector(
            TEST_TENANT, "tracker", url=BASE_URL, kind="soap", actor=TEST_ACTOR
        )


def test_the_manifest_round_trips_with_binding_and_kind(vetted):
    manifest = mcp.to_manifest(vetted)
    again = mcp.from_manifest(manifest)
    assert again.transport_kind == "rest"
    by_name = {v.remote_name: v for v in again.vetted}
    assert by_name["list_issues"].binding["method"] == "GET"
    assert by_name["create_issue"].binding["method"] == "POST"
    assert mcp.to_manifest(again) == manifest


def test_rest_carries_per_user_credentials(registered):
    """Finding 5 of the plan: the gate keyed on the launch kind must not refuse REST —
    a per-request header carries a per-user credential exactly as HTTP MCP does."""
    assert registered.carries_per_user_credentials
    assert mcp.supports_delegation(registered)
    mcp.check_delegation_supported(registered)  # does not raise


def test_a_user_identity_rest_tool_is_legitimate(registered):
    recorded = vet(identity="user")
    assert recorded["identity"] == "user"


# --- discovery has nothing to discover ---------------------------------------------


def test_discovery_refuses_a_rest_connector_with_the_remedy(registered):
    with pytest.raises(RuntimeError, match="does not describe itself"):
        mcp.discovery.discover(TEST_TENANT, registered, None)


# --- vetting is authoring, and every self-inconsistency refuses at the form --------


def test_vetting_records_an_authored_tool_with_an_empty_server(registered):
    recorded = vet()
    assert recorded["local_name"] == "tracker_list_issues"
    assert recorded["server"] == ""

    review = storage.active().load_vetting_record(TEST_TENANT)[0]
    assert review["vetted_by"] == TEST_ACTOR
    assert review["server_name"] == ""
    assert review["server_version"] == ""
    assert review["vetted_arguments"] == []


def test_the_vetted_tool_appears_in_the_catalogue_unchanged(vetted):
    groups = tools.catalogue(TEST_TENANT)
    tracker = next(g for g in groups if g["id"] == "tracker")
    assert tracker["origin"] == "connector"
    names = {entry["name"] for entry in tracker["tools"]}
    assert names == {"tracker_list_issues", "tracker_create_issue"}
    entry = next(t for t in tracker["tools"] if t["name"] == "tracker_list_issues")
    assert entry["description"] == "List issues in a repository."
    assert entry["server_name"] == ""


def test_a_rest_vet_without_a_binding_is_refused_with_the_remedy(registered):
    with pytest.raises(tools.RegistrationRefused, match="does not describe itself"):
        vet(binding=None)


def test_a_binding_on_an_mcp_connector_is_refused(isolated_storage):
    tools.register_connector(
        TEST_TENANT, "mcp-server", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    with pytest.raises(tools.RegistrationRefused, match="MCP server"):
        tools.vet_tool(
            TEST_TENANT, "mcp-server", "list_issues", effect="read",
            actor=TEST_ACTOR, binding=READ_BINDING,
        )


def test_an_authored_description_on_an_mcp_connector_is_refused(isolated_storage):
    tools.register_connector(
        TEST_TENANT, "mcp-server", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    with pytest.raises(tools.RegistrationRefused, match="copied from the advertisement"):
        tools.vet_tool(
            TEST_TENANT, "mcp-server", "list_issues", effect="read",
            actor=TEST_ACTOR, description="my words",
        )


def test_a_path_argument_absent_from_the_schema_is_refused(registered):
    binding = dict(READ_BINDING, path="/repos/{organisation}/{repo}/issues")
    with pytest.raises(tools.RegistrationRefused, match="'organisation'"):
        vet(binding=binding)


def test_a_schema_property_mapped_nowhere_is_refused(registered):
    binding = dict(READ_BINDING, query=[])  # `state` now goes nowhere
    with pytest.raises(tools.RegistrationRefused, match=r"\['state'\].*maps? .*nowhere|nowhere"):
        vet(binding=binding)


def test_an_argument_mapped_twice_is_refused(registered):
    binding = dict(READ_BINDING, query=["state", "repo"])  # repo is already in the path
    with pytest.raises(tools.RegistrationRefused, match="both"):
        vet(binding=binding)


def test_a_resource_argument_absent_from_the_authored_schema_is_refused(registered):
    """The argument-existence rule survives, degraded to self-consistency — the plan's
    finding 4, asserted rather than assumed."""
    elsewhere = Resource("github.repo", "repository")
    with pytest.raises(tools.RegistrationRefused, match="'repository'"):
        vet(resources=(elsewhere,))


def test_an_unscopeable_write_is_refused_on_rest_as_everywhere(registered):
    with pytest.raises(tools.RegistrationRefused, match="unscopeable"):
        vet("create_issue", effect="write", resources=(), binding=WRITE_BINDING)


def test_a_bad_method_is_refused_at_the_storage_boundary_too(registered):
    """The shape half lives at the storage boundary, so a caller that goes around
    `tools.vet_tool` still cannot store a malformed binding."""
    with pytest.raises(storage.StorageError, match="method"):
        storage.active().vet_tool(
            TEST_TENANT, "tracker",
            {"remote_name": "x", "binding": dict(READ_BINDING, method="FETCH")},
            actor=TEST_ACTOR,
        )


def test_the_kind_binding_implication_is_refused_both_ways_at_storage(isolated_storage):
    tools.register_connector(
        TEST_TENANT, "mcp-server", url=f"https://{TEST_HOST}/mcp", actor=TEST_ACTOR
    )
    tools.register_connector(
        TEST_TENANT, "restful", url=BASE_URL, kind="rest", actor=TEST_ACTOR
    )
    store = storage.active()
    with pytest.raises(storage.StorageError, match="does not speak 'rest'"):
        store.vet_tool(
            TEST_TENANT, "mcp-server",
            {"remote_name": "x", "binding": READ_BINDING}, actor=TEST_ACTOR,
        )
    with pytest.raises(storage.StorageError, match="no request binding"):
        store.vet_tool(
            TEST_TENANT, "restful", {"remote_name": "x"}, actor=TEST_ACTOR
        )


def test_a_rest_manifest_row_without_a_binding_cannot_load(registered):
    """`Connector.validate` fails closed at manifest load, covering rows that predate
    or evade every write-side guard."""
    manifest = mcp.to_manifest(registered)
    manifest["vetted"] = [{"remote_name": "orphan", "effect": "read"}]
    with pytest.raises(RuntimeError, match="no request binding"):
        mcp.from_manifest(manifest)


# --- bind(): a pure function of the manifest ----------------------------------------


def test_bind_produces_the_shape_mcp_binding_produces(vetted):
    bound = rest.bind(TEST_TENANT, vetted)
    by_name = {tool.name: tool for tool in bound}
    tool = by_name["tracker_list_issues"]
    assert tool.description == "List issues in a repository."
    assert tool.input_schema == SCHEMA
    assert tool.effect == "read"
    assert tool.identity == "service"
    assert tool.connector == "tracker"
    assert tool.credential_env == "TRACKER_TOKEN"
    assert by_name["tracker_create_issue"].effect == "write"


def test_bind_refuses_a_stored_binding_that_no_longer_matches_itself(vetted):
    """A row written wholesale can disagree with itself; bind fails closed rather
    than improvising a request."""
    manifest = mcp.to_manifest(vetted)
    manifest["vetted"][1]["binding"] = dict(READ_BINDING, query=[])
    broken = mcp.from_manifest(manifest)
    with pytest.raises(RuntimeError, match="nowhere"):
        rest.bind(TEST_TENANT, broken)


# --- the impl: one bounded request --------------------------------------------------


def impl_of(connector, name, http):
    bound = rest.bind(TEST_TENANT, connector, http=http)
    return next(tool for tool in bound if tool.name == name)


def test_a_read_renders_path_query_and_credential(vetted):
    http = FakeHttp(FakeResponse(payload={"issues": [{"number": 1}]}))
    tool = impl_of(vetted, "tracker_list_issues", http)

    result = tool.impl(token="service-secret", owner="acme", repo="platform", state="open")

    assert result == {"issues": [{"number": 1}]}
    sent = http.calls[0]
    assert sent["method"] == "GET"
    assert sent["url"] == f"{BASE_URL}/repos/acme/platform/issues"
    assert sent["params"] == {"state": "open"}
    assert sent["json"] is None
    assert sent["headers"]["Authorization"] == "Bearer service-secret"
    assert sent["headers"]["Accept"] == "application/json"
    assert sent["timeout"] == config.REQUEST_TIMEOUT


def test_a_write_carries_its_body_and_only_its_body(vetted):
    http = FakeHttp(FakeResponse(status=201, payload={"number": 7}))
    tool = impl_of(vetted, "tracker_create_issue", http)

    result = tool.impl(token=None, owner="acme", repo="platform", title="It broke")

    assert result == {"number": 7}
    sent = http.calls[0]
    assert sent["method"] == "POST"
    assert sent["json"] == {"title": "It broke"}
    assert "Authorization" not in sent["headers"]


def test_an_absent_optional_query_argument_is_omitted(vetted):
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    tool.impl(token=None, owner="acme", repo="platform")
    assert http.calls[0]["params"] == {}


def test_path_values_are_url_encoded_whole_segments(vetted):
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    tool.impl(token=None, owner="acme corp", repo="plat?form")
    assert http.calls[0]["url"] == f"{BASE_URL}/repos/acme%20corp/plat%3Fform/issues"


def test_a_slash_in_a_path_argument_is_a_tool_error_and_nothing_is_sent(vetted):
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token=None, owner="acme/../../admin", repo="platform")
    assert "owner" in result["error"] and "/" in result["error"]
    assert http.calls == []


def test_a_missing_path_argument_is_a_tool_error_naming_it(vetted):
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token=None, owner="acme")
    assert "'repo'" in result["error"]
    assert http.calls == []


def test_an_empty_path_argument_is_refused(vetted):
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token=None, owner="", repo="platform")
    assert "empty" in result["error"]
    assert http.calls == []


def test_a_non_2xx_answer_is_a_tool_error_with_status_and_fragment_not_url(vetted):
    http = FakeHttp(FakeResponse(status=422, payload={"message": "no such repo"}))
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token=None, owner="acme", repo="gone")
    assert "422" in result["error"]
    assert "no such repo" in result["error"]
    assert TEST_HOST not in result["error"]


def test_a_401_is_the_generic_credential_sentence(vetted):
    http = FakeHttp(FakeResponse(status=401, payload={"message": "bad token zzz"}))
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token="wrong", owner="acme", repo="platform")
    assert "credential" in result["error"]
    assert "tracker" in result["error"]
    # Not the vendor's body — it tends to quote the token — and not the URL.
    assert "zzz" not in result["error"]
    assert TEST_HOST not in result["error"]


def test_a_non_json_answer_names_the_content_type(vetted):
    http = FakeHttp(FakeResponse(body="<html>hello</html>", content_type="text/html"))
    tool = impl_of(vetted, "tracker_list_issues", http)
    result = tool.impl(token=None, owner="acme", repo="platform")
    assert "text/html" in result["error"]
    assert "<html>" in result["error"]


def test_an_empty_2xx_is_a_status_not_an_error(vetted):
    http = FakeHttp(FakeResponse(status=204, body=""))
    tool = impl_of(vetted, "tracker_create_issue", http)
    assert tool.impl(token=None, owner="a", repo="b", title="t") == {"status": 204}


def test_a_json_array_is_wrapped_so_the_answer_is_always_a_mapping(vetted):
    http = FakeHttp(FakeResponse(payload=[1, 2, 3]))
    tool = impl_of(vetted, "tracker_list_issues", http)
    assert tool.impl(token=None, owner="a", repo="b") == {"result": [1, 2, 3]}


def test_a_read_timeout_on_a_write_is_marked_may_have_completed(vetted):
    import requests

    http = FakeHttp(requests.exceptions.ReadTimeout("no answer"))
    tool = impl_of(vetted, "tracker_create_issue", http)
    result = tool.impl(token=None, owner="a", repo="b", title="t")
    assert result[MAY_HAVE_COMPLETED] is True
    assert "tracker" in result["error"]


def test_a_connect_timeout_is_a_plain_error_safe_to_retry(vetted):
    import requests

    http = FakeHttp(requests.exceptions.ConnectTimeout("nope"))
    tool = impl_of(vetted, "tracker_create_issue", http)
    result = tool.impl(token=None, owner="a", repo="b", title="t")
    assert MAY_HAVE_COMPLETED not in result
    assert "tracker" in result["error"]


def test_egress_is_enforced_at_dial_time_per_call(vetted):
    """The load-bearing site — a host revoked after binding refuses the next call."""
    http = FakeHttp()
    tool = impl_of(vetted, "tracker_list_issues", http)
    assert "error" not in tool.impl(token=None, owner="a", repo="b")

    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    with pytest.raises(mcp.EgressRefused, match="has not approved the host"):
        tool.impl(token=None, owner="a", repo="b")
    assert len(http.calls) == 1  # nothing reached the seam on the refused call


# --- what the call spent: `usage_map` ------------------------------------------------
#
# Step 045b. 045a stored and validated this mapping and read it nowhere; this is where it
# becomes a number. The counters live in the *vendor's* body — the Messages API answers
# `{"usage": {"input_tokens": ...}}`, and every provider does something like it — so the
# binding says where to look and the impl reads them out. The body is not modified: the
# broker pops the reserved key before anything sees the result.

USAGE_BINDING = {
    "method": "POST",
    "path": "/repos/{owner}/{repo}/messages",
    "body": ["title"],
    "input_schema": WRITE_SCHEMA,
    "usage_map": {
        "model": "model",
        "input_tokens": "usage.input_tokens",
        "output_tokens": "usage.output_tokens",
    },
}


def a_reply(**overrides):
    return {
        "model": "claude-opus-5",
        "content": "hello",
        "usage": {"input_tokens": 12, "output_tokens": 3},
        **overrides,
    }


def usage_of(vetted, http, arguments=None):
    """What one call through this binding reported, as the broker would see it."""
    (tool,) = rest.bind(TEST_TENANT, vetted, http=http)
    return tool.impl(
        token="t", **(arguments or {"owner": "acme", "repo": "sdk", "title": "x"})
    ).get(REPORTED_USAGE)


def test_a_usage_map_lifts_the_counters_out_of_the_vendors_body(registered):
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload=a_reply()))

    assert usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http) == {
        "model": "claude-opus-5",
        "input_tokens": 12,
        "output_tokens": 3,
    }


def test_the_vendors_body_comes_back_verbatim_beside_the_report(registered):
    """045a's contract, unbroken: the vendor's JSON is the result. The reserved key is
    the one addition and the broker removes it before anyone sees it — which is why it is
    popped there rather than left to ride back to the model."""
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload=a_reply()))
    (tool,) = rest.bind(TEST_TENANT, mcp.get_connector(TEST_TENANT, "tracker"), http=http)

    result = tool.impl(token="t", owner="acme", repo="sdk", title="x")

    assert {k: v for k, v in result.items() if k != REPORTED_USAGE} == a_reply()


def test_a_binding_with_no_usage_map_reports_nothing(registered, http):
    """Every REST tool that is not a model. No key means the broker records NULL usage —
    *not applicable*, which is the truth about it."""
    vet("list_issues")

    assert usage_of(
        mcp.get_connector(TEST_TENANT, "tracker"), http, {"owner": "acme", "repo": "sdk"}
    ) is None


def test_a_vendor_cannot_report_its_own_spend_in_its_body(registered):
    """**The clear is unconditional, and this is why.** `_result` returns the vendor's
    object as the result, so without it a vendor could meter itself by putting our
    reserved key in its response — and on a binding with no `usage_map` at all, nothing
    else would ever remove it. The only route to the meter is a path a vetter authored."""
    vet("list_issues")
    http = FakeHttp(
        FakeResponse(payload={"issues": [], REPORTED_USAGE: {"input_tokens": 10**9}})
    )

    assert usage_of(
        mcp.get_connector(TEST_TENANT, "tracker"), http, {"owner": "acme", "repo": "sdk"}
    ) is None


def test_a_counter_the_vendor_did_not_send_is_absent_rather_than_zero(registered):
    """A vendor that does not use prompt caching sends no cache counters. Absent reads as
    zero one layer up; inventing one here would be reporting a number nobody sent."""
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload=a_reply(usage={"input_tokens": 12})))

    assert usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http) == {
        "model": "claude-opus-5",
        "input_tokens": 12,
    }


def test_a_response_shape_that_changed_reports_nothing_rather_than_zeros(registered):
    """A vendor that moved its counters should show up as *unmeasured*, not as a free
    call — `Meter.unmeasured_replies`' distinction, one layer over."""
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload={"content": "hello"}))

    assert usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http) is None


def test_a_reply_with_a_model_and_no_usage_reports_nothing(registered):
    """**The shape the live end-to-end caught.** A vendor error body, or a response whose
    shape moved, still carries `model` — and `usage_map` names `model`, so the lift found
    something and reported it. Four zeros went on the audit row where NULL belonged.

    The lift still attaches what it found (one validator, in the broker); what changed is
    that `core.usage.parse_report` refuses a report naming no counter at all. Asserted
    here at the shape that produced it.
    """
    from carnet.core.usage import parse_report

    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload={"model": "claude-opus-5", "error": "no"}))

    lifted = usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http)

    assert lifted == {"model": "claude-opus-5"}
    assert parse_report(lifted) is None


def test_a_path_that_walks_through_a_non_mapping_is_not_an_error(registered):
    """The path language is dotted keys into mappings and deliberately nothing else — no
    indices, no wildcards, no JSONPath. Anything it cannot resolve is None, which is how
    `usage_map` says *this vendor did not send that counter*."""
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload=a_reply(usage="not a mapping")))

    assert usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http) == {
        "model": "claude-opus-5"
    }


def test_a_usage_map_naming_something_that_is_not_a_counter_is_refused_at_vet_time(
    registered
):
    """045a stored this mapping unread, so a typo was inert. Now it is a counter that
    silently never arrives — a tool that looks metered, reports nothing, and leaves a
    money ceiling bounding a number that is always short. Refused where the vetter is
    still at the form."""
    with pytest.raises(Exception) as excinfo:
        vet(
            "answer",
            effect="write",
            binding={**USAGE_BINDING, "usage_map": {"prompt_tokens": "usage.prompt"}},
        )

    assert "prompt_tokens" in str(excinfo.value)


def test_an_errored_call_still_carries_what_it_spent(registered):
    """A vendor that charged and then failed has spent money, and money spent is money
    recorded — 045b's edge table. A non-2xx is a tool error whose body this cannot read,
    so the case that matters is a 200 the *broker* later marks errored; asserted here as
    the shape that reaches it."""
    vet("answer", effect="write", binding=USAGE_BINDING)
    http = FakeHttp(FakeResponse(payload=a_reply(error="the model refused")))

    assert usage_of(mcp.get_connector(TEST_TENANT, "tracker"), http) == {
        "model": "claude-opus-5",
        "input_tokens": 12,
        "output_tokens": 3,
    }


def test_a_brokered_rest_call_records_its_usage_on_the_audit_row(
    registered, monkeypatch
):
    """The whole arc: a REST tool reports, the broker lifts it, the audit row carries it,
    and the model-visible result is the vendor's body without our key in it."""
    monkeypatch.setenv("TRACKER_TOKEN", "service-secret")
    vet("answer", effect="write", binding=USAGE_BINDING, resources=[REPO])
    http = FakeHttp(FakeResponse(payload=a_reply()))
    monkeypatch.setattr(rest, "_request", http)

    cfg = agent_config(["tracker_answer"], {"github.repo": {"write": ["acme/*"]}})
    tools.ensure_available(TEST_TENANT, cfg)

    # A `door-` correlation id, because this is the path the money ceiling reads: a run's
    # audit rows carry no usage — a run's tokens go on `runs`, where 045 put them.
    ctx = RunContext(
        run_id="door-abc123abc123",
        principal=Principal.machine("tok_1", TEST_TENANT),
        budget=Unmetered(),
    )
    result = broker.call(
        ctx, cfg, "tracker_answer", {"owner": "acme", "repo": "sdk", "title": "x"}
    )

    assert REPORTED_USAGE not in result, "bookkeeping must not ride back to the caller"
    record = read_audit()[-1]
    assert (record["model"], record["input_tokens"], record["output_tokens"]) == (
        "claude-opus-5",
        12,
        3,
    )


# --- ensure_available: binds with no session ----------------------------------------


def agent_config(names, scope):
    return {
        "name": "issue-reader",
        "runtime": "simple",
        "system": "You read issues.",
        "permissions": {"tools": names, "scope": scope},
    }


def test_ensure_available_binds_rest_without_any_session(vetted, http):
    cfg = agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}})
    tools.ensure_available(TEST_TENANT, cfg)
    assert tools.get("tracker_list_issues", TEST_TENANT) is not None
    # The pool never saw a session: there is no server to shake hands with.
    assert mcp.POOL._sessions == {}


def test_a_brokered_call_goes_out_with_the_service_credential(vetted, http, monkeypatch):
    monkeypatch.setenv("TRACKER_TOKEN", "service-secret")
    cfg = agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}})
    tools.ensure_available(TEST_TENANT, cfg)

    ctx = RunContext(
        run_id="r-1",
        principal=Principal.user(OWNER, TEST_TENANT),
        budget=Unmetered(),
    )
    result = broker.call(ctx, cfg, "tracker_list_issues",
                         {"owner": "acme", "repo": "platform"})
    assert "error" not in result
    assert http.calls[0]["headers"]["Authorization"] == "Bearer service-secret"

    record = read_audit()[-1]
    assert record["decision"] == "allow"
    assert record["tool"] == "tracker_list_issues"


def test_scope_is_enforced_before_anything_is_sent(vetted, http):
    cfg = agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}})
    tools.ensure_available(TEST_TENANT, cfg)
    ctx = RunContext(
        run_id="r-2",
        principal=Principal.user(OWNER, TEST_TENANT),
        budget=Unmetered(),
    )
    refused = broker.call(ctx, cfg, "tracker_list_issues",
                          {"owner": "rivals", "repo": "secrets"})
    assert "Denied by broker" in refused["error"]
    assert http.calls == []


def test_a_re_vetted_binding_rebinds_without_a_restart(vetted, http):
    """The `_stale_names` property, extended to the binding: a changed path must not
    keep serving the old request shape until a process restart."""
    cfg = agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}})
    tools.ensure_available(TEST_TENANT, cfg)
    bound = tools.get("tracker_list_issues", TEST_TENANT)
    bound.impl(token=None, owner="acme", repo="platform")
    assert "/repos/acme/platform/issues" in http.calls[0]["url"]

    moved = dict(READ_BINDING, path="/projects/{owner}/{repo}/issues")
    vet(binding=moved)

    tools.ensure_available(TEST_TENANT, cfg)
    rebound = tools.get("tracker_list_issues", TEST_TENANT)
    rebound.impl(token=None, owner="acme", repo="platform")
    assert "/projects/acme/platform/issues" in http.calls[1]["url"]


def test_a_re_vetted_family_rebinds_without_a_restart(vetted, http):
    """**The same property, and the mutation that found it was missing.**

    A family is what the broker will *admit*, so a bound tool snapshotted before a re-vet
    would keep answering the old policy — in either direction: a family removed and still
    honoured is a widening nobody approved, and a family added and not seen is the fix
    that appears to have been applied and was not. This is 033a's stale `identity` and
    070's stale `credential_ref` at a third address, which is why `_descriptor` carries
    it rather than why it happens to matter here.
    """
    cfg = agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}})
    # Vetted with the single-argument form first, so the only field that moves below is
    # `families` — otherwise a changed `args` or `template` would restale the tool by
    # itself and this test would pass without proving anything.
    vet(resources=(Resource("github.repo", "repo"),))
    tools.ensure_available(TEST_TENANT, cfg)
    (before,) = tools.get("tracker_list_issues", TEST_TENANT).resources
    assert before.families == ()

    vet(resources=(Resource("github.repo", "repo", families=("acme",)),))

    tools.ensure_available(TEST_TENANT, cfg)
    (after,) = tools.get("tracker_list_issues", TEST_TENANT).resources
    assert after.families == ("acme",)


# --- the full arc through the door --------------------------------------------------


@pytest.fixture
def owner_row(isolated_storage):
    storage.active().create_user(
        TEST_TENANT,
        {"id": OWNER, "issuer": "https://idp.example", "subject": "00u1",
         "email": "priya@acme.com"},
    )
    return OWNER


@pytest.fixture
def token(owner_row):
    row, presented = tokens.mint(TEST_TENANT, "priya-cursor", owner_row, actor="system:cli")
    return row, presented


@pytest.fixture
def auth(token):
    _, presented = token
    return {"Authorization": f"Bearer {presented}"}


@pytest.fixture
def client():
    return TestClient(create_app())


def grant(token_row, cfg):
    agents.save(TEST_TENANT, cfg, actor=TEST_ACTOR)
    storage.active().grant_agent(
        TEST_TENANT, cfg["name"], "machine", token_row["id"],
        role="user", granted_by=TEST_ACTOR, actor=TEST_ACTOR,
    )


def rpc(client, auth, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return client.post("/mcp", json=body, headers=auth)


def test_the_door_lists_the_rest_tool_with_its_authored_schema(vetted, http, client, auth, token):
    row, _ = token
    grant(row, agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}}))

    listed = rpc(client, auth, "tools/list").json()["result"]["tools"]
    assert [tool["name"] for tool in listed] == ["tracker_list_issues"]
    assert listed[0]["inputSchema"] == SCHEMA
    assert listed[0]["description"] == "List issues in a repository."


def test_a_door_call_reaches_the_api_and_writes_a_door_audit_row(vetted, http, client, auth, token, monkeypatch):
    monkeypatch.setenv("TRACKER_TOKEN", "service-secret")
    row, _ = token
    grant(row, agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}}))

    answered = rpc(client, auth, "tools/call", {
        "name": "tracker_list_issues",
        "arguments": {"owner": "acme", "repo": "platform"},
    })
    assert answered.status_code == 200
    body = answered.json()["result"]
    assert body.get("isError") is not True
    assert body["structuredContent"] == {"issues": []}

    assert http.calls[0]["url"] == f"{BASE_URL}/repos/acme/platform/issues"
    assert http.calls[0]["headers"]["Authorization"] == "Bearer service-secret"

    record = read_audit()[-1]
    assert record["decision"] == "allow"
    assert record["run_id"].startswith(storage.DOOR_CALL_ID_PREFIX)
    # And no run row: a door call is not a run — the premise's own rule.
    assert storage.active().list_runs(TEST_TENANT) == []


def test_a_door_call_outside_scope_is_refused_and_audited(vetted, http, client, auth, token):
    row, _ = token
    grant(row, agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}}))

    answered = rpc(client, auth, "tools/call", {
        "name": "tracker_list_issues",
        "arguments": {"owner": "rivals", "repo": "secrets"},
    })
    body = answered.json()["result"]
    assert body.get("isError") is True
    assert http.calls == []
    record = read_audit()[-1]
    assert record["decision"] == "deny"


def test_a_door_call_after_the_host_is_revoked_is_an_error_not_a_dial(vetted, http, client, auth, token):
    row, _ = token
    grant(row, agent_config(["tracker_list_issues"], {"github.repo": {"read": ["acme/*"]}}))
    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)

    answered = rpc(client, auth, "tools/call", {
        "name": "tracker_list_issues",
        "arguments": {"owner": "acme", "repo": "platform"},
    })
    body = answered.json()["result"]
    assert body.get("isError") is True
    assert "EgressRefused" in json.dumps(body)
    assert http.calls == []


# --- the API routes ----------------------------------------------------------------


def test_the_admin_routes_register_vet_and_refuse_discovery(isolated_storage, monkeypatch, http):
    """The route half of the arc: kind on registration, binding in the vet body,
    discovery refused with the remedy — driven through the FastAPI app."""
    from carnet.api.deps import admin_from_request

    app = create_app()
    admin = Principal.user("u-admin", TEST_TENANT)
    app.dependency_overrides[admin_from_request] = lambda: admin
    client = TestClient(app)

    created = client.post("/admin/connectors", json={
        "connector_id": "tracker",
        "url": BASE_URL,
        "kind": "rest",
        "credential_env": "TRACKER_TOKEN",
    })
    assert created.status_code == 201, created.text
    assert created.json()["transport"] == "rest"

    refused = client.post("/admin/connectors/tracker/discovery")
    assert refused.status_code == 400
    assert "does not describe itself" in refused.json()["detail"]

    vetted = client.put("/admin/connectors/tracker/tools/list_issues", json={
        "effect": "read",
        "resources": [{"type": "github.repo", "args": ["owner", "repo"],
                       "template": "{owner}/{repo}"}],
        "binding": READ_BINDING,
        "description": "List issues in a repository.",
    })
    assert vetted.status_code == 200, vetted.text
    assert vetted.json()["local_name"] == "tracker_list_issues"
    assert vetted.json()["server"] == ""

    detail = client.get("/admin/connectors/tracker").json()
    assert detail["transport"] == "rest"
    assert detail["tools"][0]["name"] == "tracker_list_issues"
    assert detail["tools"][0]["server_name"] == ""

    # A binding on an MCP connector's vet, through the route: 400 with the sentence.
    client.post("/admin/connectors", json={
        "connector_id": "mcp-server", "url": f"https://{TEST_HOST}/mcp",
    })
    wrong = client.put("/admin/connectors/mcp-server/tools/list_issues", json={
        "effect": "read", "binding": READ_BINDING,
    })
    assert wrong.status_code == 400
    assert "MCP server" in wrong.json()["detail"]


# --- a price on the binding, written by whoever registered the key ------------------
#
# Step 086, 080's E5. Before this a price could only be written into a JSON file on the
# server, by whoever can reach the filesystem — very often not the person who registered
# the vendor's key and knows what their contract says.

PRICED_BINDING = dict(
    USAGE_BINDING,
    pricing={
        "gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0}
    },
)


def test_a_price_rides_on_the_binding_beside_the_usage_map(registered):
    """One says where the counters are, the other says what they cost. Same vendor, same
    approval, same person."""
    vet("answer", effect="write", binding=PRICED_BINDING)

    (vetted,) = [
        v for v in mcp.get_connector(TEST_TENANT, "tracker").vetted if v.remote_name == "answer"
    ]
    assert vetted.binding["pricing"]["gpt-5"]["output"] == 10.0
    assert vetted.binding["usage_map"]["model"] == "model"


def test_a_binding_with_no_price_says_so_rather_than_nothing(registered):
    """`None`, filled by the normalizer, on `usage_map`'s device: every binding key
    present, so a row written by `--vet` and one written wholesale compare equal."""
    vet("answer", effect="write", binding=USAGE_BINDING)

    (vetted,) = [
        v for v in mcp.get_connector(TEST_TENANT, "tracker").vetted if v.remote_name == "answer"
    ]
    assert vetted.binding["pricing"] is None


def test_a_negative_rate_on_a_binding_is_refused(registered):
    """**The quiet one.** Spend *falls* as tokens are used, so a dollar ceiling is never
    reached and a deployment that believes it has one does not — with nothing anywhere
    reporting it. Refused by `config.check_rate_table`, which is the file's own checker
    shared rather than copied: two implementations of what a legal price is would diverge
    as a number rather than as an error."""
    binding = dict(
        USAGE_BINDING,
        pricing={"gpt-5": {"input": -1.0, "output": 10.0, "cache_read": 0.0, "cache_write": 0.0}},
    )
    with pytest.raises(tools.RegistrationRefused, match="negative"):
        vet("answer", effect="write", binding=binding)


def test_a_bool_where_a_rate_goes_is_refused(registered):
    """`isinstance(True, int)` is true in Python, so a JSON `true` would price a million
    tokens at one dollar. This codebase refuses a bool where a number goes in four other
    places for exactly this reason."""
    binding = dict(
        USAGE_BINDING,
        pricing={"gpt-5": {"input": True, "output": 10.0, "cache_read": 0.0, "cache_write": 0.0}},
    )
    with pytest.raises(tools.RegistrationRefused, match="missing"):
        vet("answer", effect="write", binding=binding)


def test_a_rate_missing_a_counter_is_refused(registered):
    """Three of four prices the fourth kind of token at nothing and reports a total that
    looks whole."""
    binding = dict(USAGE_BINDING, pricing={"gpt-5": {"input": 1.0, "output": 10.0}})
    with pytest.raises(tools.RegistrationRefused, match="cache_read"):
        vet("answer", effect="write", binding=binding)


def test_an_empty_rate_key_is_refused(registered):
    """`""` is a substring of every model id including the `''` a usage report with no
    model produces, so it would price every model in the deployment at this one rate."""
    binding = dict(
        USAGE_BINDING,
        pricing={"": {"input": 1.0, "output": 1.0, "cache_read": 0.0, "cache_write": 0.0}},
    )
    with pytest.raises(tools.RegistrationRefused, match="not usable as a key"):
        vet("answer", effect="write", binding=binding)


def test_the_refusal_names_the_tool_rather_than_a_file(registered):
    """`check_rate_table` takes `where` because the same rules now guard two homes, and a
    sentence about `CARNET_MODEL_RATES` shown to somebody vetting a tool would send
    them to a file they never touched."""
    binding = dict(USAGE_BINDING, pricing={"gpt-5": {"input": 1.0}})
    with pytest.raises(tools.RegistrationRefused, match="tool 'tracker_answer'"):
        vet("answer", effect="write", binding=binding)


def test_an_unknown_binding_key_is_still_refused(registered):
    """The guard that made `pricing` a code change rather than a data change: a binding
    key nothing reads would read as honoured, so both layers had to agree to it."""
    with pytest.raises(tools.RegistrationRefused, match="unknown keys"):
        vet("answer", effect="write", binding=dict(USAGE_BINDING, prices={}))


# --- the answer while it arrives: `stream_impl` --------------------------------------
#
# Step 108, decisions 2 and 3. The same binding, the same checks and the same credential
# as `impl`, read chunk by chunk instead of whole. What the tests pin is the contract the
# broker's `stream()` leans on: the bytes come through untouched, the usage counters are
# lifted off whichever chunk carries them, a refusal of *our* credential relays no body,
# a failure before the first byte is an `Upstream` with `error` and no chunks, and a stall
# mid-answer becomes a sentence rather than an exception.


class FakeStream:
    """A `requests.Response` being read as it arrives, as the seam sees it."""

    def __init__(self, chunks=(), *, status=200, content_type="text/event-stream",
                 headers=None, raise_after=None):
        self.status_code = status
        self.headers = {"Content-Type": content_type, **(headers or {})}
        self._chunks = list(chunks)
        self._raise_after = raise_after
        self.closed = False

    def iter_content(self, chunk_size=None):
        for chunk in self._chunks:
            yield chunk
        if self._raise_after is not None:
            raise self._raise_after

    def close(self):
        self.closed = True


def sse(*objects, done=True):
    """OpenAI's wire shape: one `data:` event per object, `[DONE]` last."""
    events = [f"data: {json.dumps(obj)}\n\n".encode() for obj in objects]
    if done:
        events.append(b"data: [DONE]\n\n")
    return events


CHAT_BINDING = {
    "method": "POST",
    "path": "/deployments/{model}/chat/completions",
    "body": ["messages", "stream", "stream_options"],
    "input_schema": {
        "type": "object",
        "properties": {
            "model": {"type": "string"},
            "messages": {"type": "array"},
            "stream": {"type": "boolean"},
            "stream_options": {"type": "object"},
        },
        "required": ["model", "messages"],
    },
    "usage_map": {
        "model": "model",
        "input_tokens": "usage.prompt_tokens",
        "output_tokens": "usage.completion_tokens",
    },
}
MODEL = Resource("azure.deployment", "model")


def streamed(http, **arguments):
    vet("chat", effect="write", resources=(MODEL,), binding=CHAT_BINDING)
    (tool,) = rest.bind(TEST_TENANT, mcp.get_connector(TEST_TENANT, "tracker"), http=http)
    assert tool.stream_impl is not None
    return tool.stream_impl(
        token="t", **({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}],
                       "stream": True} | arguments)
    )


def test_a_rest_tool_has_a_stream_impl_and_an_mcp_tool_does_not(registered):
    vet("list_issues")
    (tool,) = rest.bind(TEST_TENANT, mcp.get_connector(TEST_TENANT, "tracker"))
    assert tool.stream_impl is not None
    # `Tool`'s default is None; MCP's bind never sets it, which is the decision.
    from carnet.tools.base import Tool
    assert Tool.__dataclass_fields__["stream_impl"].default is None


def test_the_chunks_come_through_untouched_in_order(registered):
    """Not parsed, not reassembled, not reordered. A tool-call delta, a content-filter
    annotation and whatever the vendor adds next year survive because nothing here
    reads the bytes for the caller."""
    chunks = [b"data: {\"choices\": [{\"delta\": {\"content\": \"he", b"llo\"}}]}\n\n",
              b"data: [DONE]\n\n"]
    http = FakeHttp(FakeStream(chunks))

    upstream = streamed(http)

    assert upstream.status == 200
    assert upstream.error is None
    assert list(upstream.chunks()) == chunks
    assert http.calls[-1]["stream"] is True
    assert http.calls[-1]["timeout"] == config.MODEL_CHUNK_TIMEOUT
    assert http.calls[-1]["headers"]["Accept"].startswith("text/event-stream")


def test_usage_is_lifted_from_the_final_chunk_of_a_stream(registered):
    """Where OpenAI and Azure put it: `usage: null` on every content chunk, the object
    on the last one, then `[DONE]`. The last value seen per counter wins."""
    http = FakeHttp(FakeStream(sse(
        {"model": "gpt-4o-2024-08-06", "choices": [{"delta": {"content": "hi"}}], "usage": None},
        {"model": "gpt-4o-2024-08-06", "choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 3}},
    )))

    upstream = streamed(http)
    for _ in upstream.chunks():
        pass

    assert upstream.report() == {"model": "gpt-4o-2024-08-06", "input_tokens": 12, "output_tokens": 3}


def test_an_event_split_across_chunks_is_still_read(registered):
    """The vendor's chunking is the network's, not the event's: one JSON object can
    arrive in three pieces, and a scanner that decoded per chunk would miss it."""
    (event,) = sse({"model": "m", "usage": {"prompt_tokens": 7, "completion_tokens": 1}}, done=False)
    pieces = [event[:10], event[10:25], event[25:]]
    http = FakeHttp(FakeStream(pieces + [b"data: [DONE]\r\n\r\n"]))

    upstream = streamed(http)
    assert list(upstream.chunks()) == pieces + [b"data: [DONE]\r\n\r\n"]
    assert upstream.report() == {"model": "m", "input_tokens": 7, "output_tokens": 1}


def test_a_chunk_that_is_not_json_is_skipped_rather_than_fatal(registered):
    http = FakeHttp(FakeStream([b": keep-alive\n\n", b"data: not json\n\n",
                                *sse({"usage": {"prompt_tokens": 2}})]))

    upstream = streamed(http)
    assert len(list(upstream.chunks())) == 4
    assert upstream.report() == {"input_tokens": 2}


def test_a_json_body_is_scanned_once_at_the_end(registered):
    """A client that did not ask to stream, through the streamed path: the vendor
    answers one JSON document and the counters are lifted exactly as `impl` would."""
    body = json.dumps(a_reply(usage={"prompt_tokens": 5, "completion_tokens": 9})).encode()
    http = FakeHttp(FakeStream([body[:20], body[20:]], content_type="application/json"))

    upstream = streamed(http, stream=False)
    assert b"".join(upstream.chunks()) == body
    assert upstream.report() == {"model": "claude-opus-5", "input_tokens": 5, "output_tokens": 9}


def test_a_binding_with_no_usage_map_reports_nothing_from_a_stream(registered):
    vet("list_issues")
    http = FakeHttp(FakeStream(sse({"usage": {"prompt_tokens": 100}})))
    (tool,) = rest.bind(TEST_TENANT, mcp.get_connector(TEST_TENANT, "tracker"), http=http)

    upstream = tool.stream_impl(token="t", owner="acme", repo="sdk")
    list(upstream.chunks())
    assert upstream.report() is None


def test_a_credential_refusal_relays_no_body(registered):
    """`_result`'s rule at the streamed door: a 401 from the vendor tends to quote the
    URL and the header, and neither is the caller's. The status travels; the body does
    not; the sentence names the connector and never the key."""
    http = FakeHttp(FakeStream([b'{"error": "bad key sk-secret"}'], status=401,
                               content_type="application/json"))

    upstream = streamed(http)

    assert upstream.status == 401
    assert upstream.relay_body is False
    assert list(upstream.chunks()) == []
    assert "did not accept this call's credential" in upstream.error
    assert "sk-secret" not in upstream.error


def test_a_vendor_refusal_relays_its_body_and_its_retry_after(registered):
    """A 429 or a content-filter 400 is the caller's to read — the SDK's own backoff and
    its own error class work only on the vendor's body. `Retry-After` rides along; the
    vendor's request ids and banner do not."""
    body = b'{"error": {"code": "429", "message": "slow down"}}'
    http = FakeHttp(FakeStream([body], status=429, content_type="application/json",
                               headers={"Retry-After": "7", "x-ms-request-id": "abc"}))

    upstream = streamed(http)

    assert upstream.status == 429
    assert upstream.headers == {"Content-Type": "application/json", "Retry-After": "7"}
    assert upstream.relay_body is True
    assert list(upstream.chunks()) == [body]
    assert upstream.error == "'tracker' answered HTTP 429."


def test_a_failure_before_the_first_byte_is_an_upstream_with_no_chunks(registered):
    import requests

    http = FakeHttp(requests.exceptions.ConnectTimeout())

    upstream = streamed(http)

    assert upstream.status is None
    assert list(upstream.chunks()) == []
    assert upstream.error == "'tracker' did not accept a connection in time."
    assert upstream.may_have_completed is False


def test_a_stall_mid_answer_is_a_sentence_naming_the_dial(registered, monkeypatch):
    """S11. The read timeout is per chunk, so a stream that stops producing for the
    dial's length is closed with a sentence — not an exception up the stack, and not a
    silent end that reads as a short answer."""
    import requests

    monkeypatch.setattr(config, "MODEL_CHUNK_TIMEOUT", 61)
    response = FakeStream([b"data: {}\n\n"], raise_after=requests.exceptions.ReadTimeout())
    upstream = streamed(FakeHttp(response))

    assert list(upstream.chunks()) == [b"data: {}\n\n"]
    assert "stopped sending for 61s" in upstream.error
    assert "CARNET_MODEL_CHUNK_TIMEOUT" in upstream.error
    assert response.closed is True


def test_the_wall_clock_closes_a_stream_that_will_not_end(registered, monkeypatch):
    """A stream that has produced *anything* for the ceiling's length is a thread held
    open, not a completion. Checked between chunks, so the one in hand is not sent."""
    monkeypatch.setattr(config, "MODEL_MAX_SECONDS", -1)
    response = FakeStream([b"a", b"b"])
    upstream = streamed(FakeHttp(response))

    assert list(upstream.chunks()) == []
    assert "still answering after -1s" in upstream.error
    assert "CARNET_MODEL_MAX_SECONDS" in upstream.error
    assert response.closed is True


def test_an_unvetted_argument_is_refused_before_anything_is_dialled(registered):
    """The buffered impl's rule, through the shared preamble: `_prepare` is one
    function, so the streamed path cannot accept an argument the buffered one refuses."""
    http = FakeHttp(FakeStream())

    upstream = streamed(http, temperature=0.2)

    assert upstream.status is None
    assert "does not accept temperature" in upstream.error
    assert list(upstream.chunks()) == []
    assert http.calls == []


def test_closing_an_upstream_closes_the_response_once(registered):
    response = FakeStream(sse({}))
    upstream = streamed(FakeHttp(response))

    upstream.close()
    upstream.close()

    assert response.closed is True
    assert list(upstream.chunks()) == []
