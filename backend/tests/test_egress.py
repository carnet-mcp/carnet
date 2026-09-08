"""The egress allowlist — where a database row is allowed to cause a connection.

Step 003 flagged this and `DEFERRED.md` carried it until now: a registration command
that takes a URL and dials it is a server-side request forgery primitive with a friendly
form in front of it. These are the rules that make it not one.

**Most of this file uses a tenant `conftest` has not touched**, because the fixture
pre-approves a host for `TEST_TENANT` so that unrelated tests do not have to. The
property that an *empty* allowlist denies cannot be asserted against a tenant something
already allowed a host for, and it is the most important property here.
"""

import pytest

from carnet import storage
from carnet.tools import mcp
from carnet.tools.mcp import egress

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT

FRESH = "t-fresh"


@pytest.fixture
def fresh(isolated_storage):
    """A tenant with an empty allowlist. The state every new customer starts in."""
    isolated_storage.create_tenant(FRESH, "Fresh Customer")
    return FRESH


# --- an empty allowlist denies ------------------------------------------------------


def test_an_empty_allowlist_denies(fresh):
    """The decision somebody will be tempted to invert, and the reason not to.

    This matches `_check_domain`'s reading of an empty `allowed_domains` — *no identity
    provider for this customer may vouch for anybody* — and it is the correct starting
    state. An allowlist whose empty state permits everything is a control that is off by
    default and looks on.
    """
    assert storage.active().allowed_hosts(fresh) == []

    with pytest.raises(egress.EgressRefused, match="has not approved the host"):
        egress.check(fresh, "https://anything.example.com/mcp")


def test_the_refusal_says_what_would_have_worked(fresh):
    """A refusal that does not name what is approved sends somebody to the schema."""
    storage.active().allow_host(fresh, "one.example.com", actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused) as raised:
        egress.check(fresh, "https://two.example.com/mcp")

    message = str(raised.value)
    assert "one.example.com" in message
    assert "--allow-host two.example.com" in message


def test_an_approved_host_is_allowed_and_returns_its_host(fresh):
    storage.active().allow_host(fresh, "mcp.acme.com", actor=TEST_ACTOR)

    assert egress.check(fresh, "https://mcp.acme.com/mcp/v1?x=1") == "mcp.acme.com"


def test_the_allowlist_is_per_tenant(fresh):
    """Which hosts are acceptable is a customer's answer, not the platform's."""
    storage.active().allow_host(fresh, "mcp.acme.com", actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused):
        egress.check(TEST_TENANT, "https://mcp.acme.com/mcp")


# --- the host, never the URL --------------------------------------------------------


def test_a_path_is_not_a_security_boundary(fresh):
    """Approving a host approves the host. A server that will serve `/mcp` will serve
    whatever else it serves, and an allowlist carrying paths reads as narrower than it
    is — which is worse than one that admits its own width."""
    storage.active().allow_host(fresh, "mcp.acme.com", actor=TEST_ACTOR)

    assert egress.check(fresh, "https://mcp.acme.com/admin/../internal") == "mcp.acme.com"


def test_a_url_cannot_be_stored_as_a_host(fresh):
    """`normalize_host` refuses anything that is not a bare host, and says which part.

    A normalizer that quietly accepted a URL would store an entry matching nothing — a
    control that looks configured and is not, which is the worst of the three states.
    """
    for bad, expected in (
        ("https://mcp.acme.com/mcp", "a scheme"),
        ("mcp.acme.com/mcp", "a path"),
        ("mcp.acme.com:8080", "a port"),
        ("user@mcp.acme.com", "a credential"),
    ):
        with pytest.raises(storage.StorageError, match=expected):
            storage.active().allow_host(fresh, bad, actor=TEST_ACTOR)


def test_hosts_are_normalized_on_the_way_in_and_on_the_way_out(fresh):
    """Case and a trailing dot are the same host to every resolver, so storing both
    would let one be allowed while the other is refused."""
    storage.active().allow_host(fresh, "MCP.Acme.COM.", actor=TEST_ACTOR)

    assert [row["host"] for row in storage.active().allowed_hosts(fresh)] == [
        "mcp.acme.com"
    ]
    assert egress.check(fresh, "https://MCP.ACME.com/mcp") == "mcp.acme.com"


# --- refused whatever the allowlist says --------------------------------------------


@pytest.mark.parametrize(
    "host,because",
    [
        ("localhost", "a name for this machine"),
        ("127.0.0.1", "loopback"),
        # The single most valuable address on a cloud host.
        ("169.254.169.254", "link-local"),
        ("10.0.0.5", "private"),
        ("192.168.1.1", "private"),
        ("172.16.0.1", "private"),
        ("0.0.0.0", "reserved, multicast or unspecified"),
        ("224.0.0.1", "reserved, multicast or unspecified"),
    ],
)
def test_some_hosts_may_never_be_dialled_even_if_approved(fresh, host, because):
    """Not a customer's decision to make, so it is not stored as one.

    An operator who adds `169.254.169.254` to a tenant's allowlist has not consented to
    anything on that tenant's behalf, because the address does not belong to them. These
    are checked **before** the allowlist is read, so no configuration can reach them —
    which is what this test asserts by approving each one first.
    """
    # Approved. It makes no difference, which is the assertion.
    storage.active().allow_host(fresh, host, actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused, match=because):
        egress.check(fresh, f"https://{host}/mcp")


@pytest.mark.parametrize(
    "spelling",
    [
        # Every one of these is loopback to a resolver, and `ipaddress.ip_address`
        # **rejects all three** — so a check built on it alone would call them names and
        # wave them through to the allowlist. See `egress._as_ip`, which was written
        # because this list failed.
        "2130706433",
        "0x7f.0.0.1",
        "127.1",
    ],
)
def test_loopback_is_caught_however_it_is_spelled(fresh, spelling):
    storage.active().allow_host(fresh, spelling, actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused, match="loopback"):
        egress.check(fresh, f"https://{spelling}/mcp")


@pytest.mark.parametrize("literal", ["::1", "::ffff:127.0.0.1", "fe80::1"])
def test_ipv6_literals_are_refused_at_the_url_even_though_none_can_be_approved(
    fresh, literal
):
    """A stated limit, tested in both halves rather than left implicit.

    `normalize_host` refuses anything containing a colon, because a colon is how a port
    is spelled and the two are ambiguous without bracket syntax the allowlist does not
    accept. So **an IPv6 literal can never be an allowlist entry** — which is a real
    limitation for anybody whose MCP endpoint is addressed by one, and is written down
    here rather than discovered.

    It costs nothing in safety, because the check side parses IPv6 fine: `https://[::1]/`
    is refused as loopback whatever the allowlist holds. The limit is that an IPv6
    endpoint cannot be *allowed*, not that one could sneak through.
    """
    with pytest.raises(storage.StorageError):
        storage.active().allow_host(fresh, literal, actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused):
        egress.check(fresh, f"https://[{literal}]/mcp")


def test_a_url_with_no_host_is_refused(fresh):
    with pytest.raises(egress.EgressRefused, match="has no host"):
        egress.check(fresh, "not-a-url")


# --- what this does not do, asserted rather than only documented ---------------------


def test_the_name_check_still_passes_what_the_dial_then_vets(fresh, monkeypatch):
    """What used to assert DNS rebinding open now asserts the division that closed it.

    This test's previous body proved `check` passes a name whose record points at
    `10.0.0.1` — the documented gap, kept visible. Step 058 closed it in a different
    function on purpose: `check` stays a name surface (the allowlist stores names),
    and `pinned` — which every real dial calls, inside the two functions that touch
    the network — resolves the name and refuses the answer. Both halves asserted
    here, in order, against one host.
    """
    storage.active().allow_host(fresh, "internal.acme.com", actor=TEST_ACTOR)
    assert egress.check(fresh, "https://internal.acme.com/mcp") == "internal.acme.com"

    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("10.0.0.1"))
    with pytest.raises(egress.EgressRefused, match="rebinding"):
        egress.pinned("https://internal.acme.com/mcp")


# --- the dial resolves, and the name is not the address (step 058) -------------------


def _answers(*addresses):
    """A `getaddrinfo` stand-in answering with these addresses, in this order."""

    def fake(host, port, **_kwargs):
        return [
            (0, 0, 0, "", (a, port, 0, 0) if ":" in a else (a, port))
            for a in addresses
        ]

    return fake


def test_the_pin_dials_the_checked_address(monkeypatch):
    """The whole mechanism in one shape: address into the authority, name into Host
    and the TLS assertion, port and path and query untouched."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("93.184.216.34"))

    pin = egress.pinned("https://mcp.acme.com:8443/v1/mcp?x=1")

    assert pin.url == "https://93.184.216.34:8443/v1/mcp?x=1"
    assert pin.headers == {"Host": "mcp.acme.com:8443"}
    assert pin.server_hostname == "mcp.acme.com"


def test_one_poisoned_answer_poisons_the_record(monkeypatch):
    """Every answer is vetted, not only the one dialled: a resolver rotating between a
    public face and a private target must not win by ordering."""
    monkeypatch.setattr(
        egress.socket, "getaddrinfo", _answers("93.184.216.34", "127.0.0.1")
    )

    with pytest.raises(egress.EgressRefused, match="rebinding"):
        egress.pinned("https://evil.example/mcp")


def test_metadata_is_refused_whatever_is_consented(monkeypatch):
    """Link-local is where the cloud metadata service lives, and no setting this
    product has may admit it — not the operator's own list, not the operator flag."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("169.254.169.254"))
    monkeypatch.setattr(
        egress.config, "EGRESS_INTERNAL_HOSTS", frozenset({"evil.example"})
    )

    with pytest.raises(egress.EgressRefused, match="metadata"):
        egress.pinned("https://evil.example/mcp")
    with pytest.raises(egress.EgressRefused, match="metadata"):
        egress.pinned("https://evil.example/mcp", operator_consented=True)


def test_an_operator_named_internal_host_may_resolve_private(monkeypatch):
    """The consent split: the tenant approves hosts, the operator approves networks —
    a BYOC deployment's own connectors legitimately live on private addresses."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("10.0.0.7"))
    monkeypatch.setattr(
        egress.config, "EGRESS_INTERNAL_HOSTS", frozenset({"internal.acme.com"})
    )

    pin = egress.pinned("https://internal.acme.com/mcp")

    assert pin.url == "https://10.0.0.7/mcp"
    assert pin.headers == {"Host": "internal.acme.com"}
    assert pin.server_hostname == "internal.acme.com"


def test_the_refusal_names_the_operator_remedy(monkeypatch):
    """A refusal whose remedy does not remedy is a dead end (the house rule): the
    private-answer refusal names the setting; the metadata refusal names none, because
    none exists on purpose."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("10.0.0.7"))

    with pytest.raises(
        egress.EgressRefused, match="CARNET_EGRESS_INTERNAL_HOSTS"
    ):
        egress.pinned("https://internal.acme.com/mcp")

    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("169.254.169.254"))
    with pytest.raises(egress.EgressRefused) as refusal:
        egress.pinned("https://evil.example/mcp")
    assert "CARNET_EGRESS_INTERNAL_HOSTS" not in str(refusal.value)


def test_an_ipv6_answer_is_bracketed(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("2606:2800:220:1::1"))

    pin = egress.pinned("https://mcp.acme.com/mcp")

    assert pin.url == "https://[2606:2800:220:1::1]/mcp"


def test_a_literal_address_needs_no_pin(monkeypatch):
    """A public literal already IS its address: nothing resolves, nothing rewrites —
    asserted with a resolver that would fail the test if consulted."""

    def never(*_args, **_kwargs):
        raise AssertionError("a literal must not be resolved")

    monkeypatch.setattr(egress.socket, "getaddrinfo", never)

    assert egress.pinned("https://93.184.216.34/mcp") == (
        "https://93.184.216.34/mcp", {}, ""
    )


def test_an_unresolvable_name_sends_nothing(monkeypatch):
    def gone(*_args, **_kwargs):
        raise OSError("no such name")

    monkeypatch.setattr(egress.socket, "getaddrinfo", gone)

    with pytest.raises(egress.EgressRefused, match="could not be resolved"):
        egress.pinned("https://vanished.example/mcp")


def test_operator_consent_admits_a_local_provider(monkeypatch):
    """The jwks shape (058's second half): a `--local` provider lives on loopback, by
    literal or by the `localhost` name, and the operator registered it — while under
    no consent at all the same URLs stay refused, as they always were."""
    pin = egress.pinned("http://127.0.0.1:8901/jwks", operator_consented=True)
    assert pin == ("http://127.0.0.1:8901/jwks", {}, "")

    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("127.0.0.1"))
    pin = egress.pinned("http://localhost:8901/jwks", operator_consented=True)
    assert pin.url == "http://127.0.0.1:8901/jwks"
    assert pin.headers == {"Host": "localhost:8901"}
    assert pin.server_hostname == ""

    with pytest.raises(egress.EgressRefused, match="loopback"):
        egress.pinned("http://127.0.0.1:8901/jwks")
    with pytest.raises(egress.EgressRefused, match="machine"):
        egress.pinned("http://localhost:8901/jwks")


# --- the check is in the one place a transport is built ------------------------------


def test_a_stdio_connector_has_no_host_to_check(isolated_storage, vetted_github):
    """Decision 3's other half, and one of the reasons decision 2 refuses stdio.

    A command has no host, so the egress question is only *one* question when the answer
    to "where does this go" is a URL. The shipped connector still connects with an empty
    allowlist because there is nothing about it an allowlist could say.
    """
    storage.active().revoke_host(TEST_TENANT, TEST_HOST, actor=TEST_ACTOR)
    connector = mcp.get_connector(TEST_TENANT, "github-mcp")

    # Does not raise. Built rather than asserted-about, because the assertion is that
    # construction reaches the transport at all.
    assert mcp._transport_for(TEST_TENANT, connector, None) is not None


def test_the_shipped_connectors_are_subject_to_the_check_too(isolated_storage):
    """No provenance exemption, and that is deliberate.

    A branch where the check does not run is the branch everything eventually takes. The
    cost is real and stated in `_transport_for`: a tenant holding an HTTP connector from
    before migration 023 stops connecting until its host is approved.
    """
    storage.active().save_connector(
        TEST_TENANT,
        {
            "id": "ours",
            "launch": {"kind": "http", "url": "https://vendor.example.com/mcp"},
            "vetted": [{"remote_name": "search_issues", "effect": "read"}],
        },
        actor=TEST_ACTOR,
    )

    with pytest.raises(egress.EgressRefused):
        mcp._transport_for(
            TEST_TENANT, mcp.get_connector(TEST_TENANT, "ours"), None
        )


# --- the record ----------------------------------------------------------------------


def test_approving_a_host_records_who_and_when(fresh):
    storage.active().allow_host(
        fresh, "mcp.acme.com", actor="user:u_priya", note="security approved 2026-08"
    )

    row = storage.active().allowed_hosts(fresh)[0]
    assert row["host"] == "mcp.acme.com"
    assert row["allowed_by"] == "user:u_priya"
    assert row["note"] == "security approved 2026-08"
    assert row["allowed_at"]

    record = storage.active().admin_audit_records(fresh)[-1]
    assert record["action"] == "egress.allow"
    assert record["target_kind"] == "host"
    assert record["target_id"] == "mcp.acme.com"
    assert record["actor_id"] == "u_priya"


def test_re_approving_records_the_second_decision(fresh):
    """The last person to say yes is the one an incident wants to talk to."""
    storage.active().allow_host(fresh, "mcp.acme.com", actor="user:u_priya")
    storage.active().allow_host(fresh, "mcp.acme.com", actor="user:u_sam", note="re-checked")

    row = storage.active().allowed_hosts(fresh)[0]
    assert row["allowed_by"] == "user:u_sam"
    assert row["note"] == "re-checked"
    assert len(storage.active().allowed_hosts(fresh)) == 1


def test_revoking_an_unapproved_host_is_not_an_error_and_records_nothing(fresh):
    """The log records changes rather than attempts — `delete_agent`'s precedent."""
    before = len(storage.active().admin_audit_records(fresh))

    assert storage.active().revoke_host(fresh, "never.example.com", actor=TEST_ACTOR) is False
    assert len(storage.active().admin_audit_records(fresh)) == before


def test_an_actor_is_required(fresh):
    """Approving a host is the decision that lets a row cause an outbound connection,
    which makes it the one most worth being able to attribute afterwards."""
    with pytest.raises(storage.StorageError, match="actor"):
        storage.active().allow_host(fresh, "mcp.acme.com", actor="")


# --- https everywhere except the operator's own networks (step 063) ------------------


def test_plain_http_is_refused_with_both_remedies(fresh):
    """A bearer credential on a clear wire is 063's whole subject; the refusal names
    https and the operator's consent knob, because a refusal whose remedy does not
    remedy is a dead end."""
    storage.active().allow_host(fresh, "api.acme.com", actor=TEST_ACTOR)

    with pytest.raises(egress.EgressRefused, match="https") as refusal:
        egress.check(fresh, "http://api.acme.com/v1")
    assert "CARNET_EGRESS_INTERNAL_HOSTS" in str(refusal.value)


def test_plain_http_on_an_operator_named_host_passes(fresh, monkeypatch):
    """"TLS optional here" and "this is my own network" are the same claim, made by
    the same person — 058's consent boundary, reused rather than invented twice."""
    monkeypatch.setattr(
        egress.config, "EGRESS_INTERNAL_HOSTS", frozenset({"internal.acme.com"})
    )
    storage.active().allow_host(fresh, "internal.acme.com", actor=TEST_ACTOR)

    assert (
        egress.check(fresh, "http://internal.acme.com/mcp") == "internal.acme.com"
    )


# --- one dial, and every caller goes through it (step 064) --------------------------


class _Recorder:
    """A `requests.Session` stand-in that records what it was asked to send.

    Not a mock of `dial`'s internals — the point of these tests is that `dial` performs
    the sequence, so what is asserted is what arrived at the socket layer: the URL, the
    `Host`, and that a redirect was refused at the request rather than after it.
    """

    def __init__(self):
        self.mounted: list = []
        self.calls: list = []

    def mount(self, prefix, adapter):
        self.mounted.append((prefix, adapter))

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return "the response"


def test_dial_sends_to_the_checked_address_and_never_follows_a_redirect(monkeypatch):
    """The three guarantees `dial` exists to make, in one call: the socket goes to the
    vetted address, the origin still sees the name it serves, and a 3xx cannot move the
    dial because redirects were refused before one could arrive."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("93.184.216.34"))
    session = _Recorder()

    assert (
        egress.dial(session, "POST", "https://api.acme.com/token", data={"a": "b"})
        == "the response"
    )

    sent = session.calls[0]
    assert sent["url"] == "https://93.184.216.34/token"
    assert sent["headers"]["Host"] == "api.acme.com"
    assert sent["allow_redirects"] is False
    assert sent["data"] == {"a": "b"}
    # The TLS name is asserted against the certificate even though the URL is an
    # address — the half of the pin that keeps it honest.
    assert session.mounted and session.mounted[0][0] == "https://"


def test_dial_refuses_a_rebinding_answer_before_anything_is_sent(monkeypatch):
    """The reason `dial` exists at all: a caller cannot forget the check, because the
    check is not the caller's to perform. Nothing reaches the session."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("169.254.169.254"))
    session = _Recorder()

    with pytest.raises(egress.EgressRefused, match="link-local"):
        egress.dial(session, "POST", "https://api.acme.com/token")

    assert session.calls == []


def test_dial_reuses_a_caller_supplied_pin_without_resolving_again(monkeypatch):
    """`transport` resolves once per transport on purpose. Passing the pin back is how
    that survives the move to `dial` — and a second resolution here would be a DNS
    query per JSON-RPC message."""
    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("93.184.216.34"))
    pin = egress.pinned("https://mcp.acme.com/mcp")

    def refuse(*_args, **_kwargs):
        raise AssertionError("dial resolved again despite being handed a pin")

    monkeypatch.setattr(egress.socket, "getaddrinfo", refuse)
    session = _Recorder()
    egress.dial(session, "POST", "https://mcp.acme.com/mcp", pin=pin)

    assert session.calls[0]["url"] == "https://93.184.216.34/mcp"


def test_mounting_the_same_pin_twice_leaves_one_adapter(monkeypatch):
    """Idempotent so `dial` may call it unconditionally. Re-mounting per message would
    build an adapter and a pool manager per request on the long-lived transport
    session — and re-mounting for a *different* name would silently replace a live
    pin's certificate assertion, which is a mis-verified dial, not a wasted object."""
    session = _Recorder()

    egress.mount_pinned(session, "mcp.acme.com")
    egress.mount_pinned(session, "mcp.acme.com")

    assert len(session.mounted) == 1


def test_the_webhook_dial_is_pinned_too(monkeypatch):
    """`post_message`'s delivery was the *other* call 058's closure missed (step 064).

    A webhook URL is a credential the broker injects, so nothing above this ever sees
    the host and no allowlist is consulted for it — which made an unpinned dial there
    the quietest of the two gaps. Driven through the tool itself rather than through
    `dial`, because what is being asserted is that this caller reaches the network the
    one way there is to.
    """
    from carnet.tools import messaging

    monkeypatch.setattr(egress.socket, "getaddrinfo", _answers("169.254.169.254"))

    with pytest.raises(egress.EgressRefused, match="link-local"):
        messaging.post_message(
            "#eng", "hello", webhook_url="https://hooks.acme.com/services/T0/B0/x"
        )


def test_every_dial_in_the_codebase_goes_through_dial():
    """The property the step is actually about, asserted as a property.

    Five call sites reach the network, and 058's failure was that the sequence was
    copy-pasted at three of them and forgotten at two — a defect no test of any single
    dial could have caught, because each dial was individually fine. So this greps the
    source: a bare `requests.get`/`requests.post`/`session.get` outside `egress.py` is
    a dial that has not been vetted, and the next one somebody adds fails here with a
    sentence saying what to do instead.
    """
    import pathlib

    # `parents[2]` is the `carnet` package, NOT `tools/`. Worth naming, because the
    # first version of this test walked `parents[1]` and so never looked at `access/` —
    # where `oauth._post_form`, the worst of the two missed dials, actually lives. A
    # property test whose scope excludes the defect it was written for is worse than no
    # test: it reports the property as held.
    root = pathlib.Path(egress.__file__).resolve().parents[2]
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "egress.py":
            continue  # where the sanctioned dial lives
        for number, line in enumerate(path.read_text().splitlines(), 1):
            code = line.split("#")[0]
            if "requests.get(" in code or "requests.post(" in code:
                offenders.append(f"{path.relative_to(root)}:{number}")

    assert offenders == [], (
        "these reach the network without egress.dial, so nothing vets what their name "
        f"resolves to at dial time: {offenders}. Use egress.dial(session, ...) — see "
        "step 064, which exists because two such dials went unnoticed for six steps."
    )
