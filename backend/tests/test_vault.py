"""Pointer credentials, driven against a vault that really answers. Step 070.

**Nothing here mocks the resolver**, and that is the whole design of this module. The
three things this step is bought to survive — a vault that is *slow*, a vault that is
*down*, and a pointer that resolves to something that is **not a credential** — are
invisible to a test that patches `vault.resolve` and asserts it was called. So there is a
real 1Password Connect stub on a real socket, and the tests stop it, slow it, and feed it
items that are the wrong shape.

Loopback needs no allowlist here because `core/vault` dials under **operator** consent:
the vault URL is the deployment's own setting, not a tenant's row. That is a reversal of
what plan 070 decided and the argument is in `core/vault`'s docstring.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from carnet import config, storage, tools
from carnet.core import credentials, vault
from carnet.core.principal import Principal

from conftest import TEST_ACTOR, TEST_HOST, TEST_TENANT, run_context

VAULT_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbb"
ITEM_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"

# One item, carrying every shape the field matcher has an opinion about: a plain label, a
# field addressable only by id, one whose value is empty, and a sectioned pair whose
# labels collide with the top-level ones.
ITEM = {
    "id": ITEM_ID,
    "title": "GitHub Deploy Key",
    "fields": [
        {"id": "cred1", "label": "credential", "value": "ghp_the_real_one"},
        {"id": "bare-id-only", "label": "", "value": "found-by-id"},
        {"id": "cred2", "label": "blank", "value": ""},
        {"id": "cred3", "purpose": "PASSWORD", "label": "", "value": "by-purpose"},
        # A note, which is where somebody pastes a key — and the reason `UNUSABLE` exists.
        {"id": "cred5", "label": "notes", "value": "line one\nline two"},
        {
            "id": "cred4",
            "label": "credential",
            "value": "the-staging-one",
            "section": {"id": "s1", "label": "Staging"},
        },
        # Only ever reachable by naming its section, and the reason the eleventh refusal
        # exists: two fields called `token` with nothing sectionless to prefer.
        {
            "id": "cred6",
            "label": "token",
            "value": "prod-token",
            "section": {"id": "s2", "label": "Prod"},
        },
        {
            "id": "cred7",
            "label": "token",
            "value": "dev-token",
            "section": {"id": "s3", "label": "Dev"},
        },
    ],
}


class Stub(BaseHTTPRequestHandler):
    """The smallest Connect that answers the three shapes `core/vault` asks for.

    Class attributes rather than instance state because `ThreadingHTTPServer` builds one
    handler per request: `delay` makes it slow, `status` makes it refuse, `body` makes it
    answer something that is not an item.
    """

    delay = 0.0
    status = 200
    body = None
    hits = []
    # Narrower than `body` and `status`, which apply to every endpoint: the rows the
    # items list returns, and the status of the item fetch alone — for "two items share
    # a title" and "the item vanished between the list and the read".
    item_rows = None
    item_status = 200

    # **HTTP/1.1, so the connection is keep-alive** — `BaseHTTPRequestHandler` defaults to
    # 1.0, which closes after every response. That is not what a real Connect server does,
    # and a stub that closes makes connection reuse untestable *and* makes a passing
    # reuse test impossible to write: the first draft of
    # `test_three_hops_share_one_connection` failed against the stub rather than against
    # the code. Every response below sets Content-Length, which 1.1 requires.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        # **Bound before the sleep, and that is the whole of a fix for a real flake.**
        # `hits` is class state that `a_vault` resets per test, and `server_close()` does
        # **not** join in-flight handler threads — daemon threads outlive it, measured
        # rather than assumed. So the slow-vault test below sets `delay = 0.3`, its client
        # abandons at a 0.4s budget, teardown returns in milliseconds, and the sleeping
        # handler then wakes and appends into whatever `Stub.hits` has become — the *next*
        # test's empty list. The only test that asserts `hits == []` is the filter-grammar
        # one, which is why it was the one that failed, once every few full-suite runs and
        # never when the module ran alone.
        #
        # Reading the list here means a straggler appends to the list belonging to the
        # test it was serving, which is the correct owner. Found while checking step 081;
        # the defect is this fixture's and predates it.
        hits = Stub.hits
        if Stub.delay:
            time.sleep(Stub.delay)

        split = urlsplit(self.path)
        hits.append(split.path)
        wanted = (parse_qs(split.query).get("filter") or [""])[0]

        if Stub.status != 200:
            self.send_response(Stub.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if Stub.body is not None:
            payload = Stub.body
        elif split.path == "/v1/vaults":
            rows = [{"id": VAULT_ID, "name": "Engineering"}]
            payload = json.dumps(
                [r for r in rows if f'name eq "{r["name"]}"' == wanted]
            ).encode()
        elif split.path.endswith("/items"):
            rows = Stub.item_rows or [{"id": ITEM_ID, "title": ITEM["title"]}]
            payload = json.dumps(
                [r for r in rows if f'title eq "{r["title"]}"' == wanted]
            ).encode()
        elif Stub.item_status != 200:
            self.send_response(Stub.item_status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            payload = json.dumps(ITEM).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def a_vault(monkeypatch):
    """A running Connect stub, configured as this deployment's vault. Yields the class,
    so a test can make it slow, break it, or stop it mid-test."""
    Stub.delay, Stub.status, Stub.body, Stub.hits = 0.0, 200, None, []
    Stub.item_rows, Stub.item_status = None, 200

    class Quiet(ThreadingHTTPServer):
        """A client that hangs up mid-response is what the timeout tests *do*, and
        `socketserver` prints a traceback for it. Silenced so a green run is legible —
        the failure it would be hiding is asserted by the caller, not by the server."""

        def handle_error(self, request, client_address):
            pass

    server = Quiet(("127.0.0.1", 0), Stub)
    # A short poll interval, because `shutdown()` waits for one — at the 0.5s default
    # this fixture's teardown was most of the module's runtime, which is how a suite
    # people stop running gets built.
    threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    ).start()
    monkeypatch.setattr(
        config, "VAULT_URL", f"http://127.0.0.1:{server.server_address[1]}"
    )
    monkeypatch.setattr(config, "VAULT_TOKEN", "connect-token")
    monkeypatch.setattr(config, "VAULT_TIMEOUT_SECONDS", 2.0)
    try:
        yield Stub, server
    finally:
        server.shutdown()
        server.server_close()


# --- the pointer itself -------------------------------------------------------------


def test_a_three_part_pointer_parses():
    pointer = vault.parse("op://Engineering/GitHub/credential")
    assert (pointer.vault, pointer.item, pointer.field) == (
        "Engineering",
        "GitHub",
        "credential",
    )
    assert pointer.section == ""


def test_a_four_part_pointer_names_a_section():
    pointer = vault.parse("op://Engineering/GitHub/Staging/credential")
    assert pointer.section == "Staging"
    assert pointer.field == "credential"


def test_segments_are_percent_decoded_and_re_encoded():
    """A name with a space round-trips, so a pointer echoed in a refusal is pastable."""
    pointer = vault.parse("op://Eng%20Team/GitHub%2FDeploy/credential")
    assert pointer.vault == "Eng Team"
    assert pointer.item == "GitHub/Deploy"
    assert str(pointer) == "op://Eng%20Team/GitHub%2FDeploy/credential"


@pytest.mark.parametrize(
    "raw",
    [
        "GITHUB_TOKEN",
        "vault://Engineering/GitHub/credential",
        "op://Engineering/GitHub",
        "op://Engineering/GitHub/a/b/c",
        "op://Engineering//credential",
        "",
    ],
)
def test_a_reference_that_is_not_one_is_refused_by_name(raw):
    """Case 2, and the reason it is not attempted: a scheme we do not know, looked up as
    an item title, would report a *missing item* for a *malformed reference*."""
    with pytest.raises(vault.VaultError) as caught:
        vault.parse(raw)
    assert caught.value.reason == vault.MALFORMED
    assert "op://" in str(caught.value)


def test_looks_like_a_reference_includes_a_broken_one():
    """The predicate the registration paths use decides WHICH refusal to write, so a
    broken pointer must answer True or it gets an environment variable's sentence."""
    assert vault.looks_like_reference("op://a/b")
    assert vault.looks_like_reference("  OP://A/B/C  ")
    assert not vault.looks_like_reference("GITHUB_TOKEN")


# --- resolving, against a vault that answers ----------------------------------------


def test_a_pointer_by_name_resolves_in_three_hops(a_vault):
    stub, _ = a_vault
    assert vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential")) == (
        "ghp_the_real_one"
    )
    assert len(stub.hits) == 3


def test_a_pointer_by_id_resolves_in_one(a_vault):
    """The whole of the latency advice in the README, asserted rather than asserted at."""
    stub, _ = a_vault
    assert vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential")) == (
        "ghp_the_real_one"
    )
    assert len(stub.hits) == 1


def test_a_field_is_matched_by_label_then_id_then_purpose(a_vault):
    base = f"op://{VAULT_ID}/{ITEM_ID}"
    assert vault.resolve(vault.parse(f"{base}/credential")) == "ghp_the_real_one"
    assert vault.resolve(vault.parse(f"{base}/bare-id-only")) == "found-by-id"
    assert vault.resolve(vault.parse(f"{base}/password")) == "by-purpose"


def test_a_section_selects_between_two_fields_with_one_label(a_vault):
    """The reason the four-segment form exists: an item routinely carries two fields
    called `credential`, and a reference that could not distinguish them would resolve to
    whichever the vendor happened to list first."""
    base = f"op://{VAULT_ID}/{ITEM_ID}"
    assert vault.resolve(vault.parse(f"{base}/credential")) == "ghp_the_real_one"
    assert vault.resolve(vault.parse(f"{base}/Staging/credential")) == "the-staging-one"


def test_an_unqualified_pointer_prefers_a_sectionless_field(a_vault):
    """Adding a section to an item must not silently change what an existing reference
    resolves to — which is a change in which secret is sent to a vendor."""
    assert vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential")) == (
        "ghp_the_real_one"
    )


def test_describe_fields_lists_labels_and_never_values(a_vault):
    labels = vault.describe_fields(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential"))
    assert "credential" in labels
    assert "Staging/credential" in labels
    assert not any("ghp_" in label for label in labels)


# --- the nine refusals --------------------------------------------------------------


def test_no_vault_configured_names_the_file_and_not_the_shell(monkeypatch):
    """Case 1. `anthropic_api_key`'s paragraph, which cost somebody a real evening: an
    export lives in one terminal and the worker is a different process."""
    monkeypatch.setattr(config, "VAULT_URL", "")
    monkeypatch.setattr(config, "VAULT_TOKEN", "")
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub/credential"))
    assert caught.value.reason == vault.UNCONFIGURED
    message = str(caught.value)
    assert "backend/.env" in message
    assert "CARNET_VAULT_URL" in message and "CARNET_VAULT_TOKEN" in message
    assert "export" in message


def test_a_vault_that_is_down_names_the_vault_and_the_item(a_vault):
    """Case 4, and the one a generic message destroys most completely: it must not read
    as *the credential is broken*, which sends somebody to reconnect an account."""
    _, server = a_vault
    server.shutdown()
    server.server_close()

    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.UNREACHABLE
    message = str(caught.value)
    assert "op://Engineering/GitHub%20Deploy%20Key/credential" in message
    assert config.VAULT_URL in message
    assert "not a permission problem and not a missing credential" in message


def test_a_vault_that_is_slow_gives_up_at_the_deadline(a_vault, monkeypatch):
    """Case 4 again, by the other route — and the deadline is for the WHOLE resolution,
    not per hop, or three requests at three seconds each is a nine-second door call."""
    stub, _ = a_vault
    monkeypatch.setattr(config, "VAULT_TIMEOUT_SECONDS", 0.4)
    stub.delay = 0.3

    started = time.monotonic()
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    elapsed = time.monotonic() - started

    assert caught.value.reason == vault.UNREACHABLE
    # Three hops at 0.3s each would be 0.9s; the budget is 0.4s and it is honoured.
    assert elapsed < 0.9
    assert "0.4s budget" in str(caught.value)


def test_a_vault_that_refuses_our_service_account_says_whose_problem_it_is(a_vault):
    """Case 5. `401` during a tool call reads as the caller's permissions, and the caller
    cannot fix this one — so the sentence says which credential was refused."""
    stub, _ = a_vault
    stub.status = 401
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.UNAUTHORIZED
    message = str(caught.value)
    assert "CARNET_VAULT_TOKEN" in message
    assert "not about the caller's permissions" in message
    assert "'Engineering'" in message


def test_a_vault_that_is_not_there_names_the_vault(a_vault):
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Nope/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.NO_VAULT
    assert "'Nope'" in str(caught.value)


def test_an_item_that_is_not_there_names_the_item_and_says_the_vault_opened(a_vault):
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/Nope/credential"))
    assert caught.value.reason == vault.NO_ITEM
    message = str(caught.value)
    assert "'Nope'" in message
    assert "The vault was found and opened" in message


def test_a_field_that_is_not_there_names_it_and_withholds_the_labels(a_vault):
    """Case 8, and the withholding is the decision. This sentence reaches the model
    through the broker, so the structure of an organisation's vault is not in it —
    `--check-credential` is where an administrator gets the labels."""
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/nope"))
    assert caught.value.reason == vault.NO_FIELD
    message = str(caught.value)
    assert "'nope'" in message
    assert "--check-credential" in message
    for label in ("bare-id-only", "Staging", "blank"):
        assert label not in message


def test_a_field_that_is_empty_says_the_reference_worked(a_vault):
    """Case 9. *No credential* is what this reads as otherwise, and that sends somebody
    to configure one that is already configured."""
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/blank"))
    assert caught.value.reason == vault.EMPTY
    message = str(caught.value)
    assert "the field it names is empty" in message
    assert "not a configuration problem at this end" in message


def test_a_200_that_is_not_json_is_not_reported_as_a_missing_item(a_vault):
    """A captive portal, a proxy error page, or a URL pointing at something that is not
    Connect. `it parsed to nothing` would land somebody on case 7."""
    stub, _ = a_vault
    stub.body = b"<html>sign in</html>"
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.UNREACHABLE
    assert "not JSON" in str(caught.value)


def test_an_item_that_is_not_an_object_is_refused(a_vault):
    """The pointer resolved to something that is not a credential — the third of the
    three failures a mocked resolver cannot show."""
    stub, _ = a_vault
    stub.body = b'"just a string"'
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential"))
    assert caught.value.reason in (vault.NO_ITEM, vault.NO_FIELD)


def test_two_vaults_with_one_name_resolve_to_neither(a_vault):
    """Guessing which of two vaults a customer meant is guessing which secret to send to
    a vendor. The filter is a query and the match is checked again on the way back.

    And it is its own sentence rather than *no such vault*: that one sends somebody to
    check a name that is right. `--check-credential` cannot list vaults, so the remedy
    names where the ids actually are."""
    stub, _ = a_vault
    stub.body = json.dumps(
        [{"id": VAULT_ID, "name": "Engineering"}, {"id": "c" * 26, "name": "Engineering"}]
    ).encode()
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.AMBIGUOUS
    message = str(caught.value)
    assert "2 vaults are called 'Engineering'" in message
    assert "by its id" in message and "op vault list" in message
    assert "no vault called" not in message
    # Neither id is chosen, and neither is named: the sentence reaches the model.
    assert VAULT_ID not in message and "c" * 26 not in message


def test_two_items_with_one_title_resolve_to_neither(a_vault):
    """The same refusal one level down, with the vault named so the remedy's `op item
    list --vault` is pasteable."""
    stub, _ = a_vault
    stub.item_rows = [
        {"id": ITEM_ID, "title": "GitHub Deploy Key"},
        {"id": "d" * 26, "title": "GitHub Deploy Key"},
    ]
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.AMBIGUOUS
    message = str(caught.value)
    assert "2 items in the vault 'Engineering' are called 'GitHub Deploy Key'" in message
    assert "by its id" in message and "op item list --vault 'Engineering'" in message
    assert "has no item called" not in message
    assert ITEM_ID not in message and "d" * 26 not in message
    # The list was the last request: nothing was fetched on a guess.
    assert not any(path.endswith(f"/items/{ITEM_ID}") for path in stub.hits)


@pytest.mark.parametrize(
    "reference, kind",
    [
        ('op://Eng "prod"/GitHub Deploy Key/credential', "vault"),
        ("op://Engineering/Deploy \\ Key/credential", "item"),
        ('op://Engineering/Say "hi"/credential', "item"),
    ],
)
def test_a_name_the_filter_cannot_carry_is_refused_before_any_request(
    a_vault, reference, kind
):
    """`name eq "…"` is built by interpolation, and Connect's grammar documents no
    escape — so a `"` in a name is a broken filter that the first build reported as
    *the vault answered HTTP 400*, which is true of the wrong thing. Refused up front,
    pointed at the id, and nothing is sent: a wrong guess at an escape could match."""
    stub, _ = a_vault
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(reference))
    assert caught.value.reason == vault.MALFORMED
    message = str(caught.value)
    assert f"the {kind} name" in message
    assert "cannot be sent in a 1Password Connect name filter" in message
    assert "by its id" in message and f"op {kind} list" in message
    assert "HTTP 400" not in message
    assert stub.hits == []


def test_a_server_that_ignores_the_filter_is_not_believed(a_vault):
    """Connect's filter is a query. A server that ignored or widened it would otherwise
    hand back the first row of the vault list — a credential from an item nobody named."""
    stub, _ = a_vault
    stub.body = json.dumps([{"id": VAULT_ID, "name": "Something Else"}]).encode()
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.NO_VAULT


# --- the credential layer: same Credential, same source, nothing above learns ---------


def _connector_with(a_vault, **credential):
    """A REST connector registered with one credential shape, and one vetted tool."""
    store = storage.active()
    tools.register_connector(
        TEST_TENANT,
        "tracker",
        url=f"https://{TEST_HOST}/v1",
        kind="rest",
        actor=TEST_ACTOR,
        **credential,
    )
    store.vet_tool(
        TEST_TENANT,
        "tracker",
        {
            "remote_name": "get_issue",
            "effect": "read",
            "identity": "service",
            "resources": [{"type": "tracker.issue", "args": ["id"]}],
            "binding": {
                "method": "GET",
                "path": "/issue/{id}",
                "input_schema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            },
            "description": "one issue",
        },
        actor=TEST_ACTOR,
    )


def test_a_reference_returns_a_shared_credential_and_not_a_third_source(a_vault):
    """**The decision that could not have been corrected later.** `source` says whose
    account a call went out as and is written to an append-only audit table; a pointer is
    an *encoding*. A fourth value here would have made every existing query for "calls
    made as the caller" quietly wrong on a table nothing can rewrite."""
    credential = credentials.for_connector(
        "tracker",
        Principal.system("cli", TEST_TENANT),
        ref="op://Engineering/GitHub Deploy Key/credential",
    )
    assert credential.value == "ghp_the_real_one"
    assert credential.source == credentials.SHARED


def test_a_reference_and_a_variable_are_indistinguishable_above_for_tool(
    a_vault, monkeypatch
):
    """067's first constraint: nothing above `for_tool` learns anything. The two shapes
    return the same `ToolCredentials`, field for field."""
    monkeypatch.setenv("TRACKER_TOKEN", "ghp_the_real_one")
    principal = Principal.system("cli", TEST_TENANT)

    from_env = credentials.for_tool(
        "tracker_get_issue", {}, principal, connector="tracker", env_var="TRACKER_TOKEN"
    )
    from_vault = credentials.for_tool(
        "tracker_get_issue",
        {},
        principal,
        connector="tracker",
        credential_ref="op://Engineering/GitHub Deploy Key/credential",
    )
    assert from_env == from_vault


def test_both_a_variable_and_a_reference_is_refused_at_the_read(a_vault):
    """Refused at registration too, and again here for `egress.check`'s reason: a stored
    row outlives the moment it was written, and a path may have skipped the check."""
    with pytest.raises(credentials.CredentialError) as caught:
        credentials.for_connector(
            "tracker",
            Principal.system("cli", TEST_TENANT),
            "TRACKER_TOKEN",
            ref="op://Engineering/GitHub Deploy Key/credential",
        )
    assert "no rule for which wins" in str(caught.value)


def test_a_broken_reference_refuses_rather_than_calling_unauthenticated(a_vault):
    """`_shared_credential` returns None for an unset variable because *no credential
    configured* is a legal state a server answers 401 to. A pointer is not that: somebody
    said there is a credential and where it lives, so a pointer that does not resolve is
    broken rather than absent."""
    with pytest.raises(credentials.CredentialError) as caught:
        credentials.for_connector(
            "tracker",
            Principal.system("cli", TEST_TENANT),
            ref="op://Engineering/Nope/credential",
        )
    message = str(caught.value)
    assert message.startswith("'tracker': ")
    assert "op://Engineering/Nope/credential" in message


def test_both_set_is_refused_at_registration(a_vault):
    with pytest.raises(tools.RegistrationRefused) as caught:
        _connector_with(
            a_vault,
            credential_env="TRACKER_TOKEN",
            credential_ref="op://Engineering/GitHub Deploy Key/credential",
        )
    assert "not both" in str(caught.value)


def test_a_reference_survives_the_manifest_round_trip(a_vault):
    _connector_with(a_vault, credential_ref="op://Engineering/GitHub Deploy Key/credential")
    from carnet.tools import mcp

    connector = mcp.get_connector(TEST_TENANT, "tracker")
    assert connector.launch.credential_ref == (
        "op://Engineering/GitHub Deploy Key/credential"
    )
    assert connector.launch.credential_env is None


def test_a_changed_reference_makes_a_bound_tool_stale(a_vault):
    """`_BOUND` snapshots a `Tool`, and the broker reads `credential_ref` off it — so an
    administrator who repoints a connector at a different vault item would otherwise see
    the screen agree with them while every call kept reading the old one until a restart.
    033a's stale-`identity` defect at an address where the stale value decides which
    secret is sent to a vendor."""
    _connector_with(a_vault, credential_ref=f"op://{VAULT_ID}/{ITEM_ID}/credential")
    from carnet.tools import mcp

    connector = mcp.get_connector(TEST_TENANT, "tracker")
    for tool in tools.rest.bind(TEST_TENANT, connector):
        tools.register(TEST_TENANT, tool)
    assert tools.get("tracker_get_issue", TEST_TENANT) is not None

    storage.active().delete_connector(TEST_TENANT, "tracker", actor=TEST_ACTOR)
    _connector_with(a_vault, credential_ref=f"op://{VAULT_ID}/{ITEM_ID}/Staging/credential")

    moved = mcp.get_connector(TEST_TENANT, "tracker")
    assert tools._stale_names(moved, TEST_TENANT) == {"tracker_get_issue"}


def test_a_stdio_launch_has_no_reference_at_all(a_vault):
    """Decision 2. A stdio server takes its credential at spawn and holds it for the
    process's life, so a pointer there would be resolved once and held for hours — the
    strongest claim in the product made about the weakest shape."""
    from carnet.tools.mcp.binding import StdioLaunch

    assert not hasattr(StdioLaunch(command=("x",)), "credential_ref")


# --- the audit row, which is the done-when 067 got wrong ------------------------------


def _brokered(monkeypatch, **credential):
    """One brokered call through a connector tool, and the audit row it wrote."""
    from carnet import tools as tool_registry
    from carnet.core import broker
    from carnet.tools.base import Resource, Tool

    seen = {}
    tool = Tool(
        name="tracker_get_issue",
        description="",
        input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
        impl=lambda id, token=None: seen.setdefault("token", token) and {"ok": True},
        effect="read",
        resources=[Resource("tracker.issue", "id")],
        connector="tracker",
        identity="service",
        **credential,
    )
    monkeypatch.setitem(tool_registry.REGISTRY, tool.name, tool)

    agent = {
        "name": "measured",
        "system": "irrelevant",
        "runtime": "simple",
        "permissions": {
            "tools": ["tracker_get_issue"],
            "scope": {"tracker.issue": {"read": ["*"]}},
        },
    }
    ctx = run_context(Principal.system("test", TEST_TENANT))
    broker.call(ctx, agent, "tracker_get_issue", {"id": "1"})
    return seen, storage.active().audit_records(TEST_TENANT)[-1]


def test_a_pointer_call_and_an_env_call_are_the_same_audit_row(a_vault, monkeypatch):
    """**067's done-when asked for the wrong thing and the truth is stricter.**

    It says *"the audit row is identical to a sealed-credential call except for the
    credential kind."* There is no such exception available: `audit.record`'s `credential`
    parameter takes `source` and nothing else, and `credential_kind` has never been in an
    audit row at all — it is a `connections` column that `access_token` reads and nothing
    downstream ever sees.

    So the rows are identical, full stop. Which is the right answer: the log records whose
    account a call was made from, and that is the same organisational account whether the
    secret came out of this process's environment or out of the customer's vault.
    """
    monkeypatch.setenv("TRACKER_TOKEN", "ghp_the_real_one")

    from_env, env_row = _brokered(monkeypatch, credential_env="TRACKER_TOKEN")
    from_vault, vault_row = _brokered(
        monkeypatch, credential_ref="op://Engineering/GitHub Deploy Key/credential"
    )

    # The same secret arrived by two routes, so any difference in the rows is about the
    # route rather than about the value.
    assert from_env["token"] == from_vault["token"] == "ghp_the_real_one"

    volatile = {"ts", "id", "run_id", "duration_ms"}
    assert {k: v for k, v in env_row.items() if k not in volatile} == {
        k: v for k, v in vault_row.items() if k not in volatile
    }
    assert vault_row["credential"] == credentials.SHARED


def test_a_vault_that_is_down_makes_the_tool_unavailable_and_names_the_vault(
    a_vault, monkeypatch
):
    """The refusal reaches the **model**, through the broker's `CredentialError` branch,
    and it must not read as a generic credential error. 033b's lesson: a true-sounding
    sentence that sends somebody to the wrong fix is worse than a blunt one."""
    _, server = a_vault
    server.shutdown()
    server.server_close()

    _, row = _brokered(
        monkeypatch, credential_ref="op://Engineering/GitHub Deploy Key/credential"
    )
    assert row["decision"] == "allow"
    assert row["outcome"] == "error"
    reason = row["reason"]
    assert "op://Engineering/GitHub%20Deploy%20Key/credential" in reason
    assert config.VAULT_URL in reason
    assert "not a permission problem" in reason


def test_no_refusal_ever_carries_the_secret(a_vault, monkeypatch):
    """The value is what this whole module handles, and none of the nine sentences may
    contain it. Checked against every refusal rather than against the interesting ones."""
    base = f"op://{VAULT_ID}/{ITEM_ID}"
    stub, _ = a_vault
    cases = [f"{base}/nope", f"{base}/blank", "op://Nope/x/y", "op://Engineering/Nope/y"]
    for pointer in cases:
        with pytest.raises(vault.VaultError) as caught:
            vault.resolve(vault.parse(pointer))
        for secret in ("ghp_the_real_one", "found-by-id", "by-purpose", "the-staging-one"):
            assert secret not in str(caught.value)

    stub.status = 403
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"{base}/credential"))
    assert "connect-token" not in str(caught.value)


def test_a_field_with_a_line_break_is_refused_before_it_reaches_a_header(a_vault):
    """**A tenth refusal, found by driving rather than by planning.**

    Plan 070 enumerated nine, and none of them is this — nothing about a *sealed*
    credential suggests it. A 1Password field is often a note, a note is where somebody
    pastes a key, and a credential goes into an `Authorization` header, which cannot carry
    a line break. Without this the model is told *"Invalid leading whitespace, reserved
    character(s), or return character(s) in header value"* by `requests`, two layers down:
    true, and about the wrong subject.
    """
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/notes"))
    assert caught.value.reason == vault.UNUSABLE
    message = str(caught.value)
    assert "line break" in message
    assert "multi-line note" in message
    # Not trimmed for them, and not printed at them.
    assert "line one" not in message


def test_a_wrong_id_is_a_missing_item_rather_than_a_bare_404(a_vault):
    """An id-addressed reference skips the lookup that produces cases 6 and 7, so a typo
    lands on the raw status — and *"the vault answered HTTP 404"* sends nobody anywhere.
    A 26-character id is not something anybody eyeballs."""
    stub, _ = a_vault
    stub.status = 404
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{'z' * 26}/credential"))
    assert caught.value.reason == vault.NO_ITEM
    assert "addresses by id rather than by name" in str(caught.value)


def test_a_404_on_a_list_endpoint_is_not_blamed_on_an_id_nobody_wrote(a_vault):
    """A name-addressed reference has no id in it, so *"addresses by id"* was false of
    the reference and sent somebody to check a 26-character string they never typed.
    A 404 on `/v1/vaults` is a URL that is not Connect — a proxy with no such route."""
    stub, _ = a_vault
    stub.status = 404
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.NO_ITEM
    message = str(caught.value)
    assert "addresses by id" not in message
    assert "answered HTTP 404" in message
    assert "does not point at a 1Password Connect server" in message
    assert "removed between lookup and read" in message
    assert "--check-credential" in message


def test_a_404_after_a_successful_lookup_says_the_item_vanished_not_the_id(a_vault):
    """The ids in the item fetch came from the vault's own answer a moment ago, so a
    404 there is the item going away between two requests, never a typo."""
    stub, _ = a_vault
    stub.item_status = 404
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse("op://Engineering/GitHub Deploy Key/credential"))
    assert caught.value.reason == vault.NO_ITEM
    message = str(caught.value)
    assert "addresses by id" not in message
    assert "removed between lookup and read" in message
    # The failing path is named, so the two causes can be told apart at a shell.
    assert f"/v1/vaults/{VAULT_ID}/items/{ITEM_ID}" in message


def test_a_vault_by_name_and_an_item_by_id_blames_the_id_on_a_404(a_vault):
    """Mixed addressing: the vault id came from the lookup but the item id is the
    customer's, so a 404 on the read is a wrong id and says so."""
    stub, _ = a_vault
    stub.item_status = 404
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://Engineering/{'z' * 26}/credential"))
    assert caught.value.reason == vault.NO_ITEM
    assert "addresses by id rather than by name" in str(caught.value)


# --- what a misbehaving vault can and cannot do to a door call -----------------------
#
# `Stub` is a well-behaved HTTP server, so it cannot express the shapes that actually
# hurt: a body delivered a byte at a time, a body with no end, a redirect. Those need a
# raw socket, and they are the three that a mocked resolver — or a polite stub — will
# never show.


def _raw_vault(monkeypatch, handler, budget=0.4):
    """A socket that speaks whatever `handler` writes. Returns nothing; configures the
    vault. Threads are daemons and the socket closes with the test."""
    import socket

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def accept():
        while True:
            try:
                connection, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    monkeypatch.setattr(config, "VAULT_URL", f"http://127.0.0.1:{server.getsockname()[1]}")
    monkeypatch.setattr(config, "VAULT_TOKEN", "connect-token")
    monkeypatch.setattr(config, "VAULT_TIMEOUT_SECONDS", budget)
    return server


def _drip(body, per_byte=0.1):
    def handler(connection):
        try:
            connection.recv(65536)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body)
            )
            for byte in body:
                connection.sendall(bytes([byte]))
                time.sleep(per_byte)
        except OSError:
            pass
        finally:
            connection.close()

    return handler


def test_a_vault_that_answers_a_byte_at_a_time_is_bounded_by_the_budget(monkeypatch):
    """**The bug this was written for, and it was mine.**

    `requests`' read timeout is *between* reads, so a server that never stalls longer than
    the timeout never trips it — and a blocking `read(n)` returns only when `n` bytes have
    arrived. With the body buffered in one call, a **0.4s budget produced a measured 5.92s
    hold** on the door's hot path, holding an MCP request open the whole time, while
    `_Deadline`, `config.CARNET_VAULT_TIMEOUT_SECONDS` and the refusal sentence all
    claimed a whole-resolution budget.

    A timeout that is only true of a server that stops answering is not the timeout
    anybody set. The body is read byte by byte against the clock now, which is why
    `_CHUNK` is 1 and why that is a decision rather than a default.
    """
    server = _raw_vault(monkeypatch, _drip(b'[{"id":"' + b"b" * 26 + b'","name":"Engineering"}]'))
    try:
        started = time.monotonic()
        with pytest.raises(vault.VaultError) as caught:
            vault.resolve(vault.parse("op://Engineering/Item/credential"))
        elapsed = time.monotonic() - started
    finally:
        server.close()

    assert caught.value.reason == vault.UNREACHABLE
    # The body alone is 5.8s of drip. Anything near that is the defect back.
    assert elapsed < 1.5, f"a 0.4s budget took {elapsed:.2f}s"


def test_a_large_body_dripping_is_bounded_too(monkeypatch):
    """The case a *coarser* chunk gets wrong in the other direction: at 256 bytes a
    granularity, a body arriving at one byte per 100ms overshoots a 0.4s budget by 25
    seconds. The small body above cannot show that, because it is under one chunk."""

    def handler(connection):
        try:
            connection.recv(65536)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 40000\r\n\r\n"
            )
            while True:
                connection.sendall(b"x")
                time.sleep(0.1)
        except OSError:
            pass
        finally:
            connection.close()

    server = _raw_vault(monkeypatch, handler)
    try:
        started = time.monotonic()
        with pytest.raises(vault.VaultError):
            vault.resolve(vault.parse("op://Engineering/Item/credential"))
        elapsed = time.monotonic() - started
    finally:
        server.close()
    assert elapsed < 1.5, f"a 0.4s budget took {elapsed:.2f}s"


def test_a_body_with_no_end_is_refused_at_the_ceiling(monkeypatch):
    """The same hold with the clock taken out: a vault that keeps writing holds an MCP
    request open for as long as it keeps writing, and no timeout fires because data never
    stops arriving. `MAX_VAULT_RESPONSE_BYTES` is the bound, and it is 64 KiB rather than
    a megabyte because a byte-granular read of a megabyte is 1.5 seconds of CPU."""

    def handler(connection):
        try:
            connection.recv(65536)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
            )
            while True:
                connection.sendall(b"x" * 8192)
        except OSError:
            pass
        finally:
            connection.close()

    server = _raw_vault(monkeypatch, handler, budget=30.0)
    try:
        started = time.monotonic()
        with pytest.raises(vault.VaultError) as caught:
            vault.resolve(vault.parse("op://Engineering/Item/credential"))
        elapsed = time.monotonic() - started
    finally:
        server.close()

    assert caught.value.reason == vault.UNREACHABLE
    assert "longer than" in str(caught.value)
    # Refused on size, not on the 30s clock — which is the point.
    assert elapsed < 5.0


def test_a_redirect_is_named_rather_than_read_as_a_login_page(monkeypatch):
    """`egress.dial` never follows one, because a 3xx points somewhere no check saw — and
    064 says deciding what a refusal *means* is the caller's job. Without this branch it
    falls through to the not-JSON sentence, which describes a proxy or a login page; the
    common cause is a Connect deployment behind a front door that upgrades http to https,
    and the fix is the URL."""

    def handler(connection):
        try:
            connection.recv(65536)
            connection.sendall(
                b"HTTP/1.1 302 Found\r\nLocation: https://vault.acme/v1/vaults\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        except OSError:
            pass
        finally:
            connection.close()

    server = _raw_vault(monkeypatch, handler)
    try:
        with pytest.raises(vault.VaultError) as caught:
            vault.resolve(vault.parse("op://Engineering/Item/credential"))
    finally:
        server.close()

    message = str(caught.value)
    assert "redirect, which is not followed" in message
    assert "https://vault.acme/v1/vaults" in message
    assert "nothing was sent to that address" in message


def test_an_unqualified_pointer_falls_through_to_a_sectioned_field(a_vault):
    """**A divergence from 1Password that the first build shipped.**

    `op://…/credential` resolves against the *whole item* in 1Password's own tooling. The
    first `_field_of` searched sectionless fields and stopped — so a reference the
    vendor's own CLI reads was refused here, which is the kind of difference nobody would
    think to look for. Sectionless fields are still tried **first**, so adding a section
    to an item cannot change what an existing reference already resolves to; they are just
    no longer the only tier.
    """
    # `notes` is sectionless; `Staging/credential` is not, and `credential` is also a
    # sectionless label — so this asserts the fallback without disturbing the preference,
    # which the next test pins.
    labels = vault.describe_fields(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential"))
    assert "Prod/token" in labels and "Dev/token" in labels
    # Nothing sectionless is called `token`, so the second tier is the only way to it —
    # and there are two, which is the next test.


def test_two_fields_with_one_name_are_refused_rather_than_guessed(a_vault):
    """**The bug this replaced, and it is the sharpest one in the step.**

    Two fields called `token` in two sections. The first build returned whichever the
    vendor happened to list first — silently deciding *which secret gets sent to a
    vendor*, which is the exact guess `_one_id` already refuses one level up about two
    vaults sharing a name. The module was inconsistent with itself.
    """
    with pytest.raises(vault.VaultError) as caught:
        vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/token"))
    assert caught.value.reason == vault.AMBIGUOUS
    message = str(caught.value)
    assert "2 fields called 'token'" in message
    assert "nothing was guessed" in message
    # The sections are not named here for the same reason the labels are not: this
    # sentence reaches whoever holds the calling token.
    assert "Prod" not in message and "Dev" not in message
    for secret in ("prod-token", "dev-token"):
        assert secret not in message


def test_naming_the_section_resolves_what_was_ambiguous(a_vault):
    """The remedy the refusal points at actually works — otherwise it is a dead end
    wearing a sentence."""
    base = f"op://{VAULT_ID}/{ITEM_ID}"
    assert vault.resolve(vault.parse(f"{base}/Prod/token")) == "prod-token"
    assert vault.resolve(vault.parse(f"{base}/Dev/token")) == "dev-token"


def test_a_sectionless_field_still_wins_over_a_sectioned_one_with_the_same_label(a_vault):
    """The half of the ordering that must not move: `credential` exists sectionless and
    inside `Staging`, and the unqualified reference resolves to the sectionless one. If
    the tiers ever flip, an existing reference silently starts sending a different
    secret."""
    assert vault.resolve(vault.parse(f"op://{VAULT_ID}/{ITEM_ID}/credential")) == (
        "ghp_the_real_one"
    )


def test_three_hops_share_one_connection(a_vault):
    """**Two corrections in one, and neither is visible on loopback.**

    The session used to be created per request, inside `_get`. That was wrong twice: the
    streamed body was read *after* the `with` had closed the session — working only
    because urllib3's response holds its own connection, which is not a promise anybody
    made — and a name-addressed reference paid a fresh TCP **and TLS** handshake on each
    of its three hops, on the door's hot path, against a vault that is almost always
    https.

    Counted at the server, because a timing assertion would prove nothing here: the stub
    is on loopback with no TLS, which is exactly why this needed a test rather than a
    measurement.
    """
    stub, server = a_vault
    server.connections = 0
    original = server.process_request

    def counted(request, client_address):
        server.connections += 1
        return original(request, client_address)

    server.process_request = counted

    assert vault.resolve(
        vault.parse("op://Engineering/GitHub Deploy Key/credential")
    ) == "ghp_the_real_one"

    assert len(stub.hits) == 3, "three hops, or this asserts nothing"
    assert server.connections == 1, (
        f"three hops opened {server.connections} connections; over https that is "
        f"{server.connections} TLS handshakes for one credential"
    )


# --- the settings, refused at load rather than at the first pointer ------------------
#
# `core/vault` dials under operator consent and skips `egress.check`, which is the one
# place the https rule lives — so it is applied again in `config._vault`, at load, with
# `egress.check`'s own sentence. Tested the way `_retention_days` is: the
# parser called directly under a patched environment.


def _vault_setting(monkeypatch, url=None, token=None, timeout=None, internal=()):
    for name, value in (
        ("CARNET_VAULT_URL", url),
        ("CARNET_VAULT_TOKEN", token),
        ("CARNET_VAULT_TIMEOUT_SECONDS", timeout),
    ):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr(config, "EGRESS_INTERNAL_HOSTS", frozenset(internal))
    return config._vault()


def test_no_vault_is_the_default_and_says_nothing(monkeypatch):
    assert _vault_setting(monkeypatch) == ("", "", 3.0)
    assert _vault_setting(monkeypatch, url="", token="  ") == ("", "", 3.0)


def test_a_plain_http_vault_url_is_refused_at_load(monkeypatch):
    """The Connect token would go out in clear on every door call, and nothing on the
    dial path would say so: `egress.check` is skipped under operator consent."""
    with pytest.raises(ValueError) as raised:
        _vault_setting(monkeypatch, url="http://vault.example.com", token="t")
    said = str(raised.value)
    assert "CARNET_VAULT_URL" in said and "not https" in said
    assert "CARNET_VAULT_TOKEN" in said and "in clear" in said
    assert "Use https" in said and "CARNET_EGRESS_INTERNAL_HOSTS" in said


def test_a_plain_http_vault_on_the_operators_own_network_is_accepted(monkeypatch):
    """The same consent boundary 058 drew for private addresses: a name the operator
    listed is theirs, and TLS-optional there is the operator's call. Matched the way
    `_internal_hosts` stores it — lower-cased, trailing dot dropped."""
    url, token, timeout = _vault_setting(
        monkeypatch,
        url="http://Connect.acme.internal.:8080",
        token="t",
        internal={"connect.acme.internal"},
    )
    assert url == "http://Connect.acme.internal.:8080"
    assert token == "t"
    assert timeout == 3.0
    assert _vault_setting(monkeypatch, url="https://vault.example.com", token="t")[0]


@pytest.mark.parametrize("url", ["vault.example.com", "https://", "not a url", "op://x"])
def test_a_vault_url_without_a_host_is_refused(monkeypatch, url):
    with pytest.raises(ValueError) as raised:
        _vault_setting(monkeypatch, url=url, token="t")
    assert "CARNET_VAULT_URL" in str(raised.value)
    assert "scheme and a host" in str(raised.value)


def test_a_url_without_a_token_is_refused(monkeypatch):
    """Half a vault: every request would 401 and the refusal would blame the token."""
    with pytest.raises(ValueError) as raised:
        _vault_setting(monkeypatch, url="https://vault.example.com")
    said = str(raised.value)
    assert said.startswith("CARNET_VAULT_URL is set but CARNET_VAULT_TOKEN is not")
    assert "backend/.env" in said


def test_a_token_without_a_url_is_refused(monkeypatch):
    """The other half: a secret in the environment that nothing would ever read."""
    with pytest.raises(ValueError) as raised:
        _vault_setting(monkeypatch, token="ops_secret")
    said = str(raised.value)
    assert said.startswith("CARNET_VAULT_TOKEN is set but CARNET_VAULT_URL is not")
    assert "ops_secret" not in said


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "three", ""])
def test_a_timeout_that_is_not_a_positive_number_is_refused(monkeypatch, value):
    """A zero budget is a `_Deadline` that expires before its first request; `nan`
    passes every comparison a naive check would make. Empty is the default, not a
    refusal — that is the only one of these that is fine."""
    if value == "":
        assert _vault_setting(monkeypatch, timeout=value)[2] == 3.0
        return
    with pytest.raises(ValueError) as raised:
        _vault_setting(monkeypatch, timeout=value)
    said = str(raised.value)
    assert "CARNET_VAULT_TIMEOUT_SECONDS" in said and value in said
    assert "positive number of seconds" in said


def test_a_timeout_is_a_float_and_a_whole_budget(monkeypatch):
    assert _vault_setting(monkeypatch, timeout="0.4")[2] == 0.4
    assert _vault_setting(monkeypatch, timeout=" 12 ")[2] == 12.0
