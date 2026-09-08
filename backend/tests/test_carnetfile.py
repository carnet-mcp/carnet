"""`carnet.yaml`, the fileborne door. Step 095.

The file is edited by a person who cannot see a stack trace, so the refusals get more
attention than the happy path — each one is asserted to name the key it is about. The
happy path is asserted the only way that means anything: a token from the file presents
itself at `/mcp`, sees exactly what its agent grants, and a call goes out under the
connector's `${ENV}` credential through the unchanged door.
"""

import json
import sys
import textwrap

import pytest
from fastapi.testclient import TestClient

from carnet import bootstrap, carnetfile, cli, config, storage, tools
from carnet.access import tokens
from carnet.api import create_app
from carnet.tools import mcp
from carnet.tools.mcp.client import SessionPool
from conftest import TEST_HOST, TEST_TENANT, read_audit

TOKEN = tokens.new_presented()
JIRA = "jira-secret"

ADVERTISED = [
    {
        "name": "search",
        "description": "Search issues.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "jql": {"type": "string"}},
            "required": ["project"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "create",
        "description": "Open an issue.",
        "inputSchema": {
            "type": "object",
            "properties": {"project": {"type": "string"}, "title": {"type": "string"}},
            "required": ["project", "title"],
        },
    },
]


class EchoTransport:
    """Answers every call with the credential its session was built on — the trick
    `test_door.py` uses, and the only way to assert whose account a call went out as."""

    def __init__(self, credential):
        self.credential = credential

    def send(self, message):
        if "id" not in message:
            return None
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "jira", "version": "1.0"},
            }
        elif method == "tools/list":
            result = {"tools": ADVERTISED}
        elif method == "tools/call":
            result = {
                "content": [
                    {"type": "text", "text": json.dumps({"acted_as": self.credential})}
                ]
            }
        else:  # pragma: no cover
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"message": "?"}}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    def set_protocol_version(self, version):
        pass

    def close(self):
        pass


@pytest.fixture(autouse=True)
def faked_transport(monkeypatch):
    monkeypatch.setattr(mcp, "POOL", SessionPool())
    monkeypatch.setattr(
        mcp, "_transport_for", lambda tenant_id, conn, credential: EchoTransport(credential)
    )


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("JIRA_TOKEN", JIRA)
    monkeypatch.setenv("CARNET_TOKEN_ALICE", TOKEN)


THE_FILE = textwrap.dedent(
    f"""
    connectors:
      jira:
        url: https://{TEST_HOST}/mcp/
        credential: ${{JIRA_TOKEN}}
        description: Jira
        tools:
          - name: search
            effect: read
            resources:
              - type: jira.project
                args: [project]
          - name: create
            effect: write
            resources:
              - type: jira.project
                args: [project]
            note: Notifies everyone watching the project.

    agents:
      triage:
        tools: [jira_search]
        scope:
          jira.project: {{read: [ACME]}}

    tokens:
      alice-laptop:
        secret: ${{CARNET_TOKEN_ALICE}}
        agents: [triage]
    """
)


def write(tmp_path, text: str) -> str:
    path = tmp_path / "carnet.yaml"
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return str(path)


def refusal(tmp_path, text: str, environ=None) -> str:
    with pytest.raises(carnetfile.CarnetFileError) as caught:
        carnetfile.load(write(tmp_path, text), environ=environ)
    return str(caught.value)


def loaded(tmp_path, text: str = THE_FILE):
    """The file, applied to the test's own store — what boot does."""
    declaration = carnetfile.load(write(tmp_path, text))
    return carnetfile.apply(TEST_TENANT, declaration)


@pytest.fixture
def client():
    return TestClient(create_app())


def rpc(client, method, params=None, token=TOKEN):
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


# --- the happy path, end to end -------------------------------------------------------


def test_the_file_comes_up_as_rows_the_door_reads(tmp_path, client):
    summary = loaded(tmp_path)
    assert (summary.connectors, summary.tools, summary.agents, summary.tokens) == (
        1,
        2,
        1,
        1,
    )

    listed = rpc(client, "tools/list")["result"]["tools"]
    assert [t["name"] for t in listed] == ["jira_search"]
    assert listed[0]["annotations"] == {"readOnlyHint": True}


def test_a_call_goes_out_under_the_pointed_credential(tmp_path, client):
    loaded(tmp_path)
    result = rpc(
        client,
        "tools/call",
        {"name": "jira_search", "arguments": {"project": "ACME"}},
    )["result"]
    assert json.loads(result["content"][0]["text"]) == {"acted_as": JIRA}

    (record,) = [r for r in read_audit() if r["outcome"]]
    assert record["decision"] == "allow"
    assert record["agent"] == "triage"
    assert record["credential"] == "shared"
    assert record["principal_kind"] == "machine"


def test_a_tool_the_agent_does_not_carry_is_refused_by_the_door(tmp_path, client):
    loaded(tmp_path)
    answer = rpc(client, "tools/call", {"name": "jira_create", "arguments": {}})
    assert "no agent this token is granted provides a tool called 'jira_create'" in (
        answer["error"]["message"]
    )


def test_a_call_outside_scope_is_refused_by_the_broker_with_a_record(tmp_path, client):
    loaded(tmp_path)
    answer = rpc(
        client, "tools/call", {"name": "jira_search", "arguments": {"project": "OTHER"}}
    )["result"]
    assert answer.get("isError") or "error" in json.dumps(answer).lower()
    (record,) = read_audit()
    assert record["decision"] == "deny"


def test_the_shipped_example_is_not_in_a_store_loaded_from_a_file(tmp_path, monkeypatch):
    path = write(tmp_path, THE_FILE)
    monkeypatch.setattr(config, "CARNET_FILE", path)
    monkeypatch.setattr(config, "DATABASE_URL", None)
    storage.reset()
    tools.reset_bound()
    try:
        store = bootstrap.configure(TEST_TENANT, seed=True)
        assert store.get_agent(TEST_TENANT, "issue-reporter") is None
        assert store.get_agent(TEST_TENANT, "triage") is not None
        assert [c.id for c in mcp.connectors_for(TEST_TENANT)] == ["jira"]
    finally:
        storage.reset()
        tools.reset_bound()


def test_the_host_is_allowed_from_the_url(tmp_path):
    declaration = carnetfile.load(write(tmp_path, THE_FILE))
    carnetfile.apply("fresh", declaration)
    hosts = storage.active().allowed_hosts("fresh")
    assert [h["host"] for h in hosts] == [TEST_HOST]
    assert hosts[0]["note"] == "carnet.yaml"


def test_the_token_has_a_live_owner_and_resolves_like_a_minted_one(tmp_path):
    loaded(tmp_path)
    principal = tokens.resolve(TOKEN)
    assert principal.kind == "machine"
    row = storage.active().find_api_token(principal.id)
    assert row["name"] == "alice-laptop"
    owner = storage.active().get_user(TEST_TENANT, row["owner_id"])
    assert owner["issuer"] == carnetfile.FILE_ISSUER
    assert owner["status"] == "active"


def test_a_rest_tool_is_declared_with_its_binding_and_listed(tmp_path, client, monkeypatch):
    """A REST API does not describe itself, so listing it needs no dial — the binding
    the file authored is the whole descriptor."""
    monkeypatch.setenv("WEATHER_KEY", "wk")
    loaded(
        tmp_path,
        f"""
        connectors:
          weather:
            kind: rest
            url: https://{TEST_HOST}
            credential: ${{WEATHER_KEY}}
            credential_header: x-api-key
            credential_prefix: ""
            tools:
              - name: forecast
                effect: read
                method: GET
                path: /forecast/{{city}}
                schema:
                  type: object
                  properties: {{city: {{type: string}}}}
                  required: [city]
        agents:
          weather:
            tools: [weather_forecast]
        tokens:
          alice-laptop:
            secret: ${{CARNET_TOKEN_ALICE}}
            agents: [weather]
        """,
    )
    listed = rpc(client, "tools/list")["result"]["tools"]
    assert [t["name"] for t in listed] == ["weather_forecast"]


# --- the refusals, each naming its key ----------------------------------------------


def test_a_literal_credential_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            credential: hunter2
        """,
    )
    assert message.startswith(f"{tmp_path / 'carnet.yaml'}: connectors.jira.credential")
    assert "meant to be committed" in message


def test_a_literal_token_secret_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        """
        agents:
          a: {tools: [post_message]}
        tokens:
          t:
            secret: art_m_1234.abcd
            agents: [a]
        """,
    )
    assert "tokens.t.secret" in message
    assert "${VARIABLE}" in message


def test_an_unset_pointer_names_the_variable(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            credential: ${{NOT_SET_ANYWHERE}}
        """,
        environ={},
    )
    assert "connectors.jira.credential" in message
    assert "${NOT_SET_ANYWHERE} is not set" in message


def test_a_platform_variable_as_a_pointer_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            credential: ${{CARNET_SECRET_KEY}}
        """,
        environ={"CARNET_SECRET_KEY": "x"},
    )
    assert "names one of Carnet's own settings" in message


def test_a_variable_that_is_not_a_token_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        """
        agents:
          a: {tools: [post_message]}
        tokens:
          t:
            secret: ${MY_PASSWORD}
            agents: [a]
        """,
        environ={"MY_PASSWORD": "correct horse battery staple"},
    )
    assert "tokens.t.secret" in message
    assert "carnet --new-token" in message


def test_unknown_keys_name_the_path_at_every_level(tmp_path):
    assert "the document — unknown key(s) connectorz" in refusal(
        tmp_path, "connectorz: {}"
    )
    assert "connectors.jira — unknown key(s) command" in refusal(
        tmp_path, "connectors:\n  jira:\n    url: https://x\n    command: [npx]"
    )
    assert "connectors.jira.tools[0] — unknown key(s) effekt" in refusal(
        tmp_path,
        f"connectors:\n  jira:\n    url: https://{TEST_HOST}/\n    tools:\n"
        "      - name: a\n        effekt: read",
    )
    assert "agents.a — unknown key(s) tool" in refusal(
        tmp_path, "agents:\n  a:\n    tool: [x]"
    )
    assert "tokens.t — unknown key(s) agent" in refusal(
        tmp_path, "tokens:\n  t:\n    agent: [x]"
    )


def test_user_identity_is_refused_with_the_platform_sentence(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            tools:
              - name: search
                effect: read
                identity: user
        """,
    )
    assert "connectors.jira.tools[0].identity" in message
    assert "nobody signs in" in message
    assert "the same image with a database" in message


def test_stdio_is_refused_with_the_shim_sentence(tmp_path):
    message = refusal(
        tmp_path,
        """
        connectors:
          local:
            kind: stdio
            url: npx some-server
        """,
    )
    assert "connectors.local.kind" in message
    assert "mcp-proxy" in message


def test_effect_is_required_and_must_be_read_or_write(tmp_path):
    base = f"connectors:\n  jira:\n    url: https://{TEST_HOST}/\n    tools:\n      - name: a\n"
    assert "connectors.jira.tools[0].effect — is required" in refusal(tmp_path, base)
    assert "'append' is not an effect" in refusal(tmp_path, base + "        effect: append")


def test_a_grant_must_name_a_declared_local_name(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            tools:
              - name: search
                effect: read
        agents:
          triage:
            tools: [search]
        """,
    )
    assert "agents.triage.tools[0]" in message
    assert "'search' is not a tool this file declares" in message
    assert "Declared: jira_search" in message


def test_a_token_must_name_a_declared_agent_and_at_least_one(tmp_path):
    assert "tokens.t.agents[0] — 'nope' is not an agent" in refusal(
        tmp_path,
        "agents:\n  a: {tools: [post_message]}\ntokens:\n  t:\n    secret: ${CARNET_TOKEN_ALICE}\n    agents: [nope]",
    )
    assert "tokens.t.agents — a token granted nothing" in refusal(
        tmp_path,
        "tokens:\n  t:\n    secret: ${CARNET_TOKEN_ALICE}\n    agents: []",
    )


def test_two_tokens_sharing_one_secret_are_refused(tmp_path):
    message = refusal(
        tmp_path,
        """
        agents:
          a: {tools: [post_message]}
        tokens:
          one:
            secret: ${CARNET_TOKEN_ALICE}
            agents: [a]
          two:
            secret: ${CARNET_TOKEN_ALICE}
            agents: [a]
        """,
    )
    assert "tokens.two.secret — is the same token as tokens.one" in message


def test_a_rest_tool_without_its_binding_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          w:
            kind: rest
            url: https://{TEST_HOST}
            tools:
              - name: forecast
                effect: read
                method: GET
        """,
    )
    assert "connectors.w.tools[0] — a rest tool needs path, schema" in message


def test_a_binding_on_an_mcp_tool_is_an_unknown_key(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            tools:
              - name: search
                effect: read
                method: GET
        """,
    )
    assert "connectors.jira.tools[0] — unknown key(s) method" in message


def test_egress_rules_still_stand(tmp_path):
    """The host is allowed from the URL; the reasons the check exists are not waived."""

    def applying(text):
        with pytest.raises(carnetfile.CarnetFileError) as caught:
            carnetfile.apply("t", carnetfile.load(write(tmp_path, text)))
        return str(caught.value)

    plain_http = applying("connectors:\n  a:\n    url: http://api.example.net/mcp/")
    assert "connectors.a" in plain_http
    assert "https" in plain_http

    metadata = applying("connectors:\n  b:\n    url: https://169.254.169.254/")
    assert "connectors.b" in metadata
    assert "will not be dialled" in metadata


def test_a_scope_naming_an_effect_that_is_not_one_is_refused(tmp_path):
    message = refusal(
        tmp_path,
        f"""
        connectors:
          jira:
            url: https://{TEST_HOST}/mcp/
            tools: [{{name: search, effect: read}}]
        agents:
          a:
            tools: [jira_search]
            scope:
              jira.project: {{append: [X]}}
        """,
    )
    assert "agents.a.scope.jira.project — unknown key(s) append" in message


def test_a_missing_file_says_how_to_mount_it(tmp_path):
    with pytest.raises(carnetfile.CarnetFileError) as caught:
        carnetfile.load(str(tmp_path / "absent.yaml"))
    assert "no such file" in str(caught.value)
    assert "-v ./carnet.yaml:/carnet.yaml" in str(caught.value)


def test_a_directory_at_the_path_says_what_docker_did(tmp_path):
    """Found by the artefact e2e: a bind mount whose host path does not exist arrives
    as an empty directory, and a stranger's first `docker run` meets exactly this."""
    (tmp_path / "carnet.yaml").mkdir()
    with pytest.raises(carnetfile.CarnetFileError) as caught:
        carnetfile.load(str(tmp_path / "carnet.yaml"))
    assert "is a directory, not a file" in str(caught.value)
    assert "Docker creates an empty directory" in str(caught.value)


def test_invalid_yaml_is_named(tmp_path):
    assert "not valid YAML" in refusal(tmp_path, "connectors: [\n")


# --- the switch ---------------------------------------------------------------------


def test_the_file_beside_a_database_is_refused_at_import(monkeypatch):
    import importlib

    monkeypatch.setenv("CARNET_FILE", "/carnet.yaml")
    monkeypatch.setenv("CARNET_DATABASE_URL", "postgresql://x/y")
    with pytest.raises(ValueError) as caught:
        importlib.reload(config)
    assert "CARNET_FILE and CARNET_DATABASE_URL are both set" in str(caught.value)
    monkeypatch.delenv("CARNET_FILE")
    monkeypatch.delenv("CARNET_DATABASE_URL")
    importlib.reload(config)


def test_the_api_starts_from_a_file_without_the_encryption_key(tmp_path, monkeypatch):
    """Decision 9. Nothing here can seal a credential, so the key protects nothing and
    is not demanded — every database deployment keeps `configure_crypto(required=True)`."""
    from carnet.core import crypto

    monkeypatch.setattr(config, "CARNET_FILE", write(tmp_path, THE_FILE))
    monkeypatch.delenv(crypto.KEY_ENV, raising=False)
    crypto.reset()
    storage.reset()
    tools.reset_bound()
    try:
        with TestClient(create_app()) as started:
            assert started.get("/health/ready").json()["storage"] == "memory"
            listed = rpc(started, "tools/list")["result"]["tools"]
            assert [t["name"] for t in listed] == ["jira_search"]
    finally:
        storage.reset()
        tools.reset_bound()


# --- the two commands -----------------------------------------------------------------


def test_new_token_prints_a_token_the_loader_accepts(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "argv", ["carnet", "--new-token"])
    cli.main()
    printed = capsys.readouterr().out.strip()
    assert tokens.looks_like_api_token(printed)
    token_id, _ = tokens.digest_presented(printed)
    assert token_id.startswith(tokens.ID_PREFIX)

    monkeypatch.setenv("FRESH", printed)
    declaration = carnetfile.load(
        write(
            tmp_path,
            "agents:\n  a: {tools: [post_message]}\ntokens:\n  t:\n    secret: ${FRESH}\n    agents: [a]",
        )
    )
    assert declaration.tokens[0].token_id == token_id


def test_check_file_reports_the_summary_or_the_refusal(monkeypatch, capsys, tmp_path):
    path = write(tmp_path, THE_FILE)
    monkeypatch.setattr(sys, "argv", ["carnet", "--check-file", path])
    cli.main()
    assert "1 connector(s), 2 tool(s), 1 agent(s), 1 token(s)" in capsys.readouterr().out

    bad = write(tmp_path, "connectors:\n  jira:\n    url: https://x\n    credential: literal")
    monkeypatch.setattr(sys, "argv", ["carnet", "--check-file", bad])
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code != 0
    assert "connectors.jira.credential" in capsys.readouterr().err


def test_check_file_leaves_the_process_store_alone(tmp_path):
    carnetfile.check(write(tmp_path, THE_FILE), "elsewhere")
    assert storage.active().get_agent(TEST_TENANT, "triage") is None


# --- what --discover prints -----------------------------------------------------------


def test_the_tools_block_proposes_the_hint_or_the_cautious_default():
    block = carnetfile.tools_block(ADVERTISED, indent=0)
    lines = block.splitlines()
    assert lines[0] == "tools:"
    assert "  - name: create" in lines
    assert any("effect: write" in line and "cautious default" in line for line in lines)
    assert "  - name: search" in lines
    assert any("effect: read" in line and "server says read-only" in line for line in lines)
    assert any("project (string, required)" in line for line in lines)


def test_the_block_pasted_under_a_connector_loads(tmp_path):
    block = carnetfile.tools_block(ADVERTISED, indent=4)
    text = f"connectors:\n  jira:\n    url: https://{TEST_HOST}/mcp/\n{block}\n"
    declaration = carnetfile.load(write(tmp_path, text))
    (connector,) = declaration.connectors
    assert {v.remote_name: v.effect for v in connector.vetted} == {
        "search": "read",
        "create": "write",
    }


def test_discover_prints_the_block(monkeypatch, capsys, tmp_path):
    """The CLI's own startup path, with the file selected: `main()` configures a store
    from `CARNET_FILE`, so the connector it discovers is the file's."""
    monkeypatch.setattr(config, "CARNET_FILE", write(tmp_path, THE_FILE))
    # Discovery opens its own session rather than the pool's — see that module — so
    # it has its own transport seam, faked the way `test_api.py` fakes it.
    monkeypatch.setattr(
        mcp.discovery,
        "_transport_for",
        lambda tenant_id, conn, credential: EchoTransport(credential),
    )
    monkeypatch.setattr(sys, "argv", ["carnet", "--discover", "jira"])
    cli.main()
    out = capsys.readouterr().out
    assert "under connectors.jira:" in out
    assert "      - name: create" in out
    assert "effect: write" in out


# --- the example file ships checked ---------------------------------------------------


def test_the_example_file_loads_and_applies(monkeypatch):
    """`carnet.example.yaml` is the second thing a stranger reads. A file in the
    repository the suite does not load is a file that rots (098, decision 2)."""
    import pathlib

    example = pathlib.Path(__file__).resolve().parents[2] / "carnet.example.yaml"
    monkeypatch.setenv("JIRA_TOKEN", "placeholder")
    monkeypatch.setenv("WEATHER_KEY", "placeholder")
    monkeypatch.setenv("CARNET_TOKEN_LAPTOP", TOKEN)
    summary = carnetfile.check(str(example), "example")
    assert (summary.connectors, summary.tools, summary.agents, summary.tokens) == (
        2,
        3,
        2,
        1,
    )
