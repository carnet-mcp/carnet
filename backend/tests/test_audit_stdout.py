"""The audit line on stdout. Step 096.

One JSON object per brokered call and per refusal, on the `carnet.audit` logger, whose
handler `api.configure_logging` points at stdout. The world is a `carnet.yaml` — the
fileborne door is the artefact this line exists for, and the loader is tested next door.
"""

import json

import pytest
from fastapi.testclient import TestClient

from carnet import config, storage, tools
from carnet.api import create_app
from carnet.tools import mcp
from carnet.tools.mcp.client import SessionPool
from conftest import TEST_TENANT, read_audit
from test_carnetfile import JIRA, THE_FILE, TOKEN, EchoTransport, write


@pytest.fixture(autouse=True)
def world(monkeypatch, tmp_path):
    monkeypatch.setenv("JIRA_TOKEN", JIRA)
    monkeypatch.setenv("CARNET_TOKEN_ALICE", TOKEN)
    monkeypatch.setattr(mcp, "POOL", SessionPool())
    monkeypatch.setattr(
        mcp, "_transport_for", lambda tenant_id, conn, credential: EchoTransport(credential)
    )
    monkeypatch.setattr(config, "CARNET_FILE", write(tmp_path, THE_FILE))
    storage.reset()
    tools.reset_bound()
    yield
    storage.reset()
    tools.reset_bound()


@pytest.fixture
def started():
    """The app with its lifespan running — that is where the handler is installed."""
    with TestClient(create_app()) as client:
        yield client


def call(client, method, params=None):
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def lines(capsys) -> list[dict]:
    """Every stdout line that is a JSON object, parsed. Anything else fails the test:
    the stream is for a pipeline, and a pipeline does not skip lines."""
    out = capsys.readouterr().out
    parsed = []
    for raw in out.splitlines():
        if not raw.strip():
            continue
        assert raw.startswith("{"), f"not a bare object: {raw!r}"
        parsed.append(json.loads(raw))
    return parsed


def test_an_allowed_call_is_one_audit_line_with_the_rows_fields(started, capsys):
    capsys.readouterr()
    call(started, "tools/call", {"name": "jira_search", "arguments": {"project": "ACME"}})
    (line,) = lines(capsys)

    assert line["type"] == "audit"
    assert line["tenant_id"] == config.DEFAULT_TENANT_ID
    assert line["decision"] == "allow"
    assert line["outcome"] == "ok"
    assert line["tool"] == "jira_search"
    assert line["agent"] == "triage"
    assert line["args"] == {"project": "ACME"}
    assert line["principal_kind"] == "machine"
    assert line["credential"] == "shared"
    assert line["run_id"].startswith("door-")
    assert isinstance(line["duration_ms"], int)

    # A copy, never a replacement: the row is still there, and it is the same record.
    (row,) = [r for r in read_audit(config.DEFAULT_TENANT_ID) if r["outcome"]]
    assert {k: v for k, v in line.items() if k != "type"} == {
        k: (v.isoformat(timespec="milliseconds") if hasattr(v, "isoformat") else v)
        for k, v in row.items()
    }


def test_a_scope_refusal_is_an_audit_line_with_decision_deny(started, capsys):
    capsys.readouterr()
    call(started, "tools/call", {"name": "jira_search", "arguments": {"project": "OTHER"}})
    (line,) = lines(capsys)
    assert line["type"] == "audit"
    assert line["decision"] == "deny"
    assert "OTHER" in line["reason"]


def test_an_ungranted_name_is_a_denial_line_and_no_audit_line(started, capsys):
    capsys.readouterr()
    answer = call(started, "tools/call", {"name": "jira_create", "arguments": {}})
    assert "error" in answer
    (line,) = lines(capsys)
    assert line["type"] == "denial"
    assert line["tenant_id"] == config.DEFAULT_TENANT_ID
    assert line["resource_kind"] == "tool"
    assert line["resource_id"] == "jira_create"
    assert line["required"] == "grant"
    assert line["principal_kind"] == "machine"
    assert read_audit(config.DEFAULT_TENANT_ID) == []


def test_the_line_is_bare_under_json_log_format_too(monkeypatch, capsys):
    monkeypatch.setattr(config, "LOG_FORMAT", "json")
    with TestClient(create_app()) as client:
        capsys.readouterr()
        call(client, "tools/call", {"name": "jira_search", "arguments": {"project": "ACME"}})
        (line,) = lines(capsys)
    assert "message" not in line
    assert line["type"] == "audit"


def test_off_prints_nothing_and_the_row_is_still_written(monkeypatch, capsys):
    monkeypatch.setattr(config, "AUDIT_STDOUT", False)
    with TestClient(create_app()) as client:
        capsys.readouterr()
        call(client, "tools/call", {"name": "jira_search", "arguments": {"project": "ACME"}})
        assert lines(capsys) == []
        assert len([r for r in read_audit(config.DEFAULT_TENANT_ID) if r["outcome"]]) == 1


def test_a_value_that_is_neither_on_nor_off_refuses_at_import(monkeypatch):
    import importlib

    monkeypatch.setenv("CARNET_AUDIT_STDOUT", "maybe")
    with pytest.raises(ValueError) as caught:
        importlib.reload(config)
    assert "CARNET_AUDIT_STDOUT must be 'on' or 'off'" in str(caught.value)
    monkeypatch.delenv("CARNET_AUDIT_STDOUT")
    importlib.reload(config)


def test_emit_survives_a_value_that_will_not_serialise(capsys):
    """`default=str`: the line degrades, it is not lost."""
    from carnet.core import audit
    import logging

    logger = logging.getLogger(audit.AUDIT_LOGGER)
    sink = logging.StreamHandler()
    sink.setFormatter(logging.Formatter("%(message)s"))
    logger.handlers[:] = [sink]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    try:
        audit.emit("audit", TEST_TENANT, {"ts": object()})
    finally:
        logger.handlers[:] = []
    err = capsys.readouterr().err
    assert '"type": "audit"' in err
    assert "<object object" in err
