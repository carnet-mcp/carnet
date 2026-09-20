"""Decision 10, held in place: this package talks to one host and carries nothing home.

`DEFERRED_2.0.md` refused telemetry for the server on the premise, not on taste — a
self-hosted broker whose pitch is *the credential never leaves your deployment* does not
phone home, and the strongest answer to *does it?* is that no outbound path exists in
the code at all. A library inside the customer's own process is where that temptation
returns, and it is worse there because an outbound path in a `pip` package is invisible
to the review that reads our container. So:

- every request the stub saw went to the constructed URL, and the token appeared in the
  `Authorization` header and nowhere else;
- no module in the package contains a string with `://` in it — there is no address to
  send anything to;
- the core imports the standard library, `httpx` and itself, and nothing more;
- every adapter imports without its framework, and says which extra to install when
  asked to build tools without it, quoted for the shell.
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import sys

import pytest

import carnet_mcp
from carnet_mcp import AsyncDoor, Door

from conftest import TOKEN, URL

PACKAGE = pathlib.Path(carnet_mcp.__file__).parent
MODULES = sorted(PACKAGE.glob("*.py"))
ADAPTERS = ("langchain", "crewai", "autogen", "openai_agents")


def test_every_request_goes_to_the_constructed_url_and_the_token_only_in_the_header(stub):
    door = Door(URL, TOKEN, client=stub.client())
    door.tools()
    door.call("jira_search_issues", {"project": "ACME"})
    stub.mode = "denied"
    door.call("jira_search_issues", {"project": "OTHER"})
    assert stub.requests, "nothing was sent"
    for request in stub.requests:
        assert str(request.url) == URL
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert TOKEN not in str(request.url)
        assert TOKEN not in request.content.decode()
        for name, value in request.headers.items():
            if name.lower() != "authorization":
                assert TOKEN not in value


async def test_the_async_door_too(stub):
    door = AsyncDoor(URL, TOKEN, client=stub.async_client())
    await door.tools()
    await door.call("jira_search_issues", {"project": "ACME"})
    assert {str(r.url) for r in stub.requests} == {URL}


def test_no_module_names_an_address():
    for module in MODULES:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "://" not in node.value, f"{module.name} carries an address: {node.value[:60]!r}"


def test_the_core_imports_httpx_the_standard_library_and_itself_only():
    allowed_third_party = {"httpx"}
    for name in ("_door.py", "errors.py", "_version.py", "__init__.py", "_schema.py"):
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = [node.module.split(".")[0]]
            for root in roots:
                if root in allowed_third_party or root == "carnet_mcp":
                    continue
                # `_schema.py` imports pydantic lazily, inside the function that needs it,
                # and pydantic is a dependency of the frameworks that call it.
                if name == "_schema.py" and root == "pydantic":
                    continue
                assert root in sys.stdlib_module_names, f"{name} imports {root}"


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_each_adapter_imports_without_its_framework(adapter, monkeypatch):
    # `None` in `sys.modules` makes the import raise ImportError: the framework is
    # "not installed" for the duration, whatever this environment holds.
    for blocked in ("langchain_core", "langchain_core.tools", "crewai", "crewai.tools", "agents", "autogen_core", "autogen_core.tools"):
        monkeypatch.setitem(sys.modules, blocked, None)
    module_name = f"carnet_mcp.{adapter}"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    module = importlib.import_module(module_name)
    assert module.EXTRA == f"carnet-mcp[{adapter.replace('_', '-')}]"


def test_an_adapter_without_its_framework_names_the_extra(stub, monkeypatch):
    for blocked in ("langchain_core", "langchain_core.tools", "crewai", "crewai.tools"):
        monkeypatch.setitem(sys.modules, blocked, None)
    from carnet_mcp import crewai, langchain

    with pytest.raises(ImportError, match=r"carnet-mcp\[langchain\]"):
        langchain.from_doors(Door(URL, TOKEN, client=stub.client()))
    with pytest.raises(ImportError, match=r"carnet-mcp\[crewai\]"):
        crewai.from_door(Door(URL, TOKEN, client=stub.client()))
