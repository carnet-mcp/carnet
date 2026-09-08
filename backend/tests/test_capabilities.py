"""`docs/CAPABILITIES.md` names every user-facing thing, or says why not. Step 099.

The catalogue is the answer to *what can I actually do with this* for a stranger, and a
list somebody remembered is worth nothing. So the surface is enumerated from the code —
every CLI flag, every HTTP route, every `carnet.yaml` key, every `CARNET_*` setting, every
screen — and each must appear in the document verbatim. `test_every_admin_route_carries_
the_dependency`'s device, pointed at documentation.

What this proves is coverage, not accuracy: it can tell that `--vet` is mentioned, not
that what the sentence says about `--vet` is true. The acceptance report says who read it.
"""

from __future__ import annotations

import pathlib
import re

import carnet.api.routes_connections as routes_connections
from carnet import carnetfile

REPO = pathlib.Path(__file__).resolve().parents[2]
DOC = REPO / "docs" / "CAPABILITIES.md"
SRC = REPO / "backend" / "src" / "carnet"
FRONTEND = REPO / "frontend" / "src"


def catalogue() -> str:
    return DOC.read_text(encoding="utf-8")


def missing(names, text: str) -> list[str]:
    return sorted(name for name in set(names) if name not in text)


def test_every_cli_flag_is_catalogued():
    source = (SRC / "cli.py").read_text(encoding="utf-8")
    flags = re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', source)
    assert len(flags) >= 100, "the CLI shrank below a hundred flags; is the regex still right?"
    assert missing((f"`{flag}" for flag in flags), catalogue()) == []


def test_every_http_route_is_catalogued():
    text = catalogue()
    routes: list[str] = []
    for module in sorted((SRC / "api").glob("*.py")):
        source = module.read_text(encoding="utf-8")
        for method, path in re.findall(
            r'@(?:router|app)\.(get|post|put|delete|patch)\(\s*"([^"]+)"', source
        ):
            routes.append(f"`{method.upper()} {path}`")
        for method, constant in re.findall(
            r'@(?:router|app)\.(get|post|put|delete|patch)\(\s*([A-Z_]+)\b', source
        ):
            value = getattr(routes_connections, constant)
            routes.append(f"`{method.upper()} {value}`")
    assert len(routes) >= 50, "the API shrank below fifty routes; is the regex still right?"
    assert missing(routes, text) == []


def test_every_carnet_yaml_key_is_catalogued():
    text = catalogue()
    keys = set()
    for name in (
        "TOP_KEYS", "CONNECTOR_KEYS", "TOOL_KEYS", "REST_TOOL_KEYS",
        "RESOURCE_KEYS", "AGENT_KEYS", "TOKEN_KEYS",
    ):
        keys |= set(getattr(carnetfile, name))
    assert missing((f"`{key}`" for key in keys), text) == []


def test_every_setting_is_catalogued():
    """The same enumeration `e2e_deploy.py`'s knobs scene uses, pointed at the document."""
    text = catalogue()
    read_by_the_app = set(re.findall(
        r"CARNET_[A-Z_]+",
        (SRC / "config.py").read_text(encoding="utf-8")
        + (SRC / "core" / "crypto.py").read_text(encoding="utf-8")
        + (SRC / "localidp" / "frontdoor.py").read_text(encoding="utf-8"),
    ))
    declared_to_the_stack = set(re.findall(
        r"CARNET_[A-Z_]+", (REPO / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    ))
    assert missing(read_by_the_app | declared_to_the_stack, text) == []


def test_every_screen_is_catalogued():
    text = catalogue()
    app = (FRONTEND / "App.tsx").read_text(encoding="utf-8")
    paths = set(re.findall(r'path="([^"]+)"', app))
    if "path={CALLBACK_PATH}" in app:
        auth = (FRONTEND / "lib" / "auth.ts").read_text(encoding="utf-8")
        paths.add(re.search(r'CALLBACK_PATH = "([^"]+)"', auth).group(1))
    assert missing((f"`{path}`" for path in paths), text) == []
