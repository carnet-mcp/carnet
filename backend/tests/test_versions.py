"""The version sources agree. Step 073.

The same check CI runs, so a developer who bumps `__version__` and forgets the
changelog heading hears about it from `pytest` rather than from a red job. No git
here — the fast suite starts no subprocess, and the tag rule is CI's to enforce.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_versions.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_versions", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_version_source_agrees():
    mod = _load()
    assert mod.check(use_git=False) == []


def test_every_source_is_found():
    mod = _load()
    found = mod.sources()
    assert all(value is not None for value in found.values()), found
    assert len(found) == 3, "a source was added or removed — update the docstring's list too"


def test_a_tag_must_equal_the_package(monkeypatch):
    mod = _load()
    package = mod.package_version()
    assert mod.check(tag=f"v{package}", use_git=False) == []
    problems = mod.check(tag="v0.0.1", use_git=False)
    assert any("disagrees with the package version" in p for p in problems)
    problems = mod.check(tag="0.0.1", use_git=False)
    assert any("not shaped" in p for p in problems)
