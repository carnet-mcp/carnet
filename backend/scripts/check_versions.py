"""Assert every place that states Carnet's version states the same one. Step 073.

Run from anywhere::

    python backend/scripts/check_versions.py            # the file sources
    python backend/scripts/check_versions.py --tag v0.9.0   # and this tag must match
    python backend/scripts/check_versions.py --no-git   # skip the tag check entirely

Exit 0 when every source agrees, 1 with a table naming each source and what it says
when any disagrees. CI runs it on every push and pull request; on a tag push it also
refuses a tag that disagrees with the package.

## Why it exists

`__version__` reaches `--version`, `GET /health`, MCP `initialize`'s `serverInfo` and
the `carnet_build_info` metric. The changelog, the docs page and the git tags each
state a version too, and by 2026-09-02 they said `0.8.0`, `0.8.0` with twenty steps
filed under *Unreleased*, `0.8.0` in one place and `0.6.0` in another, and `v0.3.1`.
None of that was a bug on its own. All of it becomes one the first time a buyer asks
*what version are we on, what is in it, and does it have the fix* — which is the
question the client-readiness arc (049 onward) exists to answer.

## The sources, and the two that are named as not sources

Each entry below is a file and the pattern that finds the version in it. Adding a
place that states the version means adding a row here; the check is only as complete
as this list.

- `backend/src/carnet/__init__.py` — `__version__`, the one `pyproject.toml` reads.
- `CHANGELOG.md` — the newest **released** heading. The *Unreleased* section may hold
  anything; the first `## X.Y.Z — date` heading below it is what shipped.
- `frontend/package.json` — **enrolled, on purpose.** It is private and nothing reads
  it, so the honest choices were to exempt it in writing or to bump it with the rest.
  It is bumped with the rest: an exemption is a sentence somebody has to find, and a
  version that is the same everywhere is a rule nobody has to remember.

Not sources, and why:

- `docs/UPGRADING.md` lists the releases that changed an operator's obligations, not
  every release, so it may legitimately name an older version at the top.
- `CHANGELOG.md`'s older headings quote versions as history, which is what they are for.
  Only the newest released heading is a source.
- Migrations carry no version; the schema's own head is `storage/migrations/`.

## Tags

Tagging is a release, and a release is an operator's decision rather than a build's —
so the newest tag is allowed to be *behind* the package, and usually is. It is never
allowed to be *ahead*, since a tag claiming a version the code does not report is a
release that does not exist. `--tag` names the tag being pushed and requires equality:
that is the preflight, and it is the whole reason the tag check exists.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

VERSION_RE = r"(\d+\.\d+\.\d+)"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _first(pattern: str, text: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, text, flags)
    return match.group(1) if match else None


def package_version() -> str | None:
    return _first(rf'^__version__\s*=\s*"{VERSION_RE}"', _read("backend/src/carnet/__init__.py"), flags=re.M)


def changelog_version() -> str | None:
    """The first released heading — `## X.Y.Z — date` — skipping *Unreleased*."""
    return _first(rf"^## {VERSION_RE} — ", _read("CHANGELOG.md"), flags=re.M)


def frontend_version() -> str | None:
    value = json.loads(_read("frontend/package.json")).get("version")
    return value if isinstance(value, str) else None


def sources() -> dict[str, str | None]:
    found: dict[str, str | None] = {
        "backend/src/carnet/__init__.py": package_version(),
        "CHANGELOG.md (newest released heading)": changelog_version(),
    }
    found["frontend/package.json"] = frontend_version()
    return found


def _parse(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def newest_tag() -> str | None:
    """The highest `vX.Y.Z` tag, or None when there is none or git is unavailable."""
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "tag", "--list", "v*"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    tags = [t.strip() for t in out.splitlines() if re.fullmatch(rf"v{VERSION_RE}", t.strip())]
    if not tags:
        return None
    return max(tags, key=lambda t: _parse(t[1:]))


def check(*, tag: str | None = None, use_git: bool = True) -> list[str]:
    """Every disagreement, as one sentence each. Empty means the sources agree."""
    found = sources()
    problems: list[str] = []

    for name, value in found.items():
        if value is None:
            problems.append(f"{name}: no version found — the pattern this script looks for is missing")

    stated = {v for v in found.values() if v is not None}
    if len(stated) > 1:
        problems.append("the sources disagree: " + ", ".join(sorted(stated)))

    package = found["backend/src/carnet/__init__.py"]

    if tag is not None:
        tag_version = _first(rf"^v{VERSION_RE}$", tag)
        if tag_version is None:
            problems.append(f"tag {tag!r} is not shaped vX.Y.Z")
        elif package is not None and tag_version != package:
            problems.append(
                f"tag {tag} disagrees with the package version {package} — "
                "a tag is a release, and it must name what the code reports"
            )
    elif use_git and package is not None:
        newest = newest_tag()
        if newest is not None and _parse(newest[1:]) > _parse(package):
            problems.append(
                f"the newest tag {newest} is ahead of the package version {package} — "
                "a tag claiming a version the code does not report is a release that does not exist"
            )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", help="a tag that must equal the package version (the release preflight)")
    parser.add_argument("--no-git", action="store_true", help="skip the tag check")
    args = parser.parse_args(argv)

    found = sources()
    width = max(len(name) for name in found)
    for name, value in found.items():
        print(f"{name:<{width}}  {value or '(not found)'}")
    newest = None if args.no_git else newest_tag()
    print(f"{'newest git tag':<{width}}  {newest or '(none)'}")

    problems = check(tag=args.tag, use_git=not args.no_git)
    if problems:
        print()
        for problem in problems:
            print(f"error: {problem}")
        return 1
    print()
    print("every source agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
