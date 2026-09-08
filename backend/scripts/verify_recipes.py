"""Check the connector recipes against the real vendors. **Hand-run, never CI.**

Step 068 rule 5. CI checks *shape* — that every recipe parses, names bare hosts, uses
https, stays under the ceiling, and sets only fields the code it fills actually takes.
That is the failure we can prevent, because it is ours.

This checks the other half, which is not ours: whether the vendor still answers where the
recipe says it does. It is deliberately **not** in the test suite and not in CI, on the
roles script's precedent:

    A red build caused by Atlassian's marketing redirect is a build people learn to
    ignore, which costs more than not having the check.

## What this can and cannot tell you

It can tell you an endpoint is **gone** — a connection refused, a DNS failure, a 404. That
is the failure worth catching, and it is the one that turns a recipe into a preset that
wastes somebody's first hour.

It cannot tell you an endpoint is **right**. A 200 from an authorize endpoint proves a
page exists, not that it accepts the scopes the recipe asks for, not that the token
endpoint will honour the code it issues, and not that `authorize_params` are still what
the vendor mandates. **Only a completed consent flow tells you that**, which is why
`verified_on` is stamped by a person and not by this script — see rule 2. A green run
here is a reason to go and do that, not a substitute for it.

So: this narrows what a human has to check. It does not replace them.

## Running it

    python scripts/verify_recipes.py                 # every recipe
    python scripts/verify_recipes.py atlassian-jira  # one

It makes unauthenticated GET requests to third-party hosts and sends nothing but the
request line. No credential is read, so it is safe to run from anywhere with a network.

## Stamping

When a consent flow has actually been completed against a vendor, edit that recipe's file:

    "verified_on":      "2026-09-02",
    "verified_by":      "somebody@example.com",
    "verified_against": "what you actually did — the app you created, the scopes granted"

`verified_by` is required beside a date and `access/recipes.py` refuses a stamp without
one: a verification nobody signed is a claim with no author, which is the same defect
`admin_audit.actor_id` refuses with a CHECK.
"""

import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from carnet.access import recipes  # noqa: E402

TIMEOUT = 10


def probe(url: str, *, method: str = "GET", hidden: bool = False) -> tuple:
    """Returns `(True | False | None, detail)` — alive, gone, or **inconclusive**."""
    """Is anything still answering here?

    **A token endpoint that 404s is inconclusive, not gone**, which is the second thing
    this script got wrong. GitHub answers `POST /login/oauth/access_token` with 404 for
    any request that is not a real code exchange — with a form body, with none, always —
    because a token endpoint that distinguished *no such app* from *bad code* would be an
    oracle. Reporting that as a dead endpoint is a permanent false positive against a
    working vendor, and a check that cries wolf on one recipe out of six is a check people
    stop reading, which this script's own preamble says is worse than not having it.

    So endpoints that legitimately hide are marked `hidden` and their 404 is reported as
    *inconclusive*: something a person settles by completing one consent flow, which is
    the only thing that ever settled it. A connector URL or an authorize endpoint is
    browser-reachable and does not hide, so a 404 there still means gone.

    **The method matters, and getting it wrong reports live vendors as broken.** The first
    version of this script sent GET to everything and produced three false positives out
    of six recipes — which would have had somebody delete two working presets:

      - a **token endpoint is POST-only**. GitHub answers `GET
        /login/oauth/access_token` with a flat 404 and the endpoint is perfectly alive.
      - a REST connector's **base URL is not an endpoint**. `GET https://api.anthropic.com`
        is a 404 about the root of a domain that works fine; what has to be probed is the
        base joined to a vetted tool's own path.

    So token and revoke endpoints get an empty POST — a live one answers 400 or 401
    (`invalid_request`, `invalid_client`), a deleted path still answers 404 — and REST
    connectors are probed at their tools' paths with their tools' methods.

    Nothing authenticated is ever sent. An empty body to a token endpoint carries no
    client id, no secret and no code.

    **A 4xx is not a failure**, deliberately: an authorize endpoint with no query string
    is *supposed* to refuse, and that refusal is proof something is there. Only 404 and a
    transport failure mean absence.
    """
    data = b"" if method == "POST" else None
    request = urllib.request.Request(url, data=data, method=method)
    if method == "POST":
        request.add_header("content-type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return True, f"{response.status}"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None if hidden else False, "404 — nothing answered at this path"
        if exc.code == 405:
            # Something is listening and objects to the verb, which answers the only
            # question being asked.
            return True, "405 (wrong verb for a probe, but it is there)"
        return True, f"{exc.code} (a refusal, not an absence)"
    except urllib.error.URLError as exc:
        return False, f"unreachable: {exc.reason}"
    except Exception as exc:  # noqa: BLE001 — a report, not a control path
        return False, f"{type(exc).__name__}: {exc}"


def check(recipe: dict) -> list[str]:
    """Every URL this recipe would cause somebody to dial. Returns the problems."""
    problems = []
    connector = recipe["connector"]
    targets = []

    if connector.get("kind") == "rest":
        # The base URL of a REST API is a domain root and says nothing. Its tools' paths
        # are the thing a customer would actually reach, so those are what get probed —
        # unauthenticated, which is a 401 from a live endpoint and a 404 from a dead one.
        base = connector["url"].rstrip("/")
        for tool in recipe.get("tools") or ():
            binding = tool.get("binding") or {}
            if binding.get("path"):
                targets.append(
                    (f"tool {tool['remote_name']}", base + binding["path"],
                     binding.get("method", "GET"))
                )
        if not targets:
            targets.append(("connector url", connector["url"], "GET"))
    else:
        targets.append(("connector url", connector["url"], "GET"))

    app = recipe.get("oauth")
    if app:
        targets.append(("authorize endpoint", app["authorize_endpoint"], "GET", False))
        targets.append(("token endpoint", app["token_endpoint"], "POST", True))
        if app.get("revoke_endpoint"):
            targets.append(("revoke endpoint", app["revoke_endpoint"], "POST", True))

    for target in targets:
        what, url, method = target[0], target[1], target[2]
        hidden = target[3] if len(target) > 3 else False
        alive, detail = probe(url, method=method, hidden=hidden)
        mark = {True: "ok  ", False: "GONE", None: "??  "}[alive]
        print(f"    {mark} {what:<22} {method:<5} {url}  [{detail}]")
        if alive is False:
            problems.append(f"{what} {url}: {detail}")
        elif alive is None:
            print(
                "         ^ inconclusive: this kind of endpoint 404s on purpose rather "
                "than be probed.\n"
                "           Only a completed consent flow settles it."
            )
    return problems


def main() -> int:
    wanted = sys.argv[1:]
    catalogue = recipes.catalogue()
    if wanted:
        catalogue = [item for item in catalogue if item["id"] in wanted]
        missing = set(wanted) - {item["id"] for item in catalogue}
        if missing:
            print(f"no such recipe: {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    print(f"Probing {len(catalogue)} recipe(s). A 4xx is fine; a 404 or a DNS failure is not.\n")
    broken = {}
    for recipe in catalogue:
        state = recipes.staleness(recipe)
        stamp = recipe.get("verified_on") or "never verified by anyone here"
        print(f"  {recipe['id']}  ({state}, {stamp})")
        problems = check(recipe)
        if problems:
            broken[recipe["id"]] = problems
        print()

    if not broken:
        print("Every endpoint answered.")
        print(
            "\nThis does NOT mean the recipes are correct. It means nothing has been "
            "deleted.\nWhether the scopes, the authorize parameters and the token "
            "exchange still work is\nonly answerable by completing one consent flow per "
            "vendor — rule 2, and the reason\n`verified_on` is stamped by a person."
        )
        return 0

    print(f"{len(broken)} recipe(s) have an endpoint that is gone:\n")
    for recipe_id, problems in broken.items():
        for problem in problems:
            print(f"  {recipe_id}: {problem}")
    print(
        "\nPlan 068 rule 1 says what to do: **delete it, in the commit that found it.**\n"
        "Nothing in the database points back at a recipe, so deleting one costs nothing "
        "and\norphans nothing — and a catalogue of half-true presets is worse than a "
        "shorter one.\nRe-add it when somebody has fixed it and completed a consent flow."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
