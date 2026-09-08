"""Looking at a server, and comparing what it says now with what was approved.

## Discovery is not the feature

`mcp.connect()` has opened a session and called `session.list_tools()` since step 003,
and every run exercises it. *"Connect and see what it offers"* was built long before
anybody could register a connector, so this module adds almost no capability.

What it adds is one thing, and it is the thing that makes `--vet` answerable: **printing
each tool's input schema.** The argument names are the only place a person can find out
what to put in `--resource jira.project=projectKey`, and without them the flag is a
guess that `tools/validation.py` rejects at the first bind. A discovery command that
printed names and descriptions would look complete and leave the actual difficulty
exactly where it was.

## Why this does not go through `bind()`

`bind()` **raises** when a vetted tool has vanished. That is right at run time — a vetted
tool that disappeared is drift, and guessing which of the remaining ones replaced it is
not our call — and it is precisely wrong here: reporting that drift is what re-discovery
is *for*. A discovery that crashed on the condition it exists to describe would send an
operator to the one place they cannot look.

So this reads the advertisement directly and `review()` compares it to the manifest by
hand, returning findings rather than raising. The severity of each finding is decision 6,
and the loud half of it — refusing to run — belongs to the caller.

## Why a fresh session rather than the pool

`--vet` records `server_name` and `server_version` from `initialize`'s `serverInfo`, and
that record is a claim that *this is what the server said when this tool was approved*.
A pooled session's handshake may have happened an hour and a deployment ago. The claim
has to be about a handshake that just happened, so discovery opens its own session and
closes it — an interactive admin command run a handful of times, where correctness of
the record is worth more than a saved round trip.
"""

from .binding import HttpLaunch, RestLaunch
from .client import Session
from .egress import check as check_egress

# Findings, ordered by how loud they are. `severity` is a field rather than a class per
# finding because the caller's decision is a threshold — "is anything here a refusal" —
# and a threshold over a comparable value beats a chain of isinstance checks that has to
# be edited every time a finding type is added.
REFUSE = "refuse"
REPORT = "report"


def discover(tenant_id: str, connector, credential: str | None, transport=None) -> dict:
    """Connect, handshake, and list. Returns `{"server": {...}, "tools": [...]}`.

    Reads nothing from the manifest and writes nothing. That separation is decision 4:
    looking at a server and approving one of its tools are two commands because they are
    two judgments, made at two times, with a person reading something in between.

    `transport` is injectable for the same reason it is everywhere else in this package —
    so tests never spawn anything and never open a socket.
    """
    if transport is None:
        # Built here rather than through `_transport_for` to avoid an import cycle, and
        # the egress check is therefore repeated explicitly rather than inherited. That
        # duplication is deliberate and load-bearing: discovery dials a host, so it is
        # subject to the same control as every other thing that dials a host, and a
        # module that reached the network without asking would be the exact hole this
        # step exists to close.
        transport = _transport_for(tenant_id, connector, credential)

    session = Session(transport)
    try:
        session.initialize()
        advertised = session.list_tools()
    finally:
        # Always. A discovery that raises must not leave a subprocess or an HTTP session
        # behind — this is the one code path in the package that deliberately does not
        # put its session in the pool, so nothing else will ever close it.
        try:
            session.close()
        except Exception:  # noqa: BLE001 - teardown must not mask the real failure
            pass

    return {"server": dict(session.server_info or {}), "tools": advertised}


def _transport_for(tenant_id: str, connector, credential: str | None):
    """The transport, with the egress check. See `mcp._transport_for` for the argument.

    A near-duplicate of that function, and the duplication is confined to two lines
    because everything interesting about it is in the check rather than in the
    construction. Importing the real one would make `discovery` -> `mcp` -> `discovery`.
    """
    from .transport import HttpTransport, StdioTransport

    if connector.transport_kind == HttpLaunch.KIND:
        check_egress(tenant_id, connector.launch.url)
        return HttpTransport(
            connector.launch.url, headers=connector.launch_headers(credential)
        )

    # The callers that own a sentence for this — the route and `--discover` — refuse
    # earlier with the remedy in it. This is the backstop for any other path, kept
    # loud so a REST connector can never be improvised into an MCP handshake.
    if connector.transport_kind == RestLaunch.KIND:
        raise RuntimeError(
            f"connector '{connector.id}' is a REST API and does not describe itself; "
            "there is nothing to discover. Vet each tool with its schema and binding "
            "instead (--vet with --method, --path and --schema)."
        )

    return StdioTransport(connector.launch.command, env=connector.launch_env(credential))


def server_label(server: dict) -> str:
    """`{"name": "jira-mcp", "version": "2.3.0"}` -> `"jira-mcp v2.3.0"`.

    Falls back to whichever half exists, and to a sentence when neither does. A server
    that declines to identify itself is legal MCP, and the record has to be able to say
    that rather than print an empty string that reads as a rendering bug.
    """
    name = (server.get("name") or "").strip()
    version = (server.get("version") or "").strip()

    # `v` prefixed only when the version does not already carry one. Found by running
    # `--discover` against the real github-mcp-server, which reports its version as
    # "v1.8.0" and rendered as "github-mcp-server vv1.8.0".
    version = version if not version or version.startswith("v") else f"v{version}"

    if name and version:
        return f"{name} {version}"
    if name:
        return f"{name} (no version declared)"
    if version:
        return f"{version} (no name declared)"
    return "a server that declared no name or version"


def review(connector, advertised: list, vetting: dict | None = None) -> list[dict]:
    """Compare a manifest with a live advertisement. Returns findings, never raises.

    Decision 6, in three cases and one ordering:

    | a vetted tool is **gone**              | refuse |
    | a vetted tool's **schema moved**       | refuse *if* it touches an argument a `Resource` names; report otherwise |
    | the server advertises **new** tools    | report, always. Never adopt. |

    The third is the one an implementation gets wrong by being helpful. *You do not vet
    a server, you vet the tools you want* — a discovery that added newly-advertised tools
    to the allowlist would mean a server could grant itself capabilities by shipping a
    release, which is the entire property the allowlist exists to deny.

    The second is the one worth reading twice. A new optional field is not a re-vetting:
    servers add fields constantly and refusing on every one is a control nobody can live
    with. An argument a `Resource` names *disappearing* is different in kind, because
    `validation.py` says what it costs — *"a constraint on an argument that never
    arrives silently never applies"* — so the tool would read as scoped and would not be.

    `vetting` is `(connector_id, remote_name) -> the review row`, used only to say what a
    refusal was measured against. Optional because the comparison does not depend on it;
    the record is there so the message can answer "did the server change, or did somebody
    edit the manifest", which is the question migration 023 exists for.
    """
    by_name = {tool.get("name"): tool for tool in advertised}
    findings = []
    vetting = vetting or {}

    for vetted in connector.vetted:
        record = vetting.get((connector.id, vetted.remote_name), {})
        against = _vetted_against(record)
        spec = by_name.get(vetted.remote_name)

        if spec is None:
            findings.append(
                {
                    "severity": REFUSE,
                    "kind": "gone",
                    "remote_name": vetted.remote_name,
                    "message": (
                        f"'{vetted.remote_name}' is vetted and this server does not "
                        f"advertise it{against}. A vetted tool that vanished is a change "
                        "worth looking at, not one to route around — binding will refuse "
                        "to start until somebody decides what happened."
                    ),
                }
            )
            continue

        properties = (spec.get("inputSchema") or {}).get("properties") or {}

        # The argument-existence rule, applied at discovery instead of at the first run.
        # Same check `validation.py` makes, moved earlier and made explicable: it can say
        # what the tool was vetted against, which is the half a bind-time crash cannot.
        moved = [
            arg
            for ref in vetted.resources
            for arg in ref.args
            if arg not in properties
        ]
        if moved:
            findings.append(
                {
                    "severity": REFUSE,
                    "kind": "argument-moved",
                    "remote_name": vetted.remote_name,
                    "arguments": sorted(set(moved)),
                    "message": (
                        f"'{vetted.remote_name}' no longer takes "
                        f"{', '.join(repr(a) for a in sorted(set(moved)))}"
                        f"{against}, and its scoping is written against "
                        f"{'that argument' if len(set(moved)) == 1 else 'those arguments'}. "
                        "A constraint on an argument that never arrives silently never "
                        f"applies, so this tool would read as scoped to "
                        f"{', '.join(sorted({ref.type for ref in vetted.resources}))} "
                        "and would not be. Re-vet it against the arguments this server "
                        f"takes now: {', '.join(sorted(properties)) or '<none>'}."
                    ),
                }
            )
            continue

        # Decision 6's middle row, and it is reported **only against a real baseline**.
        # `vetted_arguments` is what the schema carried when this tool was approved; an
        # empty one means nobody recorded it — every `--seed` row, and every row written
        # before migration 023 — and there is nothing to diff. Reporting anyway is what
        # the first version did, and pointed at the real github-mcp-server it produced a
        # paragraph of noise per seeded tool on every run. See the migration.
        baseline = set(record.get("vetted_arguments") or ())
        if baseline:
            added = sorted(set(properties) - baseline)
            removed = sorted(baseline - set(properties))
            if added or removed:
                changes = []
                if added:
                    changes.append(f"gained {', '.join(added)}")
                if removed:
                    changes.append(f"lost {', '.join(removed)}")
                findings.append(
                    {
                        "severity": REPORT,
                        "kind": "schema-changed",
                        "remote_name": vetted.remote_name,
                        "arguments": added + removed,
                        "message": (
                            f"'{vetted.remote_name}' has {' and '.join(changes)} since it "
                            f"was vetted{against}. Reported rather than refused — every "
                            "argument the scoping names still arrives, and a new optional "
                            "field is not a re-vetting. Worth a look if one of these "
                            "widens what the call reaches."
                        ),
                    }
                )

    vetted_names = {v.remote_name for v in connector.vetted}
    new = sorted(name for name in by_name if name and name not in vetted_names)
    if new:
        findings.append(
            {
                "severity": REPORT,
                "kind": "not-vetted",
                "arguments": new,
                "message": (
                    f"{len(new)} tool(s) this server advertises are not vetted and are "
                    "invisible to every agent in this tenant: "
                    f"{', '.join(new)}. Reported, never adopted — you do not vet a "
                    "server, you vet the tools you want."
                ),
            }
        )

    return findings


def _vetted_against(record: dict) -> str:
    """`" (vetted against jira-mcp v2.3.0)"`, or `''` when nothing was recorded.

    A suffix rather than a sentence so it composes into every message above. Empty for
    every row written before migration 023 and for everything `--seed` writes, which is
    the honest rendering of a record nobody kept — and the reason the surrounding
    sentences still read correctly without it.
    """
    label = server_label(
        {"name": record.get("server_name") or "", "version": record.get("server_version") or ""}
    )
    if not record.get("server_name") and not record.get("server_version"):
        return ""
    return f" (vetted against {label})"


def refusals(findings: list[dict]) -> list[dict]:
    """The findings that mean stop. The threshold `severity` exists for."""
    return [finding for finding in findings if finding["severity"] == REFUSE]
