"""carnet — the MCP door.

People connect their own assistant to `/mcp`, and every tool call it makes goes through
the broker: scoped to that caller, under a credential the caller never holds, revocable,
metered and audited. `docs/PREMISE.md` is the full statement and outranks this docstring.

Layers, outermost first. Each layer may import downward, never upward:

    cli / api     entry points; door.py is the MCP door
    agents/       permission lists: a named set of tools, each with a scope  (config only)
    core/         the broker                        (knows no tool, no agent)
    tools/        what can actually be done         (knows no agent, no policy)
    storage/      rows in, rows out
    config.py     paths and defaults                (knows nothing)

The one rule worth protecting: nothing outside core/ may call a tool implementation
directly. Everything goes through core.broker, which is where permissions,
credentials, and audit are enforced.
"""

# The single source of truth. `pyproject.toml` reads this attribute rather than
# carrying its own copy — see `[tool.setuptools.dynamic]` — so there is one place to
# bump and no way for the manifest and the runtime to disagree about what is running.
#
# Read by `--version` and by `GET /health`, which is the point: "what are you running"
# has to have an answer from a machine you cannot see. Until 027 nothing read it at all.
__version__ = "0.10.0"
