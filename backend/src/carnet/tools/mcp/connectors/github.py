"""The official GitHub MCP server, vetted.

    https://github.com/github/github-mcp-server

Chosen as the first connector because we already have a hand-written
`get_github_issues`. Same agent, same task, once down each path — if the broker
behaves identically, the abstraction holds. See the README's connector comparison.

Two tools out of the hundred-odd this server advertises. That ratio is the point: you
do not vet a server, you vet the tools you want, and everything else stays invisible
to every agent on the platform no matter what a future version adds.

`list_issues` is the interesting one. GitHub's API takes `owner` and `repo` as separate
arguments, so the identifier policy scopes on has to be composed from two of them —
which is why `Resource` grew a template. The grant it lands under is the same
`github.repo` grant written for the hand-written tool, unchanged and unaware.

Vetted against **github-mcp-server v1.8.0**. That version is recorded because vetting
is a judgment about a specific advertisement: `get_issue` was renamed to `issue_read`
between versions, and binding refused to start until this file was updated. Which is
the intended behaviour — a vetted tool that vanished is a change worth looking at.

Not vetted, and worth saying why:

  create_issue, add_issue_comment, update_issue
      Writes. Perfectly scopeable — `Resource("github.repo", ["owner", "repo"])` and
      `effect="write"` — but this step is a read-path comparison and a write we do not
      need is a write nobody should be able to make.

  search_issues
      It does take `owner` and `repo`, but both are optional and `query` is not. The
      query is GitHub's own search syntax and may carry its own `repo:` qualifier, so
      two arguments can disagree about what the call reaches and the server decides
      which wins. Scoping the pair we can see would be a constraint that reads as
      enforced while the query goes wherever it likes. Deciding what a call touches
      by parsing a vendor's query grammar is exactly the guess a permission check
      must not make.

  list_issue_fields, list_issue_types
      `owner` is required and `repo` is not — omit it and the call returns
      organisation-level data. An optional argument that widens reach when absent is
      scopeable only with care: our check fails closed on a missing component, so a
      call without `repo` would be denied rather than silently escalated, but the
      right descriptor here is an org-level resource type we do not yet have.
"""

from ...base import Resource
from ..binding import Connector, StdioLaunch, Vetted

# The repo lives in two arguments. One grant covers this and the hand-written tool.
REPO = Resource("github.repo", ["owner", "repo"], template="{owner}/{repo}")

CONNECTOR = Connector(
    id="github-mcp",
    description="Official GitHub MCP server (read path: issues).",
    launch=StdioLaunch(
        command=(
            "docker",
            "run",
            "-i",
            "--rm",
            # Forwarded from the environment we hand the child, which contains the
            # credential and nothing else. See Launch.env_for.
            "-e",
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "-e",
            "GITHUB_TOOLSETS",
            "-e",
            "GITHUB_READ_ONLY",
            "ghcr.io/github/github-mcp-server",
        ),
        credential_env="GITHUB_PERSONAL_ACCESS_TOKEN",
        # Defence in depth, not the control. The allowlist below is what decides
        # which tools exist; this only narrows what the server bothers to offer.
        env={"GITHUB_TOOLSETS": "issues"},
        # Not set here — derived from the vetted effects, so it can never disagree
        # with them. With only reads vetted the server is launched read-only and does
        # not advertise `issue_write`, `add_issue_comment` or `sub_issue_write` at all.
        read_only_env="GITHUB_READ_ONLY",
    ),
    vetted=[
        # `description` is the server's own wording, copied from what
        # github-mcp-server v1.8.0 advertised in `tools/list` at the moment it was
        # vetted — see migration 018 for why it is stored rather than fetched. `note`
        # is ours, and optional; it says what somebody here should know before
        # granting the tool, which the vendor has no way of knowing.
        Vetted(
            "list_issues",
            effect="read",
            resources=[REPO],
            description="List issues in a GitHub repository.",
            note=(
                "Returns a page of issues at a time and can be a large response. "
                "Scope it to the repositories a team actually owns."
            ),
        ),
        # `method` is a discriminator (get / get_comments / get_labels …). Every
        # variant is a read, so one effect covers the tool.
        Vetted(
            "issue_read",
            effect="read",
            resources=[REPO],
            description=(
                "Read one issue in a GitHub repository, or its comments, labels or "
                "sub-issues."
            ),
        ),
        # The one write. Vetting it takes the server out of read-only mode — see
        # Connector.read_only — so it is deliberately the least destructive mutation
        # this server offers: a comment can be deleted, an issue cannot be un-created,
        # and neither `issue_write` nor `sub_issue_write` is vetted.
        #
        # `body` is payload, not a resource: policy has nothing to say about what the
        # comment contains, only about which repository it lands in.
        Vetted(
            "add_issue_comment",
            effect="write",
            resources=[REPO],
            description="Add a comment to an issue in a GitHub repository.",
            note=(
                "Everyone watching the repository is notified, and the comment carries "
                "the name of whichever account the run acts as. It can be deleted "
                "afterwards; the notification cannot."
            ),
        ),
    ],
)
