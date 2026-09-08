# Security

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting**, on the
[Security tab](https://github.com/carnet-mcp/carnet/security/advisories/new). It is
private between you and the maintainers, it needs no email address from either of us, and
it gives us a place to prepare a fix and an advisory before anything is public.

**Please do not open a public issue for a vulnerability.** Carnet sits in front of other
people's credentials, so a public report is a working exploit against every deployment
that has not upgraded yet.

If private reporting is unavailable to you for any reason, open a public issue that says
only *"security issue, please open a private channel"* — with no detail — and we will.

## What to expect

This is a small project and honesty about that is more useful than a promise nobody can
keep:

| | |
| --- | --- |
| First response | within a week, usually sooner |
| Fix | as fast as the severity warrants; you will be told what we think it is and why |
| Credit | in the advisory and the changelog, unless you would rather not be named |
| Embargo | we will agree one with you rather than impose one |

There is no bounty programme.

## What is in scope

Anything that breaks one of the properties the product is *for*:

- **A call the broker should have refused, admitted.** A tool outside a token's grants, a
  resource outside its scope, a call after revocation or after its owner was disabled.
- **A credential reaching somewhere it should not.** The shipped secret in a response, an
  audit row, a log line or an error; one person's connected account used for another
  person's call.
- **One tenant reading or writing another's rows**, through any route, the door included.
- **Authentication or consent flaws**: a token accepted that should not verify, an OAuth
  code or state reused, a redirect that goes somewhere the client did not register.
- **Egress control bypassed** — reaching a host the tenant never approved, a private
  address, or cloud metadata.
- **An unauthenticated request that reaches storage or spends money.**

## What is not

- **Anything the assistant does without going through the door.** Carnet governs calls
  routed through `/mcp`. An agent on somebody's laptop can dial a vendor directly, and
  saying so is the first thing [docs/PREMISE.md](docs/PREMISE.md) does. That is a stated
  boundary, not a vulnerability.
- **A tool doing what it was vetted to do.** If somebody approved a `write` tool and
  scoped it widely, the broker admitting the call is the system working. Vetting is the
  control.
- **Denial of service by an authenticated caller against their own deployment**, and
  findings from a scanner with no working request behind them.
- **`carnet --local`, and the local identity provider**, which exist for a laptop and say
  so. Binding them to a network is refused unless you type the flag that asks for it.

## Where the security properties are written down

- [docs/PREMISE.md](docs/PREMISE.md) — what is governed, and what is explicitly not.
- [docs/DESIGN.md](docs/DESIGN.md) — the trust boundary, tenancy, permissions and the
  audit log, with the reasoning behind each.
- [docs/LIMITS.md](docs/LIMITS.md) — what is known to be missing or weak. If you are
  about to report something, it is worth a look; if it is listed there, we already know,
  and a report that tells us the *consequence* is still worth having.

## Supported versions

The newest release, and the migration path from every earlier one — see
[docs/UPGRADING.md](docs/UPGRADING.md). There is no long-term-support branch; a fix lands
on the newest release.
