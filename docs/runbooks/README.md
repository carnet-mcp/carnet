# Runbooks

Three procedures, each of which has been run at least once against a real deployment.
That last clause is the point of this directory: every other guarantee in this repository
points at code and a test, and these point at somebody having actually done the thing and
kept what the terminal said.

| Procedure | What it is for | Last run | Transcript |
| --- | --- | --- | --- |
| [Offboarding](offboarding.md) | Somebody leaves | 2026-09-04 | [transcript](transcripts/offboarding.md) |
| [Key rotation](key-rotation.md) | A `CARNET_SECRET_KEY` is suspect | 2026-09-04 | [transcript](transcripts/key-rotation.md) |
| [Tenant deletion](tenant-deletion.md) | A DPA deletion clause is invoked | 2026-09-04 | [transcript](transcripts/tenant-deletion.md) |

**A questionnaire can be answered from a roadmap and a drill cannot.** The transcripts are
the deliverable, not these documents: each is the verbatim output of running the procedure
against a real deployment on real PostgreSQL, including the commands that failed. A
procedure nobody has executed is a description of what somebody hopes would happen.

## How these were produced

`backend/scripts/drill_world.py` builds a customer with something to lose — two people, an
agent, a service token, a personal token, and every sealed column populated (the
trigger secret is seeded straight into its row since step 078 — nothing fires it, and
the key drill sweeps the column regardless). `backend/scripts/drill_run.sh` runs a procedure's
commands and records them verbatim into `transcripts/`. Re-running either is how the next
drill is produced; the transcripts are dated and kept rather than overwritten in place when
the answer changes.

The three drills in the transcripts above were run in one session against one world, in
this order, because the order is the only one available: deletion destroys what the other
two operate on.

## What the first run found — and what was done about it

Four things, none of which any test had reported. This is what drills are for and it is
why the register grades them *"flat, but every drill not run is a claim not yet true"*.
**All four are fixed.** Each is written below as it was found, with the remedy after it: a
findings list that quietly turns into a list of solved problems is a list nobody can
check.

1. **A door-only deployment cannot show an operator what a deprovision stopped.** The
   schedules and triggers that fired as the person's tokens were disabled by
   `users.set_active`, correctly, and the only evidence was the `user.disable` record's
   `detail`, which is not where anybody would look. **Fixed** at the time by printing the
   ids; **moot** since step 078, which removed schedules and triggers from the tree.
2. **`--agent-access` refuses the operator holding the database, and answers with 90 lines
   of usage.** `system:cli` is an administrator to `roles.is_admin` but holds no *grant* on
   the agent, and the agent ladder is what `--agent-access` checks. The register's own
   argument for keeping role granting on the CLI is that the operator can read any tenant
   directly, so refusing them here protects nothing — and a permission refusal that prints
   the whole argument parser is the wrong shape besides. **Fixed**: it reads as an
   administrator, and all four commands sharing that refusal print a sentence. The
   composition is at the CLI entry point rather than in the grant ladder, so a platform
   role still does not imply agent access for an HTTP caller.
3. **The deletion confirmation claims a terminal and accepts a pipe.** The refusal reads
   *"--delete-tenant needs a terminal to confirm in, and stdin is closed. This is the one
   command that will not run unattended"* — and `echo northwind | carnet --delete-tenant
   northwind` deletes the customer. The check is "stdin is readable", the sentence promises
   "a human is present", and the gap between them is the one an automated script falls
   through. **Fixed**: the check is `sys.stdin.isatty()`, and the one way past it is an
   environment variable named in full inside the refusal, for the rehearsal script.
4. **A CI scene had been passing on leftover state.** Not from a drill, but found in the
   same session: the deploy e2e's second-deployment-in-a-cluster scene needs the tenant
   role to already exist and never created it, so it passed on any long-lived container and
   failed on a fresh one. **Fixed** in `e2e_deploy.py`: the scene creates the role it
   needs, as the cluster's administrator rather than as the deployment's own role.

Each of the first three has a row in the deferred-work register recording what was found and what was
done. The rows are closed rather than deleted, because the finding is the useful part.
