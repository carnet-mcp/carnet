# Tenant deletion: a customer invokes their deletion clause

**Run this when a customer leaves and their contract says their data goes.** It is the only
irreversible procedure in this directory. There is no undo, no soft-delete flag and no
recycle bin; when it returns, the customer is not in the database.

Latest transcript: [`transcripts/tenant-deletion.md`](transcripts/tenant-deletion.md).

## Before you start

**Have the deletion request in writing, and have the tenant id in front of you.** The
command asks you to type the id back, and that prompt is the last thing standing between a
typo and somebody else's customer.

**Take a backup if the contract allows one.** A DPA deletion clause usually forbids
keeping one; if yours does not, this is the moment. After the command there is nothing to
restore from.

**Know what it does not reach.** Deletion empties this deployment's database. It does not
reach the customer's own systems, the accounts their people connected, or anything a
model provider logged. If the contract covers those, they are separate requests to
separate parties, and the deletion of our rows is not evidence about them.

## The procedure

**1. Write down what is about to go.** The transcript's value is the before-and-after, and
the after is all zeroes whatever happened.

```
carnet --list-users
carnet --list-tokens
carnet --list        # agents
```

For a row-level record, count the tables directly:

```sql
select 'users' t, count(*) from users
union all select 'agents', count(*) from agents
union all select 'api_tokens', count(*) from api_tokens
union all select 'admin_audit', count(*) from admin_audit
union all select 'audit', count(*) from audit
order by 1;
```

**2. Suspend the customer.** Deletion is refused while they are active, and suspension is
a separate, reversible act:

```
carnet --tenant-status <tenant-id> suspended
```

Sign-ins stop, and so does every machine caller — a suspended customer's token is refused
with the same sentence their staff get. Nothing is erased. **If the request turns out to be
premature, this is the state to stop in**; `--tenant-status <id> active` puts everything
back exactly as it was.

Confirm it took effect before going on. Present a token belonging to that customer and
expect a refusal.

**3. Erase.**

```
carnet --delete-tenant <tenant-id>
```

It prompts for the tenant id and does nothing until you type it back. Five tables that hold
the customer without a cascade are emptied explicitly inside one transaction, in dependency
order, and the rest follow their foreign keys. A table added later and forgotten fails
loudly rather than orphaning rows, which is why this is a method rather than a `DELETE FROM
tenants`.

**4. Prove it.** Re-run the counts from step 1. Every one should be `0`, and the tenant
row itself should be gone:

```sql
select id, name, status from tenants;
```

Then present a credential that customer's machine held. Expect a refusal: there is no
longer anybody for it to act as.

**5. Record it.** The customer's own `admin_audit` rows went with them — that is what
deletion means — so the evidence that it happened lives outside the database. Keep the
transcript, the date, and who ran it, wherever your DPA obligations are tracked.

## Known friction, found by running this — and closed

**The confirmation prompt used to claim more than it checked.** With stdin closed the
refusal read *"--delete-tenant needs a terminal to confirm in, and stdin is closed. This
is the one command that will not run unattended"* — and the check was that stdin was
*readable*, not that a person was there, so `echo <tenant-id> | carnet --delete-tenant
<tenant-id>` deleted the customer with nobody watching.

It checks `sys.stdin.isatty()` now, so the sentence is true. The one way past it is an
environment variable named at length in the refusal itself
(`CARNET_TENANT_DELETION_REHEARSAL_I_AM_NOT_A_PERSON`), which exists so
`scripts/e2e_tenant_deletion.py` can rehearse this command against a scratch database.
It is named in the refusal rather than hidden, because hiding it would only mean finding
it in the source — and it is a sentence rather than a flag so that nothing sets it by
accident.

**Still true, and not a defect**: this command is the only one in the product that cannot
be scripted. That is the point of it.
