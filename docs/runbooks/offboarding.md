# Offboarding: somebody leaves

**Run this when a person leaves, or the moment their access must stop for any other
reason.** It takes about two minutes and every step is reversible except the ones you
choose to make permanent.

Latest transcript: [`transcripts/offboarding.md`](transcripts/offboarding.md).

## What this does, and what it deliberately does not

> **Everything that acts *as* the person stops. Nothing the person *made* is deleted.**

| Stops | How |
| --- | --- |
| Signing in | The status is read on every authenticated request |
| Every API token they own, service and personal | The owner is re-read on every call |
| Anything acting for them | An acting-for identity resolving to a disabled account is refused |

| Survives | Why |
| --- | --- |
| Agents they own | An agent is the tenant's permission list, not the person's. An orphan is visible; a silent reassignment is not |
| Grants they made | Their colleagues are relying on those. Revoking because the sharer left is a mass revocation nobody asked for |
| Group memberships | The directory owns those, and reactivation must not restore somebody into no groups |
| Connections | Sealed to their principal and reachable by nobody once nothing can act as them |
| Every audit row | Revocation closes a door and reaches through none |

**There is no hard delete, on purpose.** Every audit row that person ever produced names
their id. A row that vanished would turn a decade of history into a decade of nothing, so
a disable is what there is, and a later read answers `disabled`.

## The procedure

Set `CARNET_DATABASE_URL` and `CARNET_TENANT` first, or pass `--tenant`.

**1. Find them, and see what they hold.**

```
carnet --list-users
carnet --list-tokens
```

Record the ids. `--list-tokens` shows every credential they own and whether it is a service
or a personal token; both die with them, and the listing is what resolves a
`machine:m_…` in an old audit record to a name and an owner.

**2. Confirm the access is live before you remove it.** A drill that cannot show the
"before" proves nothing about the "after".

```
carnet --reach <their-token-id>
```

**3. Cut them off.**

```
carnet --disable-user their.address@example.com
```

It is idempotent and says what it did. It takes an address or a principal id.

**4. Verify from outside, with their own credential.** This is the step that matters and
the one a description of the procedure cannot substitute for. Present a token they own to
the running API:

```
curl -s -H "Authorization: Bearer <their token>" https://<deployment>/api/agents
```

Expect **403** and a sentence naming the reason: *the owner of this API token is no longer
an active account, so the token does not act for anybody.*

**5. Verify from the deployment.**

```
carnet --list-users        # status is `disabled`
carnet --admin-log         # user.disable, naming who did it
```

**6. Decide about what survived.** The command deliberately leaves it. Ask, in this order:

- **Did they own an agent nobody else can edit?** `carnet --list` shows agents;
  `--share-agent <agent> <colleague> --role owner` hands it over.
- **Did they hold the only connected account for a connector?** `--list-connections`.
  Reconnecting is the colleague's own act; nobody can move a sealed credential.

## Undoing it

```
carnet --enable-user their.address@example.com
```

Restores sign-in and every token.

## Known friction, found by running this — and closed

**The deprovision used to name the schedules and triggers it stopped.** Those left the
tree in step 078, and with them the half of an offboarding that used to be the one nobody
remembered to check; what stops now is sign-in and every token, and both are verified
from outside in step 4.

**`--agent-access` answers the operator now.** It refused whoever ran the CLI — `system:cli`
is an administrator to the platform role and holds no *grant* on the agent, and the agent
ladder was what the flag checked — and it refused through the argument parser, so a
permission failure printed ninety lines of usage. It reads as an administrator now, and
every permission refusal in this file prints a sentence. The check was moved to the CLI
entry point rather than into the grant ladder on purpose: widening the ladder would make a
platform role imply agent access for every HTTP caller too, which is a different and much
larger decision.
