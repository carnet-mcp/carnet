# Key rotation: `CARNET_SECRET_KEY` is suspect

**Run this when the encryption key may have been seen by somebody who should not have seen
it** — a leaked `.env`, a departed operator who held it, a backup that went somewhere
unexpected — or on a schedule, if the customer's policy sets one.

That key decrypts every delegated credential, every OAuth client secret and every trigger
secret in the deployment. Losing it is losing all of them; leaking it is worse, because
nothing tells you it happened.

Latest transcript: [`transcripts/key-rotation.md`](transcripts/key-rotation.md).

## The shape of it

Three keys exist at once during a rotation, and the whole procedure is arranged so that
**nothing is unreadable at any moment**:

| | |
| --- | --- |
| `CARNET_SECRET_KEY` | The key new writes are sealed under |
| `CARNET_SECRET_KEYS_OLD` | Keys still offered for *opening*, never for sealing |
| Neither | A row naming one of these cannot be read by this deployment at all |

`--finish-rotation` moves every row from the second column to the first. It is **safe to
interrupt and safe to re-run**: a re-sealed row leaves the population, so re-running is
itself the checkpoint. There is no job, no queue and no resume state to corrupt.

It sweeps four columns, each sealed against its own row's identity, so each is a separate
pass: `connections.ciphertext`, `connector_oauth.client_secret`,
`triggers.secret_ciphertext`, `pending_authorizations`.

## The procedure

**1. Generate the replacement.** The output goes to your secret store. Do not leave it in a
shell history.

```
carnet --generate-key
```

**2. Cut over, keeping the suspect key readable.** In `backend/.env`, or wherever the
deployment's environment is set:

```
CARNET_SECRET_KEY=<the new key>
CARNET_SECRET_KEYS_OLD=<the suspect key>
```

Restart every process that reads it — every API replica. **Every process, not just
one**: a server still holding the old configuration seals new rows under the old key,
and the sweep in step 3 will not see them because it has already passed.

Confirm nothing broke before going on. `carnet --list-connections` should list exactly
what it listed before; the `key` column still shows the old key's id.

**3. Re-seal.**

```
carnet --finish-rotation
```

It prints the current and retired key ids, a count per column, and a verdict. **Exit 0
means and only means: no row names a retired key.** Exit 1 means at least one row still
does, or one names a key this deployment has never held. Exit 2 means it could not run.

**4. Re-run it.** Two reasons, and the second is the real one: it confirms the population
is empty, and it is what you would do anyway after fixing anything the first run reported.
The second run should re-seal `0` of everything and print the same verdict.

**5. Drop the suspect key.** Only now, and only if step 3 exited 0:

```
CARNET_SECRET_KEYS_OLD=
```

Restart everything again.

**6. Prove the suspect key is worthless.** Run `--finish-rotation` in a process holding
*only* the old key. Every sealed row should be reported as `COULD NOT RE-SEAL`, each naming
the key it wants and a remedy. That is the proof the rotation actually happened.

Note that `--list-connections` is **not** that proof: it reads metadata and never opens the
blob, so it answers happily under any key. The `key` column changing between step 2 and
step 5 is the visible half; the refusal in step 6 is the other.

## If a row cannot be re-sealed

`--finish-rotation` names each row, the key it wants, and what to do. It never deletes one
and never holds one hostage. Three cases, and the first is the only one that keeps the
credential:

- **A key was dropped from `CARNET_SECRET_KEYS_OLD` too early.** Put it back and run
  again. This is the one remedy that loses nothing, and it is why step 5 comes after step 3
  rather than beside it.
- **A connection** — the person connects the account again, through `--connect-account` or
  the consent flow. Reconnecting replaces the row.
- **A consent flow** — `--set-oauth` writes a fresh sealed client secret.
- **A trigger row** — nothing fires one since step 078; delete the row.

## What this does not cover

**API tokens are hashed, not sealed**, so they are not in the population
and a key rotation does not touch them. If the *database* is what leaked rather than the
key, hashes are not credentials and the tokens are not recoverable from them — but revoke
them anyway: `--list-tokens`, then `--revoke-token` each.

**Connectors whose credential is a vault reference are not in the population either.**
Nothing was sealed, so nothing needs re-sealing. A rotation on a deployment that has moved
its connectors to `op://` references will report fewer rows than it used to. That is
correct, and it reads as a bug once.
