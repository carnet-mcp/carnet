# Drill transcript: key-rotation

| | |
| --- | --- |
| Run at | 2026-09-04 18:41:11Z |
| Run by | Claude Opus 5, at Pranav Sistla's direction |
| Commit | `07d7b49` |
| Database | `carnet_drill` on PostgreSQL 16 |
| Procedure | [`../key-rotation.md`](../key-rotation.md) |

Output is verbatim, including the failures. Secrets are redacted where one was
printed; nothing else is edited. `--generate-key` in step 2 really did print a key
and it is redacted above — it was a throwaway against a scratch database that has
since been deleted, and it was never the key anything was sealed under, but a drill
about key hygiene does not commit a key into git to make a point about verbatim
output.


## 1. Before: the deployment serves under the key that is now suspect

```console
$ CARNET_SECRET_KEY=$OLD .venv/bin/carnet --list-connections
principal                         connector         account                 how     key       changed
user:u_tom                        support-desk      tom@northwind.example   static  fa3d845d  2026-09-04  expires 2026-10-04
```

## 2. Generate the replacement. It goes to the secret store, not into a shell history

```console
$ .venv/bin/carnet --generate-key

Store this somewhere you can restore it from, then set CARNET_SECRET_KEY.
Every delegated credential is encrypted with it and unreadable without it.
<a key was printed here; redacted>
```

## 3. Cut over: the new key serves; the suspect one is still offered for opening

```console
$ CARNET_SECRET_KEY=$NEW CARNET_SECRET_KEYS_OLD=$OLD .venv/bin/carnet --list-connections
principal                         connector         account                 how     key       changed
user:u_tom                        support-desk      tom@northwind.example   static  fa3d845d  2026-09-04  expires 2026-10-04
```

## 4. Re-seal every sealed column under the new key

```console
$ CARNET_SECRET_KEY=$NEW CARNET_SECRET_KEYS_OLD=$OLD .venv/bin/carnet --finish-rotation
current key   e9f1ec8c
retired keys  fa3d845d

  connections                 1 re-sealed
  connector_oauth             1 re-sealed
  triggers                    1 re-sealed
  pending_authorizations      0 re-sealed

No row names a retired key.
CARNET_SECRET_KEYS_OLD can be emptied, on every process.
```

## 5. Re-run it. A re-sealed row leaves the population, so re-running IS the checkpoint

```console
$ CARNET_SECRET_KEY=$NEW CARNET_SECRET_KEYS_OLD=$OLD .venv/bin/carnet --finish-rotation
current key   e9f1ec8c
retired keys  fa3d845d

  connections                 0 re-sealed
  connector_oauth             0 re-sealed
  triggers                    0 re-sealed
  pending_authorizations      0 re-sealed

No row names a retired key.
CARNET_SECRET_KEYS_OLD can be emptied, on every process.
```

## 6. Drop the retired key. Exit 0 above is what authorises this step

```console
$ CARNET_SECRET_KEY=$NEW .venv/bin/carnet --list-connections
principal                         connector         account                 how     key       changed
user:u_tom                        support-desk      tom@northwind.example   static  e9f1ec8c  2026-09-04  expires 2026-10-04
```

## 7. The proof that the suspect key is now worthless: a process holding only it can open nothing

```console
$ CARNET_SECRET_KEY=$OLD .venv/bin/carnet --finish-rotation
current key   fa3d845d
retired keys  none listed in CARNET_SECRET_KEYS_OLD

  connections                 0 re-sealed
  connector_oauth             0 re-sealed
  triggers                    0 re-sealed
  pending_authorizations      0 re-sealed

  COULD NOT RE-SEAL  connections: user:u_tom @ support-desk, tenant northwind
      names key 'e9f1ec8c', which this process does not hold.
      Remedy: if that key was dropped from the list too early, put it back in CARNET_SECRET_KEYS_OLD and run this again; otherwise the person connects the account again (--connect-account, or the consent flow); reconnecting replaces the row.

  COULD NOT RE-SEAL  connector_oauth: connector 'support-desk', tenant northwind
      names key 'e9f1ec8c', which this process does not hold.
      Remedy: if that key was dropped from the list too early, put it back in CARNET_SECRET_KEYS_OLD and run this again; otherwise reconfigure the consent flow: --set-oauth writes a fresh sealed client secret.

  COULD NOT RE-SEAL  triggers: trigger trg_7c3f74ff1b694f3a, tenant northwind
      names key 'e9f1ec8c', which this process does not hold.
      Remedy: if that key was dropped from the list too early, put it back in CARNET_SECRET_KEYS_OLD and run this again; otherwise rotate the trigger's secret (--rotate-trigger-secret) — it reseals under the current key and keeps the URL, so the outside system changes one field.

No row names a retired key.

3 row(s) above name keys this process has never held, so this deployment cannot read them. The rotation itself is finished; these are a separate problem and this command exits 1 until they are gone.
If a key was dropped from CARNET_SECRET_KEYS_OLD too early, put it back and run this again — that is the one remedy that keeps the credentials.
[exit 1]
```
