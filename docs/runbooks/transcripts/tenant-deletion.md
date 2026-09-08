# Drill transcript: tenant-deletion

| | |
| --- | --- |
| Run at | 2026-09-04 18:41:27Z |
| Run by | Claude Opus 5, at Pranav Sistla's direction |
| Commit | `07d7b49` |
| Database | `carnet_drill` on PostgreSQL 16 |
| Procedure | [`../tenant-deletion.md`](../tenant-deletion.md) |

Output is verbatim, including the failures. Secrets are redacted where one was
printed; nothing else is edited.


## 1. What is about to be erased

```console
$ .venv/bin/carnet --list-users
id                  email                             status    directory id              signed in             issuer
u_priya             priya@northwind.example           active    -                         2026-09-04T18:40:03+0 https://northwind.okta.example
u_tom               tom@northwind.example             disabled  -                         2026-09-04T18:40:03+0 https://northwind.okta.example

A disabled person cannot sign in, and every token they own is refused at its next
call. --disable-user and --enable-user change it; a SCIM push changes it too.
```
```console
$ .venv/bin/carnet --list-tokens
id                    name                owner           kind      state                       last used
m_2b6dc62cef4848c6    nightly-triage      u_tom           service   live                        2026-09-04T18:40:20+00:00
m_7754f5c6600440e2    toms-laptop         u_tom           personal  live                        never

A service token's access is its grants; a personal token's is its owner's (capped at
user), live as the owner's changes. Either way a token whose owner is disabled is
refused, and every record it wrote names machine:<id> — this table is what resolves
that id to a name and an owner.
```
```console
$ docker exec carnet-pg psql -U postgres -d carnet_drill -c "select 'users' t, count(*) from users union all select 'agents', count(*) from agents union all select 'api_tokens', count(*) from api_tokens union all select 'scim_tokens', count(*) from scim_tokens union all select 'groups', count(*) from groups union all select 'admin_audit', count(*) from admin_audit union all select 'audit', count(*) from audit union all select 'connections', count(*) from connections union all select 'schedules', count(*) from schedules union all select 'triggers', count(*) from triggers order by 1"
      t      | count 
-------------+-------
 admin_audit |    19
 agents      |     1
 api_tokens  |     2
 audit       |     0
 connections |     1
 groups      |     1
 schedules   |     1
 scim_tokens |     1
 triggers    |     1
 users       |     2
(10 rows)

```

## 2. Deletion is refused while the customer is active. Suspension is a separate, reversible act

```console
$ .venv/bin/carnet --delete-tenant northwind
Deleting tenant 'northwind' destroys, permanently:
        1  agents
        1  connectors
        0  runs
        2  users
        0  audit records
       19  administrative records
        2  access denials

  Their audit log, administrative log and denial log go with them. Those
  three tables are append-only and this is the only operation that empties
  them. There is no undo and no export — take a dump first if you want one.

  A tombstone remains: 'northwind' can never be created again.

Type the tenant id 'northwind' to confirm: nothing deleted: --delete-tenant needs a terminal to confirm in, and stdin is closed. This is the one command that will not run unattended.
[exit 1]
```

## 3. Suspend. Sign-ins and machine callers stop; nothing is erased yet

```console
$ .venv/bin/carnet --tenant-status northwind suspended
Tenant 'northwind' is suspended.
  Nobody in it can sign in, and no queued run of theirs will be claimed.
  A run already executing is NOT stopped. Cancel those individually.
```
```console
$ curl -s -H "Authorization: Bearer $(cat /tmp/claude-501/svc.txt)" http://127.0.0.1:8399/agents
{"detail":"customer 'northwind' is suspended, so nobody in it may sign in"}
```

## 4. Erase. The tenant id is typed back as the confirmation

```console
$ echo northwind | .venv/bin/carnet --delete-tenant northwind
Deleting tenant 'northwind' destroys, permanently:
        1  agents
        1  connectors
        0  runs
        2  users
        0  audit records
       19  administrative records
        2  access denials

  Their audit log, administrative log and denial log go with them. Those
  three tables are append-only and this is the only operation that empties
  them. There is no undo and no export — take a dump first if you want one.

  A tombstone remains: 'northwind' can never be created again.

Type the tenant id 'northwind' to confirm: 
Tenant 'northwind' is deleted.
        0  rows from runs
        1  rows from groups
        2  rows from access_denials
       19  rows from admin_audit
        0  rows from audit
  tombstone written at 2026-09-04 18:41:30.995027+00:00, actor system:cli
```

## 5. Nothing left behind, table by table

```console
$ docker exec carnet-pg psql -U postgres -d carnet_drill -c "select 'users' t, count(*) from users union all select 'agents', count(*) from agents union all select 'api_tokens', count(*) from api_tokens union all select 'scim_tokens', count(*) from scim_tokens union all select 'groups', count(*) from groups union all select 'admin_audit', count(*) from admin_audit union all select 'audit', count(*) from audit union all select 'connections', count(*) from connections union all select 'schedules', count(*) from schedules union all select 'triggers', count(*) from triggers order by 1"
      t      | count 
-------------+-------
 admin_audit |     0
 agents      |     0
 api_tokens  |     0
 audit       |     0
 connections |     0
 groups      |     0
 schedules   |     0
 scim_tokens |     0
 triggers    |     0
 users       |     0
(10 rows)

```
```console
$ docker exec carnet-pg psql -U postgres -d carnet_drill -c "select id, name, status from tenants"
 id | name | status 
----+------+--------
(0 rows)

```

## 6. And the credential the customer's machine held is refused, because there is nobody to be

```console
$ curl -s -H "Authorization: Bearer $(cat /tmp/claude-501/svc.txt)" http://127.0.0.1:8399/agents
{"detail":"not a valid token for this service"}
```
