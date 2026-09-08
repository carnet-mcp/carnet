# Drill transcript: offboarding

| | |
| --- | --- |
| Run at | 2026-09-04 18:40:55Z |
| Run by | Claude Opus 5, at Pranav Sistla's direction |
| Commit | `07d7b49` |
| Database | `carnet_drill` on PostgreSQL 16 |
| Procedure | [`../offboarding.md`](../offboarding.md) |

Output is verbatim, including the failures. Secrets are redacted where one was
printed; nothing else is edited.


## 1. Find them, and see what they hold

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
$ .venv/bin/carnet --list-schedules
id                agent             cadence                       state     next
sch_b0ca711aff2a  issue-triage      every day at 07:30            off       2026-09-05T07:30+01:00  (2026-09-05T06:30+00:00)
                  fires as machine:m_2b6dc62cef4848c6

A schedule holds no access of its own — what it may run is the machine's grants.
--edit-schedule changes the task, cadence, zone or machine and keeps the id; a new
cadence recomputes the next fire from now and backfills nothing.
--schedule-runs shows what one has actually run.
```
```console
$ .venv/bin/carnet --list-triggers
id                    name              agent             state   last delivery
trg_7c3f74ff1b694f3a  issue-arrived     issue-triage      off     never
                      fires as machine:m_2b6dc62cef4848c6
                      URL http://localhost:8080/api/hooks/trg_7c3f74ff1b694f3a

A trigger holds no access of its own — what it may run is the machine's grants, and
its spend is bounded by the per-principal run ceiling. The secret is shown once and
cannot be re-read: --rotate-trigger-secret issues a new one and keeps this URL, so
the sender changes one field instead of every field.
```

## 2. Confirm the access is live before removing it

```console
$ curl -s -o /dev/null -w 'GET /agents as their service token -> %{http_code}\n' -H "Authorization: Bearer art_<redacted>" http://127.0.0.1:8399/agents
GET /agents as their service token -> 403
```
```console
$ .venv/bin/carnet --reach m_2b6dc62cef4848c6
API token 'm_2b6dc62cef4848c6' reaches 1 tool(s) through 1 agent(s).

  post_message  (write)
      via issue-triage: chat.channel #support


This is the grant. Whether the token still works — revoked, expired, owner disabled
— is `--list-tokens`.
```

## 3. Cut them off

```console
$ .venv/bin/carnet --disable-user tom@northwind.example
u_tom (tom@northwind.example) is already disabled.
```

## 4. Verify from outside, with their own credential

```console
$ curl -s -o /dev/null -w 'GET /agents as their service token -> %{http_code}\n' -H "Authorization: Bearer art_<redacted>" http://127.0.0.1:8399/agents
GET /agents as their service token -> 403
```
```console
$ curl -s -H "Authorization: Bearer art_<redacted>" http://127.0.0.1:8399/agents
{"detail":"the owner of this API token ('u_tom') is no longer an active account, so the token does not act for anybody. A machine credential belongs to a person; when they go, it goes."}
```

## 5. Verify from the deployment

```console
$ .venv/bin/carnet --list-users
id                  email                             status    directory id              signed in             issuer
u_priya             priya@northwind.example           active    -                         2026-09-04T18:40:03+0 https://northwind.okta.example
u_tom               tom@northwind.example             disabled  -                         2026-09-04T18:40:03+0 https://northwind.okta.example

A disabled person cannot sign in, and every token they own is refused at its next
call. --disable-user and --enable-user change it; a SCIM push changes it too.
```
```console
$ .venv/bin/carnet --list-schedules
id                agent             cadence                       state     next
sch_b0ca711aff2a  issue-triage      every day at 07:30            off       2026-09-05T07:30+01:00  (2026-09-05T06:30+00:00)
                  fires as machine:m_2b6dc62cef4848c6

A schedule holds no access of its own — what it may run is the machine's grants.
--edit-schedule changes the task, cadence, zone or machine and keeps the id; a new
cadence recomputes the next fire from now and backfills nothing.
--schedule-runs shows what one has actually run.
```
```console
$ .venv/bin/carnet --list-triggers
id                    name              agent             state   last delivery
trg_7c3f74ff1b694f3a  issue-arrived     issue-triage      off     never
                      fires as machine:m_2b6dc62cef4848c6
                      URL http://localhost:8080/api/hooks/trg_7c3f74ff1b694f3a

A trigger holds no access of its own — what it may run is the machine's grants, and
its spend is bounded by the per-principal run ceiling. The secret is shown once and
cannot be re-read: --rotate-trigger-secret issues a new one and keeps this URL, so
the sender changes one field instead of every field.
```

## 6. The record: what was done, by whom, and what it stopped

```console
$ .venv/bin/carnet --admin-log
when                  who                             what                  to                          detail
2026-09-04T18:40:02   system:cli                      role.grant            user:u_priya                role=admin
2026-09-04T18:40:02   system:cli                      group.create          group:g_cc65ec6749984b27    external_id=dir-eng, name=engineering
2026-09-04T18:40:02   system:cli                      group.member.add      group:g_cc65ec6749984b27    member_id=u_tom, member_kind=user
2026-09-04T18:40:02   system:cli                      agent.save            agent:issue-triage          fields=['name', 'permissions', 'runtime'], scope={'chat.channel': {'write': ['#support']}}, tools=['post_message']
2026-09-04T18:40:02   system:cli                      grant.create          agent:issue-triage          grantee_id=u_tom, grantee_kind=user, role=owner
2026-09-04T18:40:02   system:cli                      grant.create          agent:issue-triage          grantee_id=g_cc65ec6749984b27, grantee_kind=group, role=user
2026-09-04T18:40:02   system:cli                      token.mint            machine:m_2b6dc62cef4848c6  acts_as_owner=False, expires_at=, name=nightly-triage, owner=u_tom
2026-09-04T18:40:02   system:cli                      grant.create          agent:issue-triage          grantee_id=m_2b6dc62cef4848c6, grantee_kind=machine, role=user
2026-09-04T18:40:03   system:cli                      schedule.create       schedule:sch_b0ca711aff2a   agent=issue-triage, cadence=every day at 07:30, fires_as=machine:m_2b6dc62cef4848c6, timezone=Europe/London
2026-09-04T18:40:03   system:cli                      token.mint            machine:m_7754f5c6600440e2  acts_as_owner=True, expires_at=, name=toms-laptop, owner=u_tom
2026-09-04T18:40:03   system:cli                      trigger.create        trigger:trg_7c3f74ff1b694f3 agent=issue-triage, fires_as=machine:m_2b6dc62cef4848c6, name=issue-arrived
2026-09-04T18:40:03   system:cli                      egress.allow          host:mcp.northwind.example  note=
2026-09-04T18:40:03   system:cli                      connector.create      connector:support-desk      allow_asserted_identity=False, from_recipe=, kind=http, url=https://mcp.northwind.example/mcp
2026-09-04T18:40:03   system:cli                      connector.oauth.configureconnector:support-desk      client_id=northwind-carnet, scopes=['read:tickets', 'write:tickets'], token_endpoint=https://mcp.northwind.example/token
2026-09-04T18:40:03   user:u_tom                      connection.create     connector:support-desk      kind=static, label=tom@northwind.example, principal=user:u_tom
2026-09-04T18:40:03   system:cli                      scim.token.mint       scim_token:sc_c7505910e15b4 issuer=https://northwind.okta.example, name=okta-provisioning
2026-09-04T18:40:20   system:cli                      schedule.disable      schedule:sch_b0ca711aff2a   
2026-09-04T18:40:20   system:cli                      trigger.disable       trigger:trg_7c3f74ff1b694f3 
2026-09-04T18:40:20   system:cli                      user.disable          user:u_tom                  cause=--disable-user, schedules=['sch_b0ca711aff2a'], triggers=['trg_7c3f74ff1b694f3a']
```

## 7. What survived, on purpose: the agent they owned and the grants they made

```console
$ .venv/bin/carnet --list
issue-triage  (runtime: simple)   [not shared with system:cli]
    tools: post_message
    scope:
        write  chat.channel  ->  #support
```
```console
$ .venv/bin/carnet --agent-access issue-triage
  refusing system:cli user on 'issue-triage' in tenant northwind
usage: carnet [-h] [--version] [--agent AGENT] [--task TASK] [--upload PATH]
                [--deny-demo] [--list] [--list-tools] [--quiet] [--runs [N]]
                [--usage [DAYS]] [--admin-log [N]] [--denials [N]] [--worker]
                [--follow RUN_ID] [--cancel RUN_ID] [--compare RUN_A RUN_B]
                [--migrate] [--seed] [--generate-key] [--finish-rotation]
                [--share-agent AGENT WHO] [--role {user,editor,owner}]
                [--unshare-agent AGENT WHO] [--agent-access AGENT]
                [--rename-agent OLD NEW] [--add-group NAME [DESCRIPTION ...]]
                [--delete-group GROUP] [--group-add GROUP WHO]
                [--group-remove GROUP WHO] [--group-link GROUP DIRECTORY_ID]
                [--group-unlink GROUP] [--groups [GROUP]]
                [--grant-role ROLE WHO] [--revoke-role ROLE WHO]
                [--list-roles] [--mint-token NAME WHO] [--expires-days N]
                [--as-owner] [--revoke-token TOKEN_ID] [--list-tokens]
                [--reach TOKEN_ID] [--simulate TOKEN_ID] [--call TOOL]
                [--arg NAME=VALUE] [--list-users] [--disable-user WHO]
                [--enable-user WHO] [--mint-scim-token NAME] [--idp ISSUER]
                [--list-scim-tokens] [--revoke-scim-token TOKEN_ID]
                [--create-schedule AGENT] [--schedule-task TEXT]
                [--cadence SPEC] [--schedule-timezone ZONE]
                [--fire-as TOKEN_ID] [--list-schedules [AGENT]]
                [--enable-schedule ID] [--disable-schedule ID]
                [--delete-schedule ID] [--edit-schedule ID]
                [--schedule-runs ID] [--rotate-trigger-secret ID]
                [--create-trigger AGENT] [--trigger-name TEXT]
                [--trigger-task TEXT] [--list-triggers [AGENT]]
                [--enable-trigger ID] [--disable-trigger ID]
                [--delete-trigger ID] [--add-connector ID] [--url URL]
                [--kind {http,rest}] [--credential-env NAME]
                [--check-credential CONNECTOR]
                [--credential-ref op://VAULT/ITEM/FIELD]
                [--credential-header NAME] [--credential-prefix TEXT]
                [--header NAME=VALUE] [--description DESCRIPTION]
                [--list-recipes] [--from-recipe ID]
                [--allow-asserted-identity]
                [--set-asserted-identity ID ON|OFF]
                [--allow-host HOST [NOTE ...]] [--revoke-host HOST]
                [--list-hosts] [--discover ID] [--vet ID] [--tool TOOL]
                [--effect {read,write}] [--identity {service,user}]
[... 
25 further lines, unedited but cut for length ...]
[exit 2]
```
