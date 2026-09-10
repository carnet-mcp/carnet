"""Which failure becomes which status code.

The table, and the reasoning for the two rows that are not obvious:

| Condition                          | Status | |
| ---------------------------------- | ------ | |
| no token, bad token, wrong audience| 401    | authenticate again — see api/deps.py |
| a real person who may not use this | 403    | authenticating again will not help |
| unknown agent                      | 404    | |
| an agent nobody shared with you    | 404    | **the same 404**, deliberately — see below |
| a share you may make but is invalid| 400    | `ShareRefused` — the agent is not the secret |
| a real person who is not an admin  | 403    | `RoleRequired` — and **403 here, 404 there**; see below |
| a machine with no grant on the agent | 403 | `AccessDenied` — names the `--share-agent` line; see below |
| a token you may not aim: not yours, not there, or revoked | 400 | `ValueRefused` — one sentence for all three since 069, on 028's rule |
| a group operation that is invalid  | 400    | `GroupRefused` — a group is not a secret either |
| agent exists, its config is invalid| 422    | `agents.get` raises rather than returning None |
| unknown tenant                     | 404    | never leaks whether it exists elsewhere |
| creating an agent whose name exists| 409    | `AgentNameTaken` — see below |
| granting to a group that does not exist | 400 | `NoSuchGroupError` — the same reasoning |
| granting a role that is not one    | 400    | refused in the route, beside the grantee kind |
| editing an agent somebody else just edited | 409 | `AgentChanged` — see below |
| a PATCH with no `If-Match`         | 428    | raised in the route — see below |
| connecting where no consent flow exists | 400 | `OAuthRefused` — see below |
| a forged, replayed or expired `state`   | 303 | **not an error** — the callback redirects |
| vetting or registration refused    | 400    | `RegistrationRefused` — 12c |
| registering a connector id that exists | 409 | `ConnectorExistsError` — `AgentNameTaken`'s reasoning |
| the caller's own credential is broken | 400  | `CredentialError` — 12c, and see below |
| **the customer's own MCP server did not answer** | **502** | `TransportError` — 12c, and see below |
| a value a column will never accept | 400    | `ValueRefused` — 12c, and see below |
| a sealed secret this process cannot open | 503 | `CryptoError` — 023, and see below |
| storage unavailable                | 503    | |

**A row missing from this table is a 500, and 7b found that twice.** `OAuthRefused` and
`ConnectionRefused` both reach routes and neither had a handler, so clicking Connect on a
connector an administrator had not set up answered *"Internal Server Error"* — and a bad
`return_to` answered **503 "storage unavailable"**, because the check lives in storage and
`StorageError` had the only matching handler. Step 011 hit the identical shape with
`NoSuchGroupError`, and its note says so: *"found by running the grant routes at their
edges, which is where a route added after a handler table was written goes unmapped"*.
Both were found the same way again. The table above is a checklist for the next route.

**The consent callback is the one place a refusal is not a status code.** A forged or
replayed `state` is a security event, and the thing on the other end of it is a person's
browser — so the honest response is not a 400 body they will never see but a redirect back
to the Connections page carrying a sentence. Nothing was sealed in any of those cases,
which is what makes reporting it gently rather than loudly the correct call.

**A brokered denial is not an HTTP error.** The broker refusing a tool call is the
system working exactly as designed: the model is told, and it carries on. It surfaces
as a `denied` count on a 200, the same way the door log shows it. Mapping it to a 403 would
report a successful enforcement as a server failure — and would make the most important
records in the audit log look like outages.

**A name that is taken is a 409, and the message does not say whose.** `POST /agents` is
reachable by anybody authenticated in the tenant, which is deliberate — creation is not a
permission, see routes_agents.py. That makes the refusal a small enumeration oracle: a
caller learns that `payroll-bot` exists. Unavoidable, because the alternative is
accepting the name and silently replacing somebody's agent, which is the whole reason
`create_agent` is not an upsert. What is avoidable is making it *useful*, so the sentence
names no owner and there is deliberately no route that answers "is this name free"
without also creating the agent.

**A stale edit is a 409 that says what differs, and a missing `If-Match` is a 428.** The
first is the same family as the name conflict above: honouring a save whose base version is gone
hands one editor the power to silently revert another's scope narrowing, which is a wrong
result that looks exactly like a correct one. The body names the current `updated_at` and
the top-level keys the request disagrees with the stored config about, because "somebody
else edited this" with nothing further leaves a person diffing two configs by eye.

The 428 is the case where the question could not even be asked. A `PATCH` with no
precondition is last-write-wins, and accepting it *by default* is how a system grows a
concurrency guard that most callers do not use. Refusing is a status code invented for
this exact problem, and it tells a client author what to send.

**An agent whose config is invalid is still a 200 on `GET /agents/{name}` as of 10d, and
the 422 moved rather than vanishing.** It stands for the write that would put the
config to use: the agent exists, it is broken, and what cannot happen is *serving* it
through the door. Answering 422 to a **read** meant the detail screen never
rendered for exactly the agent somebody needed to fix, while `GET /agents` deliberately
listed it with its reason — two representations of one state, and the fix is one of them.
The reason the ordering below is still load-bearing is unchanged: the grant check runs
first, so an ungranted agent and an absent one stay indistinguishable.

**An administrative route answers 403 where an agent route answers 404, and the inversion
is a decision rather than an inconsistency.** The two rows disagree because the *resource*
differs. An agent route names an agent, whose existence is worth hiding — see the next
paragraph. An administrative route names **the route itself**: `/admin-audit` exists
identically for every tenant, is published in the OpenAPI document, and is not a secret
anybody can be protected from. A 404 there would tell an authenticated colleague a lie —
*this product has no administrative log* — that costs support tickets and protects
nothing. The body is `deps.py`'s doctrine, actionable by a person, and it deliberately
**names no current administrators**: a directory of who to phish is not an error
message's job.

**An agent you have no grant on is a 404, not a 403** — and this is the row people want
to change. A 403 is the honest status for "you are who you say and may not have this",
which is exactly why it is wrong here: it *confirms the agent exists*. In a tenant you
share with colleagues, a 403 sweep over plausible names enumerates every agent in the
company, and the enumeration is more valuable than the access.

That makes the ordering inside the routes load-bearing rather than incidental. The grant
check runs **before** the config is loaded, because an invalid config is a 422 — so
checking access second would answer 404 for an agent that does not exist and 422 for an
ungranted one that does, and the leak reopens through a status code nobody thought of as
an authorization decision.
"""

import logging

from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from ..access.connections import ConnectionRefused
from ..access.grants import NoAccess, ShareRefused
from ..access.groups import GroupRefused
from ..access.oauth import OAuthRefused
from ..access.recipes import RecipeRefused
from ..access.roles import RoleRequired
from ..access.oauth_server import OAuthError
from .responses import AsciiJSONResponse
from .routes_mcp import mcp as door_endpoint
from .routes_mcp import widen_challenge
from ..access.users import AccessDenied, UserRefused
from ..agents import AgentChanged, InvalidAgentError
from ..core.credentials import CredentialError
from ..tools import RegistrationRefused
from ..tools.mcp.egress import EgressRefused
from ..core.crypto import CryptoError
from ..tools.mcp.transport import TransportError
from ..storage.base import (
    AgentNameTaken,
    ConnectorExistsError,
    NoSuchGroupError,
    StorageError,
    UnknownTenantError,
    ValueRefused,
)

log = logging.getLogger(__name__)


def _problem(code: int, detail: str, **extra) -> JSONResponse:
    """The HTTP status is `code`, not `status`, and that is not bikeshedding.

    `status` is a **body field** in this API, and a handler that has to report one in
    a conflict body would find a parameter of the same name makes that a TypeError
    rather than a response.
    """
    return JSONResponse(status_code=code, content={"detail": detail, **extra})


def install(app) -> None:
    """Attach the handlers. Called once, from the app factory."""

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException):
        # Step 083. FastAPI's own handler, with one addition: a 401 at the MCP door
        # carries `resource_metadata` in its challenge, because that header is how a
        # client that was handed only the door's URL finds out where to sign in. Here
        # rather than in a dependency so that overriding `principal_from_request` in a
        # test still overrides the door, and because a 401 becoming bytes is this
        # file's job. Every other `HTTPException` is rendered exactly as before.
        # Keyed on the matched endpoint, not on the path: behind the shipped front
        # door uvicorn runs with `--root-path /api`, so `request.url.path` is
        # `/api/mcp` there and `/mcp` in a test — the router has already put the
        # endpoint it matched into the scope, and that is the same object either way.
        if request.scope.get("endpoint") is door_endpoint and exc.status_code == 401:
            exc = widen_challenge(exc)
        return await http_exception_handler(request, exc)

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError):
        # Step 087. FastAPI's own handler, byte-for-byte in status and shape, rendered
        # through `_AsciiJSONResponse` — see its docstring for the one input that made
        # the default a 500. Pydantic had already refused the request correctly as
        # `string_unicode`; what failed was telling the caller so.
        return AsciiJSONResponse(
            status_code=422, content={"detail": jsonable_encoder(exc.errors())}
        )

    @app.exception_handler(OAuthError)
    def _oauth(_request: Request, exc: OAuthError):
        # Step 083. **The RFCs' shape, not this API's `detail`**: RFC 6749 §5.2 and
        # RFC 7591 §3.2.2 both specify `{"error": …, "error_description": …}`, and
        # the MCP SDK's client parses exactly that. The status is the RFC's too — 400
        # for every client error at these endpoints, 401 nowhere, because none of them
        # authenticates a bearer.
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(UnknownTenantError)
    def _unknown_tenant(_request: Request, exc: UnknownTenantError):
        # 404 rather than 403: a caller who names a tenant that is not theirs learns
        # only that there is nothing here for them.
        return _problem(404, str(exc))

    @app.exception_handler(NoAccess)
    def _no_access(_request: Request, exc: NoAccess):
        # 404, and the message is the one an absent agent produces. `grants.require`
        # raises this with the same text either way, so the equality is a property of
        # that function rather than of this handler agreeing with a route.
        return _problem(404, str(exc))

    @app.exception_handler(ShareRefused)
    def _share_refused(_request: Request, exc: ShareRefused):
        # 400, not the 404 `NoAccess` becomes. The caller has already proved `editor` on
        # this agent, so its existence is not a secret from them — what is wrong is the
        # share they asked for, and saying so leaks nothing. Registered before any share
        # endpoint exists so the two exceptions cannot silently collapse back into one.
        return _problem(400, str(exc))

    @app.exception_handler(InvalidAgentError)
    def _invalid_agent(_request: Request, exc: InvalidAgentError):
        # 422, not 404 and not 500. The row exists and is unusable, and the message is
        # the one written to be read by a person at 3am — who is now a form user.
        return _problem(422, str(exc))

    @app.exception_handler(AgentChanged)
    def _agent_changed(_request: Request, exc: AgentChanged):
        # 409, carrying the current `updated_at` and the keys that differ — both as
        # fields, because prose is not something a client can branch on. `updated_at` is
        # what a client sends back as `If-Match` to retry, so it is the one field here
        # that is machinery rather than explanation.
        return _problem(
            409,
            str(exc),
            updated_at=exc.updated_at.isoformat(),
            changed=exc.changed,
        )

    @app.exception_handler(AgentNameTaken)
    def _agent_name_taken(_request: Request, exc: AgentNameTaken):
        # 409, and it must be registered even though `StorageError` below already has a
        # handler: Starlette resolves by walking the exception's MRO, so the subclass
        # wins — and without this row a name collision would arrive as a **503**, which
        # tells a person to try again later about something that will never work.
        return _problem(409, str(exc))

    @app.exception_handler(NoSuchGroupError)
    def _no_such_group(_request: Request, exc: NoSuchGroupError):
        # 400, and registered for the reason `AgentNameTaken` is: Starlette resolves by
        # walking the MRO, so without this row a grant naming a group that does not exist
        # arrives as a **503** — "storage unavailable" for a caller who mistyped an id.
        # Found by running the grant routes at their edges, which is where a route added
        # after a handler table was written goes unmapped.
        #
        # Safe to explain, on `ShareRefused`'s reasoning: the caller has already proved
        # `editor` on this agent, so nothing here is a secret from them.
        return _problem(400, str(exc))

    @app.exception_handler(OAuthRefused)
    def _oauth_refused(_request: Request, exc: OAuthRefused):
        # 400, on `ShareRefused`'s reasoning: the caller is entitled to connect their own
        # account and *this particular request* is wrong — a connector with no consent
        # flow, a `return_to` that would leave the application, a provider that refused
        # the exchange. Nothing here is a secret from somebody authenticated in the
        # tenant, and every one of these is a sentence they can act on.
        #
        # **Registered because a route added after this table was written goes unmapped**,
        # which is exactly how `NoSuchGroupError` arrived as a 503 in step 011. Without
        # this row an `OAuthRefused` is an unhandled exception and a **500** — "the
        # server broke" for somebody who clicked Connect on a connector an administrator
        # has not set up yet. Found by driving the route rather than by reading it.
        return _problem(400, str(exc))

    @app.exception_handler(UserRefused)
    def _user_refused(_request: Request, exc: UserRefused):
        # 400: a request about a person that names nobody. Only `users.set_active`
        # raises it, and every HTTP caller of that has already read the row, so this is
        # a row that vanished mid-request rather than a typo — still the caller's to
        # retry, still not an outage. Step 071.
        return _problem(400, str(exc))

    @app.exception_handler(RecipeRefused)
    def _recipe_refused(_request: Request, exc: RecipeRefused):
        # **500, and it is the one refusal in this table that is not the caller's fault.**
        # A recipe is a file in this repository. If it will not parse, does not validate,
        # or sets a field the code it fills no longer takes, the caller did nothing wrong
        # and there is nothing they can do — so a 4xx would be a lie about whose problem
        # it is. The sentence names the file, because the reader is whoever has to open
        # it.
        #
        # Registered in the same commit as the class, which is what `RoleRequired`'s
        # comment says this table's last four rows taught — and it was still nearly
        # missed: the route shipped first and a malformed recipe was an unhandled
        # exception with no sentence and no filename, exactly the shape 7b found twice
        # and 011 shipped as a 503. Found by driving the route with a broken file.
        #
        # Deliberately **not** degraded to "skip the bad one and serve the rest": a
        # catalogue quietly one shorter than it should be is how a broken preset survives
        # a release, and the picker would look complete while the vendor somebody came
        # for was missing.
        return _problem(500, str(exc))

    @app.exception_handler(ConnectionRefused)
    def _connection_refused(_request: Request, exc: ConnectionRefused):
        # 400, and registered beside the one above for the identical reason. It is
        # `OAuthRefused`'s sibling in `access/connections.py` and reaches a route through
        # the same paths.
        return _problem(400, str(exc))

    @app.exception_handler(RoleRequired)
    def _role_required(_request: Request, exc: RoleRequired):
        # 403, and **registered in the same commit as the class**, which is the whole of
        # what this table's last four rows taught. `OAuthRefused`, `ConnectionRefused` and
        # `EgressRefused` were all 500s because a route arrived after the table was
        # written; 011's `NoSuchGroupError` was a 503 for the same reason. The
        # handler-table test grows this class in the same change, so forgetting is a
        # failing test rather than an outage.
        #
        # Not 404. See the paragraph above — the resource an administrative route names is
        # the route, and its existence is published.
        return _problem(403, str(exc))

    @app.exception_handler(AccessDenied)
    def _access_denied(_request: Request, exc: AccessDenied):
        # 403, and it is the same mapping `deps.py` has always made for this class during
        # authentication — where a disabled account or a mismatched customer answers 403
        # with the real sentence. What was missing is the mapping for one raised *by a
        # request body* — a route refusing a machine with no grant on the agent was a
        # 500 until this line existed. `RoleRequired`'s lesson, one class over, and its
        # comment is the one to read.
        #
        # **What no longer arrives here: somebody else's token.** Until 069 this class
        # also carried *only <owner> may aim it*, a 403 naming a colleague to a caller
        # with no claim on the row — within a tenant, an existence oracle over token ids.
        # `tokens.require_owner_or_admin` now refuses not-yours in the same `ValueRefused`
        # sentence as not-there, on 028's rule, and carries the argument. The 403 that
        # remains names a `--share-agent` line for a token the caller already holds.
        return _problem(403, str(exc))

    @app.exception_handler(GroupRefused)
    def _group_refused(_request: Request, exc: GroupRefused):
        # 400, on `ShareRefused`'s reasoning, and it arrives at a route for the first time
        # in 12b: a group that does not exist, a name already taken, a member kind that is
        # not a principal kind. The caller has already proved they may administer this
        # tenant, so nothing here is a secret from them and every one of these is a
        # sentence they can act on.
        #
        # **Distinct from `RoleRequired` on purpose.** One means *you may not do this at
        # all*, the other means *you may, and this request is wrong* — the same split that
        # keeps `NoAccess` and `ShareRefused` apart, which cost a real bug when they were
        # one class.
        return _problem(400, str(exc))

    @app.exception_handler(EgressRefused)
    def _egress_refused(_request: Request, exc: EgressRefused):
        # 400, and **this is the third unmapped exception 7b found by driving routes at
        # their edges** — after `OAuthRefused` and `ConnectionRefused`, and after 011's
        # `NoSuchGroupError`. Without it, an administrator revoking a host turns every
        # in-flight consent callback into "Internal Server Error".
        #
        # Safe to explain: the caller is authenticated in this tenant, and the message
        # names a host their own administrator approved or revoked. It is the same
        # sentence `--add-connector` prints.
        return _problem(400, str(exc))

    @app.exception_handler(RegistrationRefused)
    def _registration_refused(_request: Request, exc: RegistrationRefused):
        # 400, and it reaches a route for the first time in 12c. Every refusal this class
        # carries is one an administrator can act on: a connector id that is not
        # registered, a tool the server does not advertise (named beside what it does
        # offer), a local name that would shadow a hand-written tool, and a connector
        # whose existing vetting has drifted. Nothing about any of them is a secret from
        # somebody who has already proved they may administer this tenant.
        #
        # Registered in the same commit as the routes that raise it, which is the whole of
        # what the last five rows of this table taught.
        return _problem(400, str(exc))

    @app.exception_handler(ConnectorExistsError)
    def _connector_exists(_request: Request, exc: ConnectorExistsError):
        # 409, and registered for `AgentNameTaken`'s reason twice over. Starlette resolves
        # by walking the MRO, so without this row a re-registration would arrive as the
        # **503** `StorageError` gives — "try again later" about a name that is taken and
        # will stay taken.
        #
        # 409 rather than the 400 a group-name collision gets, and the split is
        # `AgentNameTaken`'s: a connector id is a URL and an identity, so colliding on one
        # is a conflict about a resource that already exists at this address. A group name
        # is a label with no URL yet, because its id has not been minted.
        return _problem(409, str(exc))

    @app.exception_handler(CredentialError)
    def _credential_error(_request: Request, exc: CredentialError):
        # 400, and **it is here because 12c added a route that reads a credential in order
        # to do something else.** Discovery and vetting dial the customer's server with the
        # caller's own stored connection, and `for_connector` raises this for a row that
        # exists and will not decrypt or has expired — deliberately, rather than falling
        # back to the shared credential, because a broken credential has to look broken.
        #
        # Unmapped it would be a **500**: "the server broke" for an administrator whose own
        # OAuth token expired, whose remedy is one click on the Connections page. That is
        # the sixth time this table has caught the shape, and the first time it was caught
        # by reading the table rather than by driving the route.
        return _problem(400, str(exc))

    @app.exception_handler(TransportError)
    def _transport_error(_request: Request, exc: TransportError):
        # **502, and this is the one row in this table that is not about us.** A customer's
        # own MCP server did not answer, answered something that is not MCP, or dropped
        # the connection — which is precisely what a gateway status means, and none of the
        # alternatives are honest. A 503 claims *our* storage is down and sends an
        # administrator to check our status page. A 400 blames a request that was correct.
        # A 500 says we have a bug, and is what an unmapped exception would actually have
        # produced.
        #
        # The message is the transport's own and is safe to relay: it names the customer's
        # host, to an administrator of that customer, about a server they registered.
        return _problem(502, str(exc))

    @app.exception_handler(ValueRefused)
    def _value_refused(_request: Request, exc: ValueRefused):
        # 400, and **this row is the fifth and sixth times this table has been wrong in
        # the same way — found together, by driving 12c's routes at their edges.**
        #
        # `POST /admin/hosts` with a pasted URL, which is the single commonest thing
        # anybody will do on that screen, answered **503 "storage unavailable"** — try
        # again later, about a string that will never be accepted, while `normalize_host`
        # had a sentence ready naming exactly what to strip. `PUT .../oauth` with an
        # `http://` token endpoint did the same, and plan 012c's own edge table asserted
        # that one was *"already mapped"*. It was not.
        #
        # `ValueRefused` is deliberately one class over several validation helpers rather
        # than a fifth narrow subclass, because four narrow subclasses is what four
        # separate incidents produced. See its docstring.
        return _problem(400, str(exc))

    @app.exception_handler(CryptoError)
    def _crypto(_request: Request, exc: CryptoError):
        # **503, and it was a 500 until an edge hunt sent a request under a key that had
        # been rotated away.** Two states reach here and neither is the caller's
        # doing: a rotation that dropped a key rows still name (`MissingKeyError`), and
        # a ciphertext that will not authenticate because it was altered or copied out
        # of another row (`UndecryptableError`, which is a security event). Both mean
        # *this deployment cannot read its own storage*, which is what 503 says. Every
        # caller that lands here is authenticated, and owed the true sentence.
        #
        # The reason is logged and not returned, on `_storage`'s rule: `crypto.py`'s
        # sentence names a key id and the variable that restores it, which is an
        # operator's instruction and a prober's map. The caller gets the subsystem and
        # nothing else.
        log.exception("crypto failure")
        return _problem(
            503,
            "a stored secret could not be read, so this request cannot be completed. "
            "This is a problem with the deployment's encryption key rather than with "
            "the request; the reason is in the server log.",
        )

    @app.exception_handler(StorageError)
    def _storage(_request: Request, exc: StorageError):
        # Logged with a traceback, reported without one. A DSN or a schema detail in a
        # response body is a gift to whoever is probing.
        log.exception("storage failure")
        return _problem(503, f"storage unavailable: {exc}")
