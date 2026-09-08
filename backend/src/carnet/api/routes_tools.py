"""The catalogue: what this tenant may grant, and which of it writes.

Read-only, and it will stay read-only. **Producing** a review record is the connector
admin's job and stays on the CLI — the two personas were separated in migration 003 on
purpose, and a route that let an agent creator vet a tool would collapse them into one.
This reads what that person wrote down.

## Why the route is `/tools` and not `/connectors`

010 named it after the table. The set a form has to express is the union of two
registries:

    known_names(tenant) == frozenset(REGISTRY) | mcp.declared_names(tenant)

`REGISTRY` is hand-written tools — process-global, because they are code. `_BOUND` is
connector tools, per tenant. `agents.validate` accepts a grant naming either, so a
catalogue of *connectors* cannot describe `post_message`, and `post_message` is in the
grant of `issue-reporter`, the one worked example this repo ships. A form built on
`GET /connectors` could not reproduce it.

There is deliberately **no** `GET /connectors` alongside this. A second route over the
same rows is a second answer to "what may I grant", and the other reader of that table
— connector administration — is deliberately not self-serve.
"""

from fastapi import APIRouter, Depends

from .. import tools
from ..core import Principal
from .deps import principal_from_request
from .schemas import ToolGroup

router = APIRouter(tags=["tools"])


@router.get("/tools", response_model=list[ToolGroup])
def list_tools(principal: Principal = Depends(principal_from_request)):
    """Everything this tenant may grant, grouped by where it came from.

    **No grant is required, and every other route in this API is grant-filtered — so
    this is a departure and it is worth stating as one.** What it discloses is which
    connectors this customer has vetted and which tools they approved: not what any
    agent may do, not what anybody has access to, and not a single resource identifier.
    It is the menu, not anybody's order.

    Requiring some grant fails the case the route exists for. The person about to
    create their first agent has no grants at all, and 006's *absence is denial* is a
    rule about the tenant's **data**, not about the tenant's own configuration
    vocabulary.

    Authentication is still required, and not as a formality: the tenant comes off the
    principal and there is no other place it could come from. `api/deps.py` refuses a
    tenant in the URL for exactly that reason, so an unauthenticated catalogue would be
    a catalogue of nothing in particular.

    **This contacts no server.** Connector tools are described from the stored
    manifest, which is what migration 018 bought: a page about *choosing* a tool that
    depends on every vetted server being *up* is a page that is down whenever Docker
    is.
    """
    return tools.catalogue(principal.tenant_id)
