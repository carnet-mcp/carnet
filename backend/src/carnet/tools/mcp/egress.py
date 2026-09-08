"""Which hosts a tenant will let us dial.

This is the first time in this project's life that **a database row causes an outbound
connection**. Step 003 flagged it and `DEFERRED.md` has carried it since: a registration
command that takes a URL and dials it is a server-side request forgery primitive with a
friendly form in front of it. Everything about this module follows from taking that
sentence literally.

Five decisions, and each is a place a plausible alternative is worse:

**Per tenant.** Which hosts are acceptable is a customer's answer. A platform-wide
allowlist would make one customer's approval reach another's connectors.

**On the host, never the URL.** A path is not a security boundary. A server that will
serve `/mcp` will serve whatever else it serves, and an allowlist that carries paths
reads as narrower than it is — which is worse than one that admits its own width.

**Checked in `_transport_for`.** That is the one place a transport is built, for the
same reason `core.broker.call` is the only route to a tool. A check anywhere else is a
check something can be constructed around.

**Empty denies.** A tenant that has approved no hosts can register and reach no
connectors. This matches `_check_domain`'s reading of an empty `allowed_domains` — *no
identity provider for this customer may vouch for anybody* — and it is the property
somebody will be tempted to invert the first time a fresh tenant cannot dial anything.
The temptation is the feature: an allowlist whose empty state permits everything is a
control that is off by default and looks on.

**Loopback and link-local are refused whatever the allowlist says.** A customer cannot
meaningfully consent to us dialling our own metadata service, and `169.254.169.254` is
the single most valuable address on a cloud host. This one is not a tenant's decision
to make, so it is not stored as one — it is a rule in code, checked before the
allowlist is even read.

## What this does not do, said plainly

It bounds **where we will dial**, not **what answers**. A vetted server that is later
compromised is still on the allowlist and still reached; the controls for what comes
back are the response cap and the fact that a tool's effect and resources were annotated
by a person rather than declared by the server.

**`check` resolves nothing; `pinned` resolves everything — and every dial goes through
both.** The check is on the name (allowlist, literals, the never-consentable ranges);
`pinned` runs at dial time, resolves the name once, refuses if any answer is an address
nobody may consent to, and returns the URL rewritten to the checked address with the
TLS name kept — so the socket dials what was checked, and a DNS record that moves after
the check moves nothing. That closed the register's DNS-rebinding row (step 058). The
seam it sits behind is the same one tests inject fakes into, so nothing hermetic ever
resolves.

**`dial` is how a caller gets that, and step 064 is why it exists.** 058 left the
sequence to be hand-assembled at each site, and the sentence that used to stand here —
*"the only two functions that touch the network"* — was wrong when it was written:
`oauth._post_form` (the token exchange, the refresh, the revoke, carrying the client
secret and the refresh token) and `messaging.post_message` were dialling unpinned, and
`oidc._fetch_jwks` had drifted. There are five dials in this codebase and they all go
through `dial` now, which is a property something can be checked against rather than a
discipline five files have to keep.

One consent question came with the closure: a BYOC deployment's own connectors
legitimately resolve to private addresses, and the tenant allowlist is the wrong place
to say so — a tenant cannot consent to somebody else's network. So the operator names
their own networks' hosts in `CARNET_EGRESS_INTERNAL_HOSTS`, and a listed name may
resolve to loopback or private space; link-local — the metadata service — is refused
for every name, listed or not.
"""

import ipaddress
import socket
from typing import NamedTuple
from urllib.parse import urlsplit, urlunsplit

from ... import config, storage


class EgressRefused(RuntimeError):
    """A host is not on this tenant's allowlist, or is one nobody may approve.

    Its own class rather than a `TransportError`, and the distinction is the same one
    `DelegationUnsupported` draws: nothing was sent, nothing failed, and the fix is an
    administrator approving a host rather than anybody retrying. A `TransportError`
    would put "could not reach the server" in an audit record about a connection that
    was deliberately never attempted.
    """


def host_of(url: str) -> str:
    """The host of a URL, lowercased, without port or brackets. Raises if there is none.

    The one direction that parses. `storage.normalize_host` deliberately refuses
    anything carrying a scheme or a path, so this is where a URL becomes a host and
    there is exactly one such place — the alternative is two normalizers that disagree
    about `https://Example.COM:443/mcp`, one of them writing the allowlist and the other
    checking it.
    """
    split = urlsplit(url)
    if not split.hostname:
        raise EgressRefused(
            f"'{url}' has no host. A connector's URL is what decides which host we "
            "dial, so a URL we cannot take a host out of is one we will not dial."
        )
    return split.hostname.rstrip(".").lower()


def _as_ip(host: str):
    """The host as an IP address, or None if it is a name.

    **Two parsers, and the second one is the point.** `ipaddress.ip_address` is strict:
    it wants a dotted quad or a proper IPv6 literal, and it *rejects* every legacy
    spelling of an address:

        2130706433      ip_address: ValueError      inet_aton: 127.0.0.1
        0x7f.0.0.1      ip_address: ValueError      inet_aton: 127.0.0.1
        127.1           ip_address: ValueError      inet_aton: 127.0.0.1

    A resolver — and therefore `requests`, and therefore us — treats all three as
    loopback. So a check built on `ip_address` alone would classify them as *names*,
    find nothing forbidden about them, and let `https://2130706433/mcp` through to the
    allowlist, where an operator who approved `2130706433` for a reason that seemed good
    at the time has approved loopback. That is not a hypothetical class of bypass; it is
    the standard one.

    `socket.inet_aton` is what the resolver actually uses for these forms, so asking it
    is asking the same question the socket will ask. It is tried second because it is
    the more permissive of the two — `inet_aton("1")` is `0.0.0.1` — and a host that
    parses strictly should be reported as what it strictly is.

    Found by a test that approved each spelling and expected a refusal, which is the
    shape worth keeping: the parametrised list is the list of things somebody would try.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    try:
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))
    except (OSError, ValueError):
        return None


# Names that resolve to loopback by convention, and are the spelling somebody uses
# before they reach for a literal. Checked as names because `localhost` is not an
# address, so no amount of `ipaddress` parsing sees it.
_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def forbidden_reason(host: str) -> str:
    """Why this host may never be dialled, or `''` if it may be.

    Refused regardless of the allowlist, so an administrator cannot approve their way
    into it — which is the point. These are not a customer's decision to make: an
    operator who adds `169.254.169.254` to a tenant's allowlist has not consented to
    anything on that tenant's behalf, because the address does not belong to them.
    """
    if host in _LOOPBACK_NAMES:
        return "it is a name for this machine"

    address = _as_ip(host)
    if address is None:
        # A name. Whether it *resolves* to one of the ranges below is the rebinding
        # question, answered at dial time by `pinned` — see the module docstring.
        return ""

    # Ordered most specific first, because `is_private` is the widest of these and
    # subsumes several of the others — `0.0.0.0` is both unspecified and private, and
    # "it is a private address" is the less useful of the two things to be told.
    if address.is_loopback:
        return "it is a loopback address"
    if address.is_link_local:
        # 169.254.0.0/16 and fe80::/10. The cloud metadata service lives here, and it
        # is the single address most worth reaching from inside somebody's network.
        return "it is a link-local address, which is where cloud metadata services live"
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return "it is a reserved, multicast or unspecified address"
    if address.is_private:
        return "it is a private address, so it is inside somebody's network rather than on the internet"

    return ""


def approval_warning(host: str) -> str:
    """What to tell somebody who just approved a host that will never be dialled. `''`
    when there is nothing to say.

    **The sentence, not just the reason** — and it lives here as of 12c because it grew a
    second caller. It was computed in `cli._allow_host` and printed to stderr, and over
    HTTP there is no stderr: `POST /admin/hosts` carries it in the response body instead.
    A route that reproduced the wording would be a second answer to *did this approval do
    anything*, and the two would drift on the first edit.

    A **warning and not a refusal**, which is `_allow_host`'s decision and survives the
    move. The row is legitimate — it records that somebody approved a host — and the
    refusal belongs at dial time, where `check` makes it and where it is load-bearing.
    What must not happen is the other thing: an administrator being told *yes* about a
    control that is not in force, which is the precise failure this module is written
    against and the reason the warning exists at all.

    Takes an already-normalized host, because both callers have one by the time they ask:
    `allow_host` normalizes before it writes, and the thing worth warning about is the
    string that landed in the table rather than the one somebody typed.
    """
    reason = forbidden_reason(host)
    if not reason:
        return ""

    return (
        f"Recorded, but '{host}' will NOT be dialled: {reason}. This is refused whatever "
        "a tenant approves — a customer cannot consent on behalf of a network that is "
        "not theirs. The row is kept because it records that somebody asked; nothing "
        "will act on it."
    )


def check(tenant_id: str, url: str) -> str:
    """May this tenant dial this URL? Returns the host, or raises `EgressRefused`.

    Returns the host rather than None so a caller that wants to log or record what was
    checked has it without parsing the URL a second time — two parses of one URL is how
    the thing that was checked stops being the thing that was dialled.
    """
    host = host_of(url)

    # Before the allowlist is read, so no configuration can reach these.
    reason = forbidden_reason(host)
    if reason:
        raise EgressRefused(
            f"'{host}' will not be dialled because {reason}. This is refused whatever "
            "the tenant's allowlist says: a customer cannot consent on behalf of a "
            "network that is not theirs, and the metadata service of the host we run "
            "on is the clearest case of that."
        )

    # https everywhere except the operator's own networks (step 063): a plain-http
    # connector URL puts a bearer credential on the wire in clear across whatever
    # sits between. `CARNET_EGRESS_INTERNAL_HOSTS` is the same consent boundary
    # 058 drew for private addresses, because "TLS optional here" and "this is my
    # own network" are the same claim, made by the same person.
    if urlsplit(url).scheme != "https" and host not in config.EGRESS_INTERNAL_HOSTS:
        raise EgressRefused(
            f"'{url}' is not https, which would put this connector's credential on "
            "the wire in clear. Use https — or, if this host is on the deployment's "
            "own network, the operator may name it in CARNET_EGRESS_INTERNAL_HOSTS."
        )

    allowed = {row["host"] for row in storage.active().allowed_hosts(tenant_id)}

    if host not in allowed:
        # The message names what *is* allowed, because the overwhelmingly common cause
        # is a fresh tenant with an empty list and the second most common is a typo. A
        # refusal that does not say what would have worked sends somebody to the schema.
        approved = ", ".join(sorted(allowed)) if allowed else "nothing yet"
        raise EgressRefused(
            f"tenant '{tenant_id}' has not approved the host '{host}', so it will not "
            f"be dialled. Approved: {approved}.\n"
            f"  carnet --allow-host {host}\n"
            "An empty allowlist denies rather than permits — a customer who has "
            "approved no hosts has approved no hosts."
        )

    return host


class PinnedDial(NamedTuple):
    """What a dial needs to reach exactly the address that was checked. Step 058.

    `url` carries the checked address in its authority; `headers` carries the `Host`
    the origin server expects; `server_hostname` is the name TLS must verify against
    (`''` when there is nothing to pin — an http URL, or a literal address). Built by
    `pinned`, consumed by the two real dial functions and by nothing else.
    """

    url: str
    headers: dict
    server_hostname: str


def _never_consentable(address) -> str:
    """Why NO operator setting may admit this resolved address, or `''`.

    The subset of `forbidden_reason` that survives `CARNET_EGRESS_INTERNAL_HOSTS`:
    link-local is the cloud metadata service, and multicast/reserved/unspecified are
    not unicast destinations at all. Loopback and private are deliberately consentable
    — they are exactly what an operator's own network is made of, and consenting to
    them is that setting's whole purpose. Loopback is answered first because Python
    classifies `::1` as *reserved* as well as loopback, and "reserved" would smuggle
    the consentable case into the never list.
    """
    if address.is_loopback:
        return ""
    if address.is_link_local:
        return "it is a link-local address, which is where cloud metadata services live"
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return "it is a reserved, multicast or unspecified address"
    return ""


def pinned(url: str, *, operator_consented: bool = False) -> PinnedDial:
    """Resolve at dial time, refuse forbidden answers, pin the checked address.

    The rebinding close (step 058): `check` above vets the *name* against the
    allowlist, and this vets what the name *resolves to*, in the same breath as the
    dial — the returned URL carries the checked address, so there is no second
    resolution for a moved record to win. Every answer is vetted, not just the one
    dialled: a half-poisoned record is a poisoned record.

    A literal IP passes through unchanged after a re-check, so this function is safe
    even called without `check` — though every connector path calls both. An
    unresolvable name is an `EgressRefused` on that class's own meaning: nothing was
    sent.

    `operator_consented=True` is for URLs the *operator* registered rather than a
    tenant — a tenant identity provider's `jwks_uri`, written by `--add-idp` — and it
    relaxes exactly what the operator may consent to: loopback and private answers
    (and literals, and `localhost` itself), which is where a `--local` provider or an
    in-network IdP actually lives. The never-consentable ranges — link-local, where
    the metadata service lives — are refused under every flag this function has.
    """
    split = urlsplit(url)
    host = host_of(url)

    literal = _as_ip(host)
    if literal is not None or host in _LOOPBACK_NAMES:
        reason = (
            _never_consentable(literal) if literal is not None else ""
        ) if operator_consented else forbidden_reason(host)
        if reason:
            raise EgressRefused(f"'{host}' will not be dialled because {reason}.")
        if literal is not None:
            return PinnedDial(url, {}, "")
        # `localhost` under operator consent: a name, resolved below like any other.

    try:
        infos = socket.getaddrinfo(
            host, split.port or (443 if split.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise EgressRefused(
            f"'{host}' could not be resolved ({exc}), so nothing was dialled."
        ) from exc

    answers: list = []
    for info in infos:
        if info[4][0] not in answers:
            answers.append(info[4][0])

    internal = operator_consented or host in config.EGRESS_INTERNAL_HOSTS
    for answer in answers:
        address = ipaddress.ip_address(answer)
        reason = _never_consentable(address)
        if not reason and not internal:
            reason = forbidden_reason(answer)
        if reason:
            remedy = (
                ""
                if _never_consentable(address)
                else "\n  If this host is on this deployment's own network, the "
                "operator may say so: add it to CARNET_EGRESS_INTERNAL_HOSTS "
                "in the deployment's environment."
            )
            raise EgressRefused(
                f"'{host}' resolves to {answer}, which will not be dialled because "
                f"{reason}. A name is not an address — this is the DNS-rebinding "
                f"check, and it vets every answer the name gives.{remedy}"
            )

    # The first IPv4 answer when there is one, the first answer otherwise. A pin is
    # one address — it cannot do happy-eyeballs — and preferring the A record is the
    # conservative reach: dual-stack hosts answer on it, and a v6-only host still
    # pins its AAAA.
    address = next((a for a in answers if ":" not in a), answers[0])
    authority = f"[{address}]" if ":" in address else address
    if split.port:
        authority = f"{authority}:{split.port}"
    rewritten = urlunsplit(
        (split.scheme, authority, split.path, split.query, split.fragment)
    )
    served_as = f"{host}:{split.port}" if split.port else host
    return PinnedDial(
        rewritten,
        {"Host": served_as},
        host if split.scheme == "https" else "",
    )


def mount_pinned(session, server_hostname: str) -> None:
    """Verify TLS against the NAME while the socket dials the ADDRESS.

    The adapter half of `pinned`: with the URL rewritten to an IP, default
    verification would check the certificate against the address and fail (or worse,
    be turned off by a caller who "fixes" that). urllib3 takes the name for both SNI
    (`server_hostname`) and certificate verification (`assert_hostname`), so pinning
    costs no TLS honesty.

    **Idempotent per session**, which is what lets `dial` call it unconditionally
    rather than leaving each caller to remember. A session that is already adaptered
    for this name is left alone: re-mounting would build a second adapter and a second
    pool manager per request on the long-lived transport session, and — worse — a
    session mounted for a *different* name would silently have its first pin replaced,
    which is a mis-verified dial rather than a wasted allocation.
    """
    from requests.adapters import HTTPAdapter

    if getattr(session, "_carnet_pinned_host", None) == server_hostname:
        return

    class _PinnedTLS(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            kwargs["assert_hostname"] = server_hostname
            kwargs["server_hostname"] = server_hostname
            return super().init_poolmanager(*args, **kwargs)

    session.mount("https://", _PinnedTLS())
    session._carnet_pinned_host = server_hostname


def dial(
    session,
    method: str,
    url: str,
    *,
    pin: PinnedDial | None = None,
    operator_consented: bool = False,
    headers: dict | None = None,
    **kwargs,
):
    """Make one pinned request. **The one way anything here reaches the network.**

    Step 064, and it exists because the alternative was tried: `pinned` and
    `mount_pinned` were hand-assembled at three call sites, and hand-assembly is why
    two dials never got the treatment at all — `oauth._post_form`, which carries the
    client secret and the refresh token, and `messaging.post_message` — while a third
    drifted into refusing redirects without saying so. A sequence that must be
    performed identically in five places is not a sequence, it is a function.

    What it guarantees, in one place, for every dial:

      - the name is resolved once and **every** answer vetted (`pinned`);
      - the socket goes to the address that was vetted, with the `Host` the origin
        expects and the TLS name it must present;
      - a redirect is never followed, because a 3xx points somewhere no check saw.

    `pin` is for a caller that has already resolved and means to keep the answer —
    `transport`, which resolves once per transport on purpose and would otherwise pay
    a DNS query per JSON-RPC message. Everyone else omits it and resolves per call.

    **It returns the response without interpreting it.** A 3xx means different things
    to different callers — `rest` returns it to the model as a tool error naming its
    status, `oidc` must name the redirect rather than fail to parse it — so refusing
    to *follow* is this function's business and deciding what a refusal *means* is
    the caller's.
    """
    pin = pin if pin is not None else pinned(url, operator_consented=operator_consented)
    if pin.server_hostname:
        mount_pinned(session, pin.server_hostname)
    return session.request(
        method,
        pin.url,
        headers={**(headers or {}), **pin.headers},
        allow_redirects=False,
        **kwargs,
    )
