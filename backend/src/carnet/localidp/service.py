"""The bundled identity provider as a service: `python -m carnet.localidp.service`.

Step 121, chunk A. This is the provider behind somebody else's front door — the
compose stack's `idp` service, reached at `/idp/*` through the same Caddy that serves
the bundle and proxies `/api/*`. `frontdoor.py` is the other caller of the same
handler and owns two jobs this one does not: it *is* the front door, so it serves the
frontend and proxies the API itself.

## Why this exists rather than a second provider

An identity provider is a login page, a password check, a redirect allowlist, PKCE and
a signing key. Writing a deployed one beside `--local`'s would be two of each, and the
pair that would drift first is the pair nobody looks at — the redirect allowlist and
the PKCE check. So the deployed provider is `edge.handler_for` with
`provider_only=True`, and this module is forty lines of environment reading.

## The covenant, in this mode specifically

`localidp/__init__.py` states it: *this is a provider you run, never a bypass the
server honours.* Putting it on the compose stack is the first time that provider has
been reachable from the internet, so the two halves are worth restating at the address
where they are now load-bearing:

  - **There is no passwordless route here**, and it is structural rather than
    remembered. `scripts/dev_idp.py` keeps a `/_be/` switch because it is a test
    fixture; `deploy/Dockerfile` copies `backend/pyproject.toml` and `backend/src` and
    nothing else, so that file is not in the image at all. A test asserts both halves.
  - **The API still verifies these tokens through the production path.** It fetches
    this service's JWKS over HTTP and checks the signature, the issuer and the
    audience, exactly as it would Okta's. `access/oidc.py` dials with
    `operator_consented=True`, which is why a compose-internal `http://idp:8080/...`
    is a legal `jwks_uri` and needs nothing in `CARNET_EGRESS_INTERNAL_HOSTS`.

## Who may hold an account

On `--local` the deployment is a loopback trial and registration defaults open. Here
the stack publishes 443, so it is exposed by construction and **registration defaults
closed** — with `edge._closed_to_newcomers`'s first-account carve-out, which is what
lets the first administrator register at all.

That default is the whole admission control on this path, and the reason is worth
naming where somebody changing it will read it: the provider's row carries
`allowed_domains: ("*",)`, legal for this one issuer (`storage.base`'s
`check_allowed_domains`) because the provider is itself the account authority. So on
`bundled`, *who may register* is not a domain list — it is this setting.
"""

import os
import signal
import sys
import threading
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

from . import accounts as accounts_db
from .edge import EdgeConfig, serve
from .provider import LocalProvider

# The state this provider owns: the accounts database, the signing key and the cookie
# key. One directory, one volume, and `deploy/README.md` backs it up in the same
# sentence as the database — losing it is losing every password.
DEFAULT_STATE = "/var/lib/carnet-idp"

# Not a setting. `deploy/Caddyfile` routes `/idp/*` to `idp:8080` and the compose
# healthcheck asks this port for the JWKS, so a deployment that could move it would be
# a deployment that could route past its own provider — the knob whose only safe value
# is the default, which `EdgeConfig.host` below refuses for the same reason.
PORT = 8080

# Where the rest of the deployment reaches this provider, and the two places that
# matter are on opposite sides of the stack: `deploy/Caddyfile` (written by the front
# door's entrypoint) routes the browser's `/idp/*` here, and the `tenant_idps` row
# `carnet --setup` writes points the API's JWKS fetch here. A name and a port, said
# once, so the row and the route cannot name different services — and
# `test_the_compose_route_and_the_registered_jwks_uri_agree` compares this against the
# entrypoint's literal, which is shell and cannot import it.
#
# Plain http, and legal: `access/oidc._fetch_jwks` dials with `operator_consented=True`
# precisely so a provider the operator runs on their own network can be reached. The
# hop is inside the compose network and never crosses it.
COMPOSE_HOST = "idp"
COMPOSE_JWKS_URI = f"http://{COMPOSE_HOST}:{PORT}/idp/v1/keys"


def _refuse(message: str) -> NoReturn:
    """Refuse at start, naming the setting.

    `deploy/frontdoor-entrypoint.sh`'s rule, in Python: a half-declared provider is
    always a mistake, and serving anyway would fail later, quieter, and in a browser.
    """
    print(f"idp: {message}", file=sys.stderr)
    raise SystemExit(1)


def _browser_origin() -> str:
    """The origin a browser reaches this deployment at, from the one place it is said.

    `CARNET_PUBLIC_ORIGIN` is the API's external address — the origin plus `/api` —
    and `compose.yaml` derives it from `CARNET_DOMAIN` when it is not set explicitly.
    The browser's origin is its scheme and host, so the path is **dropped entirely**
    rather than stripped of a trailing `/api`: the bundle builds its redirect as
    `window.location.origin + "/login/callback"` (`frontend/src/lib/auth.ts`), which
    has no path in it either, and a suffix strip would quietly produce a different
    answer for an origin carrying some other path.

    Declared once, derived here, so the redirect allowlist cannot disagree with the
    address the app actually runs at — the same argument `frontdoor-entrypoint.sh`
    makes for deriving the CSP origin from the issuer.
    """
    raw = os.environ.get("CARNET_PUBLIC_ORIGIN", "").strip()
    if not raw:
        _refuse(
            "CARNET_PUBLIC_ORIGIN is not set, so there is no address to register a "
            "sign-in redirect for. compose.yaml derives it from CARNET_DOMAIN; set "
            "one of them."
        )
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        _refuse(f"CARNET_PUBLIC_ORIGIN must be an http(s) URL, got: {raw!r}")
    return f"{parts.scheme}://{parts.netloc}"


def config_from_environment() -> tuple[EdgeConfig, str]:
    """The `EdgeConfig` this service runs under, and the state directory it owns.

    Separated from `main` so a test can read the decisions without binding a socket —
    and because every refusal in it is a sentence somebody will meet in
    `docker compose logs idp`.
    """
    origin = _browser_origin()

    registration = os.environ.get("CARNET_IDP_REGISTRATION", "closed").strip() or "closed"
    if registration not in ("open", "closed"):
        _refuse(
            f"CARNET_IDP_REGISTRATION must be 'open' or 'closed', not "
            f"{registration!r}. Closed still admits the FIRST account, which is how "
            "this deployment gets its administrator."
        )

    # The one path here that is genuinely a path: the compose file mounts a volume at
    # the default, and a deployment that keeps its provider's state somewhere else
    # mounts it somewhere else.
    state = os.environ.get("CARNET_IDP_STATE", "").strip() or DEFAULT_STATE

    cfg = EdgeConfig(
        # 0.0.0.0 is honest here for the API's reason (`deploy/Dockerfile`): only the
        # front door publishes a port, so this listens on the compose-internal network
        # alone. Not a setting — a knob whose only safe value is the default is a knob
        # that exists to be got wrong.
        host="0.0.0.0",  # noqa: S104 - see above
        port=PORT,
        dist_dir="",  # unreachable: the front door serves the bundle
        api_port=0,  # unreachable: the front door proxies the API
        provider_only=True,
        registration=registration,
        # Prefilled into the first registration form, so the address that becomes the
        # administrator is typed once (in `.env`) rather than twice. It grants nothing
        # here — `access/users._bootstrap_admin` is what appoints, against the same
        # variable, and only while the tenant holds no roles.
        admin_email=os.environ.get("CARNET_BOOTSTRAP_ADMIN", "").strip(),
        redirect_uris=(f"{origin}/login/callback",),
        # The front door terminates TLS and speaks plain HTTP to this service, so the
        # browser's scheme cannot be read off this connection — it is read off the
        # declared origin, exactly as `--local` reads it off `--public-url`.
        secure_cookie=origin.startswith("https://"),
    )
    return cfg, state


def main() -> int:
    cfg, state = config_from_environment()

    directory = Path(state)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _refuse(
            f"cannot create the state directory {state}: {exc}. It holds the accounts "
            "database and the signing key, and must be a writable volume."
        )

    provider = LocalProvider(directory)
    db = accounts_db.open_db(str(directory / "accounts.db"))

    server = serve(cfg, provider, db)
    print(
        f"idp: serving /idp/* on port {cfg.port}; registration is "
        f"{cfg.registration}; sign-in returns to {cfg.redirect_uris[0]}",
        flush=True,
    )
    if not cfg.secure_cookie:
        print(
            "idp: WARNING — CARNET_PUBLIC_ORIGIN is not https, so the session cookie "
            "cannot carry Secure and passwords cross the network in the clear unless "
            "something in front of this deployment is terminating TLS.",
            file=sys.stderr,
            flush=True,
        )

    # `docker stop` sends SIGTERM, whose default is dying on the spot — no finally, so
    # the SQLite handle and the listening socket are dropped rather than closed.
    # `frontdoor.py` learned this as ten zombie APIs after a probe; the same shape at
    # a smaller size.
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    try:
        stopping.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
