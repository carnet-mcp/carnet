"""One HTTP server, one origin, three jobs.

    /idp/*        the identity provider — pages, authorize, token, keys
    /config.json  how the SPA finds its provider at runtime
    /api/*        a reverse proxy to the API on loopback
    /.well-known/oauth-*   the same proxy, path kept — the door's OAuth documents (083)
    (the rest)    the built frontend, with the SPA fallback

One origin is the load-bearing decision. The shipped frontend CSP says
`connect-src 'self'; frame-src 'self'` — so serving the provider and the API from the
SPA's own origin means the token exchange and the silent-renewal iframe are permitted
by the policy that ships, with no dev-mode relaxation and no rebuild. It also makes
the provider's session cookie first-party in the renewal iframe, so `prompt=none`
genuinely works here — the thing the real org's third-party-cookie behaviour denies.

The provider half validates what `dev_idp.py` deliberately does not: `client_id`,
`redirect_uri` (exact match, at authorize and again at token), and PKCE. A bad
client_id or redirect_uri is a 400 page, never a redirect — an unvalidated redirect
target is an open redirect wearing an error message.
"""

import http.client
import http.cookies
import http.server
import json
import mimetypes
import threading
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from . import accounts as accounts_db
from . import pages
from .provider import CLIENT_ID, LocalProvider, config_json, discovery_json
from .throttle import LoginThrottle

SESSION_COOKIE = "carnet_idp"

# End-to-end request headers only; whatever is hop-by-hop stays on its own hop.
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}

# The most a request body may declare (step 059), mirroring the deployed Caddyfile's
# per-path shape: provider form posts get the hooks-class ceiling (a credential form
# is hundreds of bytes), the proxy passes what Caddy's general `max_size` passes,
# because the API's file surface takes real uploads. The deployed path was always
# capped in front; `--local` is its own front — the exposed mode since 043 — and read
# `Content-Length` bytes uncapped, so `Content-Length: 2000000000` buffered into
# memory. Constants, not knobs, like the Caddyfile's own.
_MAX_FORM_BYTES = 64 * 1024
_MAX_PROXY_BYTES = 12 * 1024 * 1024


class _BodyRefused(Exception):
    """A request body this edge will not read: too big, unmeasurable, or misdeclared.

    Raised by `_body`, answered by the `do_*` dispatchers — the one place a refusal
    can be turned into a response whatever handler asked for the body.
    """

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


_PAGE_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "base-uri 'none'"
)

# The full policy for the *app's* HTML, served as a header exactly like the deploy
# front door does (plan 031, decision 7 — parity is the rule: the local mode must not
# quietly run under a different effective policy than the artifact ships). The bundle's
# meta tag keeps only the provider-independent directives; `connect-src`/`frame-src`
# live here, and here they are `'self'` alone because one origin is this front door's
# load-bearing decision. The browser enforces the *intersection* of this and the meta.
#
# `frame-ancestors 'self'`, NOT 'none', and a browser found the difference: silent
# renewal is the provider's authorize URL in a hidden iframe, and its last hop is a
# redirect back to `/login/callback` — a document of THIS app, framed by this app.
# 'none' blocks that (ERR_BLOCKED_BY_RESPONSE), so every silent re-entry fails and a
# reload lands on the sign-in screen. 'self' keeps the clickjacking protection —
# framing by any OTHER origin stays blocked — and lets the app frame its own callback.
_APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-src 'self'; base-uri 'none'; "
    "form-action 'none'; object-src 'none'; frame-ancestors 'self'"
)


@dataclass
class EdgeConfig:
    host: str
    port: int
    dist_dir: str
    api_port: int
    registration: str = "open"  # "open" | "closed"
    admin_email: str = ""
    redirect_uris: tuple[str, ...] = field(default_factory=tuple)
    # Whether the session cookie carries `Secure` — step 052, blocker B3. True exactly
    # when a browser reaches this deployment over HTTPS (an `https` public URL), because
    # the edge speaks plain HTTP and cannot read the browser's scheme off its own
    # connection. False on loopback and on a plain-http origin, where a `Secure` cookie
    # would be dropped by the browser and silently refuse every login.
    secure_cookie: bool = False

    @property
    def origin(self) -> str:
        shown = "localhost" if self.host == "127.0.0.1" else self.host
        return f"http://{shown}:{self.port}"


def handler_for(cfg: EdgeConfig, provider: LocalProvider, db, throttle=None):
    # One backoff map per running edge — step 053, blocker B2. Slows a guesser against a
    # single account (8-character passwords are a guessable space) without a shared store,
    # because `--local` is one process. Injectable so a test can drive its clock.
    throttle = throttle if throttle is not None else LoginThrottle()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        # --- plumbing ------------------------------------------------------------

        def _send(
            self,
            code: int,
            body: bytes,
            content_type: str = "application/json",
            extra: dict | None = None,
        ):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _page(self, code: int, body: bytes):
            """A provider-rendered page, under the provider's own strict CSP.

            **Only** the provider's pages — a CSP *header* combines with a CSP *meta*
            tag by intersection, so stamping this on the SPA's `index.html` silences
            the app's own scripts. Found by the browser check rendering a blank page;
            the suite pins it from both sides now.
            """
            return self._send(
                code,
                body,
                "text/html; charset=utf-8",
                extra={"Content-Security-Policy": _PAGE_CSP},
            )

        def _redirect(self, target: str, cookie: str | None = None):
            self.send_response(302)
            self.send_header("Location", target)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _session_cookie(self, account_id: str) -> str:
            # `Secure` when the deployment is reached over HTTPS (step 052, B3) — so the
            # 12-hour session cannot be harvested off a forced plaintext request.
            secure = "; Secure" if cfg.secure_cookie else ""
            return (
                f"{SESSION_COOKIE}={provider.session_for(account_id)}; "
                f"Path=/idp; HttpOnly; SameSite=Lax{secure}; Max-Age=43200"
            )

        def _current_account(self) -> dict | None:
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            entry = jar.get(SESSION_COOKIE)
            account_id = provider.session_account(entry.value if entry else None)
            if account_id is None:
                return None
            account = accounts_db.get_account_by_id(db, account_id)
            if account is None or account["disabled"]:
                return None
            return account

        def _body(self, limit: int) -> bytes:
            """The request body, bounded — or `_BodyRefused`, before a byte is read.

            The refusal happens on the DECLARED length (step 059), which is the
            front door's discipline: what cannot be afforded is not buffered first.
            Chunked has no declared length at all — this server never advertises
            chunked support, so a body it cannot measure is a 411, not a read.
            """
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                raise _BodyRefused(
                    411, "this server reads only requests with a Content-Length."
                )
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise _BodyRefused(400, "Content-Length is not a number.") from None
            if length < 0:
                raise _BodyRefused(400, "Content-Length is negative.")
            if length > limit:
                raise _BodyRefused(
                    413,
                    f"the request body ({length} bytes) is over this edge's "
                    f"{limit}-byte ceiling.",
                )
            return self.rfile.read(length)

        def _form(self) -> dict:
            raw = self._body(_MAX_FORM_BYTES).decode()
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

        def log_message(self, *args):
            pass

        # --- routing -------------------------------------------------------------

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}

            if url.path == "/idp/v1/keys":
                return self._send(200, json.dumps(provider.jwks()).encode())
            if url.path == "/idp/v1/authorize":
                return self._authorize(query)
            if url.path == "/idp/login":
                return self._page(
                    200,
                    pages.login_page(
                        query, registration_open=cfg.registration == "open"
                    ),
                )
            if url.path == "/idp/register":
                return self._register_page(query)
            if url.path == "/idp/logout":
                return self._redirect(
                    "/",
                    cookie=f"{SESSION_COOKIE}=; Path=/idp; HttpOnly; Max-Age=0",
                )
            if url.path == "/config.json":
                # `no-cache` for the same reason the deployed front door sets it: a
                # response with no max-age is still heuristically cacheable, and a
                # stale identity provider is a sign-in failure with no visible cause.
                return self._send(
                    200, config_json(), extra={"Cache-Control": "no-cache"}
                )
            if url.path == "/idp/.well-known/openid-configuration":
                return self._send(200, discovery_json())
            if url.path == "/api" or url.path.startswith("/api/"):
                return self._proxy()
            # Step 083. The door's OAuth discovery documents live at the origin root
            # and are the API's — the same rule `deploy/Caddyfile` and the Vite proxy
            # carry, and for the same reason: the static fallback would answer them
            # with index.html.
            if url.path.startswith("/.well-known/oauth-"):
                return self._proxy(keep_path=True)
            if url.path.startswith("/idp"):
                return self._send(404, b'{"error":"not_found"}')
            return self._static(url.path)

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            try:
                if url.path == "/idp/v1/token":
                    return self._token()
                if url.path == "/idp/login":
                    return self._login()
                if url.path == "/idp/register":
                    return self._register()
                if url.path == "/api" or url.path.startswith("/api/"):
                    return self._proxy()
            except _BodyRefused as refused:
                return self._refuse_body(refused)
            return self._send(404, b'{"error":"not_found"}')

        def do_PUT(self):
            return self._proxy_or_404()

        def do_PATCH(self):
            return self._proxy_or_404()

        def do_DELETE(self):
            return self._proxy_or_404()

        def _proxy_or_404(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/api" or path.startswith("/api/"):
                try:
                    return self._proxy()
                except _BodyRefused as refused:
                    return self._refuse_body(refused)
            return self._send(404, b'{"error":"not_found"}')

        def _refuse_body(self, refused: _BodyRefused):
            """Step 059's answer: the refusal as a sentence, in the API's own shape.

            `Connection: close` (and the handler flag that enforces it) because the
            unread body is still on the wire — the next thing on this keep-alive
            connection would be the middle of it, parsed as a request line.
            """
            self.close_connection = True
            return self._send(
                refused.status,
                json.dumps({"detail": refused.detail}).encode(),
                extra={"Connection": "close"},
            )

        # --- the provider --------------------------------------------------------

        def _flow_ok(self, params: dict) -> bytes | None:
            """A 400 page when the client half of the request is wrong, else None.

            client_id and redirect_uri failures must never redirect: the redirect
            target is exactly the thing that has not been validated yet.
            """
            if params.get("client_id") != CLIENT_ID:
                return b"this deployment's client id is 'carnet-local'."
            if params.get("redirect_uri") not in cfg.redirect_uris:
                return (
                    b"that redirect_uri is not registered for this deployment."
                )
            return None

        def _authorize(self, query: dict):
            refusal = self._flow_ok(query)
            if refusal is not None:
                return self._send(400, refusal, "text/plain; charset=utf-8")

            redirect_uri = query["redirect_uri"]
            state = query.get("state", "")

            def bounce(error: str):
                joiner = "&" if "?" in redirect_uri else "?"
                return self._redirect(
                    f"{redirect_uri}{joiner}error={urllib.parse.quote(error)}"
                    f"&state={urllib.parse.quote(state)}"
                )

            if (
                not query.get("code_challenge")
                or query.get("code_challenge_method") != "S256"
            ):
                return bounce("invalid_request")

            account = self._current_account()
            if account is None:
                if query.get("prompt") == "none":
                    # The conformant refusal — a redirect the SPA's silent-renewal
                    # iframe reads instantly, not the 400 HTML page the real org
                    # stalls on.
                    return bounce("login_required")
                return self._page(
                    200,
                    pages.login_page(
                        query, registration_open=cfg.registration == "open"
                    ),
                )

            code = provider.issue_code(
                account["id"],
                query["code_challenge"],
                redirect_uri,
                query["client_id"],
            )
            joiner = "&" if "?" in redirect_uri else "?"
            return self._redirect(
                f"{redirect_uri}{joiner}code={urllib.parse.quote(code)}"
                f"&state={urllib.parse.quote(state)}"
            )

        def _finish_login(self, account: dict, params: dict):
            """Set the session and, when a flow is waiting, finish it."""
            cookie = self._session_cookie(account["id"])
            if params.get("redirect_uri"):
                refusal = self._flow_ok(params)
                if refusal is not None:
                    return self._send(400, refusal, "text/plain; charset=utf-8")
                if (
                    not params.get("code_challenge")
                    or params.get("code_challenge_method") != "S256"
                ):
                    return self._send(
                        400, b"missing PKCE challenge.", "text/plain; charset=utf-8"
                    )
                code = provider.issue_code(
                    account["id"],
                    params["code_challenge"],
                    params["redirect_uri"],
                    params["client_id"],
                )
                state = params.get("state", "")
                joiner = "&" if "?" in params["redirect_uri"] else "?"
                return self._redirect(
                    f"{params['redirect_uri']}{joiner}"
                    f"code={urllib.parse.quote(code)}"
                    f"&state={urllib.parse.quote(state)}",
                    cookie=cookie,
                )
            return self._redirect("/", cookie=cookie)

        def _login(self):
            form = self._form()
            email = form.get("email", "")

            # Per-account backoff (step 053, B2), checked before the password is verified
            # so a blocked attempt costs neither a scrypt nor a database read. Keyed on the
            # address whether or not it names a real account, so it is not an oracle for
            # which addresses exist.
            wait = throttle.blocked_for(email)
            if wait:
                retry = str(int(wait) + 1)
                return self._send(
                    429,
                    pages.login_page(
                        form,
                        error=(
                            "Too many attempts for that address. "
                            f"Try again in {retry} seconds."
                        ),
                        registration_open=cfg.registration == "open",
                    ),
                    "text/html; charset=utf-8",
                    extra={"Content-Security-Policy": _PAGE_CSP, "Retry-After": retry},
                )

            account = accounts_db.verify_login(db, email, form.get("password", ""))
            if account is None:
                throttle.failed(email)
                return self._page(
                    400,
                    pages.login_page(
                        form,
                        error="That address and password do not match an active account.",
                        registration_open=cfg.registration == "open",
                    ),
                )
            throttle.succeeded(email)
            return self._finish_login(account, form)

        def _closed_to_newcomers(self) -> bool:
            """Is registration shut for everybody who is not the first account?

            One predicate for the page and the POST (step 064). It was spelled twice,
            two different ways, and a rule that decides who may create an account is
            the worst kind to keep two copies of: the two can drift and only one of
            them is the one an attacker meets.

            **This is what renders the refusal, not what enforces it.** The enforcement
            is `create_account(only_if_first=...)`, which settles the question inside
            the INSERT — see there for the race this check cannot win on its own.
            """
            return cfg.registration != "open" and accounts_db.count(db) > 0

        def _register_page(self, params: dict, error: str = ""):
            nobody_yet = accounts_db.count(db) == 0
            # Closed registration still lets the *first* account in — otherwise an
            # exposed deployment that defaults to closed (step 052, B3) could never
            # appoint its first administrator. Every account after the first is refused.
            if self._closed_to_newcomers():
                return self._page(403, pages.registration_closed_page())
            return self._page(
                200 if not error else 400,
                pages.register_page(
                    params,
                    error=error,
                    prefill_email=cfg.admin_email if nobody_yet else "",
                    first_account=nobody_yet,
                ),
            )

        def _register(self):
            # The same first-account carve-out the page uses (step 052, B3): a closed
            # deployment still admits the first account and refuses every one after it.
            # Checked here too so the POST is never a path around the page's gate.
            if self._closed_to_newcomers():
                return self._page(403, pages.registration_closed_page())
            form = self._form()
            try:
                account = accounts_db.create_account(
                    db,
                    form.get("email", ""),
                    form.get("password", ""),
                    form.get("name", ""),
                    # **The check above cannot be what decides this** (step 064). It
                    # and the insert are two statements with a scrypt between them, so
                    # on a threaded server two registrations against an empty store
                    # both passed it and both wrote. Under a closed deployment the
                    # store settles it inside the INSERT instead, and the check above
                    # is what renders a refusal early for the overwhelmingly common
                    # case where nobody is racing anybody.
                    only_if_first=cfg.registration != "open",
                )
            except accounts_db.RegistrationClosed:
                # Lost the race for the one account this deployment admits. Nothing
                # they typed was wrong, so it is the closed page rather than the form.
                return self._page(403, pages.registration_closed_page())
            except accounts_db.AccountError as exc:
                return self._register_page(form, error=str(exc))
            return self._finish_login(account, form)

        def _token(self):
            form = self._form()
            if form.get("grant_type") != "authorization_code":
                return self._send(400, b'{"error":"unsupported_grant_type"}')
            account_id = provider.redeem(
                form.get("code", ""),
                form.get("code_verifier", ""),
                form.get("redirect_uri", ""),
                form.get("client_id", ""),
            )
            account = (
                accounts_db.get_account_by_id(db, account_id) if account_id else None
            )
            if account is None or account["disabled"]:
                return self._send(400, b'{"error":"invalid_grant"}')
            return self._send(
                200,
                json.dumps(
                    {
                        "access_token": provider.mint(account),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                ).encode(),
            )

        # --- the proxy -----------------------------------------------------------

        def _proxy(self, keep_path: bool = False):
            path = self.path if keep_path else (self.path.removeprefix("/api") or "/")
            body = self._body(_MAX_PROXY_BYTES) or None

            upstream = http.client.HTTPConnection("127.0.0.1", cfg.api_port, timeout=120)
            try:
                headers = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower() not in _HOP_BY_HOP
                }
                upstream.request(self.command, path, body=body, headers=headers)
                response = upstream.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in _HOP_BY_HOP | {"content-length"}:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (ConnectionError, OSError):
                self._send(502, b'{"detail":"the API is not answering"}')
            finally:
                upstream.close()

        # --- the frontend --------------------------------------------------------

        def _static(self, path: str):
            dist = Path(cfg.dist_dir).resolve()
            candidate = (dist / path.lstrip("/")).resolve()
            if not candidate.is_relative_to(dist) or not candidate.is_file():
                candidate = dist / "index.html"
            if not candidate.is_file():
                return self._send(
                    503,
                    b"the frontend bundle is missing - run the front door again "
                    b"and let it build, or `npm run build` in frontend/.",
                    "text/plain; charset=utf-8",
                )
            content_type = (
                mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            )
            body = candidate.read_bytes()
            extra = (
                {"Cache-Control": "public, max-age=31536000, immutable"}
                if "/assets/" in str(candidate)
                else {"Cache-Control": "no-cache"}
            )
            # The app's policy rides on its documents, not its assets — a CSP governs
            # the document that carries it.
            if content_type == "text/html":
                extra["Content-Security-Policy"] = _APP_CSP
            return self._send(200, body, content_type, extra=extra)

    return Handler


def serve(
    cfg: EdgeConfig, provider: LocalProvider, db, throttle=None
) -> http.server.ThreadingHTTPServer:
    """Start the edge and return the server; the caller owns shutdown.

    The default bind is loopback and choosing anything else is the caller typing it —
    `frontdoor` owns the warning that accompanies that choice. `throttle` is the login
    backoff (step 053); a caller passes one only to control its clock in a test.
    """
    server = http.server.ThreadingHTTPServer(
        (cfg.host, cfg.port), handler_for(cfg, provider, db, throttle)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
