"""The local identity provider: accounts, the OIDC flow, and the keystone.

The keystone is the last test class: a token this provider mints goes through
`providers.resolve` and `users.resolve` **unchanged** — the same two calls
`api/deps.py` makes for an Okta token. That is the whole covenant of the package:
"local" is a fact about who signs, never about what is checked.

The HTTP tests drive a real edge server on a real loopback socket, because the flow
under test — form post, cookie, redirect, code exchange — is made of HTTP details a
handler called directly would not exercise.
"""

import base64
import hashlib
import json
import secrets
import stat
import urllib.parse

import pytest

pytest.importorskip("jwt", reason="install the 'access' extra to run these")

import httpx  # noqa: E402

from carnet import storage  # noqa: E402
from carnet.access import oidc, providers, users  # noqa: E402
from carnet.access.oidc import JwksCache  # noqa: E402
from carnet.localidp import accounts, edge as edge_mod  # noqa: E402
from carnet.localidp.edge import EdgeConfig, serve  # noqa: E402
from carnet.localidp.provider import (  # noqa: E402
    AUDIENCE,
    CLIENT_ID,
    ISSUER,
    LocalProvider,
)

REDIRECT = "http://localhost:8080/login/callback"


# --- accounts ---------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    return accounts.open_db(str(tmp_path / "accounts.db"))


def test_the_account_store_is_owner_only(tmp_path):
    """The one secret this package left at the process umask.

    `secret.key`, the signing PEM and the cookie key are all `0o600`; `accounts.db` was
    not, so on a shared host the scrypt records were typically world-readable. Strong
    hashes are not a reason to publish them.

    The write-ahead files are asserted too, because WAL is where the rows actually live
    between checkpoints — a locked-down database beside a readable `-wal` is the control
    looking present and being absent.
    """
    path = tmp_path / "accounts.db"
    db = accounts.open_db(str(path))
    accounts.create_account(db, "priya@example.com", "correct horse", "Priya")

    for name in ("accounts.db", "accounts.db-wal", "accounts.db-shm"):
        target = tmp_path / name
        if target.exists():
            mode = stat.S_IMODE(target.stat().st_mode)
            assert mode == 0o600, f"{name} is {oct(mode)}, not owner-only"


def test_a_password_verifies_and_a_wrong_one_does_not(db):
    accounts.create_account(db, "priya@example.com", "correct horse", "Priya")

    assert accounts.verify_login(db, "priya@example.com", "correct horse")
    assert accounts.verify_login(db, "priya@example.com", "wrong") is None
    assert accounts.verify_login(db, "nobody@example.com", "correct horse") is None


def test_the_lookup_is_case_insensitive_and_the_record_is_not_the_password(db):
    created = accounts.create_account(db, "Priya@Example.com", "correct horse")

    assert accounts.verify_login(db, "priya@example.com", "correct horse")
    assert "correct horse" not in created["password"]
    assert created["password"].startswith("scrypt$")


def test_a_record_from_yesterdays_parameters_still_verifies():
    """The parameters live in the record, not in the constants — so tightening the
    constants later does not sign everybody out of their own accounts."""
    record = accounts.hash_password("some password")
    weakened = record.replace("$32768$", "$16384$")
    # Not the same record any more, so it must simply fail — never raise.
    assert accounts.check_password("some password", weakened) is False
    # And a scheme from the future fails closed the same way.
    assert accounts.check_password("some password", "argon2id$x$y") is False
    assert accounts.check_password("some password", record) is True


def test_scrypt_concurrency_is_bounded(monkeypatch):
    """Step 051 (B2): no more than `_SCRYPT_MAX_CONCURRENCY` hashes run at once, so a
    login flood cannot each allocate 32 MiB and exhaust the host. Proven by counting how
    many threads are inside the guarded computation simultaneously, with the real scrypt
    swapped for a barrier that would deadlock if the cap were not enforced."""
    import threading

    permits = 3
    guard = threading.BoundedSemaphore(permits)
    monkeypatch.setattr(accounts, "_SCRYPT_GUARD", guard)

    inside = 0
    peak = 0
    lock = threading.Lock()
    release = threading.Event()

    def fake_scrypt(password, **kwargs):
        nonlocal inside, peak
        with lock:
            inside += 1
            peak = max(peak, inside)
        # Hold the permit until the test lets go, so every thread that got in is
        # counted at once — if the cap did not hold, `peak` would exceed `permits`.
        release.wait(timeout=5)
        with lock:
            inside -= 1
        return b"x" * 64

    monkeypatch.setattr(accounts.hashlib, "scrypt", fake_scrypt)

    threads = [
        threading.Thread(target=accounts.hash_password, args=("pw",)) for _ in range(12)
    ]
    for t in threads:
        t.start()
    # Give the first wave time to fill the permits, then let everyone finish.
    import time

    time.sleep(0.2)
    observed_cap = peak
    release.set()
    for t in threads:
        t.join(timeout=5)

    assert observed_cap == permits, f"expected at most {permits} concurrent, saw {peak}"


def test_a_duplicate_address_is_refused_with_a_sentence(db):
    accounts.create_account(db, "priya@example.com", "correct horse")

    with pytest.raises(accounts.DuplicateEmail, match="already exists"):
        accounts.create_account(db, "PRIYA@example.com", "another pass")


def test_a_short_password_is_refused(db):
    with pytest.raises(accounts.WeakPassword, match="at least"):
        accounts.create_account(db, "priya@example.com", "short")


@pytest.mark.parametrize(
    "junk",
    [
        "<script>alert(1)</script>@x.com",  # found by probing: the old check took it
        "no-at-sign.example.com",
        "two@@ats.com",
        "spaces in@local.test",
        "nodot@localhost",
        "@nolocal.test",
        "nodomain@",
        "",
    ],
)
def test_an_address_that_could_never_match_a_share_is_refused(db, junk):
    """This address becomes the product's `users.email` — what shares match against
    and screens display — so the floor is enforced at the door, with a sentence."""
    with pytest.raises(accounts.AccountError, match="does not look like"):
        accounts.create_account(db, junk, "long enough password")
    assert accounts.count(db) == 0


def test_a_disabled_account_cannot_sign_in(db):
    accounts.create_account(db, "priya@example.com", "correct horse")
    db.execute("UPDATE accounts SET disabled = 1")
    db.commit()

    assert accounts.verify_login(db, "priya@example.com", "correct horse") is None


# --- the edge, over real HTTP -----------------------------------------------------


@pytest.fixture
def world(tmp_path):
    """A provider, an accounts db, and an edge on a real loopback socket."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>app</title>")

    db = accounts.open_db(str(tmp_path / "accounts.db"))
    provider = LocalProvider(tmp_path)
    cfg = EdgeConfig(
        host="127.0.0.1",
        port=0,  # a real socket, any free port
        dist_dir=str(dist),
        api_port=1,  # nothing listens there; these tests never proxy
        admin_email="priya@example.com",
        redirect_uris=(REDIRECT,),
    )
    server = serve(cfg, provider, db)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield type("World", (), {"base": base, "db": db, "provider": provider, "cfg": cfg})
    server.shutdown()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def flow_params(challenge: str, **extra) -> dict:
    return {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "state": "s-123",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **extra,
    }


def register(world, email="priya@example.com", password="correct horse") -> httpx.Response:
    verifier, challenge = pkce_pair()
    response = httpx.post(
        f"{world.base}/idp/register",
        data={**flow_params(challenge), "email": email, "password": password},
    )
    response.verifier = verifier
    return response


def code_from(response: httpx.Response) -> str:
    location = response.headers["location"]
    return urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]


def test_register_finishes_the_flow_it_interrupted(world):
    response = register(world)

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(REDIRECT)
    assert "code=" in location and "state=s-123" in location
    cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie and "Path=/idp" in cookie


def test_the_exchange_returns_a_token_and_a_code_is_single_use(world):
    response = register(world)
    code = code_from(response)

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": response.verifier,
        "redirect_uri": REDIRECT,
        "client_id": CLIENT_ID,
    }
    first = httpx.post(f"{world.base}/idp/v1/token", data=form)
    second = httpx.post(f"{world.base}/idp/v1/token", data=form)

    assert first.status_code == 200
    assert first.json()["access_token"]
    assert second.status_code == 400
    assert second.json() == {"error": "invalid_grant"}


def test_a_wrong_verifier_is_refused_and_burns_the_code(world):
    response = register(world)
    code = code_from(response)

    wrong = httpx.post(
        f"{world.base}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "not-the-verifier",
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
        },
    )
    retry = httpx.post(
        f"{world.base}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": response.verifier,
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
        },
    )

    assert wrong.status_code == 400
    # The failed attempt spent the code — a stolen code is not retryable against.
    assert retry.status_code == 400


@pytest.mark.parametrize(
    "tamper",
    [{"redirect_uri": "http://evil.example/callback"}, {"client_id": "someone-else"}],
)
def test_the_exchange_rechecks_what_the_code_was_issued_against(world, tamper):
    response = register(world)

    refused = httpx.post(
        f"{world.base}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code_from(response),
            "code_verifier": response.verifier,
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
            **tamper,
        },
    )

    assert refused.status_code == 400
    assert refused.json() == {"error": "invalid_grant"}


def test_an_unregistered_redirect_uri_never_gets_a_redirect(world):
    """A bad redirect_uri is a 400 page — redirecting to it would be an open
    redirect wearing an error message."""
    _, challenge = pkce_pair()
    response = httpx.get(
        f"{world.base}/idp/v1/authorize",
        params=flow_params(challenge, redirect_uri="http://evil.example/callback"),
    )

    assert response.status_code == 400
    assert "location" not in response.headers


def test_a_missing_or_downgraded_pkce_challenge_bounces_as_invalid_request(world):
    """No challenge, or a method weaker than S256, never reaches a login screen —
    the flow is refused back to the app before anybody types a password into it."""
    for params in (
        {k: v for k, v in flow_params("x").items() if k != "code_challenge"},
        flow_params("x", code_challenge_method="plain"),
    ):
        response = httpx.get(f"{world.base}/idp/v1/authorize", params=params)
        assert response.status_code == 302
        assert "error=invalid_request" in response.headers["location"]


def test_an_unknown_grant_type_is_named(world):
    response = httpx.post(
        f"{world.base}/idp/v1/token", data={"grant_type": "password"}
    )
    assert response.status_code == 400
    assert response.json() == {"error": "unsupported_grant_type"}


def test_an_expired_code_is_refused(world):
    response = register(world)
    code = code_from(response)
    world.provider.codes[code].expires_at = 0  # two minutes pass

    refused = httpx.post(
        f"{world.base}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": response.verifier,
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
        },
    )
    assert refused.status_code == 400
    assert refused.json() == {"error": "invalid_grant"}


def test_an_account_disabled_after_the_code_gets_no_token(world):
    """Disabling wins the race against a code already issued: the token endpoint
    re-reads the account, so a code in flight when the account is cut off dies with
    it rather than outliving the decision."""
    response = register(world)
    world.db.execute("UPDATE accounts SET disabled = 1")
    world.db.commit()

    refused = httpx.post(
        f"{world.base}/idp/v1/token",
        data={
            "grant_type": "authorization_code",
            "code": code_from(response),
            "code_verifier": response.verifier,
            "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID,
        },
    )
    assert refused.status_code == 400


def test_state_with_reserved_characters_round_trips(world):
    """`state` is the app's, echoed byte-for-byte however it is spelled — an `&` or
    `%` in it must survive both the code redirect and the error redirect."""
    verifier, challenge = pkce_pair()
    weird = "s&weird=1 %"
    granted = httpx.post(
        f"{world.base}/idp/register",
        data={
            **flow_params(challenge, state=weird),
            "email": "state@example.com",
            "password": "long enough",
        },
    )
    query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(granted.headers["location"]).query
    )
    assert query["state"] == [weird]

    _, challenge = pkce_pair()
    bounced = httpx.get(
        f"{world.base}/idp/v1/authorize",
        params=flow_params(challenge, state=weird, prompt="none"),
    )
    bounced_query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(bounced.headers["location"]).query
    )
    assert bounced_query["state"] == [weird]


def test_a_failed_register_keeps_the_flow_alive(world):
    """The error page re-renders with the authorize parameters still in the form, so
    fixing a typo continues the sign-in instead of stranding somebody on a page whose
    submit would go nowhere."""
    register(world)  # takes the address
    _, challenge = pkce_pair()
    dup = httpx.post(
        f"{world.base}/idp/register",
        data={
            **flow_params(challenge, state="s&kept"),
            "email": "priya@example.com",
            "password": "long enough",
        },
    )

    assert dup.status_code == 400
    assert "already exists" in dup.text
    assert 'name="code_challenge"' in dup.text
    assert "s&amp;kept" in dup.text


def test_logout_clears_the_session_cookie(world):
    response = httpx.get(f"{world.base}/idp/logout")
    assert response.status_code == 302
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_a_dead_api_is_a_502_not_a_hang(world):
    """`api_port` in this world points at nothing — which is exactly the case under
    test: the proxy answers with a sentence instead of a traceback or a stall."""
    response = httpx.get(f"{world.base}/api/health", timeout=10)
    assert response.status_code == 502
    assert "not answering" in response.text


def test_prompt_none_without_a_session_is_a_conformant_refusal(world):
    """A redirect carrying `error=login_required` — never a 400 HTML page. The SPA's
    silent-renewal iframe reads the redirect instantly; the 400 page is the shape
    that used to cost twenty seconds against the real org."""
    _, challenge = pkce_pair()
    response = httpx.get(
        f"{world.base}/idp/v1/authorize",
        params=flow_params(challenge, prompt="none"),
    )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(REDIRECT)
    assert "error=login_required" in location and "state=s-123" in location


def test_a_session_survives_and_prompt_none_then_succeeds(world):
    registered = register(world)
    session = registered.headers["set-cookie"].split(";")[0]

    _, challenge = pkce_pair()
    silent = httpx.get(
        f"{world.base}/idp/v1/authorize",
        params=flow_params(challenge, prompt="none"),
        headers={"Cookie": session},
    )

    assert silent.status_code == 302
    assert "code=" in silent.headers["location"]


def test_a_tampered_cookie_is_a_login_form_not_a_session(world):
    register(world)
    forged = f"{edge_mod.SESSION_COOKIE}=" + base64.urlsafe_b64encode(
        b"lu_someone|9999999999"
    ).decode() + "." + base64.urlsafe_b64encode(b"not a signature").decode()

    _, challenge = pkce_pair()
    response = httpx.get(
        f"{world.base}/idp/v1/authorize",
        params=flow_params(challenge),
        headers={"Cookie": forged},
    )

    assert response.status_code == 200
    assert "Sign in" in response.text


def test_wrong_password_rerenders_the_form_without_an_oracle(world):
    register(world)
    _, challenge = pkce_pair()

    response = httpx.post(
        f"{world.base}/idp/login",
        data={
            **flow_params(challenge),
            "email": "priya@example.com",
            "password": "not it",
        },
    )
    unknown = httpx.post(
        f"{world.base}/idp/login",
        data={
            **flow_params(challenge),
            "email": "nobody@example.com",
            "password": "not it",
        },
    )

    assert response.status_code == 400 and unknown.status_code == 400
    # One sentence for both, so the form does not answer "does this address exist".
    assert response.text.count("do not match") == unknown.text.count("do not match")


class TestLoginThrottle:
    """Step 053 (B2): the per-account backoff, on a fake clock so it is deterministic."""

    def _throttle(self):
        from carnet.localidp.throttle import LoginThrottle

        self.now = 1000.0
        return LoginThrottle(clock=lambda: self.now)

    def test_below_the_threshold_nothing_is_blocked(self):
        t = self._throttle()
        for _ in range(5):
            t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") == 0.0

    def test_past_the_threshold_backoff_grows_and_is_capped(self):
        t = self._throttle()
        for _ in range(6):  # one past the threshold of 5
            t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") == 1.0  # base * 2**0

        self.now += 2  # wait it out, then fail again
        t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") == 2.0  # base * 2**1

        for _ in range(40):  # drive it well past the cap
            t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") == 900.0  # capped at 15 minutes

    def test_the_key_is_normalized_so_case_and_spacing_do_not_evade(self):
        t = self._throttle()
        for _ in range(6):
            t.failed("  Priya@Example.com ")
        assert t.blocked_for("priya@example.com") > 0

    def test_success_clears_the_penalty(self):
        t = self._throttle()
        for _ in range(6):
            t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") > 0
        t.succeeded("priya@example.com")
        assert t.blocked_for("priya@example.com") == 0.0

    def test_an_idle_record_resets_and_is_evicted(self):
        t = self._throttle()
        for _ in range(6):
            t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") > 0
        self.now += 1000  # past the 15-minute reset window
        assert t.blocked_for("priya@example.com") == 0.0
        # And the slot is gone, not merely zeroed — the next failure starts fresh.
        t.failed("priya@example.com")
        assert t.blocked_for("priya@example.com") == 0.0  # 1 failure, below threshold


def test_login_backs_off_after_repeated_failures(tmp_path):
    """Step 053 (B2), end to end: past the threshold the login answers 429 with a
    Retry-After, rendering the whole page, and a right password is refused while blocked."""
    from carnet.localidp.edge import EdgeConfig, serve
    from carnet.localidp.throttle import LoginThrottle

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>app</title>")
    db = accounts.open_db(str(tmp_path / "accounts.db"))
    accounts.create_account(db, "priya@example.com", "correct horse", "Priya")
    provider = LocalProvider(tmp_path)

    clock = {"t": 1000.0}
    throttle = LoginThrottle(clock=lambda: clock["t"])
    cfg = EdgeConfig(
        host="127.0.0.1", port=0, dist_dir=str(dist), api_port=1,
        redirect_uris=(REDIRECT,),
    )
    server = serve(cfg, provider, db, throttle)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        _, challenge = pkce_pair()

        def attempt(password):
            return httpx.post(
                f"{base}/idp/login",
                data={**flow_params(challenge), "email": "priya@example.com",
                      "password": password},
            )

        # Six wrong passwords: the first five re-render the form, the sixth trips the block.
        for _ in range(6):
            assert attempt("wrong") .status_code == 400

        blocked = attempt("wrong")
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
        assert "Try again" in blocked.text and "Sign in" in blocked.text

        # Even the *right* password is refused while the account is blocked.
        assert attempt("correct horse").status_code == 429

        # Wait out the block: the right password now gets in and clears the penalty.
        clock["t"] += 60
        assert attempt("correct horse").status_code == 302
    finally:
        server.shutdown()


def test_closed_registration_refuses_the_form_and_the_post(world):
    # An account already exists, so the first-account carve-out (step 052) does not apply
    # and closed registration refuses both the page and the post.
    accounts.create_account(world.db, "first@example.com", "correct horse", "First")
    world.cfg.registration = "closed"

    page = httpx.get(f"{world.base}/idp/register")
    post = register(world, email="late@example.com")

    assert page.status_code == 403
    assert post.status_code == 403
    assert accounts.get_account(world.db, "late@example.com") is None


def test_closed_registration_still_admits_the_first_account(world):
    """Step 052 (B3): an exposed deployment defaults to closed, so the first account —
    the one that appoints the first administrator — must still get in, and only it."""
    world.cfg.registration = "closed"

    page = httpx.get(f"{world.base}/idp/register")
    assert page.status_code == 200, "the first account's register page is served"

    first = register(world, email="first@example.com")
    assert first.status_code == 302
    assert accounts.get_account(world.db, "first@example.com") is not None

    # Now the store is non-empty, so the carve-out closes behind the first account.
    second = register(world, email="second@example.com")
    assert second.status_code == 403
    assert accounts.get_account(world.db, "second@example.com") is None


def test_the_session_cookie_is_secure_only_when_configured(world):
    """Step 052 (B3): `Secure` when the deployment is reached over HTTPS, and not on a
    plain-http origin where the browser would drop the cookie."""
    plain = register(world, email="plain@example.com")
    assert "Secure" not in plain.headers.get("set-cookie", "")

    world.cfg.secure_cookie = True
    secured = register(world, email="secured@example.com")
    cookie = secured.headers.get("set-cookie", "")
    assert "Secure" in cookie and "HttpOnly" in cookie


def test_the_first_register_page_prefills_the_admin(world):
    page = httpx.get(f"{world.base}/idp/register")
    assert "priya@example.com" in page.text
    assert "becomes the administrator" in page.text

    register(world)
    second = httpx.get(f"{world.base}/idp/register")
    assert "becomes the administrator" not in second.text


def test_config_json_names_a_relative_issuer(world):
    config = httpx.get(f"{world.base}/config.json").json()

    assert config["issuer"] == "/idp"
    assert config["client_id"] == CLIENT_ID


def test_static_paths_cannot_escape_dist(world):
    """A raw socket, because every HTTP client normalises `..` away before sending —
    which is exactly why a server must not rely on the client having done so."""
    import socket

    host, port = urllib.parse.urlsplit(world.base).netloc.split(":")
    with socket.create_connection((host, int(port)), timeout=5) as raw:
        raw.sendall(
            b"GET /../accounts.db HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        data = b""
        while chunk := raw.recv(65536):
            data += chunk

    # Whatever the traversal spells, what comes back is the app, never a file
    # outside dist.
    assert b"<title>app</title>" in data


def test_idp_pages_carry_their_own_strict_csp(world):
    page = httpx.get(f"{world.base}/idp/login")
    assert "default-src 'none'" in page.headers.get("content-security-policy", "")


def test_the_spa_is_never_served_under_the_providers_csp(world):
    """A CSP header combines with the page's CSP meta by intersection, so the
    provider's `default-src 'none'` stamped onto the SPA's `index.html` silences the
    app's own scripts. The browser check found this as a blank page; this pins it.

    Since plan 031 the SPA *does* carry a header — the app's own full policy, the one
    the bundle's meta tag no longer holds the provider-dependent half of — so the pin
    is now "the app's policy, never the provider's"."""
    app = httpx.get(f"{world.base}/")
    policy = app.headers.get("content-security-policy", "")
    assert "default-src 'none'" not in policy
    assert "script-src 'self'" in policy
    assert "<title>app</title>" in app.text


def test_the_spa_html_carries_the_full_policy_and_assets_do_not(world):
    """The front door owns `connect-src`/`frame-src` now (plan 031, decision 7): the
    meta tag cannot name a deployment's provider, and an intersection cannot be
    widened, so the header is where the whole policy lives. `'self'` alone here,
    because one origin is this front door's load-bearing decision — and
    `frame-ancestors` rides along, the directive a meta tag is ignored for.

    `frame-ancestors 'self'`, not 'none': the silent-renewal iframe's last hop is a
    redirect back to `/login/callback` — this app framed by this app — and 'none'
    blocks it, which a real browser found as every silent re-entry failing."""
    app = httpx.get(f"{world.base}/")
    policy = app.headers.get("content-security-policy", "")
    assert "connect-src 'self'" in policy
    assert "frame-src 'self'" in policy
    assert "frame-ancestors 'self'" in policy
    assert "unsafe-inline" not in policy.split("style-src")[0]  # never in script-src

    # The policy governs documents; an asset carrying it is noise, not protection.
    import pathlib

    assets = pathlib.Path(world.cfg.dist_dir) / "assets"
    assets.mkdir(exist_ok=True)
    (assets / "app.js").write_text("export {}")
    asset = httpx.get(f"{world.base}/assets/app.js")
    assert asset.status_code == 200
    assert "content-security-policy" not in asset.headers


def test_the_discovery_document_names_the_endpoints(world):
    """The SPA resolves endpoints from discovery now rather than concatenating
    Okta-shaped `/v1/*` paths; this document is what keeps the local mode working."""
    doc = httpx.get(f"{world.base}/idp/.well-known/openid-configuration")
    assert doc.status_code == 200
    assert doc.headers["content-type"].startswith("application/json")
    body = doc.json()
    assert body["authorization_endpoint"] == "/idp/v1/authorize"
    assert body["token_endpoint"] == "/idp/v1/token"
    assert body["code_challenge_methods_supported"] == ["S256"]


def test_the_maintenance_dsn_is_parsed_never_assumed(tmp_path):
    """An operator's `CARNET_DATABASE_URL` names whatever database they chose.
    The first version string-replaced our own default name, so maintenance connected
    to *their* not-yet-existing database and died with a FATAL about it."""
    from carnet.localidp import frontdoor

    name, maintenance = frontdoor._split_dsn(
        "postgresql://postgres:pw@localhost:55432/their_name"
    )
    assert name == "their_name"
    assert maintenance == "postgresql://postgres:pw@localhost:55432/postgres"

    # The socket spelling keeps its host in the query string; splicing must keep it.
    name, maintenance = frontdoor._split_dsn(
        "postgresql://postgres:@/carnet_local?host=/tmp/sock"
    )
    assert name == "carnet_local"
    assert maintenance == "postgresql://postgres:@/postgres?host=/tmp/sock"

    with pytest.raises(SystemExit, match="names no database"):
        frontdoor._split_dsn("postgresql://postgres:@localhost:55432/")


def test_fresh_reopens_registration(tmp_path, monkeypatch):
    """A fresh world with zero accounts and `registration: closed` carried over is a
    deployment nobody can ever enter. Found by running --fresh on a closed state."""
    from carnet.localidp import frontdoor

    settings = {"admin": "a@b.co", "registration": "closed", "port": 1, "host": "h"}
    (tmp_path / "state.json").write_text(json.dumps(settings))
    (tmp_path / "accounts.db").write_bytes(b"x")
    (tmp_path / "accounts.db-wal").write_bytes(b"x")
    monkeypatch.setattr("builtins.input", lambda prompt="": "fresh")

    frontdoor._fresh(tmp_path, settings)

    assert settings["registration"] == "open"
    assert json.loads((tmp_path / "state.json").read_text())["registration"] == "open"
    assert not list(tmp_path.glob("accounts.db*")), "the WAL twins go with the db"
    assert settings["_drop_database"] is True


def test_fresh_without_the_word_drops_nothing(tmp_path, monkeypatch):
    from carnet.localidp import frontdoor

    settings = {"registration": "closed"}
    (tmp_path / "accounts.db").write_bytes(b"x")
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")

    with pytest.raises(SystemExit, match="nothing dropped"):
        frontdoor._fresh(tmp_path, settings)

    assert (tmp_path / "accounts.db").exists()
    assert settings.get("registration") == "closed"
    assert "_drop_database" not in settings


def test_the_default_bind_is_loopback(tmp_path):
    """The front door's default host is loopback; anything wider is the operator
    typing it. Driven through `_settings` — the same function the real run uses."""
    from types import SimpleNamespace

    from carnet.localidp import frontdoor

    args = SimpleNamespace(
        local_admin="priya@example.com",
        local_port=None,
        local_host=None,
        local_public_url=None,
        local_registration=None,
    )
    settings = frontdoor._settings(tmp_path, args)

    assert settings["host"] == "127.0.0.1"
    assert settings["registration"] == "open"
    # And the choice persists: the second run is the same deployment.
    assert json.loads((tmp_path / "state.json").read_text())["host"] == "127.0.0.1"


@pytest.mark.parametrize(
    "public_url, host, expected",
    [
        ("https://box.example.com", None, "closed"),  # a public URL: exposed
        (None, "0.0.0.0", "closed"),                  # a non-loopback host: exposed
        (None, None, "open"),                         # loopback trial: unchanged
    ],
)
def test_an_exposed_deployment_defaults_to_closed_registration(
    tmp_path, public_url, host, expected
):
    """Step 052 (B3): registration defaults to closed when the deployment is exposed —
    a public URL or a non-loopback host — and stays open on a loopback trial."""
    from types import SimpleNamespace

    from carnet.localidp import frontdoor

    args = SimpleNamespace(
        local_admin="priya@example.com",
        local_port=None,
        local_host=host,
        local_public_url=public_url,
        local_registration=None,
    )
    settings = frontdoor._settings(tmp_path, args)
    assert settings["registration"] == expected


def test_an_explicit_registration_choice_wins_over_the_exposed_default(tmp_path):
    """An operator who says `--registration open` on a public URL is not second-guessed."""
    from types import SimpleNamespace

    from carnet.localidp import frontdoor

    args = SimpleNamespace(
        local_admin="priya@example.com",
        local_port=None,
        local_host=None,
        local_public_url="https://box.example.com",
        local_registration="open",
    )
    settings = frontdoor._settings(tmp_path, args)
    assert settings["registration"] == "open"


# --- the keystone -----------------------------------------------------------------


class TestTheKeystone:
    """A local token through the production verification path, unchanged."""

    def test_a_minted_token_resolves_to_a_principal(self, isolated_storage, tmp_path):
        provider = LocalProvider(tmp_path)
        store = storage.active()
        store.create_tenant("t-local", "Local")
        store.save_tenant_idp(
            "t-local", LocalProvider.idp_row(jwks_uri="http://127.0.0.1:1/idp/v1/keys")
        )
        cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks(provider.jwks()))

        token = provider.mint(
            {"id": "lu_abc123", "email": "priya@example.com", "display_name": "Priya"}
        )
        row, claims = providers.resolve(token, cache)
        principal = users.resolve(row, claims)

        assert row["tenant_id"] == "t-local"
        assert principal.kind == "user"
        assert principal.tenant_id == "t-local"
        user = store.find_user(ISSUER, "lu_abc123")
        assert user["email"] == "priya@example.com"

    def test_the_issuer_and_audience_are_checked_not_assumed(
        self, isolated_storage, tmp_path
    ):
        """A second local provider — somebody else's state directory — does not
        verify against this deployment's row, because the *keys* differ. Same iss,
        same aud, different signer: refused by the signature, which is the check
        that matters."""
        ours = LocalProvider(tmp_path / "ours")
        theirs = LocalProvider(tmp_path / "theirs")
        store = storage.active()
        store.create_tenant("t-local", "Local")
        store.save_tenant_idp(
            "t-local", LocalProvider.idp_row(jwks_uri="http://127.0.0.1:1/idp/v1/keys")
        )
        cache = JwksCache(fetch=lambda uri: oidc.keys_from_jwks(ours.jwks()))

        forged = theirs.mint({"id": "lu_x", "email": "x@example.com", "display_name": ""})

        with pytest.raises(oidc.TokenError):
            providers.resolve(forged, cache)

    def test_the_row_shape_is_what_the_cli_would_register(self):
        row = LocalProvider.idp_row(jwks_uri="http://127.0.0.1:8080/idp/v1/keys")

        assert row["issuer"] == ISSUER == "carnet-local"
        assert row["audience"] == AUDIENCE
        assert row["allowed_domains"] == ("*",)
        # Spec-shaped claims, so the defaults apply — no subject_claim override.
        assert "subject_claim" not in row


# --- the covenant -----------------------------------------------------------------


def test_the_server_never_imports_the_local_idp():
    """The dependency arrow points one way. The provider may know the product; the
    product must not know the provider — deleting `localidp/` has to leave `api/`
    and `access/` byte-for-byte untouched, which is only true while nothing in them
    references it. Mirrors `test_the_dev_auth_header_is_gone`."""
    import pathlib
    import sys

    import carnet.access  # noqa: F401
    import carnet.api  # noqa: F401

    src = pathlib.Path(carnet.api.__file__).resolve().parents[1]
    offenders = [
        path
        for folder in ("api", "access")
        for path in (src / folder).rglob("*.py")
        if "localidp" in path.read_text()
    ]
    assert offenders == []

    # And the import graph agrees with the grep — checked in a fresh interpreter,
    # because this very file imports the provider and would poison `sys.modules`.
    import subprocess

    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import carnet.api, carnet.access; "
            "assert not any(n.startswith('carnet.localidp') for n in sys.modules)",
        ],
        check=True,
    )


# --- step 043: a public name beside localhost ---------------------------------------


def test_a_public_url_is_added_to_the_redirects_and_never_replaces_localhost():
    """The operator's own browser and a colleague's reach the same deployment.

    A list that swapped one for the other would break the person configuring it at the
    moment they configured it — the failure would look like the feature working.
    """
    from carnet.localidp import frontdoor

    settings = {
        "host": "127.0.0.1",
        "port": 8081,
        "public_url": "https://box.tailnet.ts.net",
    }
    uris = frontdoor._redirect_uris(settings)

    assert "https://box.tailnet.ts.net/login/callback" in uris
    assert "http://localhost:8081/login/callback" in uris
    assert "http://127.0.0.1:8081/login/callback" in uris


def test_without_a_public_url_the_redirects_are_exactly_what_they_were():
    from carnet.localidp import frontdoor

    uris = frontdoor._redirect_uris({"host": "127.0.0.1", "port": 8081})

    assert uris == (
        "http://127.0.0.1:8081/login/callback",
        "http://localhost:8081/login/callback",
    )


@pytest.mark.parametrize(
    "raw",
    [
        "box.tailnet.ts.net",  # no scheme: the commonest paste
        "ftp://box.tailnet.ts.net",  # a scheme no browser will speak here
        "https://",  # a scheme and nothing to reach
    ],
)
def test_a_public_url_that_is_not_an_origin_is_refused_at_parse(raw):
    """Refused where it is typed, not at the sign-in of a person who is not here.

    This value cannot be shown to be wrong by using the deployment yourself: the
    operator's own browser goes on working off the localhost entry.
    """
    from carnet.localidp import frontdoor

    with pytest.raises(SystemExit) as refusal:
        frontdoor._public_origin(raw)

    assert "--public-url" in str(refusal.value)


def test_a_page_url_is_refused_naming_the_origin_to_use_instead():
    from carnet.localidp import frontdoor

    with pytest.raises(SystemExit) as refusal:
        frontdoor._public_origin("https://box.tailnet.ts.net/agents")

    assert "https://box.tailnet.ts.net" in str(refusal.value)


def test_a_trailing_slash_is_not_a_different_deployment():
    from carnet.localidp import frontdoor

    assert (
        frontdoor._public_origin("https://box.tailnet.ts.net/")
        == "https://box.tailnet.ts.net"
    )


# --- the edge measures before it buffers (step 059) --------------------------------


def _raw_post(base: str, path: str, headers: dict) -> tuple[int, bytes]:
    """A request whose headers misdeclare on purpose — which httpx will not send.

    The refusal under test happens on the *declared* length, before a byte is read,
    so the declaration has to be free to lie.
    """
    import http.client as raw

    host, port = base.removeprefix("http://").split(":")
    conn = raw.HTTPConnection(host, int(port), timeout=5)
    try:
        conn.putrequest("POST", path)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def test_an_oversized_form_is_refused_before_scrypt_and_before_reading(
    world, monkeypatch
):
    """413 on the declared length, with `verify_login` proven unreached — 051 bounded
    what a login can make scrypt burn, and this is the sibling bound on what one can
    make the process hold."""

    def burned(*_args, **_kwargs):
        raise AssertionError("scrypt must not run for a refused body")

    monkeypatch.setattr(accounts, "verify_login", burned)

    status, body = _raw_post(
        world.base,
        "/idp/login",
        {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(20 * 1024 * 1024),
        },
    )

    assert status == 413
    assert b"ceiling" in body


def test_a_garbage_content_length_is_a_400_not_a_traceback(world):
    status, body = _raw_post(world.base, "/idp/login", {"Content-Length": "banana"})

    assert status == 400
    assert b"not a number" in body


def test_chunked_is_411_a_body_this_edge_cannot_measure(world):
    status, body = _raw_post(
        world.base, "/idp/login", {"Transfer-Encoding": "chunked"}
    )

    assert status == 411
    assert b"Content-Length" in body


def test_an_oversized_proxy_body_never_reaches_the_api(world):
    """`api_port=1`: nothing listens there, so *reaching* for the API answers 502.
    The 413 therefore proves the refusal precedes the dial as well as the read."""
    status, _body = _raw_post(
        world.base, "/api/agents", {"Content-Length": str(50 * 1024 * 1024)}
    )

    assert status == 413


def test_a_reasonable_form_still_arrives(world):
    """The ceiling is a limit, not a closed door: the register flow — a real form
    post under 64 KiB — still lands, which the flow tests also prove and this one
    states beside its new neighbours."""
    response = register(world)

    assert response.status_code in (302, 303)


# --- one account wide, actually (step 064) ------------------------------------------


def test_concurrent_first_registrations_leave_exactly_one_account(db):
    """The race step 064 closes, driven rather than argued.

    `_register` used to read `count(db) > 0` and then create, which is two statements
    with a deliberately slow scrypt between them — a window measured in hundreds of
    milliseconds on a threaded server. Two registrations against an empty store both
    passed the check and both wrote, on the deployment shape whose registration
    defaults to *closed* precisely because it is exposed.

    Twelve threads, distinct addresses so nothing is refused as a duplicate: exactly
    one must win, and the losers must be told that somebody else was first.
    """
    import threading

    start = threading.Barrier(12)
    outcomes: list = []
    lock = threading.Lock()

    def register(n):
        start.wait()
        try:
            accounts.create_account(
                db, f"racer{n}@example.com", "correct horse", only_if_first=True
            )
            result = "created"
        except accounts.RegistrationClosed:
            result = "refused"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=register, args=(n,)) for n in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert outcomes.count("created") == 1, outcomes
    assert outcomes.count("refused") == 11, outcomes
    assert accounts.count(db) == 1


def test_only_if_first_refuses_once_anybody_exists(db):
    """The ordinary case behind the race: the carve-out is for the *first* account and
    nothing else, and the refusal is its own class because nothing the person typed
    was wrong."""
    accounts.create_account(db, "first@example.com", "correct horse")

    with pytest.raises(accounts.RegistrationClosed, match="already been created"):
        accounts.create_account(
            db, "second@example.com", "correct horse", only_if_first=True
        )
    assert accounts.count(db) == 1


def test_only_if_first_still_admits_the_first_account(db):
    """An exposed deployment defaulting to closed must still be able to appoint its
    first administrator — the carve-out's whole reason for existing (step 052)."""
    account = accounts.create_account(
        db, "admin@example.com", "correct horse", only_if_first=True
    )

    assert account["email"] == "admin@example.com"
    assert accounts.count(db) == 1
