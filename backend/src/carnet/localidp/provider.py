"""The OIDC half of the local provider: keys, codes, tokens, sessions.

Three properties matter more than the rest:

  - **The signing key is generated once and persisted.** The API caches a JWKS for an
    hour (`config.JWKS_CACHE_TTL`); a provider that re-keyed on every restart would
    invalidate every session each time the front door was bounced, and the failure
    would read as "signed out for no reason" an hour late.
  - **PKCE is actually verified.** `dev_idp.py` ignores it because a fixture
    authenticates nobody; this provider authenticates people, so the code exchange
    proves possession of the verifier, the client id and the redirect URI it was
    issued against.
  - **The session is a stateless signed cookie**, HMAC over `account_id|expiry` with a
    key that persists beside the signing key. No session table; sign-out is the cookie
    expiring or being cleared.

Claims are spec-shaped — `sub` is the stable account id, `email` is the address —
unlike the test fixture, which deliberately mimics the real Okta org's inverted shape.
A provider we author should be conformant, and the row it registers under uses the
default claim mapping for the same reason.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..storage.base import LOCAL_ISSUER_WILDCARD_OK

# Imported rather than spelled again: `storage.base` owns the rule that this is the one
# issuer whose `allowed_domains` may be `"*"`, and a second copy of the string is a second
# copy of that exemption waiting to drift out of agreement with the guard.
ISSUER = LOCAL_ISSUER_WILDCARD_OK
AUDIENCE = ISSUER
CLIENT_ID = ISSUER
KID = "local-1"

CODE_TTL_SECONDS = 120
TOKEN_TTL_SECONDS = 3600
SESSION_TTL_SECONDS = 12 * 3600

_KEY_FILE = "idp_signing.pem"
_COOKIE_KEY_FILE = "idp_cookie.key"


@dataclass
class PendingCode:
    account_id: str
    challenge: str
    redirect_uri: str
    client_id: str
    expires_at: float


def _load_or_create(path: Path, create) -> bytes:
    if path.exists():
        return path.read_bytes()
    data = create()
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return data


class LocalProvider:
    def __init__(self, state_dir: str | Path):
        state = Path(state_dir)
        state.mkdir(parents=True, exist_ok=True)

        pem = _load_or_create(
            state / _KEY_FILE,
            lambda: rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        self.key = serialization.load_pem_private_key(pem, password=None)
        self.cookie_key = _load_or_create(
            state / _COOKIE_KEY_FILE, lambda: secrets.token_bytes(32)
        )
        self.codes: dict[str, PendingCode] = {}
        self.lock = threading.Lock()

    # --- keys and tokens ---------------------------------------------------------

    def jwks(self) -> dict:
        entry = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        entry.update({"kid": KID, "use": "sig", "alg": "RS256"})
        return {"keys": [entry]}

    def mint(self, account: dict) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": account["id"],
                "email": account["email"],
                "name": account["display_name"] or account["email"],
                "iat": now,
                "exp": now + TOKEN_TTL_SECONDS,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": KID},
        )

    # --- authorization codes -----------------------------------------------------

    def issue_code(
        self, account_id: str, challenge: str, redirect_uri: str, client_id: str
    ) -> str:
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = PendingCode(
                account_id=account_id,
                challenge=challenge,
                redirect_uri=redirect_uri,
                client_id=client_id,
                expires_at=time.time() + CODE_TTL_SECONDS,
            )
        return code

    def redeem(
        self, code: str, verifier: str, redirect_uri: str, client_id: str
    ) -> str | None:
        """The account id, when everything the code was issued against matches.

        The pop is unconditional — a failed exchange burns the code, exactly as a
        real provider does, so a stolen code cannot be retried against.
        """
        with self.lock:
            pending = self.codes.pop(code, None)
        if pending is None or pending.expires_at < time.time():
            return None
        if pending.redirect_uri != redirect_uri or pending.client_id != client_id:
            return None
        digest = hashlib.sha256(verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not hmac.compare_digest(computed, pending.challenge):
            return None
        return pending.account_id

    # --- the session cookie ------------------------------------------------------

    def session_for(self, account_id: str) -> str:
        expires = int(time.time()) + SESSION_TTL_SECONDS
        payload = f"{account_id}|{expires}".encode()
        sig = hmac.new(self.cookie_key, payload, hashlib.sha256).digest()
        return (
            base64.urlsafe_b64encode(payload).decode()
            + "."
            + base64.urlsafe_b64encode(sig).decode()
        )

    def session_account(self, cookie: str | None) -> str | None:
        if not cookie or "." not in cookie:
            return None
        payload_b64, sig_b64 = cookie.split(".", 1)
        try:
            payload = base64.urlsafe_b64decode(payload_b64)
            sig = base64.urlsafe_b64decode(sig_b64)
        except (ValueError, TypeError):
            return None
        expected = hmac.new(self.cookie_key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        account_id, _, expires = payload.decode().rpartition("|")
        if not account_id or not expires.isdigit() or int(expires) < time.time():
            return None
        return account_id

    # --- what the row registers --------------------------------------------------

    @staticmethod
    def idp_row(jwks_uri: str) -> dict:
        """The `tenant_idps` row this provider is registered under.

        The issuer is an opaque name, not a URL — the API never fetches it, and an
        issuer with no host in it is what lets the deployment move behind any
        hostname without re-registering. The claim mapping is the default one
        (`sub`/`email`), because the claims are spec-shaped. The wildcard is the
        provider being the account authority: who may register is this package's
        gate, so the product's domain gate would only refuse the first teammate on
        a personal address.
        """
        return {
            "issuer": ISSUER,
            "jwks_uri": jwks_uri,
            "audience": AUDIENCE,
            "allowed_domains": ("*",),
        }


def config_json() -> bytes:
    """What the SPA fetches at boot to find its provider — see `/config.json`.

    The issuer is origin-relative on purpose: the SPA fetches its discovery document
    from `{issuer}/.well-known/openid-configuration`, so same origin means the served
    CSP's `'self'` already covers every request, on any hostname the deployment ends
    up behind. (It is not the token's `iss` claim — that is `ISSUER`, and the API's
    registered row matches on it, not on this.)
    """
    return json.dumps(
        {"issuer": "/idp", "client_id": CLIENT_ID, "scopes": "openid profile email"}
    ).encode()


def discovery_json() -> bytes:
    """The OIDC discovery document, served at `/idp/.well-known/openid-configuration`.

    The SPA stopped concatenating Okta-shaped `/v1/*` paths in plan 031 and asks this
    document where the endpoints are, like it does every other provider. One deliberate
    deviation from the spec: the endpoint URLs are origin-relative, for the same
    hostname-agnosticism as `config_json` — the only consumer is the SPA on this same
    origin, and a relative URL resolves correctly in `fetch`, an iframe `src` and a
    top-level navigation alike.
    """
    return json.dumps(
        {
            "issuer": ISSUER,
            "authorization_endpoint": "/idp/v1/authorize",
            "token_endpoint": "/idp/v1/token",
            "jwks_uri": "/idp/v1/keys",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
        }
    ).encode()
