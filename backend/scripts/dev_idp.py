"""A local OpenID provider, so a **browser** check does not need a person at the keyboard.

`scripts/dev_token.py` mints a real Okta token and opens a browser to do it, which means
every browser verification in this project's history has needed somebody sitting there.
That is why 10a's screens were checked by hand once and the plan's *"run it in a browser,
signed in as two real people"* keeps being the done-when nobody gets to.

This serves the four endpoints the SPA actually uses — the discovery document at
`/.well-known/openid-configuration`, which is how the app finds the other three since
step 031, and `/v1/authorize`, `/v1/token`, `/v1/keys` — against a key it generates at
startup, and hands out a token for whichever
person is currently selected. The backend verifies those tokens **through exactly the
production path**: `access/oidc.py` fetches the JWKS over HTTP and checks the signature,
the issuer and the audience, and `access/users.py` creates the principal. Nothing in the
server knows this provider is a fake.

**It is a fake in one direction and that direction is the whole point: it does not
authenticate anybody.** `/_be/{subject}` switches who the next authorization is for, with
no password and no consent screen. That is a development affordance and it must never be
reachable from anything but a developer's own machine:

  - it binds 127.0.0.1 only,
  - it is not importable by the app — nothing under `src/` references it,
  - and the tenant it is registered against is one `scripts/e2e_browser.py` creates and
    drops.

What it is **not** a substitute for: the real Okta org, which is what proves the token
shape, the discovery, the claim mapping (`subject_claim=uid`, `email_claim=sub` — see
migration 010, which exists because of a real token) and the third-party-cookie behaviour
of silent renewal. Those need `dev_token.py` and a person. This proves the *screens*.

    .venv/bin/python scripts/dev_idp.py --port 8902
"""

import argparse
import http.server
import json
import secrets
import threading
import time
import urllib.parse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

AUDIENCE = "api://dev"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True)
JWK.update({"kid": "dev", "use": "sig", "alg": "RS256"})


class Provider:
    """The mutable half: who the next authorization is for, and the codes issued.

    A code is single-use and expires, which is not security here — it is so that a stale
    tab replaying an old callback fails the way a real provider fails, rather than
    silently signing somebody in as whoever was selected last.
    """

    def __init__(self, issuer: str):
        self.issuer = issuer
        self.subject = "priya@acme.com"
        self.codes: dict[str, tuple[str, float]] = {}
        self.lock = threading.Lock()
        # Step 033e: which directory groups each person's token says they are in.
        # Per subject rather than global, because the whole feature is that two people
        # signing in against one provider land in different groups.
        self.groups: dict[str, list[str]] = {}

    def be(self, subject: str, groups: list[str] | None = None) -> None:
        with self.lock:
            self.subject = subject
            if groups is not None:
                self.groups[subject] = groups

    def issue_code(self) -> str:
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.codes[code] = (self.subject, time.time() + 120)
        return code

    def redeem(self, code: str) -> str | None:
        with self.lock:
            entry = self.codes.pop(code, None)
        if entry is None or entry[1] < time.time():
            return None
        return entry[0]

    def token_for(self, subject: str) -> str:
        now = int(time.time())
        with self.lock:
            groups = list(self.groups.get(subject, ()))
        return jwt.encode(
            {
                "iss": self.issuer,
                "aud": AUDIENCE,
                # Only when this person has been given some. A provider that emits no
                # claim at all is the ordinary shape for somebody in no group, and it is
                # the shape `access/directory.py` has to read as an empty membership.
                **({"groups": groups} if groups else {}),
                # `sub` is the address and `uid` is the opaque id, which is the **real**
                # Okta org's shape rather than the spec's — see migration 010. A fake
                # that used the conformant shape would exercise a claim mapping this
                # deployment does not use.
                "sub": subject,
                "uid": f"u_{subject.split('@')[0]}",
                "iat": now,
                "exp": now + 3600,
            },
            KEY,
            algorithm="RS256",
            headers={"kid": "dev"},
        )


def handler_for(provider: Provider):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, body: bytes, content_type="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # The SPA calls the token endpoint from `http://localhost:8080`. Okta needs
            # that origin registered as a Trusted Origin and says so in `auth.ts`'s error
            # message; a fake that forgot this would fail with exactly that message and
            # send somebody looking at an Okta console.
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(url.query)

            if url.path == "/.well-known/openid-configuration":
                # The SPA resolves its endpoints from discovery now (plan 031) rather
                # than concatenating Okta-shaped /v1/* paths; this document is what
                # keeps `VITE_OIDC_ISSUER=http://127.0.0.1:8902` working.
                return self._send(
                    200,
                    json.dumps(
                        {
                            "issuer": provider.issuer,
                            "authorization_endpoint": f"{provider.issuer}/v1/authorize",
                            "token_endpoint": f"{provider.issuer}/v1/token",
                            "jwks_uri": f"{provider.issuer}/v1/keys",
                            "response_types_supported": ["code"],
                            "grant_types_supported": ["authorization_code"],
                            "code_challenge_methods_supported": ["S256"],
                        }
                    ).encode(),
                )

            if url.path == "/v1/keys":
                return self._send(200, json.dumps({"keys": [JWK]}).encode())

            if url.path.startswith("/_be/"):
                who = urllib.parse.unquote(url.path.removeprefix("/_be/"))
                # `?groups=a,b` sets what this person's tokens claim from now on, and
                # `?groups=` clears it — step 033e. Directory membership is the one
                # thing about a person that changes between two sign-ins, so being able
                # to change it between two is the whole point of driving it by hand.
                # Parsed again with `keep_blank_values`, because `?groups=` — *this
                # person is in none* — is the shape that matters most here and the
                # default parse drops it, leaving the previous claim standing. Found by
                # an e2e whose removals all silently did nothing.
                claimed = urllib.parse.parse_qs(url.query, keep_blank_values=True).get(
                    "groups"
                )
                groups = (
                    [g for g in claimed[0].split(",") if g] if claimed is not None else None
                )
                provider.be(who, groups)
                return self._send(
                    200,
                    json.dumps({"subject": who, "groups": provider.groups.get(who, [])}).encode(),
                )

            if url.path == "/v1/authorize":
                # **`prompt=none` is honoured rather than refused**, which is the one place
                # this is *kinder* than the real org and it is worth saying so: Okta
                # answers a silent renewal with a 400 HTML page when the session cookie is
                # blocked as third-party, and that failure — half-fixed, documented — is
                # invisible here. A browser check against this provider therefore cannot
                # tell you anything about silent renewal.
                redirect = query.get("redirect_uri", [""])[0]
                state = query.get("state", [""])[0]
                code = provider.issue_code()
                target = f"{redirect}?code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None

            return self._send(404, b'{"error":"not_found"}')

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            if url.path != "/v1/token":
                return self._send(404, b'{"error":"not_found"}')

            length = int(self.headers.get("Content-Length", 0))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            subject = provider.redeem(form.get("code", [""])[0])
            if subject is None:
                return self._send(400, b'{"error":"invalid_grant"}')

            return self._send(
                200,
                json.dumps(
                    {
                        "access_token": provider.token_for(subject),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                ).encode(),
            )

        def log_message(self, *args):
            pass

    return Handler


def serve(port: int) -> tuple[http.server.ThreadingHTTPServer, Provider]:
    """Start the provider on 127.0.0.1 and return it with its control object."""
    provider = Provider(issuer=f"http://127.0.0.1:{port}")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler_for(provider))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, provider


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8902)
    args = parser.parse_args()

    server, provider = serve(args.port)
    print(f"dev identity provider on {provider.issuer}")
    print(f"  jwks:   {provider.issuer}/v1/keys")
    print(f"  be:     {provider.issuer}/_be/<email>   (currently {provider.subject})")
    print(f"  groups: {provider.issuer}/_be/<email>?groups=dir-eng,dir-ops")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
