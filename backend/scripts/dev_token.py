"""Get a real, signed access token from a dev identity provider.

    python scripts/dev_token.py

Opens a browser, signs in, catches the redirect, exchanges the code, and prints the
token. Authorization Code + PKCE, no client secret — the app is a public client.

## Why this exists rather than a screenshot of Okta's admin console

Okta has a "Token Preview" tab that looks like it does this job. **It strips the
signature**, so the token it produces cannot verify against anything and is useless for
testing the one thing worth testing. That is not obvious until you have pasted one in
and watched it fail for the wrong reason.

## What it is not

Not a login flow for the product, and not a thing any user runs. `frontend/` will do
this properly with a real redirect and a session. This is a developer getting one token
so they can `curl` an endpoint.

Configure with the environment. `DEV_OIDC_ISSUER` and `DEV_OIDC_CLIENT_ID` are required
and have no defaults: a public repository must not name anybody's real tenant, even though
neither value is a secret — a client id is public by design, and PKCE is what makes a
public client safe.
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import urllib.parse
import urllib.request
import webbrowser

# **Okta-shaped, and deliberately not discovery-based.** The endpoints below are built
# by concatenating `/v1/authorize` and `/v1/token` onto this — which is Okta's URL
# shape and nobody else's. The SPA stopped doing that in step 031 (it reads the
# issuer's discovery document instead, so any OIDC provider works); this script did
# not, because its whole job is the *real Okta org* and a second implementation of
# discovery here would be a fixture pretending to be a client. Point `DEV_OIDC_ISSUER`
# at a non-Okta provider and these two URLs will 404 where the app succeeds.
#
# **No defaults.** These used to name the org the product was developed against, and a
# public tree that carries a real tenant's address — however public a client id is — is
# an invitation to send it traffic. Missing means the script says which two to set.
ISSUER = os.environ.get("DEV_OIDC_ISSUER", "").rstrip("/")
CLIENT_ID = os.environ.get("DEV_OIDC_CLIENT_ID", "")
if not ISSUER or not CLIENT_ID:
    raise SystemExit(
        "set DEV_OIDC_ISSUER (the provider's issuer URL, e.g. "
        "https://your-org.okta.com/oauth2/default) and DEV_OIDC_CLIENT_ID (the SPA "
        "client id registered there with redirect URI http://localhost:8080/login/callback)"
    )
REDIRECT = os.environ.get("DEV_OIDC_REDIRECT", "http://localhost:8080/login/callback")
SCOPES = os.environ.get("DEV_OIDC_SCOPES", "openid profile email")

# **Forces a sign-in even when the browser already has a session, and the default is
# `login` because the alternative fails silently.**
#
# Without it, a developer who is already signed in gets a token for *themselves* no
# matter whose account they meant to use. Nothing in the output says so — the flow
# completes, the token is valid, and it is for the wrong person. That cost a real
# session during step 9a's two-login verification: an incognito window was opened, the
# browser reused the session anyway, and the token that came back was the operator's.
#
# Set `DEV_OIDC_PROMPT=` (empty) to allow session reuse, which is only ever what you
# want when re-minting a token for yourself.
PROMPT = os.environ.get("DEV_OIDC_PROMPT", "login")


def main() -> int:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(16)

    authorize = f"{ISSUER}/v1/authorize?" + urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": SCOPES,
            "redirect_uri": REDIRECT,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            **({"prompt": PROMPT} if PROMPT else {}),
        }
    )

    caught: dict = {}
    done = threading.Event()
    port = urllib.parse.urlparse(REDIRECT).port or 80

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            caught.update({k: v[0] for k, v in query.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<h2>Got it.</h2><p>Close this tab and go back to the terminal.</p>"
                if "code" in caught
                else b"<h2>No authorization code came back.</h2>"
            )
            done.set()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("localhost", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"Opening a browser to sign in at {ISSUER}")
    print(f"If it does not open, paste this:\n\n{authorize}\n")
    webbrowser.open(authorize)

    if not done.wait(timeout=300):
        print("timed out waiting for the redirect")
        return 1
    server.shutdown()

    if "code" not in caught:
        print(f"no authorization code: {caught}")
        return 1
    if caught.get("state") != state:
        # Not ceremony. A mismatch means the response is not the one this process
        # started, and continuing would be trusting a code somebody else asked for.
        print("state did not match — refusing to continue")
        return 1

    request = urllib.request.Request(
        f"{ISSUER}/v1/token",
        data=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": caught["code"],
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        tokens = json.load(response)

    print(f"\nexpires in {tokens.get('expires_in')}s, scopes: {tokens.get('scope')}")

    # **Say who this is for.** Not decoration: the one thing that can go wrong here and
    # produce a perfectly valid result is getting somebody else's identity, and a token
    # is opaque to the person holding it. Printing the claims turns a silent wrong
    # answer into an obvious one.
    #
    # Read, never verified — this is the client that just fetched it over TLS from the
    # issuer, so there is nothing to authenticate against. The SERVER verifies
    # signatures; a script that pretended to would be teaching the wrong lesson.
    try:
        payload = tokens["access_token"].split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        print(f"this token is for: {claims.get('sub')}  (uid {claims.get('uid')})\n")
    except Exception:  # pragma: no cover - a token we cannot read is still usable
        print("(could not read the claims — the token below is still what came back)\n")

    # The ACCESS token, not the id token. An API validates access tokens; sending an
    # ID token to an API is a known anti-pattern, and its audience is the client rather
    # than the API so it would be refused anyway.
    print(tokens["access_token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
