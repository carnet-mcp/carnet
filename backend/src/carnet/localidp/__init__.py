"""The local identity provider: a real OIDC provider this deployment runs itself.

This package exists so a person without an enterprise identity provider can sign into
the product: email and password, the first account is the first administrator, and the
tokens it mints are verified by the API **through exactly the production path** —
`access/oidc.py` fetches the JWKS over HTTP and checks the signature, the issuer and
the audience. Nothing in `api/` or `access/` knows this provider exists, and a test
walks their source to keep it that way.

The covenant, inherited by name from the grave in `config.py` where
`AGENT_RUNTIME_INSECURE_DEV_AUTH` is buried (spelled as it actually was — the
variable predates the rename, and see that grave for why it is not restyled):

  - **This is a provider you run, never a bypass the server honours.** There is no
    header, no flag and no impersonation endpoint here. The only way to a token is a
    password this package checked. (`scripts/dev_idp.py` keeps its passwordless
    `/_be/` switch precisely because it is a test fixture and stays one.)
  - **Deleting this package deletes the capability whole.** The verification path is
    byte-for-byte the one Okta tokens take; "local" is a fact about who signs, not
    about what is checked.
  - **The dependency arrow points one way.** This package may know about the product —
    the edge proxies `/api/*` to it — and the product never imports this package.

The pieces:

  - `accounts`  — email + password accounts in the provider's own SQLite file,
                  hashed with scrypt. The product's database never sees a password.
  - `provider`  — the OIDC half: a persisted signing key, authorization codes with
                  PKCE actually verified, and a signed session cookie.
  - `pages`     — the login and register screens, server-rendered.
  - `edge`      — one HTTP server for one origin: `/idp/*` is the provider,
                  `/api/*` proxies to the API on loopback, everything else is the
                  built frontend. One origin is what makes the shipped CSP
                  (`connect-src 'self'`) hold without a special case.
  - `frontdoor` — `carnet --local`: state, database, migration, seed, the
                  provider row, and every process, ending in a URL.
"""
