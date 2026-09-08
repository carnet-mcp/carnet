-- Which identity provider speaks for which customer.
--
-- This table IS the tenant isolation of the access layer. Every other guard in this
-- codebase decides what an authenticated principal may do; this decides which customer
-- a token belongs to at all, and getting it wrong is not a permission bug — it is one
-- company's employees reading another company's data.
--
-- ## Why the tenant is not read from the token
--
-- Most identity providers can be configured to put an organisation id in a claim, and
-- trusting it would remove this table entirely. It would also make the customer's own
-- IdP authoritative over OUR tenancy: a mis-mapped claim in someone else's admin
-- console becomes a cross-tenant read here, in a setting we cannot see or audit.
--
-- So the token proves *who*; this row decides *whose data*.
--
-- ## Why the key is not just the issuer
--
-- The obvious design is `issuer UNIQUE`, and it holds for the two providers we expect
-- most:
--
--     Okta     https://acme.okta.com                              one per customer
--     Entra    https://login.microsoftonline.com/{dir}/v2.0       one per directory
--
-- It is false for Google Workspace, where every customer on earth authenticates
-- against the same issuer:
--
--     Google   https://accounts.google.com                        SHARED BY ALL
--
-- Under `issuer UNIQUE`, the first Google customer works and the second is silently
-- routed into the first one's data. A constraint that holds for two of the three
-- providers we are most likely to meet is not a constraint.
--
-- Google distinguishes customers with a `hd` ("hosted domain") claim, so the key is
-- the issuer plus an optional discriminating claim. Okta and Entra leave both null.
--
-- The rule a UNIQUE cannot express — a row with NO discriminator claims the whole
-- issuer, so it must be refused if any other row already uses that issuer — is
-- enforced in the storage layer, in both implementations, and tested in the contract
-- suite. See `save_tenant_idp`.

CREATE TABLE tenant_idps (
    tenant_id            TEXT        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The `iss` claim, exactly as the provider emits it. Compared byte-for-byte: a
    -- trailing slash is a different issuer, because that is how the token will arrive
    -- and normalising it here would be this layer guessing.
    issuer               TEXT        NOT NULL,

    -- Null for a provider whose issuer is already per-customer. For a shared issuer,
    -- the claim to route on ('hd') and the value that means this customer.
    -- Both null or both set; neither alone means anything.
    discriminator_claim  TEXT,
    discriminator_value  TEXT,

    -- Where the signing keys live. Stored rather than derived from the issuer's
    -- discovery document, because that is one network round trip per cold start and
    -- because a provider is entitled to host them anywhere it says it does.
    jwks_uri             TEXT        NOT NULL,

    -- The `aud` a token must carry — our client id. A token minted for a different
    -- application at the same provider is a valid token that is not for us, and
    -- accepting it is how one customer's unrelated app becomes a login here.
    audience             TEXT        NOT NULL,

    -- Which field carries the email. Providers disagree: `email` on Okta and Google,
    -- frequently `preferred_username` or `upn` on Entra. A hardcoded field name would
    -- be a provider-specific assumption inside the one module whose job is to be
    -- provider-agnostic.
    email_claim          TEXT        NOT NULL DEFAULT 'email',

    -- Email domains this provider may vouch for. The second gate on automatic user
    -- creation: a registered issuer is not permission to create anyone, only to create
    -- people who look like they belong to this customer.
    allowed_domains      TEXT[]      NOT NULL DEFAULT '{}',

    enabled              BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Global, not per-tenant. Two customers sharing a routing key is exactly the
    -- ambiguity this table exists to prevent, so it cannot be scoped by tenant.
    --
    -- **NULLS NOT DISTINCT is load-bearing and was found by a failing test.** By
    -- default Postgres treats NULL as distinct from NULL in a unique index, so a plain
    -- `UNIQUE (issuer, discriminator_claim, discriminator_value)` permits any number of
    -- rows for one issuer as long as the discriminator columns are NULL — which is
    -- exactly the Okta and Entra shape, the common case. The constraint that *is* this
    -- table's isolation would have enforced nothing for most customers.
    --
    -- The in-memory store keys a dict on the same triple, where None equals None, so it
    -- refused what Postgres allowed. A fake being STRICTER than the real thing is the
    -- rarer direction of drift and the one a contract suite has to be relied on to
    -- catch, because every test passes against the fake.
    --
    -- Requires Postgres 15 or later.
    UNIQUE NULLS NOT DISTINCT (issuer, discriminator_claim, discriminator_value),

    -- Both or neither. A claim with no value routes nothing; a value with no claim
    -- names no field to read it from.
    CONSTRAINT discriminator_is_a_pair CHECK (
        (discriminator_claim IS NULL) = (discriminator_value IS NULL)
    )
);

-- The lookup every authenticated request makes, before anything else happens.
CREATE INDEX tenant_idps_by_issuer ON tenant_idps (issuer);
