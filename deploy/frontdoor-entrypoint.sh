#!/bin/sh
# The front door's boot: turn ONE provider declaration into the THREE things a browser
# needs to sign in, then hand off to the image's own command (plan 031, decision 3;
# step 121, decision 3).
#
# The three must never disagree — /config.json (which the app fetches at boot to find
# its provider), the Content-Security-Policy header (which decides what the browser
# may connect to and frame), and, since 121, the route that decides whether /idp/*
# reaches a provider at all. Deriving all of them here, from CARNET_IDP and
# CARNET_OIDC_*, is what makes disagreement unrepresentable. The Caddyfile stays static
# and declarative; this script is the only place any logic lives, so it is the whole
# surface to audit.
#
# Unconfigured is not an error *for an external provider*: day one runs `docker compose
# up` before somebody's Okta is decided, and a front door that refused to start until
# then would be the key generation's chicken-and-egg wearing new clothes. No issuer
# means no /config.json (a real 404 — the SPA fallback deliberately does not catch it)
# and a CSP of 'self' alone; the sign-in screen says what is missing. Anything OTHER
# than "all of it" or "none of it" is a refusal, loudly and by name: a half-declared
# provider is always a mistake, and serving anyway would fail later, quieter, and in a
# browser.
#
# CARNET_IDP (step 121) is the choice *between* providers, and it has three values
# rather than two because an existing deployment must upgrade untouched:
#
#   external   yours, declared in CARNET_OIDC_* — everything above, unchanged
#   bundled    the provider this deployment runs itself (the `idp` service). No issuer
#              to declare: /config.json is origin-relative, so the CSP needs no
#              provider-dependent source and stays exactly the unconfigured one
#   unset      `external`, so nothing that worked before this variable existed changes
#
# Bundled is offered and never defaulted: the failure mode of a default here is a
# company running somebody else's account store for a year without having decided to.
# The choice is made a *conscious* one by `deploy/setup.sh`, which asks before the
# stack ever comes up — not by refusing to start, and the difference is the whole of
# the correction below.
#
# **Plan 121, decision 3 said an undeclared provider should refuse at start. That is
# wrong and the plan is the thing that is out of date.** This container serves
# `/api/*`, and `/api/mcp` is the MCP door — the product. A deployment brokering tool
# calls for machine tokens minted at the CLI needs no browser sign-in at all, and
# refusing to boot over a *browser* setting would take the door down with it. So an
# undeclared provider stays what plan 031 made it: the stack comes up, /config.json is
# a real 404, the sign-in screen says what is missing, and one line here says it too.
# What IS refused is a declaration that contradicts itself, which no working
# deployment has ever had.
set -eu

idp="${CARNET_IDP:-}"
issuer="${CARNET_OIDC_ISSUER:-}"
client_id="${CARNET_OIDC_CLIENT_ID:-}"
scopes="${CARNET_OIDC_SCOPES:-openid profile email}"
extra_origins="${CARNET_OIDC_EXTRA_ORIGINS:-}"
profiles="${COMPOSE_PROFILES:-}"

# Where the /idp/* route lands. The Caddyfile imports this file unconditionally and it
# is empty under `external`, so the routing table is composed from the same declaration
# as the other two artifacts rather than from a second one.
IDP_ROUTE=/etc/caddy/idp.caddy

refuse() {
    echo "front door: $*" >&2
    exit 1
}

# --- which provider, and what a disagreement is --------------------------------------

case "$idp" in
    "") idp=external ;;
    external | bundled) ;;
    *)
        refuse "CARNET_IDP must be 'bundled' or 'external', not '$idp'."
        ;;
esac


if [ "$idp" = bundled ]; then
    # Two providers declared is the half-declaration's bigger sibling: nothing here
    # could say which one signs the tokens the API is registered to verify.
    for name in CARNET_OIDC_ISSUER CARNET_OIDC_CLIENT_ID CARNET_OIDC_SCOPES \
        CARNET_OIDC_EXTRA_ORIGINS; do
        eval "value=\${$name:-}"
        [ -z "$value" ] || refuse "CARNET_IDP=bundled, but $name is also set." \
            "The bundled provider IS the provider — clear the CARNET_OIDC_*" \
            "settings, or choose CARNET_IDP=external and keep them."
    done
    # The `idp` service is switched on by a compose profile, which is a second line in
    # .env and therefore a second thing that can be wrong. It is not derivable from
    # here — a container cannot see which profiles compose activated — so it is passed
    # in and checked, and the check is the difference between this sentence and a 502
    # on the sign-in page. `deploy/setup.sh` writes both lines and never meets it.
    case ",$profiles," in
        *,bundled-idp,*) ;;
        *)
            refuse "CARNET_IDP=bundled, but COMPOSE_PROFILES does not list" \
                "'bundled-idp', so the provider service is not running and /idp/*" \
                "would be a 502. Add it in .env:" \
                "COMPOSE_PROFILES=bundled-db,bundled-idp"
            ;;
    esac
else
    case ",$profiles," in
        *,bundled-idp,*)
            refuse "COMPOSE_PROFILES lists 'bundled-idp', but CARNET_IDP is" \
                "'external' — so the bundled provider would run with nothing routed" \
                "to it. Remove the profile, or set CARNET_IDP=bundled."
            ;;
    esac
fi

# After the refusals above, not before them: advice about a provider nobody declared
# has no business arriving ahead of a sentence about a declaration that contradicts
# itself. Not a refusal — see the header. Said once, on stderr, because the symptom
# otherwise is a sign-in screen and a question nobody has the answer to.
if [ "$idp" = external ] && [ -z "$issuer" ] && [ -z "$client_id" ]; then
    echo "front door: no identity provider is declared, so nobody can sign in" \
        "through a browser. Set CARNET_IDP=bundled for the one this deployment can" \
        "run itself, or CARNET_OIDC_ISSUER and CARNET_OIDC_CLIENT_ID for your own." \
        "The MCP door at /api/mcp is unaffected — machine tokens do not sign in." >&2
fi

# --- what may be declared, and what half a declaration is ----------------------------

if [ -n "$issuer" ] && [ -z "$client_id" ]; then
    refuse "CARNET_OIDC_ISSUER is set but CARNET_OIDC_CLIENT_ID is not. Set both" \
        "in .env (the client id is the SPA's registration at your provider), or" \
        "neither."
fi
if [ -z "$issuer" ] && [ -n "$client_id" ]; then
    refuse "CARNET_OIDC_CLIENT_ID is set but CARNET_OIDC_ISSUER is not. Set both" \
        "in .env (the issuer is your provider's issuer URL, the same value --add-idp" \
        "registers), or neither."
fi
# A variable that is read but does nothing is the defect 030's testing pass found in
# `environment:` — set it, and nothing happens. It is refused here rather than
# ignored, because the deployer who typed it believes their provider is configured.
if [ -z "$issuer" ] && [ -n "$extra_origins" ]; then
    refuse "CARNET_OIDC_EXTRA_ORIGINS is set but CARNET_OIDC_ISSUER is not, so" \
        "it would name origins for a provider this deployment does not have."
fi
if [ -z "$issuer" ] && [ -n "${CARNET_OIDC_SCOPES:-}" ]; then
    refuse "CARNET_OIDC_SCOPES is set but CARNET_OIDC_ISSUER is not, so nothing" \
        "would request those scopes."
fi

# --- what a declared value may contain -----------------------------------------------
#
# These land inside a JSON document and a CSP header, so a value carrying a quote, a
# backslash, a semicolon or a control character does not merely fail — it produces a
# *malformed policy* or a *malformed config*, which is a browser-side failure at
# sign-in rather than a sentence here. Refuse rather than escape: none of these
# characters appears in a real issuer, client id or scope list, and an escaped
# surprise is still a surprise.
for value in "$issuer" "$client_id" "$scopes" "$extra_origins"; do
    case "$value" in
        *[\"\\\;]*)
            refuse "CARNET_OIDC_* values may not contain quotes, backslashes or" \
                "semicolons; got: $value"
            ;;
    esac
    # Control characters (a newline in a YAML block scalar is the reachable one) would
    # break the JSON string outright. Command substitution strips trailing newlines
    # from the result, so an added-or-removed control character shows up as a
    # difference either way.
    if [ "$(printf '%s' "$value" | tr -d '\001-\037')" != "$value" ]; then
        refuse "CARNET_OIDC_* values may not contain control characters."
    fi
done
case "$issuer$client_id" in
    *[[:space:]]*)
        refuse "CARNET_OIDC_ISSUER and CARNET_OIDC_CLIENT_ID may not contain" \
            "whitespace."
        ;;
esac
# A `*` in the issuer is the shape of somebody pasting a CSP source where a URL goes
# (`https://*.okta.com` was literally the directive this step deleted). It cannot be
# fetched for discovery, so it would fail in the browser with a network error; here
# it is one sentence.
case "$issuer$client_id" in
    *\**)
        refuse "CARNET_OIDC_ISSUER and CARNET_OIDC_CLIENT_ID may not contain '*'." \
            "The issuer is the provider's issuer URL, not a CSP source pattern."
        ;;
esac

origins=""
if [ -n "$issuer" ]; then
    case "$issuer" in
        http://* | https://*) ;;
        *) refuse "CARNET_OIDC_ISSUER must be an http(s) URL, got: $issuer" ;;
    esac
    # The CSP names ORIGINS (scheme://host[:port]); the issuer may carry a path
    # (Okta's custom authorization servers, Entra's tenant segment, Keycloak's realm).
    # Asking the deployer for both the issuer and its origin would be two places to
    # disagree, so the origin is derived — which is also why the e2e declares an
    # issuer that HAS a path, so this line is actually exercised.
    origin=$(printf '%s' "$issuer" | sed -E 's|^(https?://[^/]+).*$|\1|')
    origins=" $origin"

    # Every extra origin must look like one. This refuses the foot-gun (`*`, which
    # would open connect-src entirely) and the near-misses (a bare hostname, a
    # `data:`) while still allowing the deliberate `https://*.example.com`.
    for extra in $extra_origins; do
        case "$extra" in
            http://*|https://*)
                # After the scheme, an origin is a host and nothing else. Compare
                # what follows `://` — `*/*/*` against the whole string is the
                # obvious spelling and is wrong, because `https://` supplies two
                # slashes by itself, which refused every valid origin. One trailing
                # slash is forgiven; anything more is a path, and a path in a CSP
                # source means something different from what the deployer meant.
                rest=${extra#*://}
                case "${rest%/}" in
                    */*) refuse "CARNET_OIDC_EXTRA_ORIGINS takes origins, not" \
                        "URLs with a path; got: $extra" ;;
                esac
                origins="$origins ${extra%/}"
                ;;
            *)
                refuse "each entry in CARNET_OIDC_EXTRA_ORIGINS must be an http(s)" \
                    "origin like https://oauth2.googleapis.com; got: $extra"
                ;;
        esac
    done

    printf '{"issuer": "%s", "client_id": "%s", "scopes": "%s"}\n' \
        "$issuer" "$client_id" "$scopes" >/srv/config.json
elif [ "$idp" = bundled ]; then
    # The bundled provider's own /config.json, and it carries NO origin: the issuer is
    # origin-relative, so the SPA fetches {origin}/idp/.well-known/openid-configuration
    # and every request it makes is already covered by `connect-src 'self'`. That is
    # why this branch leaves `origins` empty and the CSP below is byte-for-byte the
    # unconfigured one — one origin is the load-bearing decision, inherited from
    # `carnet --local` (localidp/edge.py).
    #
    # **These three values are a copy of `localidp/provider.config_json()`**, which a
    # shell script cannot import. `test_the_front_door_and_the_provider_agree` compares
    # them, so the copy cannot drift without the suite saying so.
    printf '{"issuer": "/idp", "client_id": "carnet-local", "scopes": "openid profile email"}\n' \
        >/srv/config.json
else
    rm -f /srv/config.json
fi

# The third artifact (step 121): whether /idp/* reaches a provider. Written in both
# cases — empty under `external` — because the Caddyfile imports it unconditionally,
# and an import of a file that may or may not exist is a front door whose routing
# table depends on whether a previous boot happened to write one.
if [ "$idp" = bundled ]; then
    # Before the SPA fallback, for /config.json's reason: answered by the fallback
    # these would be index.html with a 200, and the sign-in flow would read an HTML
    # page as a discovery document.
    cat >"$IDP_ROUTE" <<'CADDY'
handle /idp/* {
	reverse_proxy idp:8080
}
CADDY
else
    # **A real 404, not an empty file** (found by the step's own audit). `/idp/*` is a
    # server namespace and never an app route, so with nothing written here the SPA
    # fallback answered `/idp/login` with index.html and a 200 — the same masking this
    # Caddyfile calls out by name for /config.json and /assets/*, and the shape that
    # once shipped a deployment nobody could sign into. A deployment that brought its
    # own provider says so plainly instead.
    cat >"$IDP_ROUTE" <<'CADDY'
handle /idp/* {
	respond "this deployment uses its own identity provider; nothing is bundled here" 404
}
CADDY
fi

# The whole policy, in one place. The bundle's meta tag carries the provider-
# independent directives too (script-src above all), and the browser enforces the
# INTERSECTION of the two — so this header must restate them, and may never be weaker
# than intended, only the meta's equal plus the provider-dependent pair.
#
# frame-ancestors 'self', NOT 'none': silent renewal is the provider's authorize URL
# in a hidden iframe whose last hop redirects back to /login/callback — this app
# framed by this app. 'none' blocks that and every silent re-entry with it, found by
# a real browser in e2e_browser_local.py. Framing by any OTHER origin stays blocked.
CARNET_CSP="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'${origins}; frame-src 'self'${origins}; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'self'"
export CARNET_CSP

# --- the certificate (step 109, decision 4) -------------------------------------------
#
# Three ways the front door gets its certificate, chosen by CARNET_TLS_MODE, and the
# Caddyfile's `{$CARNET_TLS}` line is where the choice lands — composed here, beside
# the CSP, for the same reason: the Caddyfile stays declarative and this script is
# the whole surface to audit.
#
#   acme (default)  what this file has always done: a real name gets a public
#                   certificate via ACME; `localhost` is signed by Caddy's own CA
#   internal        Caddy's own CA for ANY name — a trial, or a name Let's Encrypt
#                   cannot see, such as an intranet name behind a firewall
#   files           a certificate somebody else issued — the company's own CA. Mount
#                   the pair at /etc/carnet/tls/{cert,key}.pem (compose.yaml has the
#                   commented volume) and it is served as-is; ACME is never attempted
#
# `files` without the files is refused here, naming the mount, rather than by Caddy
# a few seconds later with a Go error about an open() — the half-declared-provider
# rule above. What this script cannot check is that the certificate names
# CARNET_DOMAIN: a mismatch is not a start failure but a handshake failure, which
# the browser reports.
tls_mode="${CARNET_TLS_MODE:-acme}"
case "$tls_mode" in
    acme)
        # Step 121. `acme` is the default and it cannot work for a name Let's Encrypt
        # will not issue for: an IP address, or a single-label hostname. Caddy handles
        # `localhost` and `*.localhost` with its own CA and those stay legal, which is
        # what the documented trial rests on.
        #
        # Refused here rather than endured, because the failure otherwise is the least
        # legible in the whole stack: the front door comes up, serves nothing usable,
        # and spends minutes retrying an ACME challenge in a log nobody is reading —
        # while the browser shows a connection error that names no cause. One sentence
        # at start, and the remedy is one word in .env. `deploy/setup.sh` picks the
        # right mode by itself, so this is for a file somebody edited by hand.
        case "${CARNET_DOMAIN:-}" in
            localhost | *.localhost) ;;
            *[!0-9.]*)
                case "${CARNET_DOMAIN:-}" in
                    *.*) ;;
                    *)
                        refuse "CARNET_TLS_MODE is acme (the default) but" \
                            "CARNET_DOMAIN is '${CARNET_DOMAIN:-}', which is a" \
                            "single-label name Let's Encrypt cannot issue for." \
                            "Set CARNET_TLS_MODE=internal for Caddy's own CA, or" \
                            "files for a certificate you mount."
                        ;;
                esac
                ;;
            "")
                refuse "CARNET_DOMAIN is empty, so there is no name to get a" \
                    "certificate for."
                ;;
            *)
                refuse "CARNET_TLS_MODE is acme (the default) but CARNET_DOMAIN is" \
                    "'${CARNET_DOMAIN}', an address rather than a name — ACME" \
                    "issues for names, and the challenge would never arrive. Set" \
                    "CARNET_TLS_MODE=internal for Caddy's own CA, or files for a" \
                    "certificate you mount."
                ;;
        esac
        CARNET_TLS=""
        ;;
    internal) CARNET_TLS="tls internal" ;;
    files)
        for f in /etc/carnet/tls/cert.pem /etc/carnet/tls/key.pem; do
            [ -r "$f" ] || refuse "CARNET_TLS_MODE=files but $f is not readable." \
                "Mount the certificate and key at /etc/carnet/tls/cert.pem and" \
                "/etc/carnet/tls/key.pem (the commented volume on the front service" \
                "in compose.yaml), or choose acme or internal."
        done
        CARNET_TLS="tls /etc/carnet/tls/cert.pem /etc/carnet/tls/key.pem"
        ;;
    *)
        refuse "CARNET_TLS_MODE must be acme, internal or files, not '$tls_mode'." \
            "acme is a public certificate for a public name (the default); internal" \
            "is Caddy's own CA for any name; files is a certificate you mount."
        ;;
esac
export CARNET_TLS

# The image's own command, not a copy of it. Hardcoding `caddy run …` here worked and
# was wrong in a way worth stating: it made the container ignore its CMD, so
# `docker run carnet-front caddy version` silently started a web server instead —
# and any future `command:` in compose.yaml would have been read by nobody.
exec "$@"
