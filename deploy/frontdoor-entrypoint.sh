#!/bin/sh
# The front door's boot: turn ONE provider declaration into the TWO things a browser
# needs to sign in, then hand off to the image's own command (plan 031, decision 3).
#
# The two things must never disagree — /config.json (which the app fetches at boot to
# find its provider) and the Content-Security-Policy header (which decides what the
# browser may connect to and frame). Deriving both here, from CARNET_OIDC_*, is what
# makes disagreement unrepresentable. The Caddyfile stays static and declarative; this
# script is the only place any logic lives, so it is the whole surface to audit.
#
# Unconfigured is not an error: day one runs `docker compose up` before a provider is
# decided, and a front door that refused to start until then would be the key
# generation's chicken-and-egg wearing new clothes. No issuer means no /config.json (a
# real 404 — the SPA fallback deliberately does not catch it) and a CSP of 'self'
# alone; the sign-in screen says what is missing. Anything OTHER than "all of it" or
# "none of it" is a refusal, loudly and by name: a half-declared provider is always a
# mistake, and serving anyway would fail later, quieter, and in a browser.
set -eu

issuer="${CARNET_OIDC_ISSUER:-}"
client_id="${CARNET_OIDC_CLIENT_ID:-}"
scopes="${CARNET_OIDC_SCOPES:-openid profile email}"
extra_origins="${CARNET_OIDC_EXTRA_ORIGINS:-}"

refuse() {
    echo "front door: $*" >&2
    exit 1
}

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
else
    rm -f /srv/config.json
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

# The image's own command, not a copy of it. Hardcoding `caddy run …` here worked and
# was wrong in a way worth stating: it made the container ignore its CMD, so
# `docker run carnet-front caddy version` silently started a web server instead —
# and any future `command:` in compose.yaml would have been read by nobody.
exec "$@"
