#!/usr/bin/env bash
# What a stranger's `docker run` can get wrong about the front-door image, asked of one
# image reference. Step 110 decision 11, extracted from `release.yml` in the pass after
# 110f so that the check CI runs and the check a person can run before a release are the
# same file rather than two that drift.
#
#   deploy/smoke-front.sh ghcr.io/carnet-mcp/carnet-front:latest   # a published image
#   deploy/smoke-front.sh carnet-front:local                       # one built here
#
# It proves the things that are true of the **image alone**: that the entrypoint hands
# off to its command, that it refuses half a provider by name rather than starting with
# a broken policy, that it serves the bundle over TLS from a certificate it made itself,
# with the policy the entrypoint composed, and that an unconfigured `/config.json` is a
# real 404 rather than `index.html` with a 200 — the Caddyfile's own defect story.
#
# What it deliberately does not prove is anything needing an API behind it: the `/api`
# rewrite, the provider in the CSP, a browser signing in. That is `e2e_deploy.py`'s, on
# the same Dockerfile target, on every pull request.
#
# The registry half — that the package is public and the pull is anonymous — belongs to
# the caller: `release.yml` does `docker logout` and pulls before calling this.
set -euo pipefail

REF="${1:?usage: smoke-front.sh <image ref>}"
PORT="${SMOKE_PORT:-8443}"
NAME="carnet-front-smoke-$$"
failed=0

ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; failed=1; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

printf '== the entrypoint hands off to the command it is given\n'
# The Dockerfile's own warning: an ENTRYPOINT that swallowed CMD once made this
# container exit 0 forever in a restart loop. `caddy version` proves the hand-off in one
# line, before a server is started.
if docker run --rm "$REF" caddy version >/dev/null 2>&1; then
  ok "caddy version runs"
else
  bad "the entrypoint swallowed its command"
fi

printf '== it refuses half a provider, by name\n'
if out=$(docker run --rm -e CARNET_OIDC_ISSUER=https://idp.example.com "$REF" caddy version 2>&1); then
  bad "an issuer without a client id started the front door"
  printf '%s\n' "$out"
elif printf '%s' "$out" | grep -q "CARNET_OIDC_CLIENT_ID"; then
  ok "refused, naming CARNET_OIDC_CLIENT_ID"
else
  bad "it refused without naming the missing variable"
  printf '%s\n' "$out"
fi

printf '== it serves the bundle over TLS, with the policy the entrypoint composed\n'
docker run -d --name "$NAME" -p "${PORT}:443" \
  -e CARNET_DOMAIN=localhost -e CARNET_TLS_MODE=internal "$REF" >/dev/null
for _ in $(seq 1 30); do
  curl -ksS -o /dev/null "https://localhost:${PORT}/" 2>/dev/null && break || sleep 1
done

headers="$(mktemp)"; index="$(mktemp)"
curl -ksS -D "$headers" -o "$index" "https://localhost:${PORT}/" || true
grep -qi '<script' "$index" && ok "the bundle is served" || { bad "/ did not serve the bundle"; docker logs "$NAME" 2>&1 | tail -20; }
grep -qi "content-security-policy: default-src 'self'; script-src 'self'" "$headers" \
  && ok "the CSP header is the one the entrypoint composes" \
  || { bad "the CSP header is missing or not the composed one"; grep -i content-security "$headers" || true; }

for path in /config.json /assets/does-not-exist.js; do
  code=$(curl -ksS -o /dev/null -w '%{http_code}' "https://localhost:${PORT}${path}")
  [ "$code" = "404" ] && ok "${path} is a real 404" || bad "${path} answered ${code}, expected 404"
done

[ "$failed" = 0 ] && printf '\nthe front door serves the bundle, the policy and honest 404s: ok\n' \
                  || printf '\nthe front-door image is not what it should be\n'
exit "$failed"
