# One Dockerfile, three targets, because the deployment is one codebase in three
# roles (plan 030, decision 2):
#
#   frontend-build   node builds the bundle; nothing from this stage ships directly
#   api              the Python runtime — run as the API or as `--migrate`,
#                    differing only in command (see compose.yaml)
#   front            the terminating proxy: Caddy, the bundle, the Caddyfile
#
# Build context is the repository root; every version here matches what CI actually
# tests (node 22, python 3.12, and compose.yaml's postgres:16).
#
# Every base image is pinned to its multi-arch index digest (step 055): a tag is a
# name somebody else can move, and two builds of one commit must not differ. The tag
# stays beside the digest so a reader sees what it was; moving a pin is a deliberate
# edit, taken with a fresh `docker buildx imagetools inspect <tag>`. Digests taken
# 2026-08-30.

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# `tsc -b` first, so a bundle that will not typecheck is an image that will not build.
RUN npm run build


FROM python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217 AS api
WORKDIR /app
# The dependencies come from the lock, first and alone (step 055): `--require-hashes`
# means a substituted or tampered wheel fails the build, and a layer that changes only
# when the lock changes is cache across every source edit. The lock is the serving
# extras — postgres, api, access — compiled for this image's Python; its own header
# carries the regeneration command. No dev, no lint: a deployment does not test itself.
COPY deploy/requirements.lock ./requirements.lock
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
# pyproject's version is dynamic (`carnet.__version__`), so the source must be
# present before pip can resolve the metadata.
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/src ./src
# `--no-deps` because everything carnet needs is already installed from the lock —
# and `pip check` is the sync guard: a dependency added to pyproject.toml without
# regenerating the lock fails HERE, with a sentence naming the unsatisfied
# requirement, rather than at a customer's first import.
RUN pip install --no-cache-dir --no-deps . && pip check

# An ordinary user, and /var/lib/carnet is CARNET_VAR_DIR — the one thing in
# var/ that is still a file (the outbox). compose.yaml mounts a volume there.
RUN useradd --system --home-dir /var/lib/carnet --create-home carnet
ENV CARNET_VAR_DIR=/var/lib/carnet
USER carnet

# The default command is the API. `--host 0.0.0.0` is honest here because only the
# front door publishes a port — this listens on the compose-internal network alone.
# `--root-path /api` matches the front door's rewrite, so /docs and openapi.json
# reference the only address a person can reach them at. No `--proxy-headers`, as a
# position: the API reads no forwarded header (plan 030, decision 5). No `--workers`:
# every ceiling in config.py is per process, and the README says so rather than
# multiplying it.
CMD ["uvicorn", "carnet.api:app", "--host", "0.0.0.0", "--port", "8000", \
     "--root-path", "/api"]


FROM caddy:2@sha256:df7f1c2fb114453b951de51a98efc010db1655a92c2e86be6706714e2417a78d AS front
COPY deploy/Caddyfile /etc/caddy/Caddyfile
# The boot step that turns CARNET_OIDC_* into /srv/config.json and the CSP header —
# one declaration, two artifacts, composed at container start so the image stays
# customer-agnostic (plan 031, decision 3). The entrypoint ends in `exec "$@"`, so a
# command given on the command line is honoured: `docker run carnet-front caddy
# version` asks caddy its version instead of silently starting a server.
#
# **CMD has to be restated here, and leaving it out is a silent crash loop.** Setting
# ENTRYPOINT in a Dockerfile *resets the base image's CMD to null* — so `"$@"` was
# empty, `exec` ran nothing, the container exited **0** with no output at all, and
# `restart: unless-stopped` did that forever. Nothing in the logs, a zero exit status,
# and `docker compose up` reporting success. This line is the whole fix, and it is the
# caddy:2 image's own command, restated.
COPY --chmod=755 deploy/frontdoor-entrypoint.sh /usr/local/bin/frontdoor-entrypoint
COPY --from=frontend-build /build/dist /srv
ENTRYPOINT ["/usr/local/bin/frontdoor-entrypoint"]
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
