#!/usr/bin/env bash
# The artefact a person carries in (plan 109, decision 6).
#
# A sealed estate — a bank, a defence contractor, a hospital — has no outbound path at
# all. Software arrives as a file. This script produces that file: one tarball holding
# the built images, the deployment directory and the documents the far side cannot go
# and read, with a manifest and checksums so whoever carries it in can say what it is.
#
# The insight that makes it cheap: the sealed estate does not need the BUILD to work
# offline. `npm ci` and `pip install` run inside the image, on this machine, where the
# internet is real. Ship the built image and neither registry is ever contacted again.
#
#     scripts/offline_bundle.sh [--platform linux/amd64] [--out DIR]
#
# Run it from a checkout on a machine with Docker and an internet connection. It builds
# the two images from THIS commit, pulls the pinned Postgres, and writes
# <out>/carnet-offline-<version>-<os>-<arch>.tar. The far side is `docs/OFFLINE.md`.
#
# --platform matters more than it looks. `docker save` writes the image this daemon
# holds, for this daemon's architecture. A laptop is arm64 and a bank's servers are
# amd64, so a bundle built on the laptop without this flag loads and then refuses to
# start with `exec format error` — on a machine where nobody can pull the right one.
# Pass the TARGET's platform; the build runs under emulation and is slow, and correct.
#
# CARNET_BASE_REGISTRY is honoured if set (decision 5): the bases come from your mirror.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
platform=""
out="$root/backend/var/offline"

while [ $# -gt 0 ]; do
  case "$1" in
    --platform) platform="${2:?--platform needs a value like linux/amd64}"; shift 2 ;;
    --out) out="${2:?--out needs a directory}"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "offline_bundle.sh: unknown argument '$1' (--platform, --out)" >&2; exit 2 ;;
  esac
done

say() { printf '\n=== %s\n' "$*" >&2; }
die() { echo "offline_bundle.sh: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is not on PATH"
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable"

# The version, the way check_versions.py reads it: one source of truth.
version="$(sed -nE 's/^__version__ = "([^"]+)"$/\1/p' "$root/backend/src/carnet/__init__.py")"
[ -n "$version" ] || die "could not read __version__ from backend/src/carnet/__init__.py"
commit="$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$root" status --porcelain 2>/dev/null)" ]; then
  commit="$commit (with uncommitted changes)"
fi

# The pinned database image, read from compose.yaml rather than typed here, so the
# bundle cannot carry a different Postgres from the one the compose file names.
db_ref="$(grep -oE 'postgres:16@sha256:[0-9a-f]{64}' "$root/deploy/compose.yaml" | head -1)"
[ -n "$db_ref" ] || die "could not find the pinned postgres:16 reference in deploy/compose.yaml"
db_tag="postgres:16"

# `${arr[@]+"${arr[@]}"}` below rather than "${arr[@]}": macOS ships bash 3.2, where an
# empty array is an unbound variable under `set -u`, and this runs on laptops.
platform_args=()
[ -n "$platform" ] && platform_args=(--platform "$platform")
registry_args=()
[ -n "${CARNET_BASE_REGISTRY:-}" ] && registry_args=(--build-arg "BASE_REGISTRY=$CARNET_BASE_REGISTRY")
db_pull="$db_ref"
if [ -n "${CARNET_BASE_REGISTRY:-}" ]; then
  db_pull="$CARNET_BASE_REGISTRY/library/$db_ref"
fi

say "building carnet-api and carnet-front from $commit${platform:+ for $platform}"
# Plain docker, not compose: compose interpolates the whole file and refuses without a
# CARNET_SECRET_KEY, and the bundle is built before any deployment's key exists.
docker build ${platform_args[@]+"${platform_args[@]}"} ${registry_args[@]+"${registry_args[@]}"} -q -t carnet-api --target api \
  -f "$root/deploy/Dockerfile" "$root" >/dev/null
docker build ${platform_args[@]+"${platform_args[@]}"} ${registry_args[@]+"${registry_args[@]}"} -q -t carnet-front --target front \
  -f "$root/deploy/Dockerfile" "$root" >/dev/null

say "pulling the pinned database image, $db_ref"
docker pull ${platform_args[@]+"${platform_args[@]}"} -q "$db_pull" >/dev/null
# Pulled by digest an image has no tag, and `docker save` of an untagged image loads
# as <none>. Tag it the way the far side's .env will name it: CARNET_DB_IMAGE=postgres:16.
docker tag "$db_pull" "$db_tag"

arch="$(docker image inspect --format '{{.Os}}-{{.Architecture}}' carnet-api)"
for image in carnet-front "$db_tag"; do
  got="$(docker image inspect --format '{{.Os}}-{{.Architecture}}' "$image")"
  [ "$got" = "$arch" ] || die "$image is $got but carnet-api is $arch; pass --platform so all three agree"
done

name="carnet-offline-$version-$arch"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage"

say "saving the three images (this is most of the time and most of the size)"
docker save carnet-api:latest carnet-front:latest "$db_tag" | gzip -1 > "$stage/images.tar.gz"

say "copying the deployment and the documents"
mkdir -p "$stage/deploy/initdb" "$stage/docs"
# The deployment, by name rather than `cp -R deploy/.`: a working checkout's deploy/
# holds a live .env and whatever else somebody left beside it (the first run of this
# script carried a `.env.pre-carnet.bak` in), and a bundle is the one artefact that
# must contain nothing it cannot name. The compose file and its .env.example, the
# Caddyfile and the entrypoint (already inside the front image, kept so they can be
# read), the initdb script the bundled database runs, the Dockerfile and lock the images
# were built from, and the README.
for f in compose.yaml .env.example Caddyfile Dockerfile frontdoor-entrypoint.sh \
         README.md requirements.lock initdb/01-app-role.sh; do
  cp "$root/deploy/$f" "$stage/deploy/$f"
done
cp "$root/carnet.example.yaml" "$stage/"
# GUIDE.md too: the far side cannot open a browser and go and read it, and it is
# the document the operator needs on the hour after `up` — registering a
# connector, vetting a tool, brokering a model.
cp "$root/docs/OFFLINE.md" "$root/docs/UPGRADING.md" "$root/docs/GUIDE.md" "$stage/docs/"
cp "$root/LICENSE" "$root/NOTICE" "$stage/"
cp "$root/backend/scripts/offline_verify.sh" "$stage/verify.sh"
chmod 755 "$stage/verify.sh"

say "writing MANIFEST"
{
  echo "carnet offline bundle"
  echo
  echo "version:  $version"
  echo "commit:   $commit"
  echo "built:    $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "platform: $arch"
  echo "by:       $(git -C "$root" config user.name 2>/dev/null || whoami)"
  echo
  echo "images (in images.tar.gz; load with: docker load -i images.tar.gz)"
  echo
  # The layer list rather than the image id, because the id is not the same thing in
  # every Docker: the classic image store names an image by its config digest, the
  # containerd store by its manifest digest, so a bundle built on one and loaded on the
  # other would 'mismatch' while being the same bytes. The uncompressed layer digests
  # are content-addressed and identical in both. verify.sh --loaded compares them.
  for image in carnet-api:latest carnet-front:latest "$db_tag"; do
    echo "  $image"
    echo "    id:      $(docker image inspect --format '{{.Id}}' "$image")"
    echo "    layers:  $(docker image inspect --format '{{join .RootFS.Layers " "}}' "$image")"
  done
  echo
  echo "$db_tag is $db_ref as deploy/compose.yaml pins it. Set CARNET_DB_IMAGE=$db_tag in"
  echo ".env: whether that digest still names the image after 'docker load' depends on"
  echo "which image store your Docker runs, and the tag is in this tarball either way."
  echo
  echo "what this proves, and what it does not: SHA256SUMS says these bytes are the bytes"
  echo "that were checked on the connected side. It does not say who built them — that is"
  echo "what the cosign signature on the published image says, and it cannot be checked"
  echo "here. Verify there, record the tarball's own sha256, carry both in."
} > "$stage/MANIFEST"

say "writing SHA256SUMS"
(
  cd "$stage"
  if command -v sha256sum >/dev/null; then
    find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum
  else
    find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256
  fi
) > "$stage/SHA256SUMS"

say "the tarball"
tarball="$out/$name.tar"
rm -f "$tarball"
tar -C "$out" -cf "$tarball" "$name"
rm -rf "$stage"
if command -v sha256sum >/dev/null; then
  sum="$(sha256sum "$tarball" | cut -d' ' -f1)"
else
  sum="$(shasum -a 256 "$tarball" | cut -d' ' -f1)"
fi
size="$(du -h "$tarball" | cut -f1)"

cat >&2 <<EOF

  $tarball  ($size)
  sha256  $sum

Record that sha256 somewhere the far side can read it — a ticket, a signed email — and
carry the tarball in. On the far side: docs/OFFLINE.md, inside the tarball.
EOF
echo "$tarball"
