#!/bin/sh
# The far side's check on a carried-in bundle (plan 109, decision 6). POSIX sh, because
# the machine this runs on is the one nobody can install anything on.
#
#     ./verify.sh            before `docker load`: every file is the file that was checked
#     ./verify.sh --loaded   after it: the images Docker now holds are the ones in MANIFEST
#
# What the first proves: the bytes on this disk are the bytes SHA256SUMS was written over
# on the connected side. Pair it with the tarball's own sha256, recorded there and
# carried in separately, and you know the tarball was not altered on the way. What it
# does NOT prove is who built them — that is the cosign signature on the published
# image, which needs Fulcio and Rekor and cannot be checked here. docs/OFFLINE.md says
# how much this is worth, and it is less than a signature.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here" || exit 1

fail=0
# `-c` and nothing else. BusyBox's sha256sum has no `--quiet` and neither does every
# shasum, and this runs on whatever the far side happens to have — so the quiet is done
# here, by printing only the lines that are not `: OK`, which every implementation of
# `-c` writes the same way.
if command -v sha256sum >/dev/null 2>&1; then
  sums() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
  sums() { shasum -a 256 "$@"; }
else
  echo "verify.sh: neither sha256sum nor shasum is available" >&2
  exit 2
fi

if [ "${1:-}" != "--loaded" ]; then
  [ -f SHA256SUMS ] || { echo "verify.sh: no SHA256SUMS beside this script" >&2; exit 2; }
  if checked="$(sums -c SHA256SUMS 2>&1)"; then
    echo "ok    every file matches SHA256SUMS ($(wc -l < SHA256SUMS | tr -d ' ') files)"
  else
    echo "FAIL  a file does not match SHA256SUMS — do not load this bundle" >&2
    echo "$checked" | grep -v ': OK$' >&2
    fail=1
  fi
  # Everything the tarball promises to carry, present.
  for f in images.tar.gz MANIFEST deploy/compose.yaml deploy/.env.example docs/OFFLINE.md; do
    if [ -f "$f" ]; then echo "ok    $f"; else echo "FAIL  $f is missing" >&2; fail=1; fi
  done
  exit $fail
fi

# --loaded: compare what Docker holds against MANIFEST, by layer list. The image id is
# deliberately not compared — MANIFEST says why (the two image stores name an image by
# different digests of the same bytes); the layers are the same in both.
command -v docker >/dev/null 2>&1 || { echo "verify.sh: docker is not on PATH" >&2; exit 2; }

# The architecture, first, because it is the failure with the worst shape: an image
# saved on an arm64 laptop loads perfectly onto an amd64 server and then exits with
# `exec format error`, on a machine that cannot pull the right one. One sentence here
# beats that, and the remedy is on the other side of the airlock.
want_platform="$(awk '/^platform: / {print $2}' MANIFEST)"
have_platform="$(docker version --format '{{.Server.Os}}-{{.Server.Arch}}' 2>/dev/null)"
if [ -n "$want_platform" ] && [ -n "$have_platform" ] && [ "$want_platform" != "$have_platform" ]; then
  echo "FAIL  this bundle is $want_platform and this machine runs $have_platform." >&2
  echo "      The images would load and then fail with 'exec format error'. Build the" >&2
  echo "      bundle again on the connected side with:" >&2
  echo "          backend/scripts/offline_bundle.sh --platform ${have_platform%%-*}/${have_platform#*-}" >&2
  fail=1
elif [ -n "$want_platform" ]; then
  echo "ok    the bundle is $want_platform and so is this machine"
fi

# Can the container runtime actually READ this bundle from where you put it? On Linux
# this is always yes. On Docker Desktop it is no unless the path is one of its shared
# folders, and the way that fails is the worst kind: the bind mounts arrive EMPTY, so
# the bundled database never runs its init script, the app role is never created, and
# the only thing anybody sees is `migrate` exiting with `password authentication failed
# for user "carnet_app"` — a sentence about a password, on a machine with no internet
# to search from. Asked here, with the image just loaded, against the bundle's own file.
probe="$(docker run --rm -v "$here/deploy/initdb:/probe:ro" carnet-api ls /probe 2>/dev/null)"
case "$probe" in
  *01-app-role.sh*)
    echo "ok    the container runtime can read this bundle from $here" ;;
  *)
    echo "FAIL  the container runtime cannot read this bundle's files from $here." >&2
    echo "      A bind mount from here arrives EMPTY, so the bundled database will" >&2
    echo "      never create its app role and 'migrate' will exit with:" >&2
    echo "          password authentication failed for user \"carnet_app\"" >&2
    echo "      Move the bundle under a path your container runtime shares and run" >&2
    echo "      this again. Docker Desktop: Settings, Resources, File Sharing." >&2
    fail=1 ;;
esac

for image in carnet-api:latest carnet-front:latest postgres:16; do
  want="$(awk -v img="  $image" '$0 == img {found=1; next} found && /layers:/ {sub(/^ *layers: */, ""); print; exit}' MANIFEST)"
  if [ -z "$want" ]; then
    echo "FAIL  MANIFEST has no layer list for $image" >&2; fail=1; continue
  fi
  got="$(docker image inspect --format '{{join .RootFS.Layers " "}}' "$image" 2>/dev/null)"
  if [ -z "$got" ]; then
    echo "FAIL  $image is not loaded (docker load -i images.tar.gz)" >&2; fail=1
  elif [ "$got" = "$want" ]; then
    echo "ok    $image is the image in MANIFEST"
  else
    echo "FAIL  $image is loaded but its layers are not MANIFEST's" >&2; fail=1
  fi
done
exit $fail
