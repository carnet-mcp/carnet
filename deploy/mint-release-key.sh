#!/usr/bin/env bash
# The release-signing ceremony, as one command. Step 110 decision 10; written in the
# pass after 110f, where the three commands in `docs/OFFLINE.md` were run for the first
# time and turned out to be worth not retyping.
#
#   deploy/mint-release-key.sh ~/carnet-release.key
#
# It mints an ECDSA P-256 key, wraps the private half in PKCS#8 under a passphrase
# openssl prompts for, writes the public half to `deploy/carnet-release.pub`, and prints
# the fingerprint to paste into `docs/OFFLINE.md`. Nothing here reaches a network and
# nothing is committed for you.
#
# `CARNET_SIGN_PASSOUT` supplies the passphrase instead of the prompt — an openssl
# `-passout` spec such as `file:/path` or `pass:…`. It is `offline_bundle.sh`'s
# `CARNET_SIGN_PASSIN` on the other side of the same ceremony, and it exists for the
# same two callers: an unattended ceremony, and a rehearsal of this script that is not
# at a terminal. A real key's passphrase belongs at a prompt or in a file the shell
# history never sees.
#
# **Run it on a machine you trust, never in CI.** A signing key in a repository secret is
# a signing key a repository compromise yields, and cutting a bundle is already a human
# act on a connected laptop. Keep the private half where you keep the encryption key's
# backup, and nowhere else: `offline_bundle.sh` refuses to sign under any key whose
# public half is not the committed one, so losing this key means publishing a new public
# half and a sentence explaining why it changed — which is a thing your readers have to
# be told, not a thing they should discover.
set -euo pipefail

key="${1:?usage: mint-release-key.sh <path for the private key>   (e.g. ~/carnet-release.key)}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pub="$root/deploy/carnet-release.pub"

[ -e "$key" ] && { echo "refusing: $key already exists. Signing keys are not overwritten." >&2; exit 1; }
if [ -e "$pub" ]; then
  echo "refusing: $pub already exists." >&2
  echo "A second key is a rotation, and a rotation is a thing to announce rather than a" >&2
  echo "file to overwrite — the far side compares the fingerprint it is told with the one" >&2
  echo "verify.sh prints. Move the old one aside deliberately if that is what you mean." >&2
  exit 1
fi

umask 077
# Two steps rather than `-genkey -out`: the first emits a bare EC key and the second
# wraps it in PKCS#8 under a passphrase. A key at rest in the clear, even briefly on the
# way to being encrypted, is the thing worth avoiding — hence the pipe.
passout_args=()
[ -n "${CARNET_SIGN_PASSOUT:-}" ] && passout_args=(-passout "$CARNET_SIGN_PASSOUT")
openssl ecparam -genkey -name prime256v1 -noout |
  openssl pkcs8 -topk8 -v2 aes-256-cbc ${passout_args[@]+"${passout_args[@]}"} -out "$key"
chmod 600 "$key"

passin_args=()
[ -n "${CARNET_SIGN_PASSOUT:-}" ] && passin_args=(-passin "${CARNET_SIGN_PASSOUT/passout/passin}")
openssl pkey ${passin_args[@]+"${passin_args[@]}"} -in "$key" -pubout -out "$pub"
chmod 644 "$pub"
fingerprint="$(openssl pkey -pubin -in "$pub" -outform DER | openssl dgst -sha256 | sed 's/^.*= //')"

cat <<MESSAGE

Minted.

  private half   $key           (passphrase-protected; back it up where the encryption key's backup lives)
  public half    $pub           (commit this)
  fingerprint    $fingerprint

Two things left, and they are the ones that make the signature worth anything:

  1. Put that fingerprint in docs/OFFLINE.md, where "The published fingerprint" is, and
     commit it with the public half. The far side needs a place OUTSIDE the bundle to
     compare against; a fingerprint that only travels inside the thing it signs proves
     nothing.
  2. Cut a bundle with it and verify it somewhere else:

       backend/scripts/offline_bundle.sh --sign-key $key
       ./verify.sh          # on the far side; compare the fingerprint it prints

MESSAGE
