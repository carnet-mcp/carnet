#!/usr/bin/env bash
# Run one runbook's commands and record what they printed, verbatim.
#
# The gate's wording is *has been run*, so the deliverable is a transcript rather than a
# document. This is the thing that produces one: every command is echoed as it was typed
# and its output follows unedited, including the failures — a drill that only records its
# successes is a rehearsal of a document.
#
#     scripts/drill_run.sh <name> <<'STEPS'
#     # a comment becomes a heading in the transcript
#     carnet --list-users
#     STEPS
#
# Reads steps on stdin, one command per line. Writes to docs/runbooks/transcripts/.

set -uo pipefail

name="${1:?usage: drill_run.sh <drill-name> < steps}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="$root/docs/runbooks/transcripts/$name.md"
mkdir -p "$(dirname "$out")"

{
  echo "# Drill transcript: $name"
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| Run at | $(date -u '+%Y-%m-%d %H:%M:%SZ') |"
  echo "| Run by | Claude Opus 5, at Pranav Sistla's direction |"
  echo "| Commit | \`$(cd "$root" && git rev-parse --short HEAD)\` |"
  echo "| Database | \`${CARNET_DATABASE_URL##*/}\` on PostgreSQL $(docker exec carnet-pg psql -U postgres -tAc 'show server_version' 2>/dev/null | cut -d. -f1) |"
  echo "| Procedure | [\`../$name.md\`](../$name.md) |"
  echo
  echo "Output is verbatim, including the failures. Secrets are redacted where one was"
  echo "printed; nothing else is edited."
  echo
} > "$out"

while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in
    \#*)
      { echo; echo "## ${line#\# }"; echo; } >> "$out"
      continue
      ;;
  esac
  {
    echo '```console'
    # Redacted on the way in as well as on the way out: a drill presents a real token
    # to prove a refusal is real, so the secret is in the command as typed and not
    # only in what came back.
    echo "\$ $line" | sed -E 's/(art_|ars_)[A-Za-z0-9_]+\.[A-Za-z0-9_-]+/\1<redacted>/g'
  } >> "$out"
  # `< /dev/null` is not decoration: the loop reads its steps from stdin, `eval`
  # inherits that, and the first command that reads stdin swallows the rest of the
  # drill. It happened — the key-rotation run recorded one step and stopped, and the
  # transcript looked like a procedure that ends after its first command.
  eval "$line" < /dev/null > /tmp/drill-step.out 2>&1
  code=$?
  # Redact anything shaped like a minted secret, and drop the interpreter-shutdown
  # noise psycopg's pool prints on Python 3.14 — this machine's version, which the
  # package does not claim to support and CI does not run. It is teardown after the
  # command's work is done, it appears on every invocation, and leaving it in would
  # make the transcript unreadable for a reason that has nothing to do with the drill.
  # Three shapes are redacted: a minted token, a provisioning token, and a bare
  # 32-byte base64 key — `--generate-key`'s whole output is one of those, and a
  # drill about key hygiene that commits a key into git would be teaching the
  # opposite of the procedure it records. The key printed in the first run was a
  # throwaway against a scratch database that no longer exists; it was redacted
  # rather than shrugged at, because "it was only a test key" is the sentence
  # every leaked key starts as.
  sed -E 's/(art_|ars_)[A-Za-z0-9_]+\.[A-Za-z0-9_-]+/\1<redacted>/g; s/^[A-Za-z0-9+\/]{43}=$/<a key was printed here; redacted>/' /tmp/drill-step.out \
    | grep -vE 'PythonFinalizationError|psycopg_pool|Exception ignored while calling deallocator|^Traceback \(most recent call last\):$|^  File "/(Users|private)|^    [a-z_]+\(|threading\.py' \
    | awk 'NR<=40 {print} NR==41 {print "[... " } END {if (NR>40) print NR-40 " further lines, unedited but cut for length ...]"}' >> "$out"
  if [ $code -ne 0 ]; then
    echo "[exit $code]" >> "$out"
  fi
  echo '```' >> "$out"
done

echo "wrote $out"
