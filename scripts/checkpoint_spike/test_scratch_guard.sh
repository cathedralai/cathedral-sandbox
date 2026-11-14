#!/bin/bash
# Harmless temp-directory regression for NAME traversal (AB#672).
set -eu
S=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scratch.sh
. "$S/scratch.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
RUNS="$TMP/runs"
OUTSIDE="$TMP/outside"
mkdir -p "$RUNS" "$OUTSIDE/existing"
echo keep > "$OUTSIDE/existing/marker"

# Traversal names must be refused before any rm.
if ckspike_require_name "../existing" 2>/dev/null; then
  echo "expected ../existing to be refused" >&2
  exit 1
fi
if ckspike_require_name "a/b" 2>/dev/null; then
  echo "expected a/b to be refused" >&2
  exit 1
fi
ckspike_require_name "safe-name"

# Even if a caller bypassed the name check, under_root must refuse escape.
if B=$(ckspike_under_root "$RUNS" "$RUNS/../outside/existing" "bundle" 2>/dev/null); then
  echo "expected path escape to be refused, got $B" >&2
  exit 1
fi
[ -f "$OUTSIDE/existing/marker" ] || { echo "outside data was deleted" >&2; exit 1; }

echo "ok scratch guard"
