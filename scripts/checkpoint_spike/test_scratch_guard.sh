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
for bad in "a/b" ".." "." "" "/etc"; do
  if ckspike_require_name "$bad" 2>/dev/null; then
    echo "expected '$bad' to be refused" >&2
    exit 1
  fi
done
ckspike_require_name "safe-name"
B=$(ckspike_under_root "$RUNS" "$RUNS/safe-name" "bundle")
[ "$B" = "$(cd "$RUNS" && pwd -P)/safe-name" ] || { echo "unexpected resolved path $B" >&2; exit 1; }

# Even if a caller bypassed the name check, under_root must refuse escape.
if B=$(ckspike_under_root "$RUNS" "$RUNS/../outside/existing" "bundle" 2>/dev/null); then
  echo "expected path escape to be refused, got $B" >&2
  exit 1
fi
[ -f "$OUTSIDE/existing/marker" ] || { echo "outside data was deleted" >&2; exit 1; }

# The real bench scripts (set -e) must refuse a traversal NAME before net setup or rm.
# Run them as separate processes: set -e is ignored inside an `if` condition.
for script in trial.sh variant.sh; do
  rc=0
  RUNS="$RUNS" IMGROOT="$RUNS" bash "$S/$script" "../outside/existing" 1 1 "" "" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] || { echo "$script: expected exit 2 for traversal NAME, got $rc" >&2; exit 1; }
done
[ -f "$OUTSIDE/existing/marker" ] || { echo "outside data was deleted by a bench script" >&2; exit 1; }

echo "ok scratch guard"
