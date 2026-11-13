#!/usr/bin/env bash
# AB#546: refuse a broker whose catalog differs from the catalog on main.
#
# On 4 Nov a broker built from 0932838 (older than the #388 pins) was swapped in
# and direct template creates got the old LFM images. A swap runs this before it
# installs a binary (binary mode) and after the restart (readback mode).
#
#   broker_catalog_pin_check.sh binary   <sandbox-git-dir> <command...>
#       <command...> must print the new binary's digest, for example
#       `thin-broker.new -print-catalog-digest`, run locally or over ssh on the
#       broker host (a Linux binary does not run on a Mac). A binary older than
#       the flag exits 2 and is refused.
#   broker_catalog_pin_check.sh readback <sandbox-git-dir> <catalog.json>
#       <catalog.json> is a GET /v1/sandboxes/catalog response (trial port or
#       live). The digest is recomputed from it (format in broker/catalog_digest.go),
#       so this also works against a broker older than the flag.
#
# Expected digest: broker/catalog.digest on cathedral-sandbox main, read after a
# fetch that must succeed (a stale origin/main would pass an old catalog).
#
# Deliberate rollback to an older catalog: ALLOW_CATALOG_DIGEST=<sha256:...> names
# the one digest that may differ from main. Any other mismatch is refused.
#
# Exit: 0 pass, 1 refuse, 2 usage. Callers must stop on any non-zero exit.
set -uo pipefail

usage() { echo "usage: $0 binary <sandbox-git-dir> <command...> | readback <sandbox-git-dir> <catalog.json>" >&2; exit 2; }
say() { echo "catalog pin check: $*"; }
refuse() { echo "CATALOG PIN: REFUSE: $*"; exit 1; }
is_digest() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }

[ $# -ge 3 ] || usage
MODE=$1 REPO=$2; shift 2
case "$MODE" in binary|readback) ;; *) usage ;; esac
[ "$MODE" = readback ] && [ $# -ne 1 ] && usage
ALLOW=${ALLOW_CATALOG_DIGEST:-}
[ -z "$ALLOW" ] || is_digest "$ALLOW" || { echo "ALLOW_CATALOG_DIGEST must be sha256:<64 hex>" >&2; exit 2; }

# Expected: main's committed digest after a fresh fetch from the real repository.
url=$(git -C "$REPO" remote get-url origin 2>/dev/null) || refuse "$REPO has no origin remote"
[[ "$url" =~ [:/]cathedralai/cathedral-sandbox(\.git)?/?$ ]] || refuse "origin is $url, not cathedralai/cathedral-sandbox"
git -C "$REPO" fetch -q origin +refs/heads/main:refs/remotes/origin/main 2>&1 || refuse "could not fetch main; a stale origin/main could pass an old catalog"
MAIN_SHA=$(git -C "$REPO" rev-parse --short origin/main) || refuse "no origin/main"
EXPECTED=$(git -C "$REPO" show origin/main:broker/catalog.digest 2>/dev/null | tr -d '\r\n') || true
is_digest "$EXPECTED" || refuse "main $MAIN_SHA has no valid broker/catalog.digest"
say "main $MAIN_SHA catalog $EXPECTED"

if [ "$MODE" = binary ]; then
  out=$("$@" 2>/dev/null); rc=$?
  [ $rc -eq 0 ] || refuse "binary did not report a catalog digest (exit $rc): built before -print-catalog-digest, so older than AB#546, or not runnable here"
  [ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = 1 ] && is_digest "$out" || refuse "binary printed no digest: $(printf '%s' "$out" | head -c 120)"
  GOT=$out
else
  GOT=$(python3 -I - "$1" <<'PY'
import hashlib, json, sys
doc = json.load(open(sys.argv[1]))
templates = doc["templates"] if isinstance(doc, dict) else doc
def b(v):
    if not isinstance(v, bool): raise SystemExit("not a boolean: %r" % (v,))
    return "true" if v else "false"
def n(v):
    if not isinstance(v, int) or isinstance(v, bool): raise SystemExit("not an integer: %r" % (v,))
    return str(v)
lines = []
for t in templates:
    r = t["resources"]
    lines.append("\t".join([t["name"], t["image"], b(t["live"]), t["sealed"], b(t.get("sealed_only", False)),
                            n(r["cpu"]), n(r["memory_gib"]), n(t["disk_gib"])]) + "\n")
print("sha256:" + hashlib.sha256("".join(lines).encode()).hexdigest())
PY
  ) || refuse "could not read a catalog from $1"
  is_digest "$GOT" || refuse "could not read a catalog from $1"
fi
say "$MODE catalog $GOT"

if [ "$GOT" = "$EXPECTED" ]; then
  echo "CATALOG PIN: PASS $GOT matches main $MAIN_SHA"
  exit 0
fi
if [ -n "$ALLOW" ] && [ "$GOT" = "$ALLOW" ]; then
  echo "CATALOG PIN: PASS ROLLBACK: $GOT differs from main $MAIN_SHA ($EXPECTED) and is allowed by ALLOW_CATALOG_DIGEST"
  exit 0
fi
refuse "$GOT differs from main $MAIN_SHA ($EXPECTED)${ALLOW:+; ALLOW_CATALOG_DIGEST names $ALLOW}"
