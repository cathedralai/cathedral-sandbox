#!/usr/bin/env bash
# Renew the signed sealed hotel list (AB#800 PLAN step 0, SPEC 5.7).
#
# One run: sign the next cathedral_sealed_hotels_v1 release with
# scripts/cathedral_sealed_hotels_publish.py (release number = recorded + 1 from
# the durable publisher state), verify it with the standalone customer verifier
# room-kit/verify_sealed_hotels.py (built-in pins, expected digest, successor of
# the recorded release), then store the exact signed bytes in Cloudflare Workers
# KV under key sealed_hotels_current (the namespace the site Worker binds as
# SEALED_HOTELS_STORE) and read them back.
#
# Runs on the host that holds the signing key. The release is a key custody
# action: install the timer only on that host, by its custodians.
#
# Configuration (environment, normally /etc/cathedral/sealed-hotels-renew.env):
#   SEALED_HOTELS_SIGNER_CONFIG   signer config (signers.json), required
#   SEALED_HOTELS_INVENTORY       reviewed hotel inventory JSON, required
#   SEALED_HOTELS_PURPOSE         signer purpose (default sealed_hotels)
#   SEALED_HOTELS_PINS            publisher pin file (default docs/keys/sealed-hotels-pins.json)
#   SEALED_HOTELS_VERIFY_PINS     verifier pin file (default: the verifier's built-in pins)
#   SEALED_HOTELS_STATE           publisher state (default /var/lib/cathedral-sealed-hotels/publisher-state.json)
#   SEALED_HOTELS_OUT_DIR         release output dir (default /var/lib/cathedral-sealed-hotels/releases)
#   SEALED_HOTELS_LIFETIME_HOURS  valid_until - generated_at (default 24)
#   CLOUDFLARE_ACCOUNT_ID         account that owns the KV namespace
#   SEALED_HOTELS_KV_NAMESPACE_ID namespace id bound as SEALED_HOTELS_STORE
#   CLOUDFLARE_API_TOKEN_FILE     file holding an API token with Workers KV Storage:Edit
#   CLOUDFLARE_API_BASE           (default https://api.cloudflare.com/client/v4)
#   PYTHON                        interpreter with the cryptography package (default python3)
#
# Usage: sealed-hotels-renew.sh [--no-upload]
#   --no-upload  sign and verify only (rehearsal). It still consumes a release number.
#
# The token is never printed, never put in argv or the environment of a child:
# curl reads the Authorization header from a config on its stdin.

set -euo pipefail
umask 077

readonly KV_KEY="sealed_hotels_current"
REPO_ROOT="${CATHEDRAL_SANDBOX_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PYTHON="${PYTHON:-python3}"
PUBLISHER="$REPO_ROOT/scripts/cathedral_sealed_hotels_publish.py"
VERIFIER="$REPO_ROOT/room-kit/verify_sealed_hotels.py"
PURPOSE="${SEALED_HOTELS_PURPOSE:-sealed_hotels}"
PINS="${SEALED_HOTELS_PINS:-$REPO_ROOT/docs/keys/sealed-hotels-pins.json}"
VERIFY_PINS="${SEALED_HOTELS_VERIFY_PINS:-}"
STATE="${SEALED_HOTELS_STATE:-/var/lib/cathedral-sealed-hotels/publisher-state.json}"
OUT_DIR="${SEALED_HOTELS_OUT_DIR:-/var/lib/cathedral-sealed-hotels/releases}"
LIFETIME_HOURS="${SEALED_HOTELS_LIFETIME_HOURS:-24}"
API_BASE="${CLOUDFLARE_API_BASE:-https://api.cloudflare.com/client/v4}"

log() { printf 'sealed-hotels-renew: %s\n' "$*" >&2; }
die() { log "refusing: $*"; exit 1; }

upload=1
case "${1:-}" in
  "") ;;
  --no-upload) upload=0 ;;
  *) die "unknown argument ${1}" ;;
esac
[ "$#" -le 1 ] || die "too many arguments"

[ -n "${SEALED_HOTELS_SIGNER_CONFIG:-}" ] || die "SEALED_HOTELS_SIGNER_CONFIG is not set"
[ -n "${SEALED_HOTELS_INVENTORY:-}" ] || die "SEALED_HOTELS_INVENTORY is not set"
[ -f "$PUBLISHER" ] && [ -f "$VERIFIER" ] || die "publisher or verifier missing under $REPO_ROOT"
[[ "$LIFETIME_HOURS" =~ ^[0-9]+$ ]] || die "SEALED_HOTELS_LIFETIME_HOURS is not a number"
# Never create state here: a lost state file must stop renewal, not restart at 1.
[ -f "$STATE" ] || die "no publisher state at $STATE; the first release is made by hand with --init-state"
mkdir -p "$OUT_DIR"

# Check the upload configuration before signing, so a broken setup does not burn
# release numbers every 6 hours.
token_file=""
if [ "$upload" = 1 ]; then
  for name in CLOUDFLARE_ACCOUNT_ID SEALED_HOTELS_KV_NAMESPACE_ID CLOUDFLARE_API_TOKEN_FILE; do
    [ -n "${!name:-}" ] || die "$name is not set (or pass --no-upload)"
  done
  [[ "$CLOUDFLARE_ACCOUNT_ID" =~ ^[0-9a-f]{32}$ ]] || die "CLOUDFLARE_ACCOUNT_ID is not a 32 hex id"
  [[ "$SEALED_HOTELS_KV_NAMESPACE_ID" =~ ^[0-9a-f]{32}$ ]] || die "SEALED_HOTELS_KV_NAMESPACE_ID is not a 32 hex id"
  token_file="$CLOUDFLARE_API_TOKEN_FILE"
  [ -f "$token_file" ] && [ ! -L "$token_file" ] || die "token file is not a regular file"
  [ -s "$token_file" ] || die "token file is empty"
  mode="$(stat -c '%a' "$token_file")"
  [ $((8#$mode & 8#077)) -eq 0 ] || die "token file must not be readable by group or others (mode $mode)"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

json_field() {
  # json_field FILE FIELD: print one top-level scalar from a JSON file.
  "$PYTHON" -I -c 'import json,sys; print(json.load(open(sys.argv[1], "rb"))[sys.argv[2]])' "$1" "$2"
}

previous_release="$(json_field "$STATE" last_release)"
previous_digest="$(json_field "$STATE" last_digest)"
expected_release=$((previous_release + 1))

# 1. Sign. The publisher holds the state lock, picks recorded + 1, verifies
# against the pin file and commits the high-water before writing the files.
"$PYTHON" -I "$PUBLISHER" \
  --signer-config "$SEALED_HOTELS_SIGNER_CONFIG" --purpose "$PURPOSE" \
  --pins "$PINS" --inventory "$SEALED_HOTELS_INVENTORY" \
  --state "$STATE" --out-dir "$OUT_DIR" \
  --lifetime-hours "$LIFETIME_HOURS" >"$work/publish.json"
release="$(json_field "$work/publish.json" release)"
digest="$(json_field "$work/publish.json" digest)"
release_file="$(json_field "$work/publish.json" release_file)"
[ "$release" = "$expected_release" ] || die "publisher made release $release, expected $expected_release"
log "signed release $release $digest"

# 2. Verify with the standalone customer verifier, as a client would.
verify_args=("$release_file" --expect-digest "$digest" --previous-release "$previous_release" --previous-digest "$previous_digest")
[ -z "$VERIFY_PINS" ] || verify_args+=(--pins "$VERIFY_PINS")
if ! "$PYTHON" -I "$VERIFIER" "${verify_args[@]}" >"$work/verify.txt"; then
  log "$(head -n 1 "$work/verify.txt")"
  die "release $release failed the standalone verifier; not uploaded"
fi
head -n 1 "$work/verify.txt" | grep -q '^PASS ' || die "verifier did not print PASS"
log "$(head -n 1 "$work/verify.txt")"

if [ "$upload" = 0 ]; then
  log "--no-upload: release $release left in $OUT_DIR"
  printf '{"release": %s, "digest": "%s", "uploaded": false}\n' "$release" "$digest"
  exit 0
fi

# 3. Upload to Workers KV and read back.
kv_url="$API_BASE/accounts/$CLOUDFLARE_ACCOUNT_ID/storage/kv/namespaces/$SEALED_HOTELS_KV_NAMESPACE_ID/values/$KV_KEY"

cf_curl() {
  # The header goes to curl through a config on stdin, so the token never
  # reaches argv (visible in ps) or this script's output.
  local token
  token="$(tr -d '\r\n' <"$token_file")"
  printf 'header = "Authorization: Bearer %s"\n' "$token" |
    curl --silent --show-error --config - --max-time 30 --retry 3 --retry-all-errors "$@"
}

# Never replace a newer or conflicting list (another signer, or restored state).
code="$(cf_curl --output "$work/current.json" --write-out '%{http_code}' "$kv_url")" || die "KV read failed"
case "$code" in
  200)
    if ! "$PYTHON" -I -c '
import hashlib, json, sys
data = open(sys.argv[1], "rb").read()
try:
    current = json.loads(data)["release"]
except Exception:
    sys.exit(0)  # not a signed list; the Worker ignores it too, so replace it
release, digest = int(sys.argv[2]), sys.argv[3]
if not isinstance(current, int) or isinstance(current, bool):
    sys.exit(0)
if current > release or (current == release and "sha256:" + hashlib.sha256(data).hexdigest() != digest):
    print(f"KV holds release {current}, not replacing it with release {release}", file=sys.stderr)
    sys.exit(1)
' "$work/current.json" "$release" "$digest"; then
      die "KV already holds a newer or conflicting release"
    fi
    ;;
  404) ;;
  *) die "KV read answered HTTP $code" ;;
esac

code="$(cf_curl --request PUT --header 'Content-Type: application/json' \
  --data-binary "@$release_file" --output "$work/put.json" --write-out '%{http_code}' "$kv_url")" || die "KV write failed"
[ "$code" = 200 ] || die "KV write answered HTTP $code"

# Verify the outcome, not the status code: the stored bytes must be the signed bytes.
want="${digest#sha256:}"
for attempt in 1 2 3 4 5 6; do
  code="$(cf_curl --output "$work/readback.json" --write-out '%{http_code}' "$kv_url")" || code=000
  if [ "$code" = 200 ] && [ "$(sha256sum "$work/readback.json" | cut -d' ' -f1)" = "$want" ]; then
    log "KV $KV_KEY holds release $release"
    printf '{"release": %s, "digest": "%s", "uploaded": true}\n' "$release" "$digest"
    exit 0
  fi
  [ "$attempt" = 6 ] || sleep "${SEALED_HOTELS_READBACK_DELAY:-10}"
done
die "KV readback does not match release $release (last HTTP $code)"
