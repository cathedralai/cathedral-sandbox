#!/bin/bash
# One parameterised re-seal roll tool (AB#453). Replaces the per-roll copies of sealed_roll_<kit>.sh,
# stage-setup, stage-collect and pin-<kit>-patch.py. Logic is copied from the 12 and 13 Nov rolls.
#
#   roll.sh stage <commit> <hotel...>   build and measure the new image next to each hotel. No live change.
#   roll.sh pin-patch <commit>          write the add-only broker pin patch for the staged hotels.
#   roll.sh apply <hotel>               preflight, then drain, install, admit, undrain. Detached, resumable.
#   roll.sh status                      plans, state files, systemd units. Local only.
#
# apply refuses unless the site list AND the broker pins contain the new measurement and the hotel has
# 0 rooms. It never deletes a room. Any failure after the drain runs recovery: roll the host back if the
# new build is not good, wait until the broker admits a known build, undrain. Only when no build is
# admitted does the hotel stay drained (state stuck_drained, logged loudly).
#
# Config (env, no secrets in the repo; keys are read at runtime from these paths):
#   ROLL_HOME (default ~/.cathedral-roll)  plans, state, logs, evidence
#   ROLL_HOTELS_CONF                       hotel table (default hotels.conf next to this script, untracked; copy hotels.conf.example)
#   ROLL_OPERATOR_KEY_FILE                 broker operator key
#   ROLL_SSH_KEY                           ssh key for hotel and broker hosts
#   ROLL_GUARD                             const guard script; last output line must say GREEN
#   ROLL_BROKER_URL, ROLL_BROKER_HOST, ROLL_SITE_URL, ROLL_ESCAPE_OPEN_URL, ROLL_ATTEST_URL_BASE
#   ROLL_FOREGROUND=1                      do not detach with systemd-run (tests, debugging)
#   HOLD_DRAINED=1                         apply stops after admission, hotel left drained
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SELF="$HERE/$(basename "${BASH_SOURCE[0]}")"
ROLL_HOME=${ROLL_HOME:-$HOME/.cathedral-roll}
HOTELS_CONF=${ROLL_HOTELS_CONF:-$HERE/hotels.conf}
BROKER=${ROLL_BROKER_URL:-https://live.cathedral.computer}
BROKER_HOST=${ROLL_BROKER_HOST:-185.191.116.231}
SITE_URL=${ROLL_SITE_URL:-https://cathedral.computer/approved-measurements.json}
OPEN_URL=${ROLL_ESCAPE_OPEN_URL:-https://api.polaris.computer/v1/escape/open}
ATTEST_BASE=${ROLL_ATTEST_URL_BASE:-https://cathedral.computer/v1/hotels}
OPKEY_FILE=${ROLL_OPERATOR_KEY_FILE:-$HOME/Documents/TOOLS/.credentials/broker-operator-key}
SSH_KEY=${ROLL_SSH_KEY:-$HOME/.ssh/id_ed25519}
GUARD=${ROLL_GUARD:-$HOME/Documents/TOOLS/scripts/mrspock/const_guard.sh}
REPO=${ROLL_REPO:-cathedralai/cathedral-sandbox}
ADMIT_TIMEOUT=${ROLL_ADMIT_TIMEOUT:-600}
POLL=${ROLL_POLL_SLEEP:-15}
DRAIN_SETTLE=${ROLL_DRAIN_SETTLE:-5}
UNDRAIN_SETTLE=${ROLL_UNDRAIN_SETTLE:-20}
STAGE_TIMEOUT=${ROLL_STAGE_TIMEOUT:-2400}
PLANS=$ROLL_HOME/plans
STATE=$ROLL_HOME/state
LOG=$ROLL_HOME/roll.log
EVID=$ROLL_HOME/evidence
mkdir -p "$PLANS" "$STATE" "$EVID"

CTX=roll
TS=$(date -u +%Y%m%dT%H%M%SZ)
SSHO=(-F /dev/null -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -i "$SSH_KEY")

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [$CTX] $*" | tee -a "$LOG"; }
usage() { sed -n '2,12p' "$SELF" | sed 's/^# \{0,1\}//' >&2; exit 2; }
opkey() { tr -d '\n\r' < "$OPKEY_FILE"; }
valid_hotel() { [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]; }
valid_commit() { [[ "$1" =~ ^[0-9a-f]{7,40}$ ]]; }
valid_meas() { [[ "$1" =~ ^[0-9a-f]{96}$ ]]; }

require_conf() {
  [ -r "$HOTELS_CONF" ] || { echo "hotel table not found: $HOTELS_CONF. Copy ops/roll/hotels.conf.example to ops/roll/hotels.conf and fill in the real hosts, or set ROLL_HOTELS_CONF." >&2; exit 2; }
}

# hotels.conf lookup: sets HOST D FLAGS
hotel_conf() {
  local id h d f
  while read -r id h d f; do
    [ "$id" = "$1" ] || continue
    HOST=$h; D=$d; FLAGS=${f:--}; return 0
  done < <(grep -vE '^\s*(#|$)' "$HOTELS_CONF")
  return 1
}

# Key=value files, parsed not sourced.
kv_get() { sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -1; }
kv_set() {
  local f=$1 k=$2 v=$3
  touch "$f"
  grep -v "^$k=" "$f" > "$f.tmp" || true
  echo "$k=$v" >> "$f.tmp"; mv "$f.tmp" "$f"
}
plan_get() { kv_get "$PLANS/$HOTEL.env" "$1"; }
st_get() { kv_get "$STATE/$HOTEL.env" "$1"; }
st_set() { kv_set "$STATE/$HOTEL.env" "$1" "$2"; }

# ---- broker, hotel and public views (all reads, plus the drain PATCH) --------------------------
guard() {
  local out; out=$("$GUARD" 2>&1 | tail -1); log "const guard: $out"
  case "$out" in *GREEN*) return 0 ;; *) return 1 ;; esac
}
drain() {
  curl -s -m 20 -o /dev/null -w '%{http_code}' -X PATCH -H "Authorization: Bearer $(opkey)" \
    -H 'Content-Type: application/json' -d "{\"drain\": $1}" "$BROKER/v1/broker/hotels/$HOTEL"
}
# One line: up admission measurement drain slots free_rooms
hotel_state() {
  curl -s -m 20 -H "Authorization: Bearer $(opkey)" "$BROKER/v1/broker/capacity" | python3 -I -c '
import json, sys
try:
    h = [x for x in json.load(sys.stdin).get("hotels", []) if x.get("id") == sys.argv[1]]
except Exception:
    h = []
if not h: print("missing - - - - -"); sys.exit()
h = h[0]; a = h.get("admission") or {}
print(h.get("up"), a.get("state"), a.get("measurement") or "-", h.get("drain"), h.get("slots"), h.get("free_rooms"))' "$HOTEL"
}
# Live rooms from the hotel's own API (as install-sealed.sh counts them). Not free_rooms: a drained hotel reports 0.
rooms() {
  ssh -n "${SSHO[@]}" "root@$HOST" "$STAGE/post_hotel.sh $D /v1/sandboxes GET < /dev/null" 2>/dev/null | python3 -I -c '
import base64, json, sys
try:
    d = json.loads(sys.stdin.read().strip().splitlines()[-1])
    b = json.loads(base64.b64decode(d["body_b64"]))
    print(len(b.get("sandboxes", [])) if d["status"] == 200 else "?")
except Exception:
    print("?")'
}
# "<live_rooms> <max_rooms> <public_open>" from the public Escape Open endpoint.
escape_open() {
  curl -s -m 20 "$OPEN_URL" | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin); print(d.get("live_rooms"), d.get("max_rooms"), d.get("public_open"))
except Exception:
    print("? ? ?")'
}
broker_pins() {  # "<count> <cur in pins> <new in pins>"
  # shellcheck disable=SC2029  # CUR and NEW are validated 96-hex strings, expanded on purpose
  ssh "${SSHO[@]}" "root@$BROKER_HOST" "python3 -I -c 'import json;p=set(json.load(open(\"/etc/thin-broker/config.json\"))[\"sealed_measurements\"]);print(len(p), \"$CUR\" in p, \"$NEW\" in p)'" 2>&1
}
site_list() {  # "<rows> <cur on list> <new on list>"
  curl -s -m 20 "$SITE_URL" | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin); l = [r.get("measurement") for r in d.get("measurements", [])]
    print(len(l), sys.argv[1] in l, sys.argv[2] in l)
except Exception:
    print("? False False")' "$CUR" "$NEW"
}

# ---- host steps -------------------------------------------------------------------------------
host_check() {
  ssh "${SSHO[@]}" "root@$HOST" bash -s -- "$D" "$S" "$NEWIMG" "$KIT" "$UNIT" <<'REMOTE' 2>&1
D=$1 S=$2 NEWIMG=$3 KIT=$4 UNIT=$5
echo "current=$(readlink "$D/images/current") booted=$(readlink -f "$D/run/booted-image" | xargs basename) unit=$(systemctl is-active "$UNIT")"
I=$S/images/$NEWIMG
[ -d "$I" ] || { echo "STAGED_MISSING"; exit 0; }
python3 -I - "$I" <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]; m = json.load(open(os.path.join(d, "manifest.json")))
want = m.get("sha256") or {}
bad = [n for n in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst") if n not in want or
       hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest() != want[n]]
line = open(os.path.join(d, "cmdline"), "rb").read()
if want.get("cmdline") not in (hashlib.sha256(line).hexdigest(), hashlib.sha256(line.rstrip(b"\n")).hexdigest()):
    bad.append("cmdline")
print("staged files vs manifest:", "OK" if not bad else "BAD " + " ".join(bad))
PY
V=$(grep -E '^SEALED_VCPUS=' "$D/sealed.env" | cut -d= -f2); C=$(grep -E '^SEALED_CPU_MODEL=' "$D/sealed.env" | cut -d= -f2)
echo "remeasured=$("$D/venv/bin/sev-snp-measure" --mode snp --vcpus "$V" --vcpu-type "$C" --ovmf "$I/OVMF.amdsev.fd" --kernel "$I/vmlinuz" --initrd "$I/initrd.cpio.zst" --append "$(cat "$I/cmdline")")"
diff <(grep -vE '^SEALED_DIR=|^SEALED_ROOM_SEALED_(SECRETS|EXEC)=' "$D/sealed.env") <(grep -vE '^SEALED_DIR=|^SEALED_ROOM_SEALED_(SECRETS|EXEC)=' "$S/sealed.env") >/dev/null && echo "env: hotel and staged differ only in SEALED_DIR and the flags" || echo "env: HOTEL SETTINGS CHANGED SINCE STAGING"
echo "kit=$(git -C "$KIT/.." rev-parse --short=7 HEAD) clean=$([ -z "$(git -C "$KIT/.." status --porcelain)" ] && echo yes || echo no)"
REMOTE
}

# Copies the staged image in, sets the two sealed flags, runs install.sh. Rolls itself back on a failed install.
host_install() {
  ssh "${SSHO[@]}" "root@$HOST" bash -s -- "$D" "$S" "$NEWIMG" "$KIT" "$UNIT" "$OLDIMG" "$1" <<'REMOTE' 2>&1
D=$1 S=$2 NEWIMG=$3 KIT=$4 UNIT=$5 OLDIMG=$6 TS=$7
set -u
[ -e "$D/sealed.env.bak-$TS" ] || cp -a "$D/sealed.env" "$D/sealed.env.bak-$TS" || { echo "RESULT=nochange backup failed"; exit 0; }
for k in SEALED_ROOM_SEALED_SECRETS SEALED_ROOM_SEALED_EXEC; do
  if grep -q "^$k=" "$D/sealed.env"; then sed -i "s/^$k=.*/$k=1/" "$D/sealed.env"; else echo "$k=1" >> "$D/sealed.env"; fi
done
diff <(grep -vE '^SEALED_DIR=' "$D/sealed.env" | sort) <(grep -vE '^SEALED_DIR=' "$S/sealed.env" | sort) >/dev/null \
  || { cp -a "$D/sealed.env.bak-$TS" "$D/sealed.env"; echo "RESULT=nochange env differs from staged after the flags"; exit 0; }
[ -d "$D/images/$NEWIMG" ] || cp -a "$S/images/$NEWIMG" "$D/images/" || { cp -a "$D/sealed.env.bak-$TS" "$D/sealed.env"; echo "RESULT=nochange image copy failed"; exit 0; }
ln -sfn "$NEWIMG" "$D/images/current"
echo "current now $(readlink "$D/images/current")"
( cd "$KIT" && SEALED_SKIP_BUILD=1 ./install.sh --sealed "$D/sealed.env" ) > "/root/sealed-roll-$(basename "$D")-$TS.log" 2>&1
rc=$?
grep -E "expected measurement|measurement matches|MEASUREMENT DIFFERS|no attestation|guest stopped|live room" "/root/sealed-roll-$(basename "$D")-$TS.log" | cut -c1-200
if [ "$rc" = 0 ]; then echo "RESULT=installed"; exit 0; fi
echo "install exit $rc: rolling back to $OLDIMG"
ln -sfn "$OLDIMG" "$D/images/current"
cp -a "$D/sealed.env.bak-$TS" "$D/sealed.env"
systemctl restart "$UNIT"; sleep 5
echo "RESULT=rolledback unit=$(systemctl is-active "$UNIT") current=$(readlink "$D/images/current")"
REMOTE
}

# Idempotent: image back to OLDIMG, env back from the backup if one exists, restart the guest.
host_rollback() {
  ssh "${SSHO[@]}" "root@$HOST" bash -s -- "$D" "$UNIT" "$OLDIMG" "$1" <<'REMOTE' 2>&1
D=$1 UNIT=$2 OLDIMG=$3 TS=$4
ln -sfn "$OLDIMG" "$D/images/current"
[ -e "$D/sealed.env.bak-$TS" ] && cp -a "$D/sealed.env.bak-$TS" "$D/sealed.env"
systemctl restart "$UNIT"; sleep 5
echo "RESULT=rolledback unit=$(systemctl is-active "$UNIT") current=$(readlink "$D/images/current")"
REMOTE
}

# ---- recovery: never leave a hotel drained when a known build is admitted ------------------------
# wait_admitted <build...>: 0 once the broker shows the hotel up and admitted on one of them.
wait_admitted() {
  local deadline up adm meas dr sl fr b
  deadline=$(( $(date +%s) + ADMIT_TIMEOUT ))
  while :; do
    read -r up adm meas dr sl fr <<< "$(hotel_state)"
    for b in "$@"; do
      [ "$up" = True ] && [ "$adm" = admitted ] && [ "$meas" = "$b" ] && { ADMITTED_ON=$b; ADMITTED_SLOTS=$sl; return 0; }
    done
    [ "$(date +%s)" -lt "$deadline" ] || { log "not admitted in ${ADMIT_TIMEOUT}s (up=$up admission=$adm measurement=${meas:0:16})"; return 1; }
    log "waiting for the broker: up=$up admission=$adm measurement=${meas:0:16}"; sleep "$POLL"
  done
}
RECOVERING=0
recover() {
  [ $RECOVERING = 1 ] && return; RECOVERING=1
  local phase; phase=$(st_get PHASE)
  case "$phase" in
    drained|installing|installed|admitted) ;;
    *) return ;;  # nothing of ours is drained yet, or already undrained
  esac
  if [ "$phase" != drained ] && [ "$(st_get NEW_GOOD)" != 1 ] && [ "$(st_get HOST_ROLLED_BACK)" != 1 ]; then
    log "recovery: rolling the host back to $OLDIMG"
    host_rollback "$(st_get TS)" | while read -r l; do log "host: $l"; done
  fi
  if wait_admitted "$CUR" "$NEW"; then
    local code; code=$(drain false)
    if [ "$code" = 200 ]; then st_set PHASE rolled_back; log "recovery: undrained on ${ADMITTED_ON:0:16}"; return; fi
    log "recovery: undrain PATCH answered $code"
  fi
  st_set PHASE stuck_drained
  log "STUCK DRAINED: $HOTEL is drained and no known build is admitted. Inspect, then: roll.sh apply $HOTEL (resumes) or PATCH drain=false by hand"
}
die() { log "STOP: $*"; recover; exit 1; }
# Refusals before any change to the hotel: no recovery needed.
refuse() { log "REFUSE: $*"; exit 1; }

load_plan() {
  [ -f "$PLANS/$HOTEL.env" ] || { echo "no plan for $HOTEL: run roll.sh stage <commit> $HOTEL first" >&2; return 1; }
  hotel_conf "$HOTEL" || { echo "$HOTEL is not in $HOTELS_CONF" >&2; return 1; }
  COMMIT=$(plan_get COMMIT); STAGE=$(plan_get STAGE); NEWIMG=$(plan_get NEWIMG)
  CUR=$(plan_get CUR); NEW=$(plan_get NEW)
  valid_commit "$COMMIT" && valid_meas "$CUR" && valid_meas "$NEW" && [ -n "$STAGE" ] && [ -n "$NEWIMG" ] \
    || { echo "plan for $HOTEL is incomplete" >&2; return 1; }
  S=$STAGE/$HOTEL; KIT=$STAGE/kit/room-kit; UNIT=room-sealed-$HOTEL.service
}

# ---- apply ---------------------------------------------------------------------------------------
preflight() {  # fresh run only; read only
  guard || refuse "const guard not GREEN; change nothing"
  local up adm meas dr sl fr
  read -r up adm meas dr sl fr <<< "$(hotel_state)"
  R0=$(rooms)
  log "broker: up=$up admission=$adm measurement=${meas:0:16} drain=$dr slots=$sl free=$fr rooms=$R0"
  [ "$meas" = "$NEW" ] && refuse "the hotel already runs the new build; nothing to do"
  [ "$up" = True ] && [ "$adm" = admitted ] || refuse "the hotel is not up and admitted before the roll"
  [ "$meas" = "$CUR" ] || refuse "pin drift: the hotel runs ${meas:0:16}, the plan expects ${CUR:0:16}"
  local pins site
  pins=$(broker_pins); log "broker config pins (count, current, new): $pins"
  case "$pins" in *" True True") ;; *) refuse "the broker does not pin both builds yet (roll.sh pin-patch, then the broker swap)" ;; esac
  site=$(site_list); log "site approved list (rows, current, new): $site"
  case "$site" in *" True True") ;; *) refuse "the site list does not approve both builds yet" ;; esac
  [ "$R0" = 0 ] || refuse "$HOTEL has rooms=$R0; it must be 0"
  if [[ ",$FLAGS," == *,escape,* ]]; then
    local live maxr popen
    read -r live maxr popen <<< "$(escape_open)"
    log "contest: Escape Open live_rooms=$live max_rooms=$maxr public_open=$popen"
    [ "$live" = 0 ] || refuse "Escape Open live_rooms=$live; wait for the Open room to end"
    [ "$maxr" = 0 ] || refuse "Escape Open max_rooms=$maxr; set CATHEDRAL_ESCAPE_OPEN_MAX_ROOMS=0 on the API first (never CATHEDRAL_ESCAPE_OPEN=false)"
  fi
  local chk; chk=$(host_check)
  while read -r l; do log "host: $l"; done <<< "$chk"
  case "$chk" in *STAGED_MISSING*) refuse "staged image $NEWIMG is missing" ;; esac
  case "$chk" in *"staged files vs manifest: OK"*) ;; *) refuse "staged image files do not match their manifest" ;; esac
  case "$chk" in *"remeasured=$NEW"*) ;; *) refuse "the staged image no longer measures ${NEW:0:16}" ;; esac
  case "$chk" in *"env: hotel and staged differ only"*) ;; *) refuse "the hotel's sealed.env changed since staging; restage" ;; esac
  case "$chk" in *"kit=${COMMIT:0:7} clean=yes"*) ;; *) refuse "the staged kit is not a clean ${COMMIT:0:7}" ;; esac
  OLDIMG=$(sed -n 's/^current=\([^ ]*\) .*/\1/p' <<< "$chk")
  [ -n "$OLDIMG" ] || refuse "could not read images/current"
  st_set OLDIMG "$OLDIMG"
}

run_apply() {
  CTX="apply $HOTEL"
  exec 9>"$STATE/$HOTEL.lock"; flock -n 9 || { echo "another roll of $HOTEL is running" >&2; exit 1; }
  local phase; phase=$(st_get PHASE)
  case "$phase" in
    ""|done|aborted|rolled_back) [ -n "$phase" ] && mv "$STATE/$HOTEL.env" "$STATE/$HOTEL.env.prev-$TS"
      st_set PHASE preflight; st_set TS "$TS"; st_set COMMIT "$COMMIT"; st_set STARTED "$TS"
      log "start: image $NEWIMG, current ${CUR:0:16}, new ${NEW:0:16}"
      preflight; st_set PHASE preflight_ok; phase=preflight_ok ;;
    preflight|preflight_ok) st_set TS "$TS"; log "restart after an interrupted preflight"
      preflight; st_set PHASE preflight_ok; phase=preflight_ok ;;
    *) TS=$(st_get TS); OLDIMG=$(st_get OLDIMG)
      log "resume from phase $phase (run $TS)"
      guard || { log "REFUSE: const guard not GREEN; resume later"; exit 1; } ;;
  esac
  OLDIMG=${OLDIMG:-$(st_get OLDIMG)}
  # drained: the hotel is closed to new rooms
  if [ "$phase" = preflight_ok ]; then
    [ "$(drain true)" = 200 ] || die "drain PATCH did not answer 200"
    st_set PHASE drained; phase=drained; log "drained at broker"; sleep "$DRAIN_SETTLE"
    local r; r=$(rooms)
    [ "$r" = 0 ] || die "$HOTEL has rooms=$r after the drain; undrained, nothing installed"
    log "0 rooms"
  fi
  if [ "$phase" = stuck_drained ]; then
    # resumed after a failed recovery: try recovery again
    st_set PHASE installing; die "resuming a stuck hotel"
  fi
  if [ "$phase" = drained ] && [ "$(rooms)" != 0 ]; then die "$HOTEL has rooms after resume; nothing installed"; fi
  if [ "$phase" = drained ]; then
    st_set PHASE installing; phase=installing
    local out; out=$(host_install "$TS")
    while read -r l; do log "host: $l"; done <<< "$out"
    case "$out" in
      *RESULT=installed*) st_set PHASE installed; phase=installed ;;
      *RESULT=nochange*) st_set PHASE drained; die "host step changed nothing: $(grep -o 'RESULT=nochange.*' <<< "$out")" ;;
      *RESULT=rolledback*) st_set HOST_ROLLED_BACK 1; die "install failed and was rolled back to $OLDIMG" ;;
      *) die "host step did not finish cleanly; read /root/sealed-roll-*-$TS.log on $HOST" ;;
    esac
  fi
  # installing (resumed) and installed both wait for the broker to admit the NEW build
  if [ "$phase" = installing ] || [ "$phase" = installed ]; then
    wait_admitted "$NEW" || die "the broker has not admitted the new build"
    log "broker admitted the new build ${NEW:0:16} (slots $ADMITTED_SLOTS)"
    local att="$EVID/$HOTEL-attestation-$TS.json" facts
    curl -s -m 30 -o "$att" "$ATTEST_BASE/$HOTEL/attestation"
    facts=$(python3 -I - "$att" "$NEW" <<'PY' 2>&1
import base64, json, sys
d = json.load(open(sys.argv[1])); b = d.get("binding") or {}
rep = base64.b64decode(d["report_b64"])
print("report measurement", "NEW" if rep[0x90:0xC0].hex() == sys.argv[2] else "OTHER",
      "| binding names sealed_secrets:", "sealed_secrets" in b, "sealed_exec:", "sealed_exec" in b)
PY
)
    log "attestation: $facts (saved $att)"
    case "$facts" in *"report measurement NEW"*"sealed_secrets: True sealed_exec: True"*) ;; *) die "the new attestation is not the new build with both sealed keys" ;; esac
    st_set NEW_GOOD 1; st_set PHASE admitted; phase=admitted
  fi
  if [ "${HOLD_DRAINED:-0}" = 1 ] && [ "$phase" = admitted ]; then
    log "HOLD_DRAINED=1: new build admitted, hotel left drained; resume with: roll.sh apply $HOTEL"
    exit 0
  fi
  if [ "$phase" = admitted ]; then
    [ "$(drain false)" = 200 ] || die "undrain PATCH did not answer 200"
    st_set PHASE undrained; log "undrained"; sleep "$UNDRAIN_SETTLE"
    guard || { log "STOP: const guard not GREEN after the roll; hotel is undrained on the new build"; exit 1; }
    st_set PHASE "done"; log "DONE $HOTEL on ${NEW:0:16}"
  elif [ "$phase" = undrained ]; then
    guard || { log "STOP: const guard not GREEN after the roll; hotel is undrained on the new build"; exit 1; }
    st_set PHASE "done"; log "DONE $HOTEL on ${NEW:0:16}"
  fi
}

cmd_apply() {
  HOTEL=${1:-}; valid_hotel "$HOTEL" || usage
  load_plan || exit 1
  if [ "${ROLL_FOREGROUND:-0}" != 1 ] && [ "${ROLL_DETACHED:-0}" != 1 ]; then
    # Read-only refusals first so the caller sees them; then the mutating part detaches so a killed
    # turn cannot strand a drained hotel.
    local ph; ph=$(st_get PHASE)
    case "$ph" in ""|done|aborted|rolled_back|preflight|preflight_ok) CTX="apply $HOTEL"; preflight ;; esac
    systemd-run --unit="roll-apply-$HOTEL-$TS" --collect -E HOME="$HOME" -E ROLL_DETACHED=1 \
      -E ROLL_HOME="$ROLL_HOME" -E ROLL_HOTELS_CONF="$HOTELS_CONF" -E ROLL_GUARD="$GUARD" \
      -E ROLL_OPERATOR_KEY_FILE="$OPKEY_FILE" -E ROLL_SSH_KEY="$SSH_KEY" -E HOLD_DRAINED="${HOLD_DRAINED:-0}" \
      "$SELF" apply "$HOTEL" || exit 1
    echo "detached as roll-apply-$HOTEL-$TS; follow: tail -f $LOG ; state: $SELF status"
    exit 0
  fi
  run_apply
}

# ---- pin-patch -----------------------------------------------------------------------------------
cmd_pin_patch() {
  local commit=${1:-} out f n=0 pairs=""
  valid_commit "$commit" || usage
  for f in "$PLANS"/*.env; do
    [ -f "$f" ] && [ "$(kv_get "$f" COMMIT)" = "$commit" ] || continue
    pairs="$pairs    \"$(kv_get "$f" CUR)\": \"$(kv_get "$f" NEW)\",  # $(basename "$f" .env)
"
    n=$((n + 1))
  done
  [ $n -gt 0 ] || { echo "no staged hotels for $commit under $PLANS" >&2; exit 1; }
  out=$PLANS/pin-$commit.py
  python3 -I - "$HERE/pin_patch_template.py" "$out" "$pairs" <<'PY' || exit 1
import re, sys
tpl, out, pairs = sys.argv[1:4]
for m in re.findall(r'"([0-9a-f]+)"', pairs):
    if len(m) != 96:
        sys.exit("bad measurement in plan: " + m[:16])
src = open(tpl).read()
marker = "PAIRS = {}  # __PAIRS__"
if marker not in src:
    sys.exit("template marker missing")
open(out, "w").write(src.replace(marker, "PAIRS = {  # current (must already be pinned) -> new\n" + pairs + "}"))
PY
  python3 -I -m py_compile "$out" || exit 1
  echo "wrote $out ($n hotels). Use: broker_swap_config.sh [--apply] <broker-binary> $out"
}

# ---- stage ---------------------------------------------------------------------------------------
stage_hotel() {  # HOTEL, COMMIT, API, BUNDLE set; hotel_conf done
  CTX="stage $HOTEL"
  local N=/root/stage-$COMMIT UNIT=room-sealed-$HOTEL.service
  scp "${SSHO[@]}" -q "$BUNDLE" "root@$HOST:/root/kit-$COMMIT.bundle" || { log "scp failed"; return 1; }
  ssh "${SSHO[@]}" "root@$HOST" bash -s -- "$N" "$HOTEL" "$D" "$COMMIT" "$API" <<'REMOTE' 2>&1 | while read -r l; do log "host: $l"; done
N=$1 H=$2 L=$3 C=$4 API=$5
set -euo pipefail
if [ ! -d "$N/kit" ]; then
  mkdir -p "$N"
  git clone -q "/root/kit-$C.bundle" "$N/kit" -b main
  git -C "$N/kit" checkout -q --detach "$C"
  git -C "$N/kit" remote set-url origin https://github.com/cathedralai/cathedral-sandbox
  ( cd "$N/kit/room-kit" && ./make-dist.sh "$API" )
  P=$(ls -dt /root/stage-*/post_hotel.sh 2>/dev/null | grep -v "^$N/" | head -1 || true)
  [ -n "$P" ] || { echo "no earlier stage dir with post_hotel.sh to copy from"; exit 1; }
  cp -a "$P" "$(dirname "$P")/post_hotel_guest.sh" "$N/"
fi
echo "kit=$(git -C "$N/kit" rev-parse --short=7 HEAD) clean=$([ -z "$(git -C "$N/kit" status --porcelain)" ] && echo yes || echo no)"
[ -e "$N/$H" ] && { echo "refuse: $N/$H exists"; exit 1; }
mkdir -p "$N/$H/build" "$N/$H/images"
cp -a "$L/build/"base-* "$N/$H/build/"
sed "s#^SEALED_DIR=.*#SEALED_DIR=$N/$H#" "$L/sealed.env" > "$N/$H/sealed.env"; chmod 600 "$N/$H/sealed.env"
for k in SEALED_ROOM_SEALED_SECRETS SEALED_ROOM_SEALED_EXEC; do
  if grep -q "^$k=" "$N/$H/sealed.env"; then sed -i "s/^$k=.*/$k=1/" "$N/$H/sealed.env"; else echo "$k=1" >> "$N/$H/sealed.env"; fi
done
diff <(grep -vE '^SEALED_DIR=|^SEALED_ROOM_SEALED_(SECRETS|EXEC)=' "$L/sealed.env") <(grep -vE '^SEALED_DIR=|^SEALED_ROOM_SEALED_(SECRETS|EXEC)=' "$N/$H/sealed.env") >/dev/null \
  && echo "env: staged = live except SEALED_DIR and the two flags" || { echo "env: DIFFERS"; exit 1; }
cat > "$N/run-build-$H.sh" <<'BUILD'
#!/bin/bash
N=$1 H=$2 L=$3
rm -f "$N/build-status-$H.log"
bash "$N/kit/room-kit/sealed/build-guest.sh" "$N/$H/sealed.env" > "$N/build-$H.log" 2>&1; rc=$?
if [ $rc = 0 ]; then ( set -a; . "$N/$H/sealed.env" >/dev/null 2>&1; set +a; IMG=$(readlink -f "$N/$H/images/current")
  "$L/venv/bin/sev-snp-measure" --mode snp --vcpus "$SEALED_VCPUS" --vcpu-type "$SEALED_CPU_MODEL" --ovmf "$IMG/OVMF.amdsev.fd" --kernel "$IMG/vmlinuz" --initrd "$IMG/initrd.cpio.zst" --append "$(cat "$IMG/cmdline")" > "$IMG/expected-measurement" ); rc=$?; fi
echo "$H build exit $rc" > "$N/build-status-$H.log"
BUILD
systemd-run --unit="stage-$C-$H" --collect bash "$N/run-build-$H.sh" "$N" "$H" "$L"
echo "build started detached as stage-$C-$H"
REMOTE
  [ "${PIPESTATUS[0]}" = 0 ] || { log "stage setup failed"; return 1; }
  local deadline st; deadline=$(( $(date +%s) + STAGE_TIMEOUT ))
  while :; do
    st=$(ssh -n "${SSHO[@]}" "root@$HOST" "cat $N/build-status-$HOTEL.log 2>/dev/null" 2>/dev/null)
    case "$st" in *"build exit 0"*) break ;; *"build exit"*) log "build failed: $st"; return 1 ;; esac
    [ "$(date +%s)" -lt "$deadline" ] || { log "build did not finish in ${STAGE_TIMEOUT}s"; return 1; }
    sleep "$POLL"
  done
  local col; col=$(ssh -n "${SSHO[@]}" "root@$HOST" bash -s -- "$N" "$HOTEL" "$D" <<'REMOTE' 2>&1
N=$1 H=$2 L=$3
I=$(readlink -f "$N/$H/images/current"); LI=$(readlink -f "$L/images/current")
NEW=$(tr -d '\n' < "$I/expected-measurement")
LIVE=$(python3 -I -c 'import json,sys;d=json.load(open(sys.argv[1]));print((d.get("binding") or {}).get("measurement") or d.get("measurement") or "?")' "$L/run/attestation.json" 2>/dev/null || echo "?")
cmpr=""; for f in vmlinuz OVMF.amdsev.fd cmdline; do cmp -s "$I/$f" "$LI/$f" && cmpr="$cmpr $f=same" || cmpr="$cmpr $f=DIFF"; done
api=$(zstd -dc "$I/initrd.cpio.zst" | cpio -i --to-stdout --quiet ./opt/room-kit/versions.lock opt/room-kit/versions.lock 2>/dev/null | grep ^CATHEDRAL_COMMIT=)
kc=$(zstd -dc "$I/initrd.cpio.zst" | cpio -i --to-stdout --quiet ./opt/room-kit/KIT_COMMIT opt/room-kit/KIT_COMMIT 2>/dev/null | cut -c1-7)
dbg=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("debug"))' "$I/manifest.json")
echo "$H NEWIMG=$(basename "$I") NEW=$NEW LIVE=$LIVE |$cmpr | kit=$(git -C "$N/kit" rev-parse --short=7 HEAD) initrd_kit=$kc api=$api debug=$dbg"
REMOTE
)
  echo "$col" >> "$PLANS/stage-$COMMIT.txt"; log "collect: $col"
  local newimg new live up adm cur dr sl fr
  newimg=$(sed -n 's/.* NEWIMG=\([^ ]*\) .*/\1/p' <<< "$col"); new=$(sed -n 's/.* NEW=\([0-9a-f]*\) .*/\1/p' <<< "$col")
  live=$(sed -n 's/.* LIVE=\([0-9a-f?]*\) .*/\1/p' <<< "$col")
  valid_meas "$new" || { log "no valid new measurement in collect output"; return 1; }
  case "$col" in *"kit=${COMMIT:0:7} initrd_kit=${COMMIT:0:7} api=CATHEDRAL_COMMIT=$API"*"debug=False"*) ;; *) log "stage facts do not match commit $COMMIT / api $API / debug False"; return 1 ;; esac
  read -r up adm cur dr sl fr <<< "$(hotel_state)"
  if ! { [ "$up" = True ] && [ "$adm" = admitted ] && valid_meas "$cur"; }; then log "hotel is not up and admitted at the broker; no plan written"; return 1; fi
  [ "$live" = "$cur" ] || log "note: hotel attestation file says ${live:0:16}, broker says ${cur:0:16}; the plan uses the broker's value"
  [ "$new" = "$cur" ] && log "note: the new build equals the current build; nothing to roll"
  {
    echo "COMMIT=$COMMIT"; echo "API=$API"; echo "STAGE=$N"; echo "NEWIMG=$newimg"
    echo "CUR=$cur"; echo "NEW=$new"; echo "STAGED_AT=$TS"
  } > "$PLANS/$HOTEL.env"
  log "plan written: $PLANS/$HOTEL.env (current ${cur:0:16} -> new ${new:0:16})"
}

cmd_stage() {
  COMMIT=${1:-}; shift || true
  valid_commit "$COMMIT" && [ $# -gt 0 ] || usage
  local h; for h in "$@"; do
    if ! { valid_hotel "$h" && hotel_conf "$h"; }; then echo "unknown hotel: $h" >&2; exit 2; fi
  done
  if [ "${ROLL_FOREGROUND:-0}" != 1 ] && [ "${ROLL_DETACHED:-0}" != 1 ]; then
    systemd-run --unit="roll-stage-${COMMIT:0:7}-$TS" --collect -E HOME="$HOME" -E ROLL_DETACHED=1 \
      -E ROLL_HOME="$ROLL_HOME" -E ROLL_HOTELS_CONF="$HOTELS_CONF" -E ROLL_OPERATOR_KEY_FILE="$OPKEY_FILE" \
      -E ROLL_SSH_KEY="$SSH_KEY" "$SELF" stage "$COMMIT" "$@" || exit 1
    echo "detached as roll-stage-${COMMIT:0:7}-$TS; follow: tail -f $LOG"; exit 0
  fi
  CTX="stage ${COMMIT:0:7}"
  local src=$ROLL_HOME/src/$COMMIT-$TS; mkdir -p "$ROLL_HOME/src"
  gh repo clone "$REPO" "$src" -- -q || { log "clone failed"; exit 1; }
  git -C "$src" checkout -q --detach "$COMMIT" || { log "commit $COMMIT not found"; exit 1; }
  # KIT_COMMIT is measured into the initrd: the commit must stay reachable on main (merge-commit the pin PR).
  git -C "$src" merge-base --is-ancestor "$COMMIT" origin/main || { log "REFUSE: $COMMIT is not on main; merge the pin PR with a merge commit first"; exit 1; }
  API=$(sed -n 's/^CATHEDRAL_COMMIT=//p' "$src/room-kit/versions.lock" | head -1)
  [[ "$API" =~ ^[0-9a-f]{7,40}$ ]] || { log "no CATHEDRAL_COMMIT in versions.lock"; exit 1; }
  BUNDLE=$src.bundle
  git -C "$src" bundle create "$BUNDLE" main -q 2>/dev/null || { log "bundle failed"; exit 1; }
  local rc=0
  for h in "$@"; do HOTEL=$h; hotel_conf "$h"; stage_hotel || rc=1; done
  rm -rf "$src" "$BUNDLE"
  if [ $rc = 0 ]; then log "stage done for $COMMIT; next: roll.sh pin-patch $COMMIT"; else log "stage finished with failures"; fi
  exit $rc
}

# ---- status --------------------------------------------------------------------------------------
cmd_status() {
  local f h
  echo "plans:"
  for f in "$PLANS"/*.env; do [ -f "$f" ] || continue
    echo "  $(basename "$f" .env) commit=$(kv_get "$f" COMMIT) image=$(kv_get "$f" NEWIMG) cur=$(kv_get "$f" CUR | cut -c1-8) new=$(kv_get "$f" NEW | cut -c1-8)"
  done
  echo "state:"
  for f in "$STATE"/*.env; do [ -f "$f" ] || continue
    h=$(basename "$f" .env)
    echo "  $h phase=$(kv_get "$f" PHASE) run=$(kv_get "$f" TS) commit=$(kv_get "$f" COMMIT)"
  done
  echo "units:"
  systemctl list-units --all --no-legend 'roll-apply-*' 'roll-stage-*' 2>/dev/null | awk '{print "  " $1, $3, $4}'
  echo "log: $LOG"
}

case "${1:-}" in
  stage) shift; require_conf; cmd_stage "$@" ;;
  pin-patch) shift; cmd_pin_patch "$@" ;;
  apply) shift; require_conf; cmd_apply "$@" ;;
  status) cmd_status ;;
  *) usage ;;
esac
