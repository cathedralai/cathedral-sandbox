#!/bin/bash
# variant.sh NAME FILL MEM "CKPT_RUNSC_FLAGS" "RESTORE_RUNSC_FLAGS" [BETWEEN_CMD]
# CKPT_BIN / RESTORE_BIN pick runsc binaries; ROOTRW=1 makes the rootfs writable;
# GUEST_PRE runs inside the guest (runsc exec) before the checkpoint.
set -eu
NAME=$1 FILL=$2 MEM=$3 CF=$4 RF=$5 BETWEEN=${6:-true}
S=$(cd "$(dirname "$0")" && pwd); RUNS=${RUNS:-/var/tmp/ckspike}
# shellcheck source=scratch.sh
. "$S/scratch.sh"
ckspike_require_name "$NAME"
B=$(ckspike_under_root "$RUNS" "$RUNS/$NAME" "bundle")
IMG_ROOT=${IMGROOT:-/tmp/ckspike-img}
IMG=$(ckspike_under_root "$IMG_ROOT" "$IMG_ROOT/$NAME-img" "image")
CB=${CKPT_BIN:-runsc} RB=${RESTORE_BIN:-runsc}
bash "$S/net.sh" down; bash "$S/net.sh" up >/dev/null
rm -rf "$B" "$IMG"; mkdir -p "$B" "$IMG"; ( cd "$B" && runsc spec )
python3 "$S/mkbundle.py" "$B" "$FILL" "$MEM" ckspike
[ -n "${ROOTRW:-}" ] && python3 -c "import json,sys;p=sys.argv[1];s=json.load(open(p));s['root']['readonly']=False;json.dump(s,open(p,'w'))" "$B/config.json"
$CB --root /run/ckspike-runsc $CF run -bundle "$B" -detach "$NAME" >"$B/out.log" 2>&1 </dev/null &
for i in $(seq 1 600); do [ -f "$B/work/ready" ] && break; sleep 0.5; done
sleep 2
[ -n "${GUEST_PRE:-}" ] && $CB --root /run/ckspike-runsc $CF exec "$NAME" /bin/sh -c "$GUEST_PRE"
t1=$(date +%s.%N); $CB --root /run/ckspike-runsc $CF checkpoint ${CKPT_EXTRA:-} -image-path "$IMG" "$NAME"; rc=$?
echo "ckpt_rc=$rc ckpt_s=$(echo "$(date +%s.%N)-$t1"|bc) img_bytes=$(du -sb "$IMG"|cut -f1)"
if [ "$rc" -ne 0 ]; then echo "checkpoint failed"; cat "$B/out.log"; exit "$rc"; fi
$CB --root /run/ckspike-runsc $CF delete -force "$NAME" 2>/dev/null
N0=$(wc -l < "$B/work/state.log")
( cd "$B" && eval "$BETWEEN" )
t3=$(date +%s.%N); $RB --root /run/ckspike-runsc $RF restore -bundle "$B" -image-path "$IMG" -detach "$NAME" >>"$B/out.log" 2>&1 </dev/null; rrc=$?
echo "restore_rc=$rrc restore_s=$(echo "$(date +%s.%N)-$t3"|bc)"
if [ "$rrc" -ne 0 ]; then echo "restore failed"; cat "$B/out.log"; exit "$rrc"; fi
sleep 4; echo "new log lines after restore: $(( $(wc -l < "$B/work/state.log") - N0 ))"; tail -2 "$B/work/state.log"; tail -3 "$B/out.log"
$RB --root /run/ckspike-runsc $RF kill "$NAME" KILL 2>/dev/null; sleep 1; $RB --root /run/ckspike-runsc $RF delete -force "$NAME" 2>/dev/null
rm -rf "$IMG"
