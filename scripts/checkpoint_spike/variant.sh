#!/bin/bash
# variant.sh NAME FILL MEM "CKPT_RUNSC_FLAGS" "RESTORE_RUNSC_FLAGS" [BETWEEN_CMD]
# CKPT_BIN / RESTORE_BIN pick runsc binaries; ROOTRW=1 makes the rootfs writable;
# GUEST_PRE runs inside the guest (runsc exec) before the checkpoint.
set -u
NAME=$1 FILL=$2 MEM=$3 CF=$4 RF=$5 BETWEEN=${6:-true}
S=$(cd "$(dirname "$0")" && pwd); RUNS=${RUNS:-/var/tmp/ckspike}
B=$RUNS/$NAME IMG=/tmp/ckspike-img/$NAME-img
CB=${CKPT_BIN:-runsc} RB=${RESTORE_BIN:-runsc}
bash "$S/net.sh" down; bash "$S/net.sh" up >/dev/null
rm -rf "$B" "$IMG"; mkdir -p "$B" "$IMG"; ( cd "$B" && runsc spec )
python3 "$S/mkbundle.py" "$B" "$FILL" "$MEM" ckspike
[ -n "${ROOTRW:-}" ] && python3 -c "import json,sys;p=sys.argv[1];s=json.load(open(p));s['root']['readonly']=False;json.dump(s,open(p,'w'))" "$B/config.json"
$CB --root /run/ckspike-runsc $CF run -bundle "$B" -detach "$NAME" >"$B/out.log" 2>&1 </dev/null &
for i in $(seq 1 600); do [ -f "$B/work/ready" ] && break; sleep 0.5; done
sleep 2
[ -n "${GUEST_PRE:-}" ] && $CB --root /run/ckspike-runsc $CF exec "$NAME" /bin/sh -c "$GUEST_PRE"
t1=$(date +%s.%N); $CB --root /run/ckspike-runsc $CF checkpoint ${CKPT_EXTRA:-} -image-path "$IMG" "$NAME"; echo "ckpt_rc=$? ckpt_s=$(echo "$(date +%s.%N)-$t1"|bc) img_bytes=$(du -sb "$IMG"|cut -f1)"
$CB --root /run/ckspike-runsc $CF delete -force "$NAME" 2>/dev/null
N0=$(wc -l < "$B/work/state.log")
( cd "$B" && eval "$BETWEEN" )
t3=$(date +%s.%N); $RB --root /run/ckspike-runsc $RF restore -bundle "$B" -image-path "$IMG" -detach "$NAME" >>"$B/out.log" 2>&1 </dev/null; echo "restore_rc=$? restore_s=$(echo "$(date +%s.%N)-$t3"|bc)"
sleep 4; echo "new log lines after restore: $(( $(wc -l < "$B/work/state.log") - N0 ))"; tail -2 "$B/work/state.log"; tail -3 "$B/out.log"
$RB --root /run/ckspike-runsc $RF kill "$NAME" KILL 2>/dev/null; sleep 1; $RB --root /run/ckspike-runsc $RF delete -force "$NAME" 2>/dev/null
rm -rf "$IMG"
