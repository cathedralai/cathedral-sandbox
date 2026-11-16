#!/bin/bash
# trial.sh NAME FILL_GIB MEM_GIB [COMPRESSION] [EXTRA_RUNSC_FLAGS]
set -eu
NAME=$1 FILL=$2 MEM=$3 COMP=${4:-none} EXTRA=${5:-}
S=$(cd "$(dirname "$0")" && pwd); RUNS=${RUNS:-/var/tmp/ckspike}
# shellcheck source=scratch.sh
. "$S/scratch.sh"
ckspike_require_name "$NAME"
B=$(ckspike_under_root "$RUNS" "$RUNS/$NAME" "bundle")
IMG=$(ckspike_under_root "${IMGROOT:-$RUNS}" "${IMGROOT:-$RUNS}/$NAME-img" "image")
R="runsc --root /run/ckspike-runsc --platform=systrap --overlay2=none --net-raw $EXTRA"
bash "$S/net.sh" down; bash "$S/net.sh" up >/dev/null
echo "load: $(cut -d" " -f1-3 /proc/loadavg)"
rm -rf "$B" "$IMG"; mkdir -p "$B" "$IMG"
( cd "$B" && runsc spec )
python3 "$S/mkbundle.py" "$B" "$FILL" "$MEM" ckspike
now() { date +%s.%N; }
t0=$(now); $R run -bundle "$B" -detach "$NAME" >"$B/out.log" 2>&1 </dev/null &
for i in $(seq 1 600); do [ -f "$B/work/ready" ] && break; sleep 0.5; done
[ -f "$B/work/ready" ] || { echo "never ready"; cat "$B/out.log"; exit 1; }
sleep 4
touch "$B/work/touch"; for i in $(seq 1 600); do [ -f "$B/work/touch" ] || break; sleep 0.2; done
CG=$(find /sys/fs/cgroup/ckspike -maxdepth 1 -name "$NAME" | head -1)
MEMCUR=$(cat "$CG/memory.current" 2>/dev/null || echo NA)
[ -n "${BUMP:-}" ] && echo $((MEM*2))G > "$CG/memory.max"
grep -E "^(max|oom|high)" "$CG/memory.events" | tr "\n" " "; echo
rc=0; t1=$(now); $R checkpoint -image-path "$IMG" -compression "$COMP" ${CKPT_EXTRA:-} "$NAME" || rc=$?; t2=$(now)
if [ "$rc" -ne 0 ]; then echo "checkpoint failed rc=$rc"; cat "$B/out.log"; exit "$rc"; fi
grep -E "^(max|oom|high)" "$CG/memory.events" 2>/dev/null | tr "\n" " "; echo
SZ=$(du -sb "$IMG" | cut -f1)
LASTPRE=$(tail -1 "$B/work/state.log")
$R delete -force "$NAME" 2>/dev/null
sync; echo 3 > /proc/sys/vm/drop_caches
sleep 3
PRELINES=$(wc -l < "$B/work/state.log")
rrc=0; t3=$(now); $R restore -bundle "$B" -image-path "$IMG" -detach "$NAME" >>"$B/out.log" 2>&1 </dev/null || rrc=$?; t4=$(now)
if [ "$rrc" -ne 0 ]; then echo "restore failed rc=$rrc"; cat "$B/out.log"; exit "$rrc"; fi
for i in $(seq 1 600); do [ "$(wc -l < "$B/work/state.log")" -gt "$PRELINES" ] && break; sleep 0.05; done
t5=$(now)
touch "$B/work/touch"; for i in $(seq 1 1200); do [ -f "$B/work/touch" ] || break; sleep 0.05; done
t6=$(now)
sleep 3
echo "RESULT name=$NAME fill=$FILL mem=$MEM comp=$COMP cgroup_mem_bytes=$MEMCUR ckpt_rc=$rc ckpt_s=$(echo "$t2-$t1"|bc) img_bytes=$SZ restore_rc=$rrc restore_cmd_s=$(echo "$t4-$t3"|bc) first_tick_s=$(echo "$t5-$t3"|bc) all_pages_s=$(echo "$t6-$t3"|bc)"
echo "last before: $LASTPRE"; grep touch "$B/work/state.log"; tail -3 "$B/work/state.log"
ls -la "$IMG"
$R kill "$NAME" KILL 2>/dev/null; sleep 1; $R delete -force "$NAME" 2>/dev/null
