#!/bin/bash
# Stage H and S check: which kernel ran the Dockerfile RUN steps?
#
# Builds an image whose RUN step records `uname -r`, starts a room from it,
# and compares the build-time kernel with the room's kernel. On a hotel that
# builds through the classic builder both are gVisor's; a BuildKit build runs
# the RUN step on the host kernel (review round 6, B62).
#
#   BROKER_KEY_FILE=/path/to/ops.key scripts/build_runtime_probe.sh
#
# Environment:
#   BROKER_KEY_FILE   file holding an ops key of the broker (required)
#   BROKER_URL        default https://live.cathedral.computer
#   BROKER_RESOLVE    optional curl --resolve value, host:443:ip, to pin the address
#   PROBE_LABEL       label value on the room, default runtime-probe
#
# The room lands on any hotel the key may use. To check one hotel, use a key
# whose hotel list is that hotel, or drain the others first. Exit 0 when both
# kernels are gVisor's, 2 when they differ, 1 when a step failed.
set -u
: "${BROKER_KEY_FILE:?set BROKER_KEY_FILE to the ops key file}"
B=${BROKER_URL:-https://live.cathedral.computer}
K=$(cat "$BROKER_KEY_FILE")
LABEL=${PROBE_LABEL:-runtime-probe}
RESOLVE=()
[ -n "${BROKER_RESOLVE:-}" ] && RESOLVE=(--resolve "$BROKER_RESOLVE")

c() { curl -s -m "${T:-60}" "${RESOLVE[@]}" -A 'ctcli/1.0' -H "Authorization: Bearer $K" "$@"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1', ''))"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf 'FROM alpine:3.20\nRUN uname -r > /build-kernel.txt\n' > "$WORK/Dockerfile"

out=$(c -F "dockerfile=<$WORK/Dockerfile" "$B/v1/images/build")
ID=$(printf '%s' "$out" | field image_id)
[ -n "$ID" ] || { echo "build request failed: ${out:0:300}" >&2; exit 1; }
echo "image $ID"
state=
for _ in $(seq 1 60); do
  state=$(c "$B/v1/images/$ID" | field state)
  case "$state" in ready|failed) break ;; esac
  sleep 5
done
[ "$state" = ready ] || { echo "image state: $state" >&2; c "$B/v1/images/$ID" >&2; exit 1; }

room=$(c -H 'Content-Type: application/json' -X POST "$B/v1/sandboxes" \
  -d "{\"image_id\":\"$ID\",\"labels\":{\"run\":\"$LABEL\"},\"lifetime_seconds\":600}")
RID=$(printf '%s' "$room" | field id)
[ -n "$RID" ] || { echo "create failed: ${room:0:300}" >&2; exit 1; }
echo "room $RID"
trap 'c -X DELETE "$B/v1/sandboxes/$RID" -o /dev/null; rm -rf "$WORK"' EXIT

result=$(T=120 c -H 'Content-Type: application/json' -X POST "$B/v1/sandboxes/$RID/exec" \
  -d '{"cmd":["sh","-c","cat /build-kernel.txt; uname -r"],"timeout_seconds":60}' | field stdout)
build_kernel=$(printf '%s' "$result" | sed -n '1p')
room_kernel=$(printf '%s' "$result" | sed -n '2p')
echo "build-time kernel: ${build_kernel:-?}"
echo "room kernel:       ${room_kernel:-?}"
case "$build_kernel" in
  *gvisor*) ;;
  *) echo "FAIL: the RUN step ran on ${build_kernel:-an unknown kernel}, not under gVisor" >&2; exit 2 ;;
esac
case "$room_kernel" in
  *gvisor*) echo "OK: build and room both under gVisor" ;;
  *) echo "FAIL: the room runs on ${room_kernel:-an unknown kernel}" >&2; exit 2 ;;
esac
