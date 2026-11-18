#!/bin/sh
# Run only inside an approved internal room. No new devices or privileges.
set -eu

evidence_dir=${1:-/tmp/hyprland-trial-evidence}
umask 077
mkdir -p "$evidence_dir" "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"
marker=$evidence_dir/keyboard.ok
if [ -e "$marker" ]; then
    printf '%s\n' 'NO-GO: evidence directory already contains a keyboard marker' >&2
    exit 1
fi
export PROBE_MARKER=$marker
compositor_pid=
vnc_pid=
terminal_pid=
cleanup() {
    for pid in "$terminal_pid" "$vnc_pid" "$compositor_pid"; do
        if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
    done
    wait 2>/dev/null || true
    printf '%s\n' 'Probe child processes stopped' > "$evidence_dir/cleanup.txt"
}
trap cleanup EXIT HUP INT TERM

Hyprland --version > "$evidence_dir/version.txt" 2>&1
wayvnc --version > "$evidence_dir/wayvnc-version.txt" 2>&1
Hyprland > "$evidence_dir/compositor.log" 2>&1 &
compositor_pid=$!

socket=
attempt=0
while [ "$attempt" -lt 40 ]; do
    if ! kill -0 "$compositor_pid" 2>/dev/null; then
        printf '%s\n' 'NO-GO: compositor exited before opening a Wayland socket' >&2
        exit 1
    fi
    for candidate in "$XDG_RUNTIME_DIR"/wayland-*; do
        if [ -S "$candidate" ]; then socket=${candidate##*/}; break; fi
    done
    if [ -n "$socket" ]; then break; fi
    attempt=$((attempt + 1))
    sleep 0.5
done
if [ -z "$socket" ]; then
    printf '%s\n' 'NO-GO: no Wayland socket after 20 seconds' >&2
    exit 1
fi
export WAYLAND_DISPLAY=$socket

hyprctl monitors -j > "$evidence_dir/monitors.json" 2> "$evidence_dir/monitors.err"
if ! grep -q HEADLESS "$evidence_dir/monitors.json"; then
    printf '%s\n' 'NO-GO: no headless output' >&2
    exit 1
fi

# The VNC server is reachable only from inside this room.
wayvnc 127.0.0.1 5900 > "$evidence_dir/wayvnc.log" 2>&1 &
vnc_pid=$!
attempt=0
while [ "$attempt" -lt 20 ]; do
    if ! kill -0 "$vnc_pid" 2>/dev/null; then
        printf '%s\n' 'NO-GO: wayvnc exited' >&2
        exit 1
    fi
    if vncdo -s localhost::5900 capture "$evidence_dir/frame-before.png" >/dev/null 2> "$evidence_dir/vnc.err"; then break; fi
    attempt=$((attempt + 1))
    sleep 0.5
done
test -s "$evidence_dir/frame-before.png"

foot -e sh -c 'read -r line; if [ "$line" = cathedral-probe ]; then printf "%s\n" ok > "$PROBE_MARKER"; fi; sleep 30' \
    > "$evidence_dir/terminal.log" 2>&1 &
terminal_pid=$!
sleep 2
hyprctl cursorpos > "$evidence_dir/cursor-before.txt" 2>&1
vncdo -s localhost::5900 move 123 234 click 1 type cathedral-probe key enter \
    > "$evidence_dir/input.log" 2>&1
hyprctl cursorpos > "$evidence_dir/cursor-after.txt" 2>&1
test -f "$marker"
test "$(cat "$marker")" = ok
if cmp -s "$evidence_dir/cursor-before.txt" "$evidence_dir/cursor-after.txt"; then
    printf '%s\n' 'NO-GO: pointer did not move' >&2
    exit 1
fi

# A second client invocation proves that a new connection can capture a frame.
vncdo -s localhost::5900 capture "$evidence_dir/frame-reconnect.png" \
    > "$evidence_dir/reconnect.log" 2>&1
test -s "$evidence_dir/frame-reconnect.png"
ps -o pid,ppid,%cpu,rss,comm -p "$compositor_pid","$vnc_pid","$terminal_pid" \
    > "$evidence_dir/processes.txt"
printf '%s\n' 'PASS: headless output, frame, keyboard, pointer and reconnect' \
    > "$evidence_dir/verdict.txt"
cat "$evidence_dir/verdict.txt"
