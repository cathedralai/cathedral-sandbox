#!/usr/bin/env bash
# Check an agent-room image: the tools at the pinned versions, the non-root
# agent, and HOME on a workspace owned by the hotel, as on a hotel.
#
#   smoke-test.sh IMAGE_REF
#
# Needs docker, and sudo to give the test workspace to another user.
set -euo pipefail

image="${1:?usage: smoke-test.sh IMAGE_REF}"
want_claude="2.1.312 (Claude Code)"
want_codex="codex-cli 0.157.1"

fail() {
    echo "smoke-test: $*" >&2
    exit 1
}

# The room as the image starts it, with no workspace.
out="$(docker run --rm --network none "$image" sh -c \
    'id -u; id -un; echo "$HOME"; claude --version; codex --version; tmux -V; git --version; python3 --version; node --version; curl --version | head -n 1')"
printf '%s\n' "$out"
mapfile -t line <<< "$out"
[[ "${line[0]}" == 1000 ]] || fail "uid is ${line[0]}, want 1000"
[[ "${line[1]}" == agent ]] || fail "user is ${line[1]}, want agent"
[[ "${line[2]}" == /workspace/home ]] || fail "HOME is ${line[2]}"
[[ "${line[3]}" == "$want_claude" ]] || fail "claude --version is ${line[3]}"
[[ "${line[4]}" == "$want_codex" ]] || fail "codex --version is ${line[4]}"

# The room as a hotel starts it: /work and a workspace owned by the hotel's
# service user (991 on a sealed hotel), the command `sleep infinity`, execs in
# /work. The room's creator makes HOME with one exec as root.
workspace="$(mktemp -d)"
work="$(mktemp -d)"
sudo chown 991:991 "$workspace" "$work"
sudo chmod 0755 "$workspace" "$work"
cid=""
cleanup() {
    if [[ -n "$cid" ]]; then docker rm -f "$cid" >/dev/null; fi
    sudo rm -rf "$workspace" "$work"
}
trap cleanup EXIT

start_room() {
    cid="$(docker run -d --network none -v "$work:/work" -w /work \
        --mount "type=bind,source=$workspace,target=/workspace" "$image" sleep infinity)"
    for _ in $(seq 1 20); do
        if [[ "$(docker inspect -f '{{.State.Running}}' "$cid")" == true ]]; then
            return 0
        fi
        sleep 0.5
    done
    docker logs "$cid" >&2 || true
    fail "the room did not start"
}

start_room
if docker exec "$cid" test -e /workspace/home; then
    fail "HOME exists on a new workspace before the root exec"
fi
docker exec -u root "$cid" install -d -o agent -g agent -m 0700 /workspace/home
out="$(docker exec "$cid" sh -c 'id -un; pwd; stat -c "%U %a" "$HOME"; echo kept > "$HOME/marker"')"
printf '%s\n' "$out"
mapfile -t line <<< "$out"
[[ "${line[0]}" == agent ]] || fail "exec user is ${line[0]}"
[[ "${line[1]}" == /work ]] || fail "exec cwd is ${line[1]}"
[[ "${line[2]}" == "agent 700" ]] || fail "HOME on the workspace is ${line[2]}"
if docker exec "$cid" sh -c 'command -v sudo' >/dev/null; then
    fail "sudo is in the image"
fi
docker rm -f "$cid" >/dev/null
cid=""

# A new room on the same workspace finds HOME and its files with no root exec.
start_room
[[ "$(docker exec "$cid" cat /workspace/home/marker)" == kept ]] || fail "HOME did not persist on the workspace"

echo "smoke-test: passed"
