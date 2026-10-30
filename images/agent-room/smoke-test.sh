#!/usr/bin/env bash
# Check an agent-room image: the tools at the pinned versions, the non-root
# agent, and HOME on a workspace that comes up owned by root, as on a hotel.
#
#   smoke-test.sh IMAGE_REF
#
# Needs docker, and sudo to give the test workspace to root.
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

# The room as a hotel starts it: /work and a workspace that root owns, the
# command `sleep infinity`, execs in /work.
workspace="$(mktemp -d)"
work="$(mktemp -d)"
sudo chown root:root "$workspace" "$work"
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
        if docker exec "$cid" test -w /workspace/home; then
            return 0
        fi
        sleep 0.5
    done
    docker logs "$cid" >&2 || true
    fail "HOME did not come up writable on the workspace"
}

start_room
out="$(docker exec "$cid" sh -c 'id -un; pwd; stat -c "%U %a" "$HOME"; echo kept > "$HOME/marker"')"
printf '%s\n' "$out"
mapfile -t line <<< "$out"
[[ "${line[0]}" == agent ]] || fail "exec user is ${line[0]}"
[[ "${line[1]}" == /work ]] || fail "exec cwd is ${line[1]}"
[[ "${line[2]}" == "agent 700" ]] || fail "HOME on the workspace is ${line[2]}"
# The sudo rule allows agent-home-init and nothing else.
if docker exec "$cid" sudo -n true 2>/dev/null; then
    fail "the agent can run other commands with sudo"
fi
docker rm -f "$cid" >/dev/null
cid=""

# A new room on the same workspace finds HOME and its files.
start_room
[[ "$(docker exec "$cid" cat /workspace/home/marker)" == kept ]] || fail "HOME did not persist on the workspace"

echo "smoke-test: passed"
