# API profile "v1": the /v1 sandbox API from cathedral-sandbox.
# A profile is a shell fragment. It must define:
#   PROFILE_DESC          one line
#   profile_exec          prints the ExecStart line of the API unit
#   profile_env           prints extra KEY=VALUE lines for the API unit
#   profile_keys_env      prints the secret env line(s) that carry the API key
# The API must listen on 127.0.0.1:$ROOM_API_PORT and start guests through
# DOCKER_HOST (the room daemon), so every guest runs under runsc.
PROFILE_DESC="/v1 sandbox API (cathedral-sandbox 'sandbox serve', runtime docker on the runsc room daemon)"

# room_api.py applies ROOM_CREATES_PER_MINUTE (the API has no setting for it),
# then runs 'python -m cathedral.cli sandbox serve'.
profile_exec() {
  echo "$ROOM_OPT/venv/bin/python $ROOM_OPT/bin/room_api.py sandbox serve --host 127.0.0.1 --port $ROOM_API_PORT --runtime docker"
}

profile_env() {
  cat <<EOV
PYTHONPATH=$ROOM_OPT/src
CATHEDRAL_SANDBOX_RUNTIME=docker
CATHEDRAL_SANDBOX_QUOTA=$SIZE_QUOTA
CATHEDRAL_SANDBOX_REGION=${ROOM_REGION:-}
CATHEDRAL_ALLOW_PRIVILEGED_DIND=${ROOM_ALLOW_DIND:-0}
CATHEDRAL_API_URL=http://127.0.0.1:$ROOM_API_PORT
CATHEDRAL_SANDBOX_OWNER=$ROOM_ID
CATHEDRAL_SANDBOX_PULL_POLICY=missing
CATHEDRAL_SANDBOX_GC_PARALLELISM=${ROOM_GC_PARALLELISM:-16}
ROOM_CREATES_PER_MINUTE=${ROOM_CREATES_PER_MINUTE:-100}
CATHEDRAL_DIND_DOCKERD_ARGS="${ROOM_DIND_DOCKERD_ARGS:-}"
CATHEDRAL_DIND_ENV="${ROOM_DIND_ENV:-}"
EOV
  # Room networks: one bridge per ROOM_NETS CIDR, ROOM_NET_SIZE guests each.
  if [ -n "${ROOM_NETS:-}" ]; then
    local nets; read -r -a nets <<< "$ROOM_NETS"
    echo "CATHEDRAL_ROOM_NETWORKS=${#nets[@]}"
    echo "CATHEDRAL_ROOM_NETWORK_SUBNETS=$(IFS=,; echo "${nets[*]}")"
    echo "CATHEDRAL_ROOM_NETWORK_SIZE=${ROOM_NET_SIZE:-1000}"
    echo "CATHEDRAL_ROOM_NETWORK_PREFIX=$ROOM_ID-net"
    echo "CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX=${ROOM_NET_BRIDGE_PREFIX:-rmnet}"
    echo "CATHEDRAL_ROOM_NETWORK_DNS=\"$ROOM_DNS\""
  fi
}

# key:project:max_running (CATHEDRAL_SANDBOX_KEYS, cathedral/sandbox_provider.py parse_sandbox_keys)
profile_keys_env() {
  echo "CATHEDRAL_SANDBOX_KEYS=$1:$ROOM_CUSTOMER:$SIZE_SLOTS"
}
