# Level 1 receipts (#288). Source this from install.sh.
# receipts_apply_defaults sets ROOM_RECEIPTS, ROOM_RECEIPTS_LISTEN and
# ROOM_HOTEL_NAME. receipts_api_upstream is the address a published front
# dials for create, exec and delete.
#
# ROOM_RECEIPTS unset or empty: 1. ROOM_RECEIPTS=0 turns receipts off.
# The default listener is 127.0.0.1:18092, which is not ROOM_API_PORT
# (18090) and not ROOM_HEALTH_PORT (18091). A listen host that is not
# loopback or all-interfaces may use the API port number: the sealed guest
# binds its own address that way.

receipts_apply_defaults() {
  if [ "${ROOM_RECEIPTS+x}" != x ] || [ -z "$ROOM_RECEIPTS" ]; then
    ROOM_RECEIPTS=1
  fi
  if [ "$ROOM_RECEIPTS" = 0 ]; then
    return 0
  fi
  if [ "$ROOM_RECEIPTS" != 1 ]; then
    echo "ROOM_RECEIPTS must be 0 or 1" >&2
    return 1
  fi
  if [ -z "${ROOM_RECEIPTS_LISTEN:-}" ]; then
    ROOM_RECEIPTS_LISTEN=127.0.0.1:18092
  fi
  if [ -z "${ROOM_HOTEL_NAME:-}" ]; then
    ROOM_HOTEL_NAME=${ROOM_ID:-room}
  fi
  local host port
  host=${ROOM_RECEIPTS_LISTEN%:*}
  port=${ROOM_RECEIPTS_LISTEN##*:}
  case "$host" in
    127.0.0.1|localhost|0.0.0.0|::|"[::]"|"*")
      if [ "$port" = "${ROOM_API_PORT:-18090}" ] || [ "$port" = "${ROOM_HEALTH_PORT:-18091}" ]; then
        echo "ROOM_RECEIPTS_LISTEN $ROOM_RECEIPTS_LISTEN uses the API port or the health port" >&2
        return 1
      fi
      ;;
  esac
  return 0
}

# Address Caddy (and any other front on this host) dials for room API calls.
# Receipts off: the API itself. Receipts on: the receipt proxy, which forwards
# to the API and signs create, exec and delete. An all-interfaces listen is
# dialed on loopback.
receipts_api_upstream() {
  if [ "${ROOM_RECEIPTS:-0}" != 1 ]; then
    echo "127.0.0.1:${ROOM_API_PORT:?}"
    return 0
  fi
  local host port
  host=${ROOM_RECEIPTS_LISTEN%:*}
  port=${ROOM_RECEIPTS_LISTEN##*:}
  case "$host" in
    0.0.0.0|::|"[::]"|"*") host=127.0.0.1 ;;
  esac
  echo "$host:$port"
}
