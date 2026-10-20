# Room network mode (#291). Source this from install.sh, then call
# resolve_room_nets after room.env is sourced.
#
#   unset or auto          ROOM_NETS_AUTO=1, ROOM_NETS empty until step 8
#                          fills one CIDR per ROOM_NET_SIZE rooms
#   none, off, or empty    ROOM_NETS_AUTO=0, ROOM_NETS empty (main bridge only)
#   a CIDR list            ROOM_NETS_AUTO=0, ROOM_NETS unchanged

resolve_room_nets() {
  ROOM_NETS_AUTO=0
  if [ "${ROOM_NETS+x}" != x ] || [ "$ROOM_NETS" = auto ]; then
    ROOM_NETS_AUTO=1
    ROOM_NETS=""
    return 0
  fi
  case "$ROOM_NETS" in
    none|off|"")
      ROOM_NETS=""
      ;;
  esac
  return 0
}
