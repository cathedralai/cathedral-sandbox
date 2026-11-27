# shellcheck shell=bash
# The one host lock of a sealed host, and the custom guest hold marker (AB#999; spec r9 5.3, 5.10).
# Sourced by install-sealed.sh and write-units.sh, and sent ahead of roll.sh's host_install and
# host_rollback blocks, so every kit lifecycle entry speaks the same protocol. Defines functions only.
#
# Lock: flock on /run/lock/cathedral-snp-host.lock, one per physical host. Only a top-level entry
# takes it, on fd 9, and writes the owner record next to it. A helper started under a holder
# (install.sh execs install-sealed.sh, which runs write-units.sh) never calls flock: a second open
# plus flock would conflict with its own parent (flock(2)). It checks instead that fd 9 is the lock
# file, that the owner record names the exported owner, and that the record's pid is one of its
# ancestors, and refuses if any check fails. Unit hooks and the kit unit guard never take the lock:
# systemd runs them while a holder waits on its own start or stop request.
#
# Marker: SEALED_DIR/custom-guest.hold, one line of JSON {"launch_id": "cg-<12 hex>", "state":
# "held" | "kit_start", ...}. The custom guest hold writes it (H6) and only its last return step
# (R15) removes it, both under the lock. One line, because the kit unit guard reads it with grep.
#
# CATHEDRAL_SNP_LOCK_DIR and CATHEDRAL_SNP_LOCK_WAIT exist for tests; ROOM_DESTDIR is the kit's
# fake root, as in install.sh and write-units.sh.

SNP_LOCK_DIR=${CATHEDRAL_SNP_LOCK_DIR:-${ROOM_DESTDIR:-}/run/lock}
SNP_LOCK_FILE=$SNP_LOCK_DIR/cathedral-snp-host.lock
SNP_LOCK_RECORD=$SNP_LOCK_DIR/cathedral-snp-host.owner
SNP_LOCK_WAIT=${CATHEDRAL_SNP_LOCK_WAIT:-60}
SNP_LOCK_MINE=0
# Set by a helper's checks from the holder's owner record: which phase, for which launch, holds it.
SNP_LOCK_PHASE=""
SNP_LOCK_LAUNCH=""

# snp_lock_take <entry> <phase> <hotel> <launch_id|-> <max_seconds|->
# Call it in the main shell, never in $( ) or a subshell: the lock lives on fd 9 of the caller.
# Top level (no CATHEDRAL_SNP_LOCK_FD or CATHEDRAL_SNP_LOCK_OWNER in the environment): flock on
# fd 9, then the owner record, then export both variables for helpers. Under a holder: the three
# inherited checks, and never a flock. Returns 0 when this process may act; else prints why and
# returns 1 (custom_guest_lifecycle_busy: another holder, whose owner record is printed) or 2 (the
# inherited lock does not check out, or a bad argument).
snp_lock_take() {
  local entry=${1:-} phase=${2:-} hotel=${3:-} launch=${4:--} max=${5:--}
  if [ -n "${CATHEDRAL_SNP_LOCK_FD:-}${CATHEDRAL_SNP_LOCK_OWNER:-}" ]; then
    snp_lock_inherited
    return
  fi
  [[ "$entry" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] && [[ "$phase" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] \
    && [[ "$hotel" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] && [[ "$launch" =~ ^(-|cg-[0-9a-f]{12})$ ]] \
    && [[ "$max" =~ ^(-|[1-9][0-9]{0,5})$ ]] && [[ "$SNP_LOCK_WAIT" =~ ^[0-9]{1,4}$ ]] \
    || { echo "host lock: bad arguments: entry=$entry phase=$phase hotel=$hotel launch=$launch max=$max wait=$SNP_LOCK_WAIT" >&2; return 2; }
  mkdir -p "$SNP_LOCK_DIR" && exec 9>"$SNP_LOCK_FILE" \
    || { echo "host lock: cannot open $SNP_LOCK_FILE" >&2; return 2; }
  local got=0
  if [ "$SNP_LOCK_WAIT" = 0 ]; then flock -n 9 && got=1; else flock -w "$SNP_LOCK_WAIT" 9 && got=1; fi
  if [ "$got" != 1 ]; then
    echo "custom_guest_lifecycle_busy: another lifecycle step holds $SNP_LOCK_FILE (waited ${SNP_LOCK_WAIT}s); owner record: $(cat "$SNP_LOCK_RECORD" 2>/dev/null || echo none)" >&2
    exec 9>&-
    return 1
  fi
  local pid=$BASHPID now started deadline=null lid=null owner
  now=$(date -u +%s)
  started=$(date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)
  [ "$max" != - ] && deadline="\"$(date -u -d "@$((now + max))" +%Y-%m-%dT%H:%M:%SZ)\""
  [ "$launch" != - ] && lid="\"$launch\""
  owner=$entry:$hotel:$pid:$now
  printf '{"owner": "%s", "phase": "%s", "hotel": "%s", "launch_id": %s, "pid": %d, "started_at": "%s", "deadline_at": %s}\n' \
    "$owner" "$phase" "$hotel" "$lid" "$pid" "$started" "$deadline" > "$SNP_LOCK_RECORD.tmp.$pid" \
    && mv -f "$SNP_LOCK_RECORD.tmp.$pid" "$SNP_LOCK_RECORD" \
    || { echo "host lock: cannot write the owner record $SNP_LOCK_RECORD" >&2; rm -f "$SNP_LOCK_RECORD.tmp.$pid"; exec 9>&-; return 2; }
  export CATHEDRAL_SNP_LOCK_FD=9 CATHEDRAL_SNP_LOCK_OWNER=$owner
  SNP_LOCK_MINE=1
  return 0
}

# The owner record's "<owner> <pid> <phase> <launch_id>", or "- 0 - -" when it does not read.
snp_lock_record() {
  python3 -I -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    o, p = d["owner"], d["pid"]
    if not isinstance(o, str) or not o or " " in o or type(p) is not int or p < 2:
        raise ValueError
    print(o, p, d.get("phase") or "-", d.get("launch_id") or "-")
except Exception:
    print("- 0 - -")' "$SNP_LOCK_RECORD" 2>/dev/null || echo "- 0 - -"
}

snp_ppid() {
  local k v
  while read -r k v; do [ "$k" = PPid: ] && { echo "$v"; return 0; }; done < "/proc/$1/status"
  return 1
}

# A helper's three checks (spec 5.3). Never acquires: a failed check refuses.
snp_lock_inherited() {
  local fd=${CATHEDRAL_SNP_LOCK_FD:-} owner=${CATHEDRAL_SNP_LOCK_OWNER:-} rec_owner rec_pid rec_phase rec_launch p n=0
  [ "$fd" = 9 ] && [ -n "$owner" ] \
    || { echo "host lock: refused: CATHEDRAL_SNP_LOCK_FD must be 9 and CATHEDRAL_SNP_LOCK_OWNER set together (fd=${fd:-unset})" >&2; return 2; }
  [ -e "$SNP_LOCK_FILE" ] && [ /dev/fd/9 -ef "$SNP_LOCK_FILE" ] \
    || { echo "host lock: refused: fd 9 is not $SNP_LOCK_FILE (device and inode differ, or fd 9 is closed)" >&2; return 2; }
  read -r rec_owner rec_pid rec_phase rec_launch <<< "$(snp_lock_record)"
  [ "$rec_owner" = "$owner" ] \
    || { echo "host lock: refused: the owner record names '$rec_owner', not the exported owner '$owner'" >&2; return 2; }
  p=$PPID
  while [ "$p" -gt 1 ] && [ "$n" -lt 64 ]; do
    [ "$p" = "$rec_pid" ] && { SNP_LOCK_PHASE=$rec_phase SNP_LOCK_LAUNCH=$rec_launch; return 0; }
    p=$(snp_ppid "$p") || break
    n=$((n + 1))
  done
  echo "host lock: refused: the owner record's pid $rec_pid is not an ancestor of this process" >&2
  return 2
}

# Removes the owner record just before the lock goes with this process. Safe to call when this
# process holds nothing (a helper, or a refusal before the lock).
snp_lock_release() {
  [ "$SNP_LOCK_MINE" = 1 ] || return 0
  local rec_owner rest
  read -r rec_owner rest <<< "$(snp_lock_record)"
  [ "$rec_owner" = "${CATHEDRAL_SNP_LOCK_OWNER:-}" ] && rm -f "$SNP_LOCK_RECORD"
  SNP_LOCK_MINE=0
  exec 9>&-
  return 0
}

# snp_hold_marker <sealed_dir>: returns 1 when no marker exists. Else prints "<state> <launch_id>"
# and returns 0; a marker that does not read prints "unreadable -" and still counts as a hold.
snp_hold_marker() {
  local m=$1/custom-guest.hold
  [ -e "$m" ] || [ -L "$m" ] || return 1
  python3 -I -c '
import json, re, sys
try:
    d = json.load(open(sys.argv[1]))
    s, l = d["state"], d["launch_id"]
    if s not in ("held", "kit_start") or not isinstance(l, str) or not re.fullmatch(r"cg-[0-9a-f]{12}", l):
        raise ValueError
    print(s, l)
except Exception:
    print("unreadable -")' "$m" 2>/dev/null || echo "unreadable -"
  return 0
}
