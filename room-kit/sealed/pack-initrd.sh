#!/bin/bash
# Pack a root directory into a zstd cpio initrd whose bytes depend only on the
# tree contents and SOURCE_DATE_EPOCH, not on build time, checkout time or
# directory order. Sourced by build-guest.sh; also run by the reproducibility test.
# Usage: pack_initrd ROOT_DIR OUT_FILE EPOCH_SECONDS
pack_initrd() {
  local root=$1 out=$2 epoch=$3
  # Every mtime is the epoch: files written by this build get "now", the kit
  # files get the checkout time, and either would change the measurement.
  find "$root" -mindepth 1 \( -path "$root/proc/*" -o -path "$root/sys/*" -o -path "$root/dev/*" \) -prune -o \
    -exec touch -h -d "@$epoch" {} +
  ( cd "$root" && find . -mindepth 1 \( -path './proc/*' -o -path './sys/*' -o -path './dev/*' \) -prune -o -print0 \
    | LC_ALL=C sort -z | cpio --null -o -H newc --reproducible --quiet ) | zstd -q -T0 -10 > "$out"
}
