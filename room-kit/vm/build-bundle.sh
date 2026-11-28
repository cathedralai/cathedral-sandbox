#!/bin/bash
# Build the files of one sealed customer VM bundle (AB#999, VM runtime spec r2 6.1 and 7.3).
# Run as root on an Ubuntu build host with mmdebstrap, e2fsprogs 1.47.1 or later, veritysetup
# (cryptsetup-bin) and kmod. VM_BUNDLE_TOOLS names a directory with the pinned static mke2fs
# and veritysetup (scripts/build_vm_initrd_tools.py); the reference build
# (.github/workflows/vm-bundle-build.yml) uses it so the image bytes do not follow the host.
#
#   build-bundle.sh base-root bundle.env [--verify-reproducible]
#       the customer's base root: ext4 image + dm-verity tree
#   build-bundle.sh kernel bundle.env [--verify-reproducible]
#       the stock Ubuntu kernel and its module tree
#   build-bundle.sh manifest bundle.env
#       OVMF and the VM initrd in, then manifest.json
#
# --verify-reproducible builds the step a second time from nothing (a fresh mmdebstrap)
# and stops unless every output is byte for byte the same. Run it before publishing.
#
# The VM initrd (PR VM1b) is built between kernel and manifest: it packs the module
# tree from $VM_BUNDLE_OUT/build/modules-<release>.tar. Both package sets come from one
# pinned snapshot.ubuntu.com id (its release, -updates and -security pockets) and must equal their packages.lock (packages_lock.py, as
# build-guest.sh's pinned base). Output in $VM_BUNDLE_OUT, all digested by the manifest:
#   OVMF.amdsev.fd vmlinuz initrd.cpio.zst base-root.raw base-root.packages.lock
#   kernel.packages.lock manifest.json
# and build/ (inputs for VM1b and logs; not published). See bundle.env.example.
set -euo pipefail
umask 022
VM=$(cd "$(dirname "$0")" && pwd)
KIT=$(cd "$VM/.." && pwd)
LOCK_TOOL=$KIT/sealed/packages_lock.py

# The customer's userland. No kernel, bootloader or initramfs package: the kernel is the
# bundle's and its modules are bind-mounted from the measured initrd. No cloud-init and no
# qemu-guest-agent (spec r2 7.3, 6.5). systemd-networkd reads the file the init writes from
# the link; sshd takes the host keys the init makes at first boot.
BASE_PKGS=systemd,systemd-sysv,systemd-resolved,systemd-timesyncd,udev,kmod,dbus,iproute2,iputils-ping,netbase,openssh-server,sudo,ca-certificates,curl,gnupg,less,vim-tiny,procps,psmisc,util-linux,passwd,e2fsprogs,tzdata,locales,bash-completion,apt-utils,lsb-release
# Stock Ubuntu kernel, the package the kit boots (build-guest.sh PKGS). Only its vmlinuz
# and module tree leave this root.
KERNEL_PKGS=linux-image-virtual
# The customer root gets this package's whole module tree (read-only, from the initrd), so
# Docker, nft, ufw, WireGuard and overlay work as on a stock Ubuntu VM.
KERNEL_TREE_PKG=linux-modules
# sev-guest (with tsm, which it needs) and qemu_fw_cfg are only in linux-modules-extra, which
# is versioned: bundle.env names the release (VM_BUNDLE_KERNEL_RELEASE) and the build stops
# unless linux-image-virtual resolves to the same one in the snapshot.
KERNEL_EXTRA_PKG=linux-modules-extra
# Loaded or built in; the VM init (7.2) needs each one before it can open the disks. The
# order is the closure's boot_modules order. aesni_intel gives dm-crypt the AES-NI xts(aes):
# without it dm-crypt takes the generic T-table AES, which is slow and whose key-dependent
# memory accesses the host can see through the cache.
KERNEL_MODULES="sev-guest dm-verity aesni_intel dm-crypt qemu_fw_cfg virtio_blk virtio_net"
KERNEL_CONFIG_Y="AMD_MEM_ENCRYPT EFI_STUB BLK_DEV_INITRD RD_ZSTD"
KERNEL_CONFIG_YM="SEV_GUEST DM_VERITY DM_CRYPT VIRTIO_BLK VIRTIO_NET CRYPTO_AES_NI_INTEL"

usage() { echo "usage: build-bundle.sh base-root|kernel bundle.env [--verify-reproducible] | manifest bundle.env" >&2; exit 2; }
[ $# = 2 ] || [ $# = 3 ] || usage
CMD=$1
case "$CMD" in base-root|kernel|manifest) ;; *) usage ;; esac
VERIFY=0
if [ $# = 3 ]; then
  [ "$3" = --verify-reproducible ] && [ "$CMD" != manifest ] || usage
  VERIFY=1
fi
ENV_FILE=$(readlink -f "$2")
# shellcheck disable=SC1090
source "$ENV_FILE"
log() { echo "[vm-bundle] $*"; }
die() { echo "[vm-bundle] $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"

# ---------------------------------------------------------------- inputs (checked before any build work)
SNAPSHOT=${VM_BUNDLE_SNAPSHOT:-}
SNAPSHOT_EPOCH=$(python3 "$LOCK_TOOL" snapshot-epoch "$SNAPSHOT") \
  || die "VM_BUNDLE_SNAPSHOT must be a snapshot.ubuntu.com id such as 20261101T000000Z: a bundle builds only from a pinned snapshot"
SUITE=${VM_BUNDLE_SUITE:-noble}
KERNEL_RELEASE=${VM_BUNDLE_KERNEL_RELEASE:-}
if [ "$CMD" = kernel ] && ! [[ "$KERNEL_RELEASE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+$ ]]; then
  die "VM_BUNDLE_KERNEL_RELEASE must name the kernel release the snapshot resolves, such as 6.8.0-151-generic"
fi
[[ "$SUITE" =~ ^[a-z]{2,20}$ ]] || die "VM_BUNDLE_SUITE must be an Ubuntu suite name"
MIRROR=https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT
KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
OUT=${VM_BUNDLE_OUT:-}
[[ "$OUT" = /* ]] || die "VM_BUNDLE_OUT must be an absolute directory"
B=$OUT/build
LOCK_UPDATE=${VM_BUNDLE_LOCK_UPDATE:-0}
TOOLS=${VM_BUNDLE_TOOLS:-}
if [ -n "$TOOLS" ] && ! { [ -x "$TOOLS/mke2fs" ] && [ -x "$TOOLS/veritysetup" ]; }; then
  die "VM_BUNDLE_TOOLS must hold executable mke2fs and veritysetup"
fi
MKE2FS=${TOOLS:+$TOOLS/}mke2fs
VERITYSETUP=${TOOLS:+$TOOLS/}veritysetup
case "$LOCK_UPDATE" in 0|1) ;; *) die "VM_BUNDLE_LOCK_UPDATE must be 0 or 1" ;; esac
# The kit commit time, so the same kit gives the same bytes on any build host.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$KIT" log -1 --format=%ct 2>/dev/null || echo 0)}
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || die "build from a git checkout or set SOURCE_DATE_EPOCH"
mkdir -p "$B"

# uuid_of LABEL: a UUID fixed by LABEL, so the file system and verity ids do not depend on the run.
uuid_of() { python3 -c 'import hashlib,sys,uuid;print(uuid.UUID(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:32]))' "$1"; }
# clamp DIR: every mtime is the epoch (pack-initrd.sh does the same for the kit initrd).
# touch cannot set ctime; mke2fs clamps that one (the e2fsprogs floor below).
clamp() { find "$1" -mindepth 1 -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +; }

# >>> e2fsprogs floor (tests/test_vm_measure.py runs this block)
# mke2fs -d copies each file's atime, ctime and mtime. Before 1.47.1 it copies them as
# they are (misc/create_inode.c set_inode_extra, v1.47.0 line 130), so ctime, which is
# the time of this build, lands in the image and two builds differ. 1.47.1 clamps every
# timestamp to SOURCE_DATE_EPOCH when that is set (clamped_time; lib/ext2fs/initialize.c
# turns it on only for SOURCE_DATE_EPOCH, not E2FSPROGS_FAKE_TIME). Older versions are
# refused, even a distribution build with the change backported: the version is all
# this can check, and --verify-reproducible is the real test.
E2FSPROGS_MIN=1.47.1
e2fsprogs_floor() {
  local have
  have=$("${MKE2FS:-mke2fs}" -V 2>&1 | awk 'NR == 1 && $1 == "mke2fs" { print $2 }')
  python3 -c 'import re, sys
have, want = sys.argv[1], sys.argv[2]
m = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", have)
sys.exit(0 if m and tuple(int(x or 0) for x in m.groups()) >= tuple(map(int, want.split("."))) else 1)' "$have" "$E2FSPROGS_MIN" \
    || { echo "[vm-bundle] mke2fs ${have:-not found} is older than $E2FSPROGS_MIN: it copies build-time ctimes into the image, so the base root would not be reproducible" >&2; exit 1; }
}
# <<< e2fsprogs floor

# pinned_root NAME PACKAGES EXPECTED_LOCK: mmdebstrap NAME from the snapshot into $B/NAME and
# write $OUT/NAME.packages.lock; stop unless it equals EXPECTED_LOCK (or LOCK_UPDATE=1).
# The release, -updates and -security pockets all come from the one snapshot id, so the
# kernel and every security fix are what that snapshot resolves, on any day it is built.
pinned_root() {
  local name=$1 pkgs=$2 want=$3 root=$B/$1 pocket sources=()
  [ "$LOCK_UPDATE" = 1 ] || [ -f "$want" ] \
    || die "$name: set its expected packages.lock in bundle.env, or VM_BUNDLE_LOCK_UPDATE=1 to make one"
  [ -f "$KEYRING" ] || die "no Ubuntu archive keyring at $KEYRING"
  for pocket in "$SUITE" "$SUITE-updates" "$SUITE-security"; do
    sources+=("deb [signed-by=$KEYRING] $MIRROR $pocket main universe")
  done
  rm -rf "${root:?}" "$root.packages.lock.tmp"
  log "mmdebstrap $SUITE $name from snapshot $SNAPSHOT ($SUITE, $SUITE-updates, $SUITE-security)"
  # The hook runs on the build host before mmdebstrap removes the apt lists, which hold
  # the sha256 of every .deb (packages_lock.py emit).
  ( export SOURCE_DATE_EPOCH=$SNAPSHOT_EPOCH
    mmdebstrap --variant=minbase --aptopt='APT::Install-Recommends "false"' \
      --customize-hook="python3 $(printf '%q' "$LOCK_TOOL") emit \"\$1\" > $(printf '%q' "$root.packages.lock.tmp")" \
      --include="$pkgs" "$SUITE" "$root" "${sources[@]}" )
  mv "$root.packages.lock.tmp" "$OUT/$name.packages.lock"
  python3 "$LOCK_TOOL" check "$root" "$OUT/$name.packages.lock" || die "$name does not match its packages.lock"
  if [ "$LOCK_UPDATE" = 1 ]; then
    log "$name: VM_BUNDLE_LOCK_UPDATE=1, new lock at $OUT/$name.packages.lock"
  elif ! cmp -s "$want" "$OUT/$name.packages.lock"; then
    diff -u "$want" "$OUT/$name.packages.lock" | head -40 >&2 || true
    die "$name: resolved packages differ from $want; set VM_BUNDLE_LOCK_UPDATE=1 to accept a new lock"
  fi
}

# host_leaks ROOT: stop if ROOT's etc or var holds a copy of the build host's resolv.conf,
# hostname, hosts or machine-id, or names its hostname or DNS search domain. mmdebstrap copies
# the host's resolv.conf and hostname in, and package scripts can keep copies of them (the
# systemd-resolved backup); such a file differs per build host and is not the customer's.
host_leaks() {
  local root=$1 f s found=0 sums=() marks=()
  for f in /etc/resolv.conf /etc/hostname /etc/hosts /etc/machine-id; do
    [ -s "$f" ] && sums+=("$(sha256sum < "$f" | cut -d' ' -f1)")
  done
  s=$(hostname 2>/dev/null || true)
  [ ${#s} -ge 8 ] && marks+=("$s")
  for s in $(awk '$1 == "search" || $1 == "domain" { for (i = 2; i <= NF; i++) print $i }' /etc/resolv.conf 2>/dev/null); do
    [ ${#s} -ge 8 ] && [[ "$s" = *.* ]] && marks+=("$s")
  done
  while IFS= read -r -d '' f; do
    s=$(sha256sum < "$f" | cut -d' ' -f1)
    if [[ " ${sums[*]} " = *" $s "* ]]; then echo "[vm-bundle] copy of a build host file: ${f#"$root"/}" >&2; found=1; fi
  done < <(find "$root/etc" "$root/var" -type f -print0)
  for s in "${marks[@]}"; do
    if grep -rlF --no-messages -- "$s" "$root/etc" "$root/var" >&2; then found=1; fi
  done
  [ "$found" = 0 ] || die "the base root holds files from this build host (listed above)"
}

# ---------------------------------------------------------------- base root (7.3)
build_base_root() {
  e2fsprogs_floor
  pinned_root base-root "$BASE_PKGS" "${VM_BUNDLE_BASE_LOCK:-}"
  local R=$B/base-root
  if grep -E '^(linux-(image|modules|headers)-|grub|initramfs-tools |cloud-init |qemu-guest-agent )' \
       "$OUT/base-root.packages.lock" >&2; then
    die "the base root must hold no kernel, bootloader, initramfs, cloud-init or guest agent package"
  fi
  in_root() { chroot "$R" "$@"; }
  # Per VM, made by the init at first boot (7.2 step 4.2): machine id, host keys, the user.
  : > "$R/etc/machine-id"
  rm -f "$R/var/lib/dbus/machine-id" "$R/var/lib/systemd/random-seed" "$R"/etc/ssh/ssh_host_*
  echo cathedral-vm > "$R/etc/hostname"
  printf '127.0.0.1 localhost\n127.0.1.1 cathedral-vm\n::1 localhost ip6-localhost ip6-loopback\n' > "$R/etc/hosts"
  : > "$R/etc/fstab"   # the init mounts the root; nothing else is mounted from a disk
  # cloud-init is not installed; this marker keeps it off if the customer installs it,
  # and the init re-asserts it on every boot (6.5).
  mkdir -p "$R/etc/cloud"
  : > "$R/etc/cloud/cloud-init.disabled"
  cat > "$R/etc/ssh/sshd_config.d/10-cathedral.conf" <<'EOF'
# Cathedral VM default: keys only. The customer owns this file after first boot.
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
  # The network file comes from the init at every boot (/run/systemd/network, from the link).
  ln -sfn ../run/systemd/resolve/stub-resolv.conf "$R/etc/resolv.conf"
  # systemd-resolved's postinst keeps the build host's resolv.conf here.
  rm -f "$R/etc/.resolv.conf.systemd-resolved.bak"
  in_root systemctl enable -q ssh.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service
  # sshd runs as ssh.service, not socket-activated. openssh's postinst enabled ssh.socket, which
  # links it into sockets.target.wants/ and ssh.service.requires/, and a mask removes neither: a
  # service that requires a masked unit is dropped from the boot with no console line (B5, port
  # 22 refused). So disable it, then mask it ("vm_bundle_build_summary.py units" checks the root).
  in_root systemctl disable -q ssh.socket
  rm -f "$R/etc/systemd/system/ssh.service.requires/ssh.socket"
  if [ -d "$R/etc/systemd/system/ssh.service.requires" ]; then
    rmdir --ignore-fail-on-non-empty "$R/etc/systemd/system/ssh.service.requires"
  fi
  in_root systemctl mask -q ssh.socket
  in_root passwd -l root >/dev/null
  # apt upgrade updates userland; the kernel is the bundle's (spec r2 4), so no kernel or
  # bootloader package is ever installed here.
  rm -f "$R/etc/apt/sources.list" "$R"/etc/apt/sources.list.d/*
  cat > "$R/etc/apt/sources.list.d/ubuntu.sources" <<EOF
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: $SUITE $SUITE-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: $SUITE-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
  cat > "$R/etc/apt/preferences.d/cathedral-no-kernel" <<'EOF'
# The VM boots the kernel of its measured bundle; a kernel here would never run.
Package: linux-image-* linux-modules-* linux-headers-* linux-generic* linux-virtual* grub* shim*
Pin: version *
Pin-Priority: -1
EOF
  # /etc/shadow field 3 is the day each account was made: pin it (build-guest.sh "shadow day").
  local day=$(( SOURCE_DATE_EPOCH / 86400 )) f
  for f in "$R/etc/shadow" "$R/etc/shadow-"; do
    [ -f "$f" ] || continue
    awk -F: -v OFS=: -v d="$day" '$3 != "" { $3 = d } { print }' "$f" > "$f.tmp"
    cat "$f.tmp" > "$f"
    rm -f "$f.tmp"
  done
  rm -rf "${R:?}"/var/cache/apt/archives/*.deb "${R:?}"/var/lib/apt/lists/* "${R:?}"/tmp/* "${R:?}"/var/tmp/*
  rm -f "$R/var/cache/ldconfig/aux-cache"   # holds inode numbers and times of this build
  find "$R/var/log" -type f -delete
  host_leaks "$R"
  clamp "$R"

  # ext4 image of the root. The init copies it into the file system area of the LUKS
  # root at first boot and grows it to the disk (7.2 step 4.2). Ids come from the lock and
  # every timestamp is the epoch, so two builds of one lock give one image;
  # --verify-reproducible checks that.
  local lock_sha size_mib data_bytes salt root_hash
  lock_sha=$(sha256sum < "$OUT/base-root.packages.lock" | cut -d' ' -f1)
  size_mib=$(( $(du -s --apparent-size --block-size=1M "$R" | cut -f1) * 5 / 4 + 512 ))
  size_mib=$(( (size_mib + 3) / 4 * 4 ))
  rm -f "$B/base-root.ext4"
  # SOURCE_DATE_EPOCH (not E2FSPROGS_FAKE_TIME) is what turns on the clamping; LC_ALL=C
  # fixes the name order mke2fs -d adds files in (scandir with alphasort). MKE2FS_CONFIG
  # names no file, so mke2fs takes its compiled-in defaults, not the host's /etc/mke2fs.conf.
  LC_ALL=C SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH MKE2FS_CONFIG=$B/no-mke2fs.conf "$MKE2FS" -t ext4 -q -F -b 4096 -L cathedral-root \
    -U "$(uuid_of "cathedral-vm-base-root-fs $lock_sha")" \
    -E "hash_seed=$(uuid_of "cathedral-vm-base-root-hash $lock_sha"),root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0,nodiscard" \
    -d "$R" "$B/base-root.ext4" "${size_mib}M"
  e2fsck -fn "$B/base-root.ext4" >/dev/null || die "the base root image fails e2fsck"

  # dm-verity tree after the data, in the same file (hash offset = data bytes), as the
  # custom guest root (spec D 5.6); the identity names the root hash and data bytes.
  data_bytes=$(stat -c %s "$B/base-root.ext4")
  [ $(( data_bytes % 4096 )) = 0 ] || die "the base root image is not 4 KiB aligned"
  salt=$(sha256sum < "$B/base-root.ext4" | cut -d' ' -f1)
  cp "$B/base-root.ext4" "$B/base-root.raw.tmp"
  "$VERITYSETUP" format "$B/base-root.raw.tmp" "$B/base-root.raw.tmp" --data-block-size=4096 --hash-block-size=4096 \
    --data-blocks=$(( data_bytes / 4096 )) --hash-offset="$data_bytes" --salt="$salt" \
    --uuid="$(uuid_of "cathedral-vm-base-root-verity $salt")" > "$B/base-root.verity.txt"
  root_hash=$(awk -F: '/^Root hash:/ { gsub(/[ \t]/, "", $2); print $2 }' "$B/base-root.verity.txt")
  [[ "$root_hash" =~ ^[0-9a-f]{64}$ ]] || die "veritysetup gave no root hash"
  "$VERITYSETUP" verify "$B/base-root.raw.tmp" "$B/base-root.raw.tmp" "$root_hash" --hash-offset="$data_bytes" \
    || die "the base root fails its own verity check"
  mv "$B/base-root.raw.tmp" "$OUT/base-root.raw"
  echo "$root_hash" > "$B/base-root.verity"
  echo "$data_bytes" > "$B/base-root.data-bytes"
  log "base root: $(du -h "$OUT/base-root.raw" | cut -f1), verity $root_hash, data bytes $data_bytes"
}

# ---------------------------------------------------------------- kernel and modules (6.1)
build_kernel() {
  pinned_root kernel "$KERNEL_PKGS,$KERNEL_EXTRA_PKG-$KERNEL_RELEASE" "${VM_BUNDLE_KERNEL_LOCK:-}"
  local K=$B/kernel kver opt m
  kver=$(python3 "$LOCK_TOOL" kernel "$OUT/kernel.packages.lock")
  [ "$kver" = "$KERNEL_RELEASE" ] \
    || die "linux-image-virtual resolves to $kver in snapshot $SNAPSHOT, but VM_BUNDLE_KERNEL_RELEASE is $KERNEL_RELEASE"
  [ -f "$K/boot/vmlinuz-$kver" ] && [ -f "$K/boot/config-$kver" ] && [ -d "$K/lib/modules/$kver" ] \
    || die "kernel $kver: vmlinuz, config or module tree missing"
  for opt in $KERNEL_CONFIG_Y; do
    grep -qx "CONFIG_$opt=y" "$K/boot/config-$kver" || die "kernel $kver: CONFIG_$opt must be y"
  done
  for opt in $KERNEL_CONFIG_YM; do
    grep -qE "^CONFIG_$opt=(y|m)$" "$K/boot/config-$kver" || die "kernel $kver: CONFIG_$opt must be y or m"
  done
  # A built-in cmdline would add kernel parameters outside the measured template.
  ! grep -qx 'CONFIG_CMDLINE_BOOL=y' "$K/boot/config-$kver" || die "kernel $kver: CONFIG_CMDLINE_BOOL must be off"
  # Each boot module is a module file or built in. A built-in one must be listed in the
  # package's modules.builtin; the VM initrd recipe then ships no file for it and the init
  # loads none (build-vm-initrd.py load_order). build/boot-modules.txt records which is which.
  local file key tree
  tree=$(readlink -f "$K/lib/modules/$kver")
  : > "$B/boot-modules.txt"
  for m in $KERNEL_MODULES; do
    file=$(modinfo -b "$K" -k "$kver" -F filename "$m" 2>/dev/null) || die "kernel $kver: module $m is missing"
    key=${m//-/_}
    if [ "$file" = "(builtin)" ]; then
      awk -v k="$key" '{ n = $0; sub(/.*\//, "", n); sub(/\.ko$/, "", n); gsub(/-/, "_", n); if (n == k) found = 1 }
        END { exit !found }' "$K/lib/modules/$kver/modules.builtin" \
        || die "kernel $kver: modinfo says $m is built in, but modules.builtin does not list it"
      echo "$m built-in" >> "$B/boot-modules.txt"
    else
      file=$(readlink -f "$file")
      [[ "$file" = "$tree/"* ]] && [ -f "$file" ] || die "kernel $kver: module $m is outside its module tree"
      echo "$m module ${file#"$tree/"}" >> "$B/boot-modules.txt"
    fi
  done
  # The one crypto guard: AES-NI built in, or loaded by the init before any disk opens.
  grep -qx 'CONFIG_CRYPTO_AES_NI_INTEL=y' "$K/boot/config-$kver" || grep -q '^aesni_intel module ' "$B/boot-modules.txt" \
    || die "kernel $kver: aesni_intel is neither built in nor a boot module, so dm-crypt would run the generic AES"
  install -m 0644 "$K/boot/vmlinuz-$kver" "$OUT/vmlinuz"
  install -m 0644 "$K/boot/config-$kver" "$B/config-$kver"
  # The module tree for the VM initrd (VM1b), which bind-mounts it read-only at
  # /lib/modules/<release> in the customer root (6.1). It holds every file $KERNEL_TREE_PKG
  # ships there, and from linux-modules-extra only the boot modules and what modules.dep says
  # they need. Links go (the vdso .build-id debug links; the initrd recipe takes no link),
  # modules.order is cut to the kept files, and the depmod of this root (its pinned kmod)
  # rebuilds the indexes for that set. The init still loads only the boot modules.
  python3 -I - "$tree" "$B/boot-modules.txt" "$K/var/lib/dpkg/info/$KERNEL_TREE_PKG-$kver.list" <<'EOF' \
    || die "kernel $kver: cannot cut the module tree"
import sys
from pathlib import Path
tree, listing, package = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
dep = {}
for line in (tree / "modules.dep").read_text().splitlines():
    name, _, needs = line.partition(":")
    dep[name] = needs.split()
keep = set()
for line in listing.read_text().splitlines():
    fields = line.split()
    if fields[1] == "module":
        if fields[2] not in dep:
            sys.exit(f"modules.dep has no entry for {fields[2]}")
        keep.add(fields[2])
        keep.update(dep[fields[2]])
boot = len(keep)
prefixes = (f"/lib/modules/{tree.name}/", f"/usr/lib/modules/{tree.name}/")
for line in package.read_text().splitlines():
    for prefix in prefixes:
        if line.startswith(prefix) and (tree / line[len(prefix):]).is_file() \
                and not (tree / line[len(prefix):]).is_symlink():
            keep.add(line[len(prefix):])
if len(keep) == boot:
    sys.exit(f"{package.name} lists no file of this tree")
indexes = {"modules.builtin", "modules.builtin.modinfo", "modules.order"}
for path in sorted(tree.rglob("*"), reverse=True):
    rel = path.relative_to(tree).as_posix()
    if path.is_symlink() or not path.is_dir():
        if rel not in keep and rel not in indexes:
            path.unlink()
    elif not any(path.iterdir()):
        path.rmdir()
order = tree / "modules.order"
kept = [line for line in order.read_text().splitlines() if line in keep or line + ".zst" in keep]
order.write_text("".join(line + "\n" for line in kept))
print(f"kept {len(keep)} files: the {package.name.removesuffix('.list')} tree and {boot} boot module files")
EOF
  chroot "$K" depmod -a "$kver"
  for m in $KERNEL_MODULES; do
    modinfo -b "$K" -k "$kver" -F filename "$m" >/dev/null 2>&1 || die "kernel $kver: module $m is missing after the cut"
  done
  clamp "$K/lib/modules/$kver"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --format=gnu \
    -C "$K/lib/modules" -cf "$B/modules-$kver.tar" "$kver"
  echo "$kver" > "$B/kernel-release"
  log "kernel $kver: vmlinuz $(sha256sum < "$OUT/vmlinuz" | cut -c1-16), modules $B/modules-$kver.tar"
}

# ---------------------------------------------------------------- manifest (6.1)
build_manifest() {
  local ovmf=${VM_BUNDLE_OVMF:-/usr/share/ovmf/OVMF.amdsev.fd} source=${VM_BUNDLE_OVMF_SOURCE:-} pkg
  local initrd=${VM_BUNDLE_INITRD:-}
  [ -s "$B/base-root.verity" ] && [ -s "$B/kernel-release" ] || die "run base-root and kernel first"
  [ -f "$ovmf" ] || die "no AmdSev firmware at $ovmf; set VM_BUNDLE_OVMF"
  [ -f "$initrd" ] || die "VM_BUNDLE_INITRD must name the VM initrd (built by the VM1b initrd recipe)"
  [[ "${VM_BUNDLE_INITRD_VERSION:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "VM_BUNDLE_INITRD_VERSION is required"
  if [ -z "$source" ]; then
    # Like the kit, the firmware is the host's AmdSev build, copied so a host ovmf
    # upgrade never changes a VM (build-guest.sh:544). Record which package it was.
    pkg=$(dpkg -S "$(readlink -f "$ovmf")" 2>/dev/null | head -1 | cut -d: -f1 || true)
    [ -z "$pkg" ] || source="$pkg=$(dpkg-query -W -f='${Version}' "$pkg")"
  fi
  [ -n "$source" ] || die "set VM_BUNDLE_OVMF_SOURCE: where $ovmf comes from"
  install -m 0644 "$ovmf" "$OUT/OVMF.amdsev.fd"
  install -m 0644 "$initrd" "$OUT/initrd.cpio.zst"
  python3 -I "$VM/vm_measure.py" bundle-manifest --dir "$OUT" --label "${VM_BUNDLE_LABEL:-}" \
    --cpu-family "${VM_BUNDLE_CPU_FAMILY:-}" --qemu-version "${VM_BUNDLE_QEMU_VERSION:-}" \
    --kernel-release "$(cat "$B/kernel-release")" --initrd-version "$VM_BUNDLE_INITRD_VERSION" \
    --snapshot "$SNAPSHOT" --base-root-verity "$(cat "$B/base-root.verity")" \
    --base-root-data-bytes "$(cat "$B/base-root.data-bytes")" --ovmf-source "$source"
  python3 -I "$VM/vm_measure.py" check-bundle "$OUT"
}

# The outputs of each step, compared by --verify-reproducible.
step_outputs() {
  case "$CMD" in
    base-root) echo base-root.raw base-root.packages.lock build/base-root.verity build/base-root.data-bytes ;;
    kernel) echo vmlinuz kernel.packages.lock build/kernel-release build/boot-modules.txt "build/config-$(cat "$B/kernel-release")" \
                 "build/modules-$(cat "$B/kernel-release").tar" ;;
  esac
}

run_step() {
  case "$CMD" in
    base-root) build_base_root ;;
    kernel) build_kernel ;;
    manifest) build_manifest ;;
  esac
}

run_step
if [ "$VERIFY" = 1 ]; then
  FIRST=$OUT
  FILES=$(step_outputs)
  OUT=$FIRST/build/second
  B=$OUT/build
  rm -rf "${OUT:?}"
  mkdir -p "$B"
  log "--verify-reproducible: building $CMD again from nothing in $OUT"
  run_step
  differ=0
  for f in $FILES; do
    if cmp -s "$FIRST/$f" "$OUT/$f"; then
      log "same: $f $(sha256sum < "$OUT/$f" | cut -c1-16)"
    else
      echo "[vm-bundle] differs: $f" >&2
      differ=1
    fi
  done
  [ "$differ" = 0 ] || die "$CMD is not reproducible; the second build is kept in $OUT"
  rm -rf "${OUT:?}"
  log "$CMD reproducible: two builds from nothing gave the same bytes"
fi
