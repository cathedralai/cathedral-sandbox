#!/bin/bash
# Runs INSIDE the linux/amd64 Alpine container started by build.sh (rehearsal-only
# test image, AB#1008). /w is the work directory: /w/src/out (the Go helpers),
# /w/init.sh, /w/sshd_config. Writes /w/out. The reference kernel has every driver
# built in, so the initrd carries no kernel module.
set -euo pipefail
: "${EPOCH:?}"
apk info -v 2>/dev/null | sort > /w/out/apk-versions.txt

R=/w/root
rm -rf "$R" && mkdir -p "$R" && cd "$R"
# The "." entry below carries this mode into the initramfs root; without it the
# root stays 1777 and sshd StrictModes refuses the key.
chmod 0755 "$R"
mkdir -p bin sbin usr/bin usr/sbin usr/lib/cathedral usr/lib/ssh etc/ssh lib dev proc sys run tmp var/empty root
chmod 0700 root; chmod 0755 var/empty; chmod 1777 tmp
install -m 0755 /w/init.sh init
install -m 0755 /bin/busybox.static bin/busybox
for a in sh ash cat chmod chown cp cut dmesg echo env grep head hostname id ip kill ln ls mkdir mknod mount \
         ps rm sed sleep sync tail test tr umount uname; do
  ln -s busybox "bin/$a"
done
ln -s ../bin/busybox sbin/poweroff
install -m 0755 /w/src/out/cathedral-attest /w/src/out/cathedral-rehearsal-bootcheck usr/lib/cathedral/
ln -s ../lib/cathedral/cathedral-attest usr/bin/cathedral-attest
install -m 0755 /usr/sbin/sshd usr/sbin/sshd
for f in /usr/lib/ssh/sshd-session /usr/lib/ssh/sshd-auth; do
  [ ! -e "$f" ] || install -m 0755 "$f" usr/lib/ssh/
done
install -m 0755 /usr/bin/ssh-keygen usr/bin/ssh-keygen

# Shared libraries of the dynamic OpenSSH binaries (musl), with their symlinks.
libs() {
  for b in usr/sbin/sshd usr/lib/ssh/* usr/bin/ssh-keygen; do
    ldd "/$b" 2>/dev/null | awk '/=>/ {print $3} /^[[:space:]]*\/lib\/ld-musl/ {print $1}'
  done | sort -u
}
for lib in $(libs); do
  [ -e "$lib" ] || continue
  mkdir -p ".$(dirname "$lib")"
  cp -a "$lib" ".$lib"
  real=$(readlink -f "$lib")
  mkdir -p ".$(dirname "$real")"
  [ -e ".$real" ] || cp -a "$real" ".$real"
done
[ -e lib/ld-musl-x86_64.so.1 ] || { echo "musl loader missing" >&2; exit 1; }
ln -sfn ld-musl-x86_64.so.1 lib/libc.musl-x86_64.so.1

install -m 0644 /w/sshd_config etc/ssh/sshd_config
printf 'root:x:0:0:root:/root:/bin/sh\nsshd:x:22:22:sshd privsep:/var/empty:/bin/false\n' > etc/passwd
printf 'root:x:0:\nsshd:x:22:\n' > etc/group
printf 'root:*:20419:0:::::\nsshd:!:20419:0:::::\n' > etc/shadow
chmod 0644 etc/passwd etc/group; chmod 0600 etc/shadow
printf 'REHEARSAL-ONLY test image for the dedicated custom SNP guest. Never offered to customers.\n' > etc/rehearsal-image
chmod 0644 etc/rehearsal-image

# Config check with a throwaway key outside the tree (the image holds no key).
mkdir -p /tmp/keycheck && ssh-keygen -q -t ed25519 -N '' -f /tmp/keycheck/k
sed 's#/run/cathedral/ssh_host_ed25519_key#/tmp/keycheck/k#' etc/ssh/sshd_config > /tmp/keycheck/cfg
mkdir -p /var/empty && /usr/sbin/sshd -t -f /tmp/keycheck/cfg
echo "sshd -t ok ($(/usr/sbin/sshd -V 2>&1 | head -1))" > /w/out/sshd-check.txt

file init bin/busybox usr/lib/cathedral/* usr/sbin/sshd usr/lib/ssh/* usr/bin/ssh-keygen > /w/out/file-types.txt

# Pack as room-kit/sealed/pack-initrd.sh does: fixed mtimes, sorted names, newc, zstd.
# mindepth 0: "." is in the archive (mode 0755, owner 0:0, fixed mtime).
find "$R" -mindepth 0 -exec touch -h -d "@$EPOCH" {} +
( cd "$R" && find . -mindepth 0 -print0 | LC_ALL=C sort -z \
  | cpio --null -o -H newc --reproducible --owner=0:0 --quiet ) | zstd -q -T1 -19 > /w/out/initrd.cpio.zst
( cd "$R" && find . -mindepth 0 | LC_ALL=C sort ) > /w/out/initrd-files.txt
# The root entry must be the first member, a 0755 directory owned by 0:0.
zstd -dc /w/out/initrd.cpio.zst | cpio -itv --quiet > /tmp/initrd-list.txt
head -1 /tmp/initrd-list.txt > /w/out/initrd-root-entry.txt
grep -Eq '^drwxr-xr-x +[0-9]+ +(root|0) +(root|0) .* \.$' /w/out/initrd-root-entry.txt \
  || { echo "initrd root entry wrong: $(cat /w/out/initrd-root-entry.txt)" >&2; exit 1; }

# root.raw: 1 MiB of zeros plus its dm-verity hash tree (fixed salt and uuid).
# The rehearsal init never mounts it. It exists because #780's launcher always
# attaches a root drive and the cmdline allowlist requires a verity hash and size.
dd if=/dev/zero of=/w/out/root.raw bs=4096 count=256 status=none
salt=$(printf 'rehearsal-test-image-v1' | sha256sum | cut -c1-64)
veritysetup format --data-block-size=4096 --hash-block-size=4096 --data-blocks=256 --hash-offset=1048576 \
  --salt="$salt" --uuid=00000000-0000-4000-8000-000000000001 /w/out/root.raw /w/out/root.raw > /w/out/verity-format.txt
size=$(stat -c %s /w/out/root.raw)
pad=$(( (4096 - size % 4096) % 4096 ))
[ "$pad" = 0 ] || truncate -s $((size + pad)) /w/out/root.raw
awk -F': *' '/^Root hash/ {print $2}' /w/out/verity-format.txt | tr -d '[:space:]' > /w/out/root.verity
veritysetup verify --hash-offset=1048576 /w/out/root.raw /w/out/root.raw "$(cat /w/out/root.verity)"
echo "stage ok"
