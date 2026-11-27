#!/bin/bash
# Offline build from the digest-pinned Ubuntu source package. No VM launch.
# Run in a private mount namespace with a scratch directory large enough for
# sources/objects. Output is a candidate kernel/config, not a hardware PASS.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset ARCH CROSS_COMPILE CC CFLAGS CPPFLAGS LDFLAGS MAKEFLAGS KCONFIG_CONFIG \
    KCONFIG_ALLCONFIG KCFLAGS KCPPFLAGS CFLAGS_KERNEL CFLAGS_MODULE
package=$(readlink -f "${1:?source .deb required}")
work=$(readlink -f "${2:?empty work directory required}")
output=$(readlink -m "${3:?new output directory required}")
expected=1ebe9c770567b8b45e81d490c4af8aa2ccb0e21433c80b94c43423a358447a03
[ -f "$package" ] && [ ! -e "$output" ]
[ "$(sha256sum "$package" | cut -d ' ' -f 1)" = "$expected" ]
[ "$(gcc -dumpfullversion)" = 15.2.0 ]
[ "$(make --version | head -n 1)" = 'GNU Make 4.4.1' ]
[ -d "$work" ] && [ -z "$(ls -A "$work")" ]
export SOURCE_DATE_EPOCH=1795770000 KBUILD_BUILD_USER=cathedral KBUILD_BUILD_HOST=reference
export KBUILD_BUILD_TIMESTAMP='2026-11-27 09:00:00 UTC' KBUILD_BUILD_VERSION=1
mkdir "$work/package" "$work/source" "$work/build"
cp -- "$package" "$work/source.deb"
[ "$(sha256sum "$work/source.deb" | cut -d ' ' -f 1)" = "$expected" ]
dpkg-deb -x "$work/source.deb" "$work/package"
tar -xjf "$work/package/usr/src/linux-source-7.0.0/linux-source-7.0.0.tar.bz2" -C "$work/source" --strip-components=1
# x86 advertises COMMAND_LINE_SIZE-1 in the boot header. Spec-r9 intake
# requires at least 2048; use a 4096-byte buffer without relaxing the guest's
# exact signed-cmdline check or the owner's 2033-byte launch allowlist.
python3 - "$work/source/arch/x86/include/asm/setup.h" <<'PY'
import pathlib
import re
import sys
path = pathlib.Path(sys.argv[1])
source = path.read_text()
updated, count = re.subn(r'(#define\s+COMMAND_LINE_SIZE\s+)2048\b', r'\g<1>4096', source)
assert count == 1, "unexpected pinned kernel command-line definition"
path.write_text(updated)
PY
make -C "$work/source" O="$work/build" x86_64_defconfig
config="$work/source/scripts/config"
for option in X86_64 IKCONFIG IKCONFIG_PROC AMD_MEM_ENCRYPT VIRT_DRIVERS SEV_GUEST TSM_REPORTS \
    VIRTIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET BLK_DEV_DM DM_VERITY DM_CRYPT DM_INTEGRITY \
    BLK_DEV_INITRD RD_ZSTD EFI EFI_STUB SQUASHFS SQUASHFS_ZSTD DEVTMPFS \
    PROC_FS SYSFS TMPFS CONFIGFS_FS FW_CFG_SYSFS NET INET UNIX \
    SERIAL_8250 SERIAL_8250_CONSOLE CRYPTO_SHA256 CRYPTO_AES CRYPTO_XTS; do
    "$config" --file "$work/build/.config" --enable "$option"
done
for option in CMDLINE_BOOL BOOT_CONFIG_EMBED BOOT_CONFIG_FORCE MODULES DEBUG_INFO \
    DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT DEBUG_INFO_BTF SYSTEM_TRUSTED_KEYRING \
    NET_9P 9P_FS DRM SOUND WLAN WIRELESS NFC ATA SCSI USB ETHERNET \
    NFS_FS NFSD CIFS CEPH_FS IPV6_SIT; do
    "$config" --file "$work/build/.config" --disable "$option"
done
"$config" --file "$work/build/.config" --set-str INITRAMFS_SOURCE '' --set-str LOCALVERSION '-cathedral-custom-v1'
"$config" --file "$work/build/.config" --disable LOCALVERSION_AUTO
make -C "$work/source" O="$work/build" olddefconfig
cp "$work/build/.config" "$output.config-check"
for option in IKCONFIG AMD_MEM_ENCRYPT SEV_GUEST TSM_REPORTS VIRTIO_PCI VIRTIO_BLK \
    VIRTIO_NET BLK_DEV_DM DM_VERITY DM_CRYPT DM_INTEGRITY BLK_DEV_INITRD RD_ZSTD EFI_STUB \
    SQUASHFS CONFIGFS_FS FW_CFG_SYSFS; do
    grep -qx "CONFIG_$option=y" "$work/build/.config" || { echo "Required builtin missing: $option" >&2; exit 1; }
done
# IPV6_SIT (on in x86_64_defconfig) makes the kernel create a device-less sit0
# at boot, and bootstate refuses any interface but the one virtio NIC. "set -e"
# ignores a "!" pipeline, so each forbidden option exits explicitly.
for option in CMDLINE_BOOL BOOT_CONFIG_EMBED BOOT_CONFIG_FORCE IPV6_SIT; do
    if grep -Eq "^CONFIG_$option=[ym]$" "$work/build/.config"; then
        echo "Forbidden option set: $option" >&2
        exit 1
    fi
done
grep -qx 'CONFIG_INITRAMFS_SOURCE=""' "$work/build/.config"
make -C "$work/source" O="$work/build" -j6 bzImage
mkdir "$output"
install -m 0444 "$work/build/arch/x86/boot/bzImage" "$output/vmlinuz"
install -m 0444 "$work/build/.config" "$output/kernel.config"
"$work/source/scripts/extract-ikconfig" "$output/vmlinuz" > "$output/embedded.config"
cmp "$output/kernel.config" "$output/embedded.config"
python3 - "$output/vmlinuz" <<'PY'
from pathlib import Path
import struct
import sys
data = Path(sys.argv[1]).read_bytes()
pe = struct.unpack_from('<I', data, 0x3c)[0]
assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
assert data[0x202:0x206] == b'HdrS'
assert struct.unpack_from('<H', data, 0x206)[0] >= 0x20c
assert struct.unpack_from('<H', data, 0x236)[0] & 1
assert struct.unpack_from('<I', data, 0x238)[0] >= 2048
PY
sha256sum "$output/vmlinuz" "$output/kernel.config" "$work/source.deb" > "$output/SHA256SUMS"
