#!/bin/bash
# Build the root disk of the REHEARSAL-ONLY test image for reference initrd v1 (#808).
# Reference initrd v1 boots cathedral-init, which mounts a dm-verity root and checks that
# /usr/bin/cathedral-attest is the helper it pins, so the zero-filled root of build.sh
# cannot boot it. This runs the reference root recipe (scripts/build_custom_guest_root.py)
# on a Debian bookworm base from a fixed snapshot, with the cathedral-attest of
# reference-build run 46063612613. Never offered to customers.
#
# Usage: build-ref-root.sh CATHEDRAL_ATTEST NEW_OUT_DIR
# Runs on a GitHub-hosted Ubuntu 26.04 runner: it installs pinned packages and runs
# mmdebstrap with sudo. Never on a hotel host.
set -euo pipefail
# The recipe makes some directories with a plain mkdir, and their modes go into root.raw.
# Ubuntu's default user umask is 0002, so fix it here or a rebuild gives other bytes.
umask 022
attest=$(readlink -f "${1:?cathedral-attest from reference-build run 46063612613}")
out=$(readlink -m "${2:?new output directory}")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
[ ! -e "$out" ] || { echo "$out exists" >&2; exit 1; }
mkdir -p "$out"

ATTEST_SHA256=44824e132fc3529c0aff01ba1f2a093d2844beb82a3478613a26b11f012f4f29
SNAPSHOT=http://snapshot.debian.org/archive/debian/20261127T000000Z
SUITE=bookworm
# sha256 of that snapshot's dists/bookworm/InRelease, as curl fetches it below. apt inside
# mmdebstrap fetches its own copy and checks only the Debian signature, so the base pin
# below is what fixes the package set.
INRELEASE_SHA256=77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa
INCLUDE=systemd-sysv,openssh-server,iproute2,e2fsprogs,ca-certificates
BASE_EPOCH=1795737600   # 2026-11-27T00:00:00Z, the snapshot time
ROOT_EPOCH=1795770000   # the reference recipe's epoch
# The published outputs (#816, CI run 46089051536). Any drift fails the build; a change that
# moves them re-pins them here on purpose.
EXPECTED_BASE_SHA256=a39b08f1ec14291957a22b6d417e2c7a70b4f4f6123700cceea9bcfa7512075a
EXPECTED_ROOT_SHA256=e674d5a55bc8ffdce0a04ec291ac70793e730d4f7428d403d46a9f380f36fdf9
EXPECTED_ROOT_VERITY=fe5b4acc14779ae720f9cbefddee6e177c08cce5804c74fdc2be359451114b1e
EXPECTED_ROOT_DATA_BYTES=71532544

sha() { sha256sum "$1" | cut -d ' ' -f 1; }
[ "$(sha "$attest")" = "$ATTEST_SHA256" ] || { echo "cathedral-attest is not $ATTEST_SHA256" >&2; exit 1; }

# Host tools, each .deb pinned by the SHA256 of the signed resolute Packages index.
debs="$out/host-debs"
mkdir "$debs"
while read -r sum url; do
  curl -fsSL --retry 3 -o "$debs/${url##*/}" "$url"
  [ "$(sha "$debs/${url##*/}")" = "$sum" ] || { echo "${url##*/}: sha256 differs from its pin" >&2; exit 1; }
done <<'EOF'
d4acfd32c9761ef219383630eb665523617ccc3c87309140a23beffdcc6b5b82 http://archive.ubuntu.com/ubuntu/pool/universe/m/mmdebstrap/mmdebstrap_1.5.7-3_all.deb
b5f307b91c4491fc6f83d0a2dbd91a876244363a4910681db0177833656f6037 http://archive.ubuntu.com/ubuntu/pool/universe/d/debian-archive-keyring/debian-archive-keyring_2025.1ubuntu1_all.deb
3d4bf31f24105c4cc44da6b69ec130ed1784236059185f6d85bdd592c37a7bca http://archive.ubuntu.com/ubuntu/pool/main/s/squashfs-tools/squashfs-tools_4.7.5-1_amd64.deb
ffc9f1fea544f200b7b47a77e0ec89f70d493b5393ea2f7a43f6b9685b3341b8 http://archive.ubuntu.com/ubuntu/pool/main/l/lzo2/liblzo2-2_2.10-3build2_amd64.deb
fc946c43ca12dc7230df72503cc1ee69e11ca994172cd8d72b4868cb78a7b6e2 http://archive.ubuntu.com/ubuntu/pool/main/c/cryptsetup/cryptsetup-bin_2.8.4-1ubuntu4_amd64.deb
EOF
sudo -n dpkg -i "$debs"/*.deb > "$out/host-debs.log"
rm -rf "$debs"
{
  mmdebstrap --version
  mksquashfs -version | head -n 1
  veritysetup --version
  dpkg-query -W mmdebstrap debian-archive-keyring squashfs-tools cryptsetup-bin
} | tee "$out/tool-versions.txt"

curl -fsSL --retry 3 -o "$out/InRelease" "$SNAPSHOT/dists/$SUITE/InRelease"
[ "$(sha "$out/InRelease")" = "$INRELEASE_SHA256" ] || { echo "snapshot InRelease differs from its pin" >&2; exit 1; }

# The base, as docs/CUSTOM_GUEST_FOUNDATION.md prepares it, from the snapshot instead of
# the live mirror. Root mode, because the image restricts unprivileged user namespaces.
# mmdebstrap copies the runner's /etc/hostname and /etc/resolv.conf into the base and
# leaves them there, so two runners gave different base.tar bytes; the root recipe writes
# its own of both, so the base carries neither.
sudo -n env SOURCE_DATE_EPOCH="$BASE_EPOCH" mmdebstrap --mode=root --variant=minbase \
  --keyring=/usr/share/keyrings/debian-archive-keyring.gpg \
  --aptopt='Acquire::Check-Valid-Until "false"' \
  --customize-hook='rm -f "$1"/etc/ssh/ssh_host_* "$1"/var/lib/systemd/random-seed "$1"/etc/hostname "$1"/etc/resolv.conf' \
  --include="$INCLUDE" "$SUITE" "$out/base.tar" "deb $SNAPSHOT $SUITE main"
sudo -n chown "$(id -u):$(id -g)" "$out/base.tar"
base_sha=$(sha "$out/base.tar")
tar -tf "$out/base.tar" | LC_ALL=C sort > "$out/base-files.txt"
[ "$base_sha" = "$EXPECTED_BASE_SHA256" ] || { echo "base.tar is $base_sha, expected $EXPECTED_BASE_SHA256" >&2; exit 1; }

# The reference root recipe, twice from the same base: the two roots must be identical.
for lane in first second; do
  python3 "$repo/scripts/build_custom_guest_root.py" --base "$out/base.tar" --base-sha256 "$base_sha" \
    --helper "$attest" --helper-sha256 "$ATTEST_SHA256" --epoch "$ROOT_EPOCH" \
    --output "$out/root-$lane.raw" > "$out/root-build-$lane.json"
done
cmp "$out/root-first.raw" "$out/root-second.raw"
cmp "$out/root-build-first.json" "$out/root-build-second.json"
mv "$out/root-first.raw" "$out/root.raw"
rm "$out/root-second.raw" "$out/root-build-second.json"
mv "$out/root-build-first.json" "$out/root-build.json"
( cd "$out" && sha256sum base.tar root.raw InRelease > SHA256SUMS )
root_sha=$(sha "$out/root.raw")
read -r root_verity root_data_bytes < <(python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print(d["root_verity"], d["root_data_bytes"])' "$out/root-build.json")
[ "$root_sha" = "$EXPECTED_ROOT_SHA256" ] || { echo "root.raw is $root_sha, expected $EXPECTED_ROOT_SHA256" >&2; exit 1; }
[ "$root_verity" = "$EXPECTED_ROOT_VERITY" ] || { echo "root_verity is $root_verity, expected $EXPECTED_ROOT_VERITY" >&2; exit 1; }
[ "$root_data_bytes" = "$EXPECTED_ROOT_DATA_BYTES" ] || { echo "root_data_bytes is $root_data_bytes, expected $EXPECTED_ROOT_DATA_BYTES" >&2; exit 1; }
echo "root.raw, root_verity and root_data_bytes match the published values"
cat "$out/root-build.json"
cat "$out/SHA256SUMS"
