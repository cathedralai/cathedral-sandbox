#!/bin/bash
# Download the pinned base image (images.lock) and keep it only when its sha256
# matches. Usage: fetch-image.sh [dest-dir]   (default $VM_ROOT/images,
# VM_ROOT default /srv/cathedral-vms). Safe to run again: a verified file stays.
set -euo pipefail
KIT=$(dirname "$(readlink -f "$0")")
url=$(sed -n 's/^IMAGE_URL=//p' "$KIT/images.lock")
sha=$(sed -n 's/^IMAGE_SHA256=//p' "$KIT/images.lock")
file=$(sed -n 's/^IMAGE_FILE=//p' "$KIT/images.lock")
[[ "$url" =~ ^https:// && "$sha" =~ ^[0-9a-f]{64}$ && "$file" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "images.lock is malformed" >&2; exit 1; }
dest=${1:-${VM_ROOT:-/srv/cathedral-vms}/images}
mkdir -p "$dest"
if [ -f "$dest/$file" ] && echo "$sha  $dest/$file" | sha256sum -c --status; then
  echo "{\"image\": \"$dest/$file\", \"sha256\": \"$sha\", \"downloaded\": false}"
  exit 0
fi
curl -fL --retry 3 --proto '=https' -o "$dest/$file.part" "$url"
if ! echo "$sha  $dest/$file.part" | sha256sum -c --status; then
  rm -f "$dest/$file.part"
  echo "sha256 of $url is not the pinned $sha; refused" >&2
  exit 1
fi
chmod 0444 "$dest/$file.part"
mv -f "$dest/$file.part" "$dest/$file"
echo "{\"image\": \"$dest/$file\", \"sha256\": \"$sha\", \"downloaded\": true}"
