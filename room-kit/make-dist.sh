#!/bin/bash
# Build the pinned API tarball for the kit: ./make-dist.sh <commit>
set -euo pipefail
C=${1:?usage: make-dist.sh <commit>}
KIT=$(cd "$(dirname "$0")" && pwd)
SHORT=$(git -C "$KIT" rev-parse --short=7 "$C")
mkdir -p "$KIT/dist"
OUT=$KIT/dist/cathedral-$SHORT.tar.gz
git -C "$KIT/.." archive --format=tar.gz --prefix="cathedral-$SHORT/" "$SHORT" pyproject.toml cathedral > "$OUT"
echo "CATHEDRAL_COMMIT=$SHORT"
echo "CATHEDRAL_TARBALL=dist/cathedral-$SHORT.tar.gz"
echo "CATHEDRAL_TARBALL_SHA256=$(shasum -a 256 "$OUT" | cut -d' ' -f1)"
