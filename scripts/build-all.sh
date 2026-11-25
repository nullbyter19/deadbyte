#!/usr/bin/env bash
# Builds all DeadByte binaries for Windows, Linux and macOS.
# Usage: scripts/build-all.sh [output-dir]   (default: dist/)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-dist}"
mkdir -p "$OUT"
LDFLAGS="-s -w"
BUILT=0
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	os="${target%/*}"; arch="${target#*/}"
	ext=""; [ "$os" = "windows" ] && ext=".exe"
	echo "==> $os/$arch"
	for bin in payload decryptor c2 xorgen; do
		GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" \
			-o "$OUT/deadbyte-$bin-$os-$arch$ext" "./cmd/$bin"
		BUILT=$((BUILT+1))
	done
done
echo "==> $BUILT binaries in $OUT"
ls -1 "$OUT"
