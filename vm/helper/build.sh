#!/bin/bash
# Build and ad-hoc sign azula-vm. Usage: build.sh [OUT_DIR]  (default: <this dir>/.build/dist)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$DIR/.build/dist}"
swift build -c release --package-path "$DIR"
BIN="$(swift build -c release --package-path "$DIR" --show-bin-path)/azula-vm"
codesign --force --sign - --entitlements "$DIR/azula-vm.entitlements" "$BIN"
mkdir -p "$OUT"
cp "$BIN" "$OUT/azula-vm"
echo "$OUT/azula-vm"
