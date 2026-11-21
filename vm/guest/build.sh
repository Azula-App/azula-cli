#!/bin/sh
# Build azula-guest as a static aarch64 Linux binary and copy it to OUT_DIR
# (default: vm/guest/target/out). Works from any cwd.
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$DIR/target/out}
TARGET=aarch64-unknown-linux-musl
rustup target add "$TARGET" >/dev/null 2>&1 || true
# cd so .cargo/config.toml (rust-lld linker) is found regardless of caller cwd
(cd "$DIR" && cargo build --release --locked --target "$TARGET")
mkdir -p "$OUT"
cp "$DIR/target/$TARGET/release/azula-guest" "$OUT/azula-guest"
echo "$OUT/azula-guest"
