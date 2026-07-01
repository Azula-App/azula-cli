#!/usr/bin/env bash
# Fast dev loop for the azula shell container: cross-build the CLI for Linux
# and hot-swap the binary into the running `azula-shell` container — no image
# rebuild, and the persisted identity (connect code) survives.
#
# The build runs in a native-arch rust:1-bookworm container with cached target/
# and registry volumes, so the first run warms the cache and later runs are
# incremental (~seconds). The produced binary is a real bookworm-glibc ELF, so
# it drops straight into the debian:bookworm-slim runtime.
#
#   ./docker/hot-swap.sh
#
# Prereqs: the container is already up (`docker compose up --build -d`).
set -euo pipefail

cd "$(dirname "$0")/.."   # azula-cli/
SERVICE=azula
CONTAINER=azula-shell
ARTIFACT=.azula-linux

echo "› building azula for linux (cached bookworm toolchain)…"
docker run --rm \
  -v "$PWD":/src -w /src \
  -v azula-build-target:/target \
  -v azula-build-registry:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target \
  rust:1-bookworm \
  bash -c "cargo build --release --bin azula --locked && cp /target/release/azula /src/$ARTIFACT && chmod +x /src/$ARTIFACT"

echo "› swapping the binary into $CONTAINER…"
docker compose stop "$SERVICE"
docker cp "$ARTIFACT" "$CONTAINER:/usr/local/bin/azula"
docker compose start "$SERVICE"

# Give it a moment to print the fresh banner, then surface the connect code.
sleep 3
echo
echo "› connect code:"
docker compose logs --no-log-prefix --no-color "$SERVICE" 2>&1 \
  | grep -oE "https://azula.app/s/endpoint[a-z0-9]+" | tail -1
