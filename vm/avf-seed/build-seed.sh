#!/bin/sh
# Build the cloud-init NoCloud seed ISO (label "cidata") for the Android AVF
# host prototype: user-data + meta-data + the static azula-guest + the vsock
# proxy shim. macOS only (hdiutil), like the Mac broker's seed; release.yml builds
# it on a macOS runner.
#   vm/avf-seed/build-seed.sh [OUT_ISO]   (default: vm/avf-seed/.build/seed.iso)
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$DIR/.build/seed.iso}
GUEST=$("$DIR/../guest/build.sh" | tail -1)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "$DIR/user-data" "$STAGE/user-data"
printf 'instance-id: azula-avf-%s\nlocal-hostname: azula-avf\n' "$(uuidgen | tr 'A-Z' 'a-z')" > "$STAGE/meta-data"
cp "$GUEST" "$STAGE/azula-guest"
cp "$DIR/azula-vsock-proxy" "$STAGE/azula-vsock-proxy"
cp "$DIR/azula-timesync" "$STAGE/azula-timesync"
chmod 755 "$STAGE/azula-guest" "$STAGE/azula-vsock-proxy" "$STAGE/azula-timesync"
mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"
hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata -o "$OUT" "$STAGE"
echo "$OUT"
