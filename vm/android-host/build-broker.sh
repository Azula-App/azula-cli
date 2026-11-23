#!/bin/sh
# Cross-build the broker the Android host app runs as its child process: a
# static aarch64-unknown-linux-musl `azula`, on macOS, using zig as the C
# compiler/linker (ring needs a C cross compiler). Prints the binary's path;
# feed it to build.sh as AZULA_BROKER_BIN.
#   vm/android-host/build-broker.sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ZIG=${ZIG:-$(command -v zig || echo "$HOME/.local/share/mise/installs/zig/0.16.0/bin/zig")}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# zig cc rejects rustc's --target and the Cortex-A53 erratum flag; it brings
# its own crt/musl, hence link-self-contained=no below (else duplicate _start).
cat > "$W/zcc" <<EOF
#!/bin/sh
args=""
for a in "\$@"; do
  case "\$a" in --target=*|-Wl,--fix-cortex-a53-843419) ;; *) set -- "\$@" "\$a" ;; esac
  shift
done
exec "$ZIG" cc -target aarch64-linux-musl "\$@"
EOF
printf '#!/bin/sh\nexec "%s" ar "$@"\n' "$ZIG" > "$W/zar"
chmod +x "$W/zcc" "$W/zar"
cd "$ROOT"
CC_aarch64_unknown_linux_musl="$W/zcc" \
AR_aarch64_unknown_linux_musl="$W/zar" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$W/zcc" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
  cargo build --release --locked --target aarch64-unknown-linux-musl >&2
echo "$ROOT/target/aarch64-unknown-linux-musl/release/azula"
