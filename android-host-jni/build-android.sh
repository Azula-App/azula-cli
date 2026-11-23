#!/usr/bin/env bash
# Build libazula_host.so for aarch64-linux-android with the Android NDK.
#   android-host-jni/build-android.sh
# Env: ANDROID_NDK (default ~/Library/Android/sdk/ndk/28.0.13004108),
#      NDK_HOST_TAG (default darwin-x86_64), ANDROID_API (default 34 = minSdk).
# Needs `rustup target add aarch64-linux-android`.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NDK=${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/28.0.13004108}
TAG=${NDK_HOST_TAG:-darwin-x86_64}
API=${ANDROID_API:-34}
BIN="$NDK/toolchains/llvm/prebuilt/$TAG/bin"
[ -x "$BIN/aarch64-linux-android$API-clang" ] || { echo "no NDK clang at $BIN/aarch64-linux-android$API-clang" >&2; exit 1; }

export CC_aarch64_linux_android="$BIN/aarch64-linux-android$API-clang"
export AR_aarch64_linux_android="$BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
# Release, stripped. Set here rather than in the workspace so the CLI's own
# release profile is untouched.
export CARGO_PROFILE_RELEASE_STRIP=symbols

cd "$ROOT"
cargo build --release --locked -p azula-android-host-jni --target aarch64-linux-android >&2
SO="$ROOT/target/aarch64-linux-android/release/libazula_host.so"
echo "$SO"
ls -l "$SO" | awk '{print $5 " bytes"}'
