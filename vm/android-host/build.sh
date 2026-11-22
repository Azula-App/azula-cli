#!/usr/bin/env bash
# Builds app.azula.avfhost with only the Android SDK + a JDK (no Gradle).
# Usage: AZULA_BROKER_BIN=/path/to/static-aarch64-azula ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/37.0.0"
AJAR="$SDK/platforms/android-37.0/android.jar"
JDK="${JAVA_BIN:-$HOME/.local/share/mise/installs/java/latest/bin}"
JAVAC="$JDK/javac"; KEYTOOL="$JDK/keytool"; JAR="$JDK/jar"
BYPASS_VER="${BYPASS_VER:-6.2}"
B=.build
BROKER="${AZULA_BROKER_BIN:-}"

rm -rf "$B/classes" "$B/stubs" "$B/apk" "$B/dex"
mkdir -p "$B/classes" "$B/stubs" "$B/dl" "$B/apk/lib/arm64-v8a" "$B/dex"

# 1. LSPosed AndroidHiddenApiBypass (runtime dependency, dexed into the APK)
if [ ! -f "$B/dl/hiddenapibypass-$BYPASS_VER.jar" ]; then
  curl -fsSL -o "$B/dl/hab.aar" \
    "https://repo1.maven.org/maven2/org/lsposed/hiddenapibypass/hiddenapibypass/$BYPASS_VER/hiddenapibypass-$BYPASS_VER.aar"
  (cd "$B/dl" && unzip -o -q hab.aar classes.jar && mv classes.jar "hiddenapibypass-$BYPASS_VER.jar")
fi
HAB="$B/dl/hiddenapibypass-$BYPASS_VER.jar"

# 2. compile-only AVF stubs (NOT dexed: real classes come from the bootclasspath)
"$JAVAC" --release 17 -d "$B/stubs" -cp "$AJAR" $(find stubs -name '*.java')

# 3. app classes
"$JAVAC" --release 17 -Xlint:-options -d "$B/classes" -cp "$AJAR:$B/stubs:$HAB" $(find java -name '*.java')

# 4. dex: app classes + bypass lib only
"$JAR" cf "$B/app-classes.jar" -C "$B/classes" .
"$BT/d8" --min-api 34 --lib "$AJAR" --output "$B/dex" "$B/app-classes.jar" "$HAB"

# 5. link manifest, add dex + native lib
"$BT/aapt2" link --manifest AndroidManifest.xml -I "$AJAR" \
  --min-sdk-version 34 --target-sdk-version 35 -o "$B/base.apk"
cp "$B/dex/classes.dex" "$B/apk/classes.dex"
if [ -n "$BROKER" ]; then
  cp "$BROKER" "$B/apk/lib/arm64-v8a/libazula.so"
else
  echo "warning: AZULA_BROKER_BIN not set; APK will have no libazula.so" >&2
  rmdir "$B/apk/lib/arm64-v8a" "$B/apk/lib"
fi
cp "$B/base.apk" "$B/unaligned.apk"
(cd "$B/apk" && zip -q -r ../unaligned.apk .)

# 6. align + sign with a debug keystore
if [ ! -f "$B/debug.keystore" ]; then
  "$KEYTOOL" -genkeypair -keystore "$B/debug.keystore" -storepass android -keypass android \
    -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=avfhost debug" >/dev/null 2>&1
fi
"$BT/zipalign" -f -p 4 "$B/unaligned.apk" "$B/aligned.apk"
"$BT/apksigner" sign --ks "$B/debug.keystore" --ks-pass pass:android --key-pass pass:android \
  --out "$B/avfhost.apk" "$B/aligned.apk"
echo "built $B/avfhost.apk"
