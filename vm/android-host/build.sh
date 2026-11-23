#!/usr/bin/env bash
# Builds app.azula.avfhost with only the Android SDK + a JDK (no Gradle).
# Usage: AZULA_HOST_SO=/path/to/libazula_host.so ./build.sh   (JNI broker, preferred)
#    or: AZULA_BROKER_BIN=/path/to/static-aarch64-azula ./build.sh  (exec'd child broker)
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
HOSTSO="${AZULA_HOST_SO:-}"

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
# AZULA_APP_ID installs the prototype under another application id (code and
# component class names stay in app.azula.avfhost).
"$BT/aapt2" link --manifest AndroidManifest.xml -I "$AJAR" \
  ${AZULA_APP_ID:+--rename-manifest-package "$AZULA_APP_ID"} \
  --min-sdk-version 34 --target-sdk-version 35 -o "$B/base.apk"
cp "$B/dex/classes.dex" "$B/apk/classes.dex"
if [ -n "$HOSTSO" ]; then
  cp "$HOSTSO" "$B/apk/lib/arm64-v8a/libazula_host.so"
fi
if [ -n "$BROKER" ]; then
  cp "$BROKER" "$B/apk/lib/arm64-v8a/libazula.so"
fi
if [ -z "$HOSTSO$BROKER" ]; then
  echo "warning: neither AZULA_HOST_SO nor AZULA_BROKER_BIN set; APK has no broker" >&2
  rmdir "$B/apk/lib/arm64-v8a" "$B/apk/lib"
fi
cp "$B/base.apk" "$B/unaligned.apk"
(cd "$B/apk" && zip -q -r ../unaligned.apk .)

# 6. align + sign with the standard Android debug keystore, so every checkout and
# worktree signs the same way and `install -r` keeps the installed app's data
# (a per-worktree keystore made each rebuild incompatible with the installed app).
KS=${AZULA_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}
if [ ! -f "$KS" ]; then
  mkdir -p "$(dirname "$KS")"
  "$KEYTOOL" -genkeypair -keystore "$KS" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi
"$BT/zipalign" -f -p 4 "$B/unaligned.apk" "$B/aligned.apk"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --out "$B/avfhost.apk" "$B/aligned.apk"
echo "built $B/avfhost.apk"
