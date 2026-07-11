#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/device-reference"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-36.0.0}"
BUILD_TOOLS="$SDK/build-tools/$BUILD_TOOLS_VERSION"
ANDROID_JAR="$SDK/platforms/android-36/android.jar"
BUILD="$HERE/build"
CLASSES="$BUILD/classes"
DEX="$BUILD/dex"
STAGING="$BUILD/staging"
KEYSTORE="$HERE/reference-debug.keystore"
APK_UNSIGNED="$BUILD/reference-unsigned.apk"
APK_ALIGNED="$BUILD/reference-aligned.apk"
APK_SIGNED="$BUILD/adjust-reference.apk"

for file in "$ANDROID_JAR" "$BUILD_TOOLS/aapt2" "$BUILD_TOOLS/d8" \
            "$BUILD_TOOLS/zipalign" "$BUILD_TOOLS/apksigner" \
            "$ROOT/adjust-android-signature-3.67.0/classes.jar" \
            "$ROOT/adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so" \
            "$HERE/gadget/frida-gadget-16.1.10-android-arm64.so"; do
  [[ -e "$file" ]] || { echo "missing required file: $file" >&2; exit 1; }
done

rm -rf "$BUILD"
mkdir -p "$CLASSES" "$DEX" "$STAGING/lib/arm64-v8a"

if [[ ! -f "$KEYSTORE" ]]; then
  keytool -genkeypair -noprompt \
    -keystore "$KEYSTORE" -storepass android -keypass android \
    -alias androiddebugkey -dname "CN=QBDI Reference,O=Local,C=CN" \
    -keyalg RSA -keysize 2048 -validity 10000
fi

find "$HERE/src" -name '*.java' -print0 | xargs -0 javac \
  -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
  -classpath "$ROOT/adjust-android-signature-3.67.0/classes.jar" \
  -d "$CLASSES"

jar cf "$BUILD/reference-app-classes.jar" -C "$CLASSES" .
"$BUILD_TOOLS/d8" --min-api 23 --lib "$ANDROID_JAR" --output "$DEX" \
  "$BUILD/reference-app-classes.jar" "$ROOT/adjust-android-signature-3.67.0/classes.jar"

"$BUILD_TOOLS/aapt2" link -o "$APK_UNSIGNED" -I "$ANDROID_JAR" \
  --manifest "$HERE/AndroidManifest.xml" --min-sdk-version 23 --target-sdk-version 35

cp "$DEX/classes.dex" "$STAGING/classes.dex"
cp "$ROOT/adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so" \
  "$STAGING/lib/arm64-v8a/libsigner.so"
cp "$HERE/gadget/frida-gadget-16.1.10-android-arm64.so" \
  "$STAGING/lib/arm64-v8a/libreference_runtime.so"
(
  cd "$STAGING"
  zip -q -r "$APK_UNSIGNED" classes.dex lib
)

"$BUILD_TOOLS/zipalign" -f -p 4 "$APK_UNSIGNED" "$APK_ALIGNED"
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KEYSTORE" --ks-key-alias androiddebugkey \
  --ks-pass pass:android --key-pass pass:android \
  --out "$APK_SIGNED" "$APK_ALIGNED"
"$BUILD_TOOLS/apksigner" verify --verbose --print-certs "$APK_SIGNED"

keytool -exportcert -keystore "$KEYSTORE" -storepass android \
  -alias androiddebugkey -file "$BUILD/reference-certificate.der" >/dev/null

printf 'REFERENCE_APK=%s\n' "$APK_SIGNED"
printf 'REFERENCE_CERTIFICATE=%s\n' "$BUILD/reference-certificate.der"
shasum -a 256 "$APK_SIGNED" "$BUILD/reference-certificate.der"
