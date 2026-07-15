#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABI="${1:-arm64-v8a}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

case "$ABI" in
  arm64-v8a|armeabi-v7a|x86_64|x86) ;;
  *) echo "unsupported ABI: $ABI" >&2; exit 2 ;;
esac

[[ -n "$NDK" ]] || { echo "set ANDROID_NDK_HOME or ANDROID_NDK_ROOT" >&2; exit 2; }
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
[[ -f "$TOOLCHAIN" ]] || { echo "Android CMake toolchain not found: $TOOLCHAIN" >&2; exit 2; }
command -v cmake >/dev/null 2>&1 || { echo "cmake not found" >&2; exit 1; }

BUILD_DIR="$HERE/build/android/$ABI"
if [[ -f "$BUILD_DIR/CMakeCache.txt" ]] \
    && ! grep -Fq "CMAKE_HOME_DIRECTORY:INTERNAL=$HERE" \
        "$BUILD_DIR/CMakeCache.txt"; then
  rm -rf "$BUILD_DIR"
fi

cmake -S "$HERE" -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM=android-21 \
  -DLIBSIGNER_COMPAT_BUILD_JNI=ON \
  -DLIBSIGNER_COMPAT_BUILD_TESTS=OFF \
  -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel
echo "Android bridge: $BUILD_DIR/libsigner_compat.so"
