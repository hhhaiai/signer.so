#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$HERE/build/host"

command -v cmake >/dev/null 2>&1 || { echo "cmake not found" >&2; exit 1; }
[[ -f "$HERE/CMakeLists.txt" ]] || { echo "missing CMake project: $HERE" >&2; exit 1; }

if [[ -f "$BUILD_DIR/CMakeCache.txt" ]] \
    && ! grep -Fq "CMAKE_HOME_DIRECTORY:INTERNAL=$HERE" \
        "$BUILD_DIR/CMakeCache.txt"; then
  rm -rf "$BUILD_DIR"
fi

cmake -S "$HERE" -B "$BUILD_DIR" \
  -DLIBSIGNER_COMPAT_BUILD_JNI=ON \
  -DLIBSIGNER_COMPAT_BUILD_TESTS=ON \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$BUILD_DIR" --parallel
echo "host bridge build: $BUILD_DIR"
