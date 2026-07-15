#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$HERE/src/recovered_primitives.cpp"
BUILD_DIR="$HERE/build"
OUTPUT="$BUILD_DIR/recovered-primitives"
CMAKE_BIN="${CMAKE:-cmake}"
CXX_BIN="${CXX:-c++}"

[[ -f "$HERE/CMakeLists.txt" ]] || { echo "missing local CMake project: $HERE/CMakeLists.txt" >&2; exit 1; }
[[ -f "$SOURCE" ]] || { echo "missing local source: $SOURCE" >&2; exit 1; }
command -v "$CMAKE_BIN" >/dev/null 2>&1 || { echo "CMake not found: $CMAKE_BIN" >&2; exit 1; }
command -v "$CXX_BIN" >/dev/null 2>&1 || { echo "C++ compiler not found: $CXX_BIN" >&2; exit 1; }

echo "+ $CMAKE_BIN -S $HERE -B $BUILD_DIR -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=$CXX_BIN"
"$CMAKE_BIN" \
  -S "$HERE" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER="$CXX_BIN" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

echo "+ $CMAKE_BIN --build $BUILD_DIR --config Release --parallel"
"$CMAKE_BIN" --build "$BUILD_DIR" --config Release --parallel

[[ -x "$OUTPUT" ]] || { echo "build completed without expected executable: $OUTPUT" >&2; exit 1; }
echo "built: $OUTPUT"
