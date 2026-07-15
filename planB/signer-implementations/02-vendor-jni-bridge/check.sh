#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$HERE/build/host"

"$HERE/test-self-contained.sh"
"$HERE/build-host.sh"
ctest --test-dir "$BUILD_DIR" --output-on-failure

case "$(uname -s)" in
  Darwin) LIBRARY="$BUILD_DIR/libsigner_compat.dylib" ;;
  Linux) LIBRARY="$BUILD_DIR/libsigner_compat.so" ;;
  *) echo "unsupported host platform" >&2; exit 1 ;;
esac

"$HERE/audit-non-sensitive-boundary.sh" "$LIBRARY"
echo "vendor JNI bridge check: PASS"
