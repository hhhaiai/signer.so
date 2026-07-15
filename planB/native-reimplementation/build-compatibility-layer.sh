#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT/build"
CXX_BIN="${CXX:-c++}"
PLATFORM="$(uname -s)"

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

run_with_sanitizers() {
  local default_asan_options="halt_on_error=1"
  if [[ "$PLATFORM" == "Darwin" ]]; then
    default_asan_options="detect_leaks=0:halt_on_error=1"
  fi
  local asan_options="${ASAN_OPTIONS:-$default_asan_options}"
  local ubsan_options="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
  printf '+ ASAN_OPTIONS=%q UBSAN_OPTIONS=%q' \
    "$asan_options" "$ubsan_options"
  printf ' %q' "$@"
  printf '\n'
  ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS="$ubsan_options" "$@"
}

resolve_java_home() {
  local candidate=""

  if [[ -n "${JAVA_HOME:-}" && -f "$JAVA_HOME/include/jni.h" ]]; then
    printf '%s\n' "$JAVA_HOME"
    return 0
  fi

  if [[ "$PLATFORM" == "Darwin" && -x /usr/libexec/java_home ]]; then
    candidate="$(/usr/libexec/java_home 2>/dev/null || true)"
    if [[ -n "$candidate" && -f "$candidate/include/jni.h" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  if [[ "$PLATFORM" == "Linux" ]] && command -v javac >/dev/null 2>&1; then
    candidate="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
    if [[ -f "$candidate/include/jni.h" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi

  return 1
}

case "$PLATFORM" in
  Darwin)
    JNI_PLATFORM="darwin"
    PRODUCTION_LIBRARY="$BUILD_DIR/libsigner_compat.dylib"
    SHARED_FLAGS=(-dynamiclib)
    DYNAMIC_LINK_FLAGS=(-ldl)
    ;;
  Linux)
    JNI_PLATFORM="linux"
    PRODUCTION_LIBRARY="$BUILD_DIR/libsigner_compat.so"
    SHARED_FLAGS=(-shared -Wl,-soname,libsigner_compat.so)
    DYNAMIC_LINK_FLAGS=(-ldl)
    ;;
  *)
    echo "unsupported host platform: $PLATFORM (expected macOS or Linux)" >&2
    exit 1
    ;;
esac

if ! JAVA_HOME_RESOLVED="$(resolve_java_home)"; then
  echo "cannot locate JNI headers; set JAVA_HOME to a JDK containing include/jni.h" >&2
  exit 1
fi
JNI_INCLUDE="$JAVA_HOME_RESOLVED/include"
JNI_PLATFORM_INCLUDE="$JNI_INCLUDE/$JNI_PLATFORM"
if [[ ! -f "$JNI_PLATFORM_INCLUDE/jni_md.h" ]]; then
  echo "cannot locate platform JNI header: $JNI_PLATFORM_INCLUDE/jni_md.h" >&2
  exit 1
fi

mkdir -p "$BUILD_DIR"

COMMON_FLAGS=(
  -std=c++17
  -O2
  -Wall
  -Wextra
  -Werror
  -pthread
  -I"$ROOT"
)
JNI_FLAGS=(
  -I"$JNI_INCLUDE"
  -I"$JNI_PLATFORM_INCLUDE"
)
SANITIZER_FLAGS=(
  -std=c++17
  -O1
  -g
  -Wall
  -Wextra
  -Werror
  -pthread
  -fno-omit-frame-pointer
  -fsanitize=address,undefined
  -I"$ROOT"
)

BACKEND_TEST="$BUILD_DIR/signer-backend-test"
BRIDGE_CONFIG_TEST="$BUILD_DIR/signer-bridge-config-test"
PRODUCTION_BRIDGE_CONFIG_TEST="$BUILD_DIR/signer-bridge-production-config-test"
BACKEND_SANITIZER_TEST="$BUILD_DIR/signer-backend-test-asan-ubsan"
BRIDGE_SANITIZER_TEST="$BUILD_DIR/signer-bridge-config-test-asan-ubsan"
PRODUCTION_BRIDGE_SANITIZER_TEST="$BUILD_DIR/signer-bridge-production-config-test-asan-ubsan"

echo "Building non-sensitive backend test"
run "$CXX_BIN" "${COMMON_FLAGS[@]}" \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/fake_signer_backend.cpp" \
  "$ROOT/signer_backend_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$BACKEND_TEST"

echo "Building non-sensitive bridge configuration test"
run "$CXX_BIN" "${COMMON_FLAGS[@]}" "${JNI_FLAGS[@]}" \
  -DLIBSIGNER_COMPAT_ENABLE_TEST_BACKEND \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/fake_signer_backend.cpp" \
  "$ROOT/signer_jni_bridge.cpp" \
  "$ROOT/signer_bridge_config_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$BRIDGE_CONFIG_TEST"

echo "Building production bridge configuration test"
run "$CXX_BIN" "${COMMON_FLAGS[@]}" "${JNI_FLAGS[@]}" \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/signer_jni_bridge.cpp" \
  "$ROOT/signer_bridge_production_config_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$PRODUCTION_BRIDGE_CONFIG_TEST"

echo "Building production compatibility library (vendor backend only)"
run "$CXX_BIN" "${COMMON_FLAGS[@]}" "${JNI_FLAGS[@]}" \
  -fPIC \
  -fvisibility=hidden \
  -fvisibility-inlines-hidden \
  "${SHARED_FLAGS[@]}" \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/signer_jni_bridge.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$PRODUCTION_LIBRARY"

echo "Running non-sensitive tests"
run "$BACKEND_TEST"
run "$BRIDGE_CONFIG_TEST"
run "$PRODUCTION_BRIDGE_CONFIG_TEST"

echo "Building ASan+UBSan backend test"
run "$CXX_BIN" "${SANITIZER_FLAGS[@]}" \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/fake_signer_backend.cpp" \
  "$ROOT/signer_backend_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$BACKEND_SANITIZER_TEST"

echo "Building ASan+UBSan bridge configuration test"
run "$CXX_BIN" "${SANITIZER_FLAGS[@]}" "${JNI_FLAGS[@]}" \
  -DLIBSIGNER_COMPAT_ENABLE_TEST_BACKEND \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/fake_signer_backend.cpp" \
  "$ROOT/signer_jni_bridge.cpp" \
  "$ROOT/signer_bridge_config_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$BRIDGE_SANITIZER_TEST"

echo "Building ASan+UBSan production bridge configuration test"
run "$CXX_BIN" "${SANITIZER_FLAGS[@]}" "${JNI_FLAGS[@]}" \
  "$ROOT/signer_backend.cpp" \
  "$ROOT/signer_jni_bridge.cpp" \
  "$ROOT/signer_bridge_production_config_test.cpp" \
  "${DYNAMIC_LINK_FLAGS[@]}" \
  -o "$PRODUCTION_BRIDGE_SANITIZER_TEST"

echo "Running ASan+UBSan tests"
run_with_sanitizers "$BACKEND_SANITIZER_TEST"
run_with_sanitizers "$BRIDGE_SANITIZER_TEST"
run_with_sanitizers "$PRODUCTION_BRIDGE_SANITIZER_TEST"

echo "Auditing the production non-sensitive boundary"
run "$ROOT/audit-non-sensitive-boundary.sh" "$PRODUCTION_LIBRARY"

echo "safe compatibility build and test: PASS"
echo "production library: $PRODUCTION_LIBRARY"
