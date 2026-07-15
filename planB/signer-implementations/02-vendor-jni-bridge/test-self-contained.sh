#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

required_files=(
  CMakeLists.txt
  include/signer_backend.h
  include/signer_jni_bridge.h
  include/fake_signer_backend.h
  src/signer_backend.cpp
  src/signer_jni_bridge.cpp
  src/fake_signer_backend.cpp
  tests/signer_backend_test.cpp
  tests/signer_bridge_config_test.cpp
  tests/signer_bridge_production_config_test.cpp
  audit-non-sensitive-boundary.sh
)

for relative_path in "${required_files[@]}"; do
  [[ -f "$HERE/$relative_path" ]] || {
    echo "missing self-contained source: $relative_path" >&2
    exit 1
  }
done

external_source_tree='native''-reimplementation'
external_source_pattern="${external_source_tree}|SOURCE_DIR=.*PROJECT_ROOT"
if grep -nE "$external_source_pattern" \
    "$HERE/CMakeLists.txt" \
    "$HERE/build-host.sh" \
    "$HERE/build-android.sh" \
    "$HERE/check.sh" \
    "$HERE/audit-non-sensitive-boundary.sh"; then
  echo "build or audit entry point still depends on an external source tree" >&2
  exit 1
fi

echo "vendor JNI bridge self-contained layout: PASS"
