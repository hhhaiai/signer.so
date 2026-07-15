#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

required=(
  "README.md"
  "ARCHITECTURE.md"
  "SOURCE_SNAPSHOTS.md"
  "verify-all.sh"
  "01-recovered-cpp/README.md"
  "01-recovered-cpp/CMakeLists.txt"
  "01-recovered-cpp/src/recovered_primitives.cpp"
  "01-recovered-cpp/build.sh"
  "01-recovered-cpp/check.sh"
  "01-recovered-cpp/run-example.sh"
  "01-recovered-cpp/config/input.env.example"
  "01-recovered-cpp/docs/INPUT_CONTRACT.md"
  "01-recovered-cpp/docs/COVERAGE.md"
  "01-recovered-cpp/docs/SECURITY_BOUNDARY.md"
  "02-vendor-jni-bridge/README.md"
  "02-vendor-jni-bridge/CMakeLists.txt"
  "02-vendor-jni-bridge/include/signer_backend.h"
  "02-vendor-jni-bridge/include/signer_jni_bridge.h"
  "02-vendor-jni-bridge/include/fake_signer_backend.h"
  "02-vendor-jni-bridge/src/signer_backend.cpp"
  "02-vendor-jni-bridge/src/signer_jni_bridge.cpp"
  "02-vendor-jni-bridge/src/fake_signer_backend.cpp"
  "02-vendor-jni-bridge/tests/signer_backend_test.cpp"
  "02-vendor-jni-bridge/tests/signer_bridge_config_test.cpp"
  "02-vendor-jni-bridge/tests/signer_bridge_production_config_test.cpp"
  "02-vendor-jni-bridge/audit-non-sensitive-boundary.sh"
  "02-vendor-jni-bridge/build-host.sh"
  "02-vendor-jni-bridge/build-android.sh"
  "02-vendor-jni-bridge/check.sh"
  "02-vendor-jni-bridge/config/vendor.env.example"
  "02-vendor-jni-bridge/examples/native_install_example.cpp"
  "02-vendor-jni-bridge/examples/java_call_example.java"
  "02-vendor-jni-bridge/docs/JNI_ABI.md"
  "02-vendor-jni-bridge/docs/LIFECYCLE.md"
  "02-vendor-jni-bridge/docs/ERROR_MODEL.md"
  "03-unidbg-runner/README.md"
  "03-unidbg-runner/pom.xml"
  "03-unidbg-runner/src/main/java/local/SignerOneClick.java"
  "03-unidbg-runner/src/main/java/local/AdjustSignatureRunner.java"
  "03-unidbg-runner/src/main/java/local/SignerEngine.java"
  "03-unidbg-runner/src/test/java/local/SignerOneClickTest.java"
  "03-unidbg-runner/build.sh"
  "03-unidbg-runner/download-dependencies.sh"
  "03-unidbg-runner/check.sh"
  "03-unidbg-runner/run-one-click.sh"
  "03-unidbg-runner/run-direct.sh"
  "03-unidbg-runner/config/device-profile.example.json"
  "03-unidbg-runner/config/request.example.json"
  "03-unidbg-runner/docs/EMULATION_MODEL.md"
  "03-unidbg-runner/docs/INPUT_CONTRACT.md"
  "03-unidbg-runner/docs/TROUBLESHOOTING.md"
)

missing=0
for path in "${required[@]}"; do
  if [[ ! -f "$ROOT/$path" ]]; then
    echo "missing: $ROOT/$path" >&2
    missing=1
  fi
done

if (( missing != 0 )); then
  exit 1
fi

if find \
    "$ROOT/01-recovered-cpp/src" \
    "$ROOT/02-vendor-jni-bridge/include" \
    "$ROOT/02-vendor-jni-bridge/src" \
    "$ROOT/02-vendor-jni-bridge/tests" \
    "$ROOT/03-unidbg-runner/src" \
    -type l -print | grep -q .; then
  echo "source trees must contain physical files, not symbolic links" >&2
  exit 1
fi

if rg -n 'native-reimplementation/recovered_primitives\.cpp|\.\./\.\./native-reimplementation' \
    "$ROOT/01-recovered-cpp"/*.sh >/dev/null; then
  echo "01-recovered-cpp scripts still depend on canonical source paths" >&2
  exit 1
fi

if rg -n '\.\./\.\./native-reimplementation|native-reimplementation/CMakeLists\.txt' \
    "$ROOT/02-vendor-jni-bridge"/*.sh >/dev/null; then
  echo "02-vendor-jni-bridge scripts still depend on canonical source paths" >&2
  exit 1
fi

if rg -n '\.\./\.\./unidbg-adjust-runner|unidbg-adjust-runner/pom\.xml' \
    "$ROOT/03-unidbg-runner"/*.sh >/dev/null; then
  echo "03-unidbg-runner scripts still depend on canonical Maven source paths" >&2
  exit 1
fi

echo "three-implementation physical-source layout: PASS"
