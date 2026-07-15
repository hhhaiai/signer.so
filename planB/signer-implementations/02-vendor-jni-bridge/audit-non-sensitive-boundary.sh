#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(uname -s)"

if (( $# > 1 )); then
  echo "usage: $0 [production-library]" >&2
  exit 2
fi

case "$PLATFORM" in
  Darwin) DEFAULT_LIBRARY="$HERE/build/host/libsigner_compat.dylib" ;;
  Linux) DEFAULT_LIBRARY="$HERE/build/host/libsigner_compat.so" ;;
  *)
    echo "unsupported host platform: $PLATFORM (expected macOS or Linux)" >&2
    exit 1
    ;;
esac

PRODUCTION_LIBRARY="${1:-$DEFAULT_LIBRARY}"
[[ -f "$PRODUCTION_LIBRARY" ]] || {
  echo "production library not found: $PRODUCTION_LIBRARY" >&2
  exit 1
}

EXPECTED_EXPORTS="$(LC_ALL=C sort <<'EOF'
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume
Java_com_adjust_sdk_sig_NativeLibHelper_nSign
libsigner_compat_backend_kind
libsigner_compat_close
libsigner_compat_install_fake_for_testing_only
libsigner_compat_install_vendor
libsigner_compat_last_error
EOF
)"

if [[ "$PLATFORM" == "Darwin" ]]; then
  ACTUAL_EXPORTS="$(nm -gU "$PRODUCTION_LIBRARY" \
    | awk '{print $3}' \
    | sed 's/^_//' \
    | LC_ALL=C sort)"
else
  ACTUAL_EXPORTS="$(nm -D --defined-only "$PRODUCTION_LIBRARY" \
    | awk '{print $3}' \
    | LC_ALL=C sort)"
fi

if [[ "$ACTUAL_EXPORTS" != "$EXPECTED_EXPORTS" ]]; then
  echo "production export allowlist mismatch" >&2
  diff -u \
    <(printf '%s\n' "$EXPECTED_EXPORTS") \
    <(printf '%s\n' "$ACTUAL_EXPORTS") >&2 || true
  exit 1
fi
echo "production export allowlist: PASS"

ALL_SYMBOLS_FILE="$(mktemp "${TMPDIR:-/tmp}/libsigner-compat-symbols.XXXXXX")"
STRINGS_FILE="$(mktemp "${TMPDIR:-/tmp}/libsigner-compat-strings.XXXXXX")"
cleanup() {
  rm -f "$ALL_SYMBOLS_FILE" "$STRINGS_FILE"
}
trap cleanup EXIT

nm "$PRODUCTION_LIBRARY" >"$ALL_SYMBOLS_FILE"
strings -a "$PRODUCTION_LIBRARY" >"$STRINGS_FILE"

if grep -Eiq \
    'FakeSignerBackend[^[:space:]]*::|fake_signer_backend|recovered_primitives|kRecovered' \
    "$ALL_SYMBOLS_FILE"; then
  echo "production library contains fake/recovered implementation symbols" >&2
  grep -Ei \
    'FakeSignerBackend[^[:space:]]*::|fake_signer_backend|recovered_primitives|kRecovered' \
    "$ALL_SYMBOLS_FILE" >&2 || true
  exit 1
fi

FORBIDDEN_MARKERS=(
  'FAKE-ADJUST'
  'FakeSignerBackend(TEST_ONLY)'
  'java/util/Map'
  'SIGNATURE_HEX'
  'kRecovered'
  'java-hmac-key'
  'native-plaintext'
  'recovered native primitives'
  'recovered_primitives'
)
for marker in "${FORBIDDEN_MARKERS[@]}"; do
  if grep -Fq -- "$marker" "$STRINGS_FILE"; then
    echo "production library contains forbidden marker: $marker" >&2
    exit 1
  fi
done
echo "production fake/recovered/sensitive marker scan: PASS"
echo "non-sensitive production boundary audit: PASS"
