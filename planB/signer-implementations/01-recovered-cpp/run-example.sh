#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${1:-}"
SOURCE="$HERE/src/recovered_primitives.cpp"
BINARY="$HERE/build/recovered-primitives"

if [[ -z "$CONFIG" ]]; then
  echo "usage: $0 <input.env>" >&2
  exit 2
fi
[[ -f "$CONFIG" ]] || { echo "input file not found: $CONFIG" >&2; exit 2; }
[[ -f "$SOURCE" ]] || { echo "missing local source: $SOURCE" >&2; exit 1; }

TIME_SECONDS_SET=0
CORRECTION_CODES_SET=0
URANDOM_HEX_SET=0
CERTIFICATE_SHA1_SET=0
NATIVE_PLAINTEXT_HEX_SET=0
STATE_SET=0
SIGNER_CODE_TRAMPOLINE_DETECTED_SET=0
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || { echo "invalid input line: $line" >&2; exit 2; }
  key="${line%%=*}"
  value="${line#*=}"
  [[ "$key" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "invalid input key: $key" >&2; exit 2; }
  case "$key" in
    TIME_SECONDS) TIME_SECONDS="$value"; TIME_SECONDS_SET=1 ;;
    CORRECTION_CODES) CORRECTION_CODES="$value"; CORRECTION_CODES_SET=1 ;;
    URANDOM_HEX) URANDOM_HEX="$value"; URANDOM_HEX_SET=1 ;;
    CERTIFICATE_SHA1) CERTIFICATE_SHA1="$value"; CERTIFICATE_SHA1_SET=1 ;;
    NATIVE_PLAINTEXT_HEX) NATIVE_PLAINTEXT_HEX="$value"; NATIVE_PLAINTEXT_HEX_SET=1 ;;
    STATE) STATE="$value"; STATE_SET=1 ;;
    SIGNER_CODE_TRAMPOLINE_DETECTED)
      SIGNER_CODE_TRAMPOLINE_DETECTED="$value"
      SIGNER_CODE_TRAMPOLINE_DETECTED_SET=1
      ;;
    *) echo "unsupported input key: $key" >&2; exit 2 ;;
  esac
done < "$CONFIG"

(( TIME_SECONDS_SET == 1 )) || { echo "missing required field: TIME_SECONDS" >&2; exit 2; }
(( CORRECTION_CODES_SET == 1 )) || { echo "missing required field: CORRECTION_CODES" >&2; exit 2; }
(( URANDOM_HEX_SET == 1 )) || { echo "missing required field: URANDOM_HEX" >&2; exit 2; }
(( CERTIFICATE_SHA1_SET == 1 )) || { echo "missing required field: CERTIFICATE_SHA1" >&2; exit 2; }
(( NATIVE_PLAINTEXT_HEX_SET == 1 )) || { echo "missing required field: NATIVE_PLAINTEXT_HEX" >&2; exit 2; }
(( STATE_SET == 1 )) || { echo "missing required field: STATE" >&2; exit 2; }

[[ -x "$BINARY" ]] || "$HERE/build.sh"

args=(
  "--time-seconds=$TIME_SECONDS"
  "--correction-codes=$CORRECTION_CODES"
  "--urandom-hex=$URANDOM_HEX"
  "--certificate-sha1=$CERTIFICATE_SHA1"
  "--native-plaintext-hex=$NATIVE_PLAINTEXT_HEX"
  "--state=$STATE"
)

if (( SIGNER_CODE_TRAMPOLINE_DETECTED_SET == 1 )); then
  args+=("--signer-code-trampoline-detected=$SIGNER_CODE_TRAMPOLINE_DETECTED")
fi

echo "warning: executing the audit-only recovered signer with caller-supplied synthetic inputs" >&2
exec "$BINARY" "${args[@]}"
