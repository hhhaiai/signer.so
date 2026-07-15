#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/mvn" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  case "$arg" in
    -Dmdep.outputFile=*)
      output="${arg#*=}"
      mkdir -p "$(dirname "$output")"
      : >"$output"
      ;;
  esac
done
SH

cat >"$TMP/java" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FAKE_JAVA_COUNT" ]]; then count="$(cat "$FAKE_JAVA_COUNT")"; fi
count=$((count + 1))
printf '%s' "$count" >"$FAKE_JAVA_COUNT"
if [[ "${FAKE_JAVA_MODE:-success}" == "transient" && "$count" -eq 1 ]]; then exit 134; fi
if [[ "${FAKE_JAVA_MODE:-success}" == "failure" ]]; then exit 1; fi
echo 'SIGNER_RESULT_JSON={"ok":true}'
SH
chmod +x "$TMP/mvn" "$TMP/java"

export PATH="$TMP:$PATH"
export SIGNER_JAVA_BIN="$TMP/java"
export FAKE_JAVA_COUNT="$TMP/count"

export FAKE_JAVA_MODE=transient
test "$("$ROOT/generate-signer.sh" "$ROOT/examples/signer-job.json")" = '{"ok":true}'
test "$(cat "$FAKE_JAVA_COUNT")" = 2

: >"$FAKE_JAVA_COUNT"
export FAKE_JAVA_MODE=failure
if "$ROOT/generate-signer.sh" "$ROOT/examples/signer-job.json" >/dev/null 2>&1; then
  echo "non-native failure unexpectedly retried/passed" >&2
  exit 1
fi
test "$(cat "$FAKE_JAVA_COUNT")" = 1

echo "generate-signer bounded native-crash retry OK"
