#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
CLASSPATH_FILE="$ROOT/unidbg-adjust-runner/target/classpath.txt"
HAD_CLASSPATH=0
if [[ -f "$CLASSPATH_FILE" ]]; then
  cp "$CLASSPATH_FILE" "$TMP/classpath.txt"
  HAD_CLASSPATH=1
fi

cleanup() {
  if [[ "$HAD_CLASSPATH" == 1 ]]; then
    cp "$TMP/classpath.txt" "$CLASSPATH_FILE"
  else
    rm -f "$CLASSPATH_FILE"
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cat >"$TMP/mvn" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
OUTPUT=""
for arg in "$@"; do
  case "$arg" in
    -Dmdep.outputFile=*) OUTPUT="${arg#*=}" ;;
  esac
done
test -n "$OUTPUT"
mkdir -p "$(dirname "$OUTPUT")"
printf 'fake-classpath\n' >"$OUTPUT"
EOF

cat >"$TMP/java" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$JAVA_CALL_LOG"
EOF

chmod +x "$TMP/mvn" "$TMP/java"
JAVA_CALL_LOG="$TMP/java-calls" PATH="$TMP:$PATH" "$ROOT/run-java.sh"

test "$(wc -l <"$TMP/java-calls" | tr -d ' ')" = 3
grep -Fq -- '--mode=native' "$TMP/java-calls"
grep -Fq -- '--mode=v4' "$TMP/java-calls"
grep -Fq -- '--mode=v5' "$TMP/java-calls"
test "$(grep -Fc -- '-XX:TieredStopAtLevel=1' "$TMP/java-calls")" = 3

echo "run-all process isolation OK"
