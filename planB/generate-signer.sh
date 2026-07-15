#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$ROOT/unidbg-adjust-runner"
INPUT="${1:-$ROOT/examples/signer-job.json}"
PROJECT_ROOT="${2:-$ROOT}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
CRASH_DIR="$ROOT/.omx/crash-diagnostics"
mkdir -p "$CRASH_DIR"

mvn -q -f "$RUNNER/pom.xml" -DskipTests package dependency:build-classpath \
  -Dmdep.includeScope=runtime -Dmdep.outputFile="$RUNNER/target/runtime-classpath.txt"

CP="$RUNNER/target/unidbg-adjust-runner-1.0-SNAPSHOT.jar:$(cat "$RUNNER/target/runtime-classpath.txt")"
JAVA_BIN="${SIGNER_JAVA_BIN:-}"
if [[ -z "$JAVA_BIN" ]] && [[ "$(uname -s)" == "Darwin" ]] && [[ -x /usr/libexec/java_home ]]; then
  JAVA_17_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
  if [[ -n "$JAVA_17_HOME" ]] && [[ -x "$JAVA_17_HOME/bin/java" ]]; then
    JAVA_BIN="$JAVA_17_HOME/bin/java"
  fi
fi
JAVA_BIN="${JAVA_BIN:-java}"

ATTEMPT=1
while true; do
  if "$JAVA_BIN" -XX:TieredStopAtLevel=1 -XX:ErrorFile="$CRASH_DIR/hs_err_pid%p.log" \
      -Dorg.slf4j.simpleLogger.defaultLogLevel=error -cp "$CP" \
      local.SignerOneClick "$INPUT" "$PROJECT_ROOT" >"$LOG" 2>&1; then
    break
  else
    STATUS=$?
  fi
  if [[ "$(uname -s)" != "Darwin" || "$ATTEMPT" -ge 2 \
      || ( "$STATUS" -ne 134 && "$STATUS" -ne 135 && "$STATUS" -ne 138 ) ]]; then
    cat "$LOG" >&2
    exit "$STATUS"
  fi
  echo "Signer JVM native crash (exit $STATUS); retrying once in a fresh JVM" >&2
  ATTEMPT=$((ATTEMPT + 1))
done

RESULT="$(awk '/^SIGNER_RESULT_JSON=/{sub(/^SIGNER_RESULT_JSON=/, ""); value=$0} END{print value}' "$LOG")"
if [[ -z "$RESULT" ]]; then
  cat "$LOG" >&2
  echo "SIGNER_RESULT_JSON not found" >&2
  exit 1
fi
printf '%s\n' "$RESULT"
