#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$ROOT/unidbg-adjust-runner"
LOG_DIR="$ROOT/.omx/full-test-logs"
mkdir -p "$LOG_DIR" "$ROOT/.omx/crash-diagnostics"

if [[ "$(uname -s)" == "Darwin" ]] && [[ -x /usr/libexec/java_home ]]; then
  JAVA_17_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
  if [[ -n "$JAVA_17_HOME" ]] && [[ -x "$JAVA_17_HOME/bin/java" ]]; then
    export JAVA_HOME="$JAVA_17_HOME"
    export PATH="$JAVA_HOME/bin:$PATH"
  fi
fi

mvn -q -f "$RUNNER/pom.xml" clean test-compile

while IFS= read -r source; do
  package="$(sed -n 's/^package \([^;]*\);/\1/p' "$source" | head -1)"
  class="$(basename "$source" .java)"
  test_name="${package:+$package.}$class"
  attempt=1
  while true; do
    log="$LOG_DIR/$class-attempt-$attempt.log"
    if mvn -q -f "$RUNNER/pom.xml" -Dtest="$test_name" test >"$log" 2>&1; then
      echo "$test_name: PASS (attempt $attempt)"
      break
    fi
    if [[ "$attempt" -ge 3 ]] || ! grep -Eq \
        'Process Exit Code: (134|135|138)|forked VM terminated without properly saying goodbye' "$log"; then
      cat "$log" >&2
      exit 1
    fi
    echo "$test_name: transient Unidbg/JVM native crash; retrying in a fresh fork" >&2
    attempt=$((attempt + 1))
  done
done < <(find "$RUNNER/src/test/java" -type f -name '*Test.java' | sort)

mvn -q -f "$RUNNER/pom.xml" -DskipTests package

awk -F'[:, ]+' \
  '/Tests run:/{run+=$3; fail+=$5; err+=$7; skip+=$9}
   END{printf "tests=%d failures=%d errors=%d skipped=%d\n",run,fail,err,skip}' \
  "$RUNNER"/target/surefire-reports/*.txt
