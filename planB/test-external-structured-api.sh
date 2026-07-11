#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$ROOT/unidbg-adjust-runner"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mvn -q -f "$RUNNER/pom.xml" -DskipTests package dependency:build-classpath \
  -Dmdep.includeScope=runtime -Dmdep.outputFile="$RUNNER/target/runtime-classpath.txt"

CP="$RUNNER/target/unidbg-adjust-runner-1.0-SNAPSHOT.jar:$(cat "$RUNNER/target/runtime-classpath.txt")"
javac -cp "$CP" -d "$TMP" "$ROOT/examples/StructuredSignerExample.java"
for n in 1 2; do
  (
    export ADJUST_NATIVE_PROCESS_ID=4242
    export ADJUST_NATIVE_TIME_SECONDS=1760000000
    export ADJUST_NATIVE_GETTIMEOFDAY_SECONDS=1760000000
    export ADJUST_NATIVE_GETTIMEOFDAY_MICROSECONDS=123000
    export ADJUST_NATIVE_CLOCK_GETTIME_SECONDS=1760000000
    export ADJUST_NATIVE_CLOCK_GETTIME_NANOSECONDS=123000000
    java -XX:TieredStopAtLevel=1 -Dorg.slf4j.simpleLogger.defaultLogLevel=error \
      -cp "$TMP:$CP" StructuredSignerExample "$ROOT" >"$TMP/output$n"
  )
done
grep '^STRUCTURED_' "$TMP/output1" >"$TMP/result1"
grep '^STRUCTURED_' "$TMP/output2" >"$TMP/result2"
cmp "$TMP/result1" "$TMP/result2"
cp "$TMP/result1" "$TMP/output"

grep -Fq 'STRUCTURED_SIGNER_SIGNED=true' "$TMP/output"
grep -Eq '^STRUCTURED_SIGNER_RAW_LENGTH=[1-9][0-9]*$' "$TMP/output"
grep -Eq '^STRUCTURED_SIGNER_SIGNATURE_BASE64=.+$' "$TMP/output"
grep -Eq '^STRUCTURED_SIGNER_NATIVE_VERSION=.+$' "$TMP/output"

cat "$TMP/output"
echo "external structured signer API deterministic OK"
