#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$ROOT/unidbg-adjust-runner"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mvn -q -f "$RUNNER/pom.xml" -DskipTests package dependency:build-classpath \
  -Dmdep.includeScope=runtime -Dmdep.outputFile="$RUNNER/target/runtime-classpath.txt"

javap -classpath "$ROOT/adjust-android-signature-3.67.0/classes.jar" -public -s \
  com.adjust.sdk.sig.Signer >"$TMP/original"
javap -classpath "$RUNNER/target/classes" -public -s \
  com.adjust.sdk.sig.Signer >"$TMP/self"
sed '1s/Compiled from ".*"/Compiled from "Signer"/' "$TMP/original" >"$TMP/original.norm"
sed '1s/Compiled from ".*"/Compiled from "Signer"/' "$TMP/self" >"$TMP/self.norm"
diff -u "$TMP/original.norm" "$TMP/self.norm"

javap -classpath "$RUNNER/target/classes" -p -s \
  com.adjust.sdk.sig.NativeLibHelper >"$TMP/native-helper"
grep -Fq 'private void nOnResume();' "$TMP/native-helper"
grep -Fq 'private byte[] nSign(android.content.Context, java.lang.Object, byte[], int);' "$TMP/native-helper"

if grep -Fq 'classes.jar' "$RUNNER/target/runtime-classpath.txt"; then
  echo "original classes.jar leaked into runtime classpath" >&2
  exit 1
fi

echo "API contract and runtime independence OK"
