#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$ROOT/unidbg-adjust-runner"
PACKAGE_NAME="${ADJUST_PACKAGE:-com.adjust.test}"
BASE_APK_SRC="${ADJUST_BASE_APK:-$ROOT/adjust-android-signature-3.67.0.aar}"
mkdir -p "$ROOT/unidbg-rootfs/data/app/$PACKAGE_NAME"
cp -f "$BASE_APK_SRC" "$ROOT/unidbg-rootfs/data/app/$PACKAGE_NAME/base.apk"
mvn -q -f "$RUNNER/pom.xml" -DskipTests compile dependency:build-classpath -Dmdep.includeScope=runtime -Dmdep.outputFile="$RUNNER/target/classpath.txt"
CP="$RUNNER/target/classes:$(cat "$RUNNER/target/classpath.txt")"
JAVA_LOG_OPTS="-Dorg.slf4j.simpleLogger.defaultLogLevel=${SLF4J_LEVEL:-error}"
UNIDBG_JAVA_OPTS="-XX:TieredStopAtLevel=1"

run_java() {
  java $UNIDBG_JAVA_OPTS $JAVA_LOG_OPTS ${JAVA_OPTS:-} -cp "$CP" local.AdjustSignatureRunner "$ROOT" "$@"
}

MODE="both"
PASSTHROUGH=("__qbdi_sentinel__")
for arg in "$@"; do
  case "$arg" in
    --mode=*) MODE="$(printf '%s' "${arg#*=}" | tr '[:upper:]' '[:lower:]')" ;;
    *) PASSTHROUGH+=("$arg") ;;
  esac
done

if [[ "$MODE" == "both" ]]; then
  # Unidbg 0.9.8's Unicorn backend is unstable when sequential emulator instances share one JVM on macOS arm64.
  # Keep the public "both" behavior, but isolate each emulator lifecycle in its own process.
  run_java --mode=native "${PASSTHROUGH[@]:1}"
  run_java --mode=v4 "${PASSTHROUGH[@]:1}"
  run_java --mode=v5 "${PASSTHROUGH[@]:1}"
else
  exec java $UNIDBG_JAVA_OPTS $JAVA_LOG_OPTS ${JAVA_OPTS:-} -cp "$CP" local.AdjustSignatureRunner "$ROOT" "$@"
fi
