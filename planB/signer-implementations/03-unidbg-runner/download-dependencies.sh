#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POM="$HERE/pom.xml"
MVN_BIN="${MVN:-mvn}"
CACHE_DIR="${MAVEN_REPO_LOCAL:-$HERE/dependencies/m2-repository}"

if (( $# > 1 )); then
  echo "usage: $0 [maven-repository-directory]" >&2
  exit 2
fi
if (( $# == 1 )); then
  CACHE_DIR="$1"
fi

[[ -f "$POM" ]] || { echo "missing pom.xml: $POM" >&2; exit 1; }
command -v "$MVN_BIN" >/dev/null 2>&1 || {
  echo "Maven not found: $MVN_BIN" >&2
  exit 1
}

mkdir -p "$CACHE_DIR"
CACHE_DIR="$(cd "$CACHE_DIR" && pwd)"

echo "Maven dependency cache: $CACHE_DIR"
echo "Downloading declared dependencies, transitive dependencies and build plugins..."
"$MVN_BIN" -B -U \
  -f "$POM" \
  -Dmaven.repo.local="$CACHE_DIR" \
  dependency:go-offline

# Surefire selects this provider dynamically after it scans the compiled test
# classpath. dependency:go-offline does not always fetch the provider itself,
# so download it explicitly before asserting that test execution is offline.
"$MVN_BIN" -B -U \
  -f "$POM" \
  -Dmaven.repo.local="$CACHE_DIR" \
  dependency:get \
  -Dartifact=org.apache.maven.surefire:surefire-junit-platform:3.2.5

# The provider aligns its launcher with the project's JUnit Platform version;
# fetch that runtime-only component explicitly as well.
"$MVN_BIN" -B -U \
  -f "$POM" \
  -Dmaven.repo.local="$CACHE_DIR" \
  dependency:get \
  -Dartifact=org.junit.platform:junit-platform-launcher:1.10.2

echo "Verifying the downloaded cache with Maven offline mode..."
"$MVN_BIN" -B -o \
  -f "$POM" \
  -Dmaven.repo.local="$CACHE_DIR" \
  dependency:go-offline

artifact_count="$(find "$CACHE_DIR" -type f \( -name '*.jar' -o -name '*.pom' \) | wc -l | tr -d ' ')"
if [[ "$artifact_count" == "0" ]]; then
  echo "download completed without any Maven artifacts: $CACHE_DIR" >&2
  exit 1
fi

echo "Downloaded Maven POM/JAR files: $artifact_count"
du -sh "$CACHE_DIR"
cat > "$CACHE_DIR/.unidbg-offline-ready" <<EOF
pom=$POM
artifact_count=$artifact_count
verified_with=maven_dependency_go_offline
EOF
echo "Unidbg Maven dependency download and offline verification: PASS"
