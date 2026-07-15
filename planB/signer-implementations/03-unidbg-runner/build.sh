#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAVEN_PROJECT="$HERE"
MVN_BIN="${MVN:-mvn}"
LOCAL_REPOSITORY="${MAVEN_REPO_LOCAL:-$HERE/dependencies/m2-repository}"

[[ -f "$MAVEN_PROJECT/pom.xml" ]] || { echo "missing Maven project: $MAVEN_PROJECT" >&2; exit 1; }
[[ -d "$MAVEN_PROJECT/src/main/java" ]] || { echo "missing main sources: $MAVEN_PROJECT/src/main/java" >&2; exit 1; }
[[ -d "$MAVEN_PROJECT/src/test/java" ]] || { echo "missing test sources: $MAVEN_PROJECT/src/test/java" >&2; exit 1; }
command -v "$MVN_BIN" >/dev/null 2>&1 || { echo "Maven not found: $MVN_BIN" >&2; exit 1; }
command -v java >/dev/null 2>&1 || { echo "Java runtime not found" >&2; exit 1; }

MAVEN_REPOSITORY_ARGS=()
if [[ -d "$LOCAL_REPOSITORY" ]]; then
  LOCAL_REPOSITORY="$(cd "$LOCAL_REPOSITORY" && pwd)"
  MAVEN_REPOSITORY_ARGS+=("-Dmaven.repo.local=$LOCAL_REPOSITORY")
  echo "Using local Maven repository: $LOCAL_REPOSITORY"
fi

"$MVN_BIN" -o -f "$MAVEN_PROJECT/pom.xml" \
  "${MAVEN_REPOSITORY_ARGS[@]}" -DskipTests package
"$MVN_BIN" -o -f "$MAVEN_PROJECT/pom.xml" \
  "${MAVEN_REPOSITORY_ARGS[@]}" \
  dependency:build-classpath \
  -Dmdep.outputFile="$MAVEN_PROJECT/target/runtime-classpath.txt"
echo "Unidbg build: $MAVEN_PROJECT/target"
