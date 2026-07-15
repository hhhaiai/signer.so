#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAVEN_PROJECT="$HERE"
PROJECT_ROOT="${SIGNER_PROJECT_ROOT:-$(cd "$HERE/../.." && pwd)}"
MVN_BIN="${MVN:-mvn}"
LOCAL_REPOSITORY="${MAVEN_REPO_LOCAL:-$HERE/dependencies/m2-repository}"

[[ -f "$MAVEN_PROJECT/pom.xml" ]] || { echo "missing Maven project: $MAVEN_PROJECT" >&2; exit 1; }
[[ -d "$PROJECT_ROOT" ]] || { echo "signer project root not found: $PROJECT_ROOT" >&2; exit 1; }
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
command -v "$MVN_BIN" >/dev/null 2>&1 || { echo "Maven not found: $MVN_BIN" >&2; exit 1; }

MAVEN_REPOSITORY_ARGS=()
if [[ -d "$LOCAL_REPOSITORY" ]]; then
  LOCAL_REPOSITORY="$(cd "$LOCAL_REPOSITORY" && pwd)"
  MAVEN_REPOSITORY_ARGS+=("-Dmaven.repo.local=$LOCAL_REPOSITORY")
  echo "Using local Maven repository: $LOCAL_REPOSITORY"
fi

tests="com.adjust.sdk.sig.ApkManifestReaderTest,com.adjust.sdk.sig.ApkSigningBlockCertificatesTest,com.adjust.sdk.sig.SignerContractTest,local.AdjustSignatureRunnerDiagnosticsTest,local.BionicRandomTest,local.DeviceProfileFlexibleTest,local.SignerEngineTest,local.SignerOneClickTest"
"$MVN_BIN" -o -f "$MAVEN_PROJECT/pom.xml" \
  "${MAVEN_REPOSITORY_ARGS[@]}" \
  -Dsigner.projectRoot="$PROJECT_ROOT" \
  -Dtest="$tests" \
  test
echo "Unidbg non-native unit checks (46 tests): PASS"
