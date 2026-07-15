#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAVEN_PROJECT="$HERE"
PROJECT_ROOT="${SIGNER_PROJECT_ROOT:-$(cd "$HERE/../.." && pwd)}"
MODE="${1:-}"
PARAMS_FILE="${2:-}"

case "$MODE" in
  native|v4|v5|both) ;;
  *) echo "usage: $0 <native|v4|v5|both> [params.json]" >&2; exit 2 ;;
esac

[[ -d "$PROJECT_ROOT" ]] || { echo "signer project root not found: $PROJECT_ROOT" >&2; exit 2; }
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
args=("$PROJECT_ROOT" "--mode=$MODE")
if [[ -n "$PARAMS_FILE" ]]; then
  [[ -f "$PARAMS_FILE" ]] || { echo "params JSON not found: $PARAMS_FILE" >&2; exit 2; }
  PARAMS_FILE="$(cd "$(dirname "$PARAMS_FILE")" && pwd)/$(basename "$PARAMS_FILE")"
  python3 -m json.tool "$PARAMS_FILE" >/dev/null
  args+=("--params-file=$PARAMS_FILE")
fi

[[ -f "$MAVEN_PROJECT/target/classes/local/AdjustSignatureRunner.class" \
   && -f "$MAVEN_PROJECT/target/runtime-classpath.txt" ]] || "$HERE/build.sh"
CLASSPATH="$MAVEN_PROJECT/target/classes:$(cat "$MAVEN_PROJECT/target/runtime-classpath.txt")"

echo "warning: starting local Unidbg direct execution mode=$MODE" >&2
exec java -cp "$CLASSPATH" local.AdjustSignatureRunner "${args[@]}"
