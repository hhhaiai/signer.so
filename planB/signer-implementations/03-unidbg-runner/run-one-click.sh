#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAVEN_PROJECT="$HERE"
PROJECT_ROOT="${SIGNER_PROJECT_ROOT:-$(cd "$HERE/../.." && pwd)}"
INPUT="${1:-}"

[[ -n "$INPUT" ]] || { echo "usage: $0 <request.json>" >&2; exit 2; }
[[ -f "$INPUT" ]] || { echo "request JSON not found: $INPUT" >&2; exit 2; }
INPUT="$(cd "$(dirname "$INPUT")" && pwd)/$(basename "$INPUT")"
[[ -d "$PROJECT_ROOT" ]] || { echo "signer project root not found: $PROJECT_ROOT" >&2; exit 2; }
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"

python3 -m json.tool "$INPUT" >/dev/null
[[ -f "$MAVEN_PROJECT/target/classes/local/SignerOneClick.class" \
   && -f "$MAVEN_PROJECT/target/runtime-classpath.txt" ]] || "$HERE/build.sh"

CLASSPATH="$MAVEN_PROJECT/target/classes:$(cat "$MAVEN_PROJECT/target/runtime-classpath.txt")"
echo "warning: starting local Unidbg execution with the caller-supplied JSON profile" >&2
exec java -cp "$CLASSPATH" local.SignerOneClick "$INPUT" "$PROJECT_ROOT"
