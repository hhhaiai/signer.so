#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE="$ROOT/device-reference/references/pixel8-api36/reference-result.json"
REFERENCE_SHA="b163eb800b2a425158f6b825e8e9439b4b9bd1bca8b0ed0be2a155f2ef9ceca0"

test "$(shasum -a 256 "$REFERENCE" | awk '{print $1}')" = "$REFERENCE_SHA"
OUTPUT="$($ROOT/generate-signer.sh "$ROOT/examples/recovered-signer-job.json")"
printf '%s\n' "$OUTPUT"
echo "recovered C++ backend exact frozen Pixel reference match OK" >&2
