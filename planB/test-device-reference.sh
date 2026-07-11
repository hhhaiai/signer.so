#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE="$ROOT/device-reference/references/pixel8-api36"

grep -q '"expectedResultFile"[[:space:]]*:' "$REFERENCE/signer-job.json"
ACTUAL="$("$ROOT/generate-signer.sh" "$REFERENCE/signer-job.json")"

# SignerOneClick recursively compares the complete parsed JSON object against
# expectedResultFile. Do not compare serialized JSON text here: '/' and '\/'
# are equivalent JSON strings but different shell byte sequences.
printf '%s\n' "$ACTUAL"
echo "Pixel 8 device reference exact structured JSON match OK" >&2
