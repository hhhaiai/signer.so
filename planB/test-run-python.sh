#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cp "$ROOT/run-python.py" "$TMP/run-python.py"
cat >"$TMP/run-java.sh" <<'EOF'
#!/usr/bin/env bash
echo 'NATIVE_SIGNATURE_HEX=aabb'
echo 'SIGNER_V4_SIGNATURE_BASE64=v4-value'
echo 'SIGNER_V5_AUTHORIZATION=v5-value'
EOF
chmod +x "$TMP/run-java.sh" "$TMP/run-python.py"

"$TMP/run-python.py" >"$TMP/output"
grep -Fq 'PYTHON_NATIVE_SIGNATURE_HEX=aabb' "$TMP/output"
grep -Fq 'PYTHON_SIGNER_V4_SIGNATURE_BASE64=v4-value' "$TMP/output"
grep -Fq 'PYTHON_SIGNER_V5_AUTHORIZATION=v5-value' "$TMP/output"

echo "python wrapper contract OK"
