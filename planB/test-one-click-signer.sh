#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
OUTPUT="$("$ROOT/generate-signer.sh" "$ROOT/examples/signer-job.json")"
OUTPUT_REPEAT="$("$ROOT/generate-signer.sh" "$ROOT/examples/signer-job.json")"

test "$OUTPUT" = "$OUTPUT_REPEAT"

printf '%s\n' "$OUTPUT" | grep -Fq '"signed":true'
printf '%s\n' "$OUTPUT" | grep -Fq '"version":"V4"'
printf '%s\n' "$OUTPUT" | grep -Eq '"rawSignatureHex":"[0-9a-f]+"'
printf '%s\n' "$OUTPUT" | grep -Eq '"signatureBase64":".+"'

python3 - "$ROOT/examples/signer-job.json" "$OUTPUT" "$TMP/verified.json" "$TMP/reference.json" <<'PY'
import json
import pathlib
import sys

job_path = pathlib.Path(sys.argv[1]).resolve()
job = json.loads(job_path.read_text())
base_apk = pathlib.Path(job["device"]["baseApk"])
if not base_apk.is_absolute():
    job["device"]["baseApk"] = str((job_path.parent / base_apk).resolve())
reference = json.loads(sys.argv[2])
pathlib.Path(sys.argv[4]).write_text(json.dumps(reference, ensure_ascii=False))
job["expectedResultFile"] = sys.argv[4]
pathlib.Path(sys.argv[3]).write_text(json.dumps(job, ensure_ascii=False))
PY
test "$("$ROOT/generate-signer.sh" "$TMP/verified.json")" = "$OUTPUT"

python3 - "$TMP/reference.json" <<'PY'
import json
import pathlib
import sys

reference_path = pathlib.Path(sys.argv[1])
reference = json.loads(reference_path.read_text())
reference["rawSignatureHex"] = "00"
reference_path.write_text(json.dumps(reference, ensure_ascii=False))
PY
if "$ROOT/generate-signer.sh" "$TMP/verified.json" >"$TMP/mismatch.out" 2>"$TMP/mismatch.err"; then
  echo "mismatched expectedResult unexpectedly passed" >&2
  exit 1
fi
grep -Fq 'expectedResult mismatch at expectedResult.rawSignatureHex' "$TMP/mismatch.err"

printf '%s\n' "$OUTPUT"
echo "one-click deterministic signer and strict reference verification OK" >&2
