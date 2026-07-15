#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/5] layout"
"$ROOT/test-layout.sh"

echo "[2/5] example JSON"
python3 -m json.tool "$ROOT/03-unidbg-runner/config/device-profile.example.json" >/dev/null
python3 -m json.tool "$ROOT/03-unidbg-runner/config/request.example.json" >/dev/null
echo "example JSON: PASS"

echo "[3/5] recovered C++ strict check and local-source build"
"$ROOT/01-recovered-cpp/check.sh"
"$ROOT/01-recovered-cpp/build.sh"

echo "[4/5] vendor JNI bridge non-sensitive checks"
"$ROOT/02-vendor-jni-bridge/check.sh"

echo "[5/5] Unidbg non-native offline unit checks"
"$ROOT/03-unidbg-runner/check.sh"

echo "all three implementation entry packages: PASS"
