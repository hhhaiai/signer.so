#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$ROOT/device-reference"
PACKAGE="local.qbdi.adjustreference"
ACTIVITY="$PACKAGE/.MainActivity"
SERIAL="${ANDROID_SERIAL:-37101FDJH0077P}"
OUT="$HERE/build/device-run"
APK="$HERE/build/adjust-reference.apk"
FRIDA_LOG="$OUT/frida.log"
LOGCAT="$OUT/logcat.txt"
LIVE_MAPS="$OUT/live-proc-self-maps.txt"
FRIDA_SCRIPT="$HERE/frida/fixed-runtime.js"
COMBINED_FRIDA_SCRIPT="$OUT/fixed-runtime-combined.js"

if [[ "${REFERENCE_REBUILD:-1}" == 1 || ! -f "$APK" ]]; then
  "$HERE/build-reference-apk.sh"
fi
mkdir -p "$OUT"
rm -f "$OUT/reference-result.json" "$OUT/device-observation.json" "$LIVE_MAPS" \
  "$OUT/reference-error.json" "$FRIDA_LOG" "$LOGCAT"

if [[ "${REFERENCE_REINSTALL:-1}" == 1 ]]; then
  adb -s "$SERIAL" install -r "$APK" >/dev/null
fi
adb -s "$SERIAL" shell pm clear "$PACKAGE" >/dev/null
adb -s "$SERIAL" logcat -c
adb -s "$SERIAL" forward --remove tcp:27042 >/dev/null 2>&1 || true
adb -s "$SERIAL" forward tcp:27042 tcp:27042 >/dev/null

adb -s "$SERIAL" shell am start -n "$ACTIVITY" >/dev/null &
START_PID=$!
gadget=0
for _ in $(seq 1 60); do
  if frida-ps -H 127.0.0.1:27042 2>/dev/null | grep -q Gadget; then
    gadget=1
    break
  fi
  sleep 0.25
done
if [[ "$gadget" != 1 ]]; then
  wait "$START_PID" 2>/dev/null || true
  adb -s "$SERIAL" logcat -d >"$LOGCAT"
  echo "Frida Gadget did not start" >&2
  grep -E 'SignerReference|AndroidRuntime|FATAL EXCEPTION|reference_runtime' "$LOGCAT" >&2 || true
  exit 1
fi

if [[ -n "${REFERENCE_FRIDA_EXTRA:-}" ]]; then
  cat "$FRIDA_SCRIPT" "$REFERENCE_FRIDA_EXTRA" > "$COMBINED_FRIDA_SCRIPT"
  FRIDA_SCRIPT="$COMBINED_FRIDA_SCRIPT"
fi

frida -H 127.0.0.1:27042 -n Gadget -l "$FRIDA_SCRIPT" \
  -q -t 60 --exit-on-error -o "$FRIDA_LOG" >/dev/null 2>&1 &
FRIDA_PID=$!
wait "$START_PID" 2>/dev/null || true

ready=0
for _ in $(seq 1 120); do
  if adb -s "$SERIAL" shell "run-as $PACKAGE sh -c 'test -f files/reference-result.json'" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if adb -s "$SERIAL" shell "run-as $PACKAGE sh -c 'test -f files/reference-error.json'" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

adb -s "$SERIAL" logcat -d >"$LOGCAT"
device_pid="$(adb -s "$SERIAL" shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
if [[ -n "$device_pid" ]]; then
  adb -s "$SERIAL" shell "run-as $PACKAGE cat /proc/$device_pid/maps" >"$LIVE_MAPS" 2>/dev/null || rm -f "$LIVE_MAPS"
fi
if kill -0 "$FRIDA_PID" 2>/dev/null; then kill "$FRIDA_PID" 2>/dev/null || true; fi
wait "$FRIDA_PID" 2>/dev/null || true
adb -s "$SERIAL" forward --remove tcp:27042 >/dev/null 2>&1 || true

if [[ "$ready" != 1 ]]; then
  adb -s "$SERIAL" exec-out run-as "$PACKAGE" cat files/reference-error.json \
    >"$OUT/reference-error.json" 2>/dev/null || true
  cat "$FRIDA_LOG" >&2 || true
  grep -E 'SignerReference|AndroidRuntime|FATAL EXCEPTION' "$LOGCAT" >&2 || true
  [[ -s "$OUT/reference-error.json" ]] && cat "$OUT/reference-error.json" >&2
  exit 1
fi

adb -s "$SERIAL" exec-out run-as "$PACKAGE" cat files/reference-result.json \
  >"$OUT/reference-result.json"
adb -s "$SERIAL" exec-out run-as "$PACKAGE" cat files/device-observation.json \
  >"$OUT/device-observation.json"

python3 -m json.tool "$OUT/reference-result.json"
printf 'REFERENCE_RESULT=%s\n' "$OUT/reference-result.json"
printf 'DEVICE_OBSERVATION=%s\n' "$OUT/device-observation.json"
printf 'FRIDA_LOG=%s\n' "$FRIDA_LOG"
[[ -f "$LIVE_MAPS" ]] && printf 'LIVE_MAPS=%s\n' "$LIVE_MAPS"
