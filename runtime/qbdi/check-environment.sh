#!/bin/sh
set -eu

abi="${LIBSIGNER_TARGET_ABI:-x86_64}"
loader="${LIBSIGNER_ANDROID_LOADER:-}"
pid="${LIBSIGNER_TARGET_PID:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --abi) abi=$2; shift 2 ;;
    --loader) loader=$2; shift 2 ;;
    --pid) pid=$2; shift 2 ;;
    -h|--help)
      echo "usage: $0 [--abi x86_64] [--loader PATH | --pid PID]"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

missing=""
add_missing() {
  if [ -z "$missing" ]; then missing=$1; else missing="$missing, $1"; fi
}

case "$(uname -s 2>/dev/null || echo unknown)" in
  Linux) ;;
  *) add_missing "compatible Android/Linux host or target container (macOS cannot dlopen Android ELF)" ;;
esac

case "$abi" in
  x86_64) ;;
  *) add_missing "x86_64 target ABI (current tracer implementation)" ;;
esac

command -v cmake >/dev/null 2>&1 || add_missing "cmake"
command -v c++ >/dev/null 2>&1 || add_missing "C++17 compiler"

qbdi_ok=false
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists qbdi 2>/dev/null; then
  qbdi_ok=true
elif [ -n "${QBDI_ROOT:-}" ] && [ -f "$QBDI_ROOT/include/QBDI.h" ]; then
  qbdi_ok=true
fi
$qbdi_ok || add_missing "QBDI headers/library (pkg-config qbdi or QBDI_ROOT)"

if [ -n "$pid" ]; then
  case "$pid" in *[!0-9]*|'') add_missing "numeric target PID" ;; esac
  [ -d "/proc/$pid" ] || add_missing "live target process /proc/$pid"
elif [ -n "$loader" ]; then
  [ -x "$loader" ] || add_missing "executable Android/Linux loader at $loader"
else
  add_missing "in-process target (--pid or --loader); QBDI does not remote-attach by itself"
fi

if [ -n "$missing" ]; then
  echo "QBDI environment unavailable: $missing" >&2
  exit 2
fi

echo "QBDI environment ready: abi=$abi target=${pid:-$loader}"

