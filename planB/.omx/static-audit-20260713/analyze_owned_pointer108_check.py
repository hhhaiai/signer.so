#!/usr/bin/env python3
"""Static cross-ABI checks for libsigner.so+0xcde4."""

import struct
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
ARM = (HERE.parent / "libsigner-arm64-objdump.txt").read_text(errors="replace")
X64 = (HERE / "x86_64-full-objdump.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin + len(start))
    return text[begin:finish]


arm = section(ARM, "    cde4:", "    d184:")
for call in ("bl\t0xd184", "bl\t0x1709c", "bl\t0xd428",
             "bl\t0x13548c", "bl\t0x139de0"):
    assert call in arm, call
assert arm.count("bl\t0xd184") == 2
assert "mov\tw1, #0x9" in arm
assert "ldr\tx25, [x19, #0x108]" in arm
assert "movk\tx9, #0x10, lsl #48" in arm

# The first PT_LOAD maps file offsets directly to VMAs here; cde4 loads the
# little-endian double at VMA/file offset 0x2f48.
with SO.open("rb") as handle:
    handle.seek(0x2F48)
    threshold = struct.unpack("<d", handle.read(8))[0]
assert threshold == 15000.0, threshold

x64 = section(X64, "   111bc:", "   11519:")
assert x64.count("callq\t0x11519") == 2
for evidence in (
    "callq\t0x18909", "$0x9", "0x108(%rbx)",
    "$0x10000000000200", "callq\t0x132810 <free@plt>",
):
    assert evidence in x64, evidence

for symbol in (
    "runRecoveredOwnedPointer108StringCheck",
    "applyProtectedCorrection09",
    "applyProtectedCorrection34",
    "applyProtectedContextMask0010000000000200",
):
    assert symbol in CPP, symbol

print("OWNED_POINTER108_CHECK_AUDIT_PASS")
