#!/usr/bin/env python3
"""Static cross-ABI checks for libsigner.so+0xd474."""

from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM = (HERE.parent / "libsigner-arm64-objdump.txt").read_text(errors="replace")
X64 = (HERE / "x86_64-full-objdump.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin + len(start))
    return text[begin:finish]


arm = section(ARM, "    d474:", "    d980:")
for evidence in (
    "bl\t0xd184", "bl\t0x18540", "bl\t0xd980",
    "mov\tw1, #0x29", "bl\t0x13548c", "bl\t0x1dbd8",
    "ldr\tx8, [x8, #0x8]", "ldr\tx9, [x8]",
):
    assert evidence in arm, evidence
assert arm.count("bl\t0xd184") == 2
assert "mov\tx9, #0x20000000000" in arm
assert "movk\tx9, #0x80, lsl #48" in arm

destructor = section(ARM, "   1dbd8:", "   1dde0:")
assert "ldr\tx8, [x20, #0x8]" in destructor
assert "str\tx8, [x19]" in destructor
assert destructor.count("bl\t0x139de0 <free@plt>") == 2
assert "str\tx19, [x19, #0x8]" in destructor

x64 = section(X64, "   1179b:", "   11bf5:")
for evidence in (
    "callq\t0x11519", "callq\t0x19bdf", "callq\t0x11bf5",
    "$0x29", "callq\t0x12f5ad", "callq\t0x22b54",
):
    assert evidence in x64, evidence
assert x64.count("callq\t0x11519") == 2

for symbol in (
    "runRecoveredPublicSourceListCheck",
    "applyProtectedCorrection29",
    "applyProtectedCorrection37",
    "applyProtectedContextMask0080020000000000",
    "runRecoveredPublicSourceListProducer",
    "RecoveredOwnedStringList",
    "destroyRecoveredOwnedStringList",
):
    assert symbol in CPP, symbol

assert "stage18540" not in CPP

print("PUBLIC_SOURCE_LIST_CHECK_AUDIT_PASS")
