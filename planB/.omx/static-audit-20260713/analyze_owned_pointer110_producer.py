#!/usr/bin/env python3
"""Static cross-ABI checks for libsigner.so+0x179f8."""

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


arm = section(ARM, "   179f8:", "   18540:")
for evidence in (
    "ldr\tx8, [x8, #0x538]", "bl\t0x92a20", "bl\t0xb3bf4",
    "bl\t0xb9cc8", "bl\t0xb2978", "bl\t0x92b24",
    "bl\t0x95020", "bl\t0x139e20 <malloc@plt>",
    "mov\tw10, #0x22", "mov\tw10, #0xf", "mov\tw10, #0x2",
):
    assert evidence in arm, evidence
assert arm.count("ldr\tx8, [x8, #0xb8]") == 4
assert "add\tx2, x2, #0x444" in arm
assert "ldrb\tw8, [x8, #0x445]" in arm
assert "stlrb\twzr, [x8]" in arm
assert "movi\tv1.16b, #0xcc" in arm

# VMA 0x1430f0 is in the writable LOAD whose file offset is VMA-0x8000.
with SO.open("rb") as handle:
    handle.seek(0x1430F0 - 0x8000)
    encoded = handle.read(16)
assert bytes(byte ^ 0xCC for byte in encoded) == b"publicSourceDir\0"

x64 = section(X64, "   18fe3:", "   19bdf:")
for evidence in (
    "callq\t*0x538(%rax)", "callq\t0x96a44", "callq\t0xab508",
    "callq\t0xaece3", "callq\t0xaa8bb", "callq\t0x96ae0",
    "callq\t0x98081", "callq\t0x132850 <malloc@plt>",
    "movl\t$0x22", "movl\t$0xf", "movl\t$0x2",
):
    assert evidence in x64, evidence
assert x64.count("callq\t*0xb8(%rax)") == 4

for symbol in (
    "RecoveredPublicSourceDirState",
    "acquireRecoveredPublicSourceDir",
    "runRecoveredOwnedPointer110Producer",
    "newStringUtf",
    "stageB3bf4",
    "stageB9cc8",
    "stageB2978",
):
    assert symbol in CPP, symbol

print("OWNED_POINTER110_PRODUCER_AUDIT_PASS")
