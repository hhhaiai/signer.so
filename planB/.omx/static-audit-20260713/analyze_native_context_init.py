#!/usr/bin/env python3
"""Static cross-ABI checks for recovered native-context initialization."""

from pathlib import Path


HERE = Path(__file__).resolve().parent
ARM = (HERE.parent / "libsigner-arm64-objdump.txt").read_text(errors="replace")
X64 = (HERE / "x86_64-full-objdump.txt").read_text(errors="replace")
CPP = (HERE.parent.parent / "native-reimplementation" /
       "recovered_primitives.cpp").read_text(errors="replace")


def section(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin + len(start))
    return text[begin:finish]


stage1 = section(ARM, "   cba90:", "   cbbd4:")
for call in ("bl\t0x13088", "bl\t0xf328", "bl\t0x13000", "bl\t0x9279c"):
    assert call in stage1, call
assert stage1.index("bl\t0x13088") < stage1.index("bl\t0xf328")
assert stage1.index("bl\t0x13000") < stage1.index("bl\t0x9279c")

stage2 = section(ARM, "   cbbd4:", "   cbe94:")
for call in (
    "bl\t0x8128", "bl\t0xe6c0", "bl\t0xf1fc", "bl\t0x16b7c",
    "bl\t0xcde4", "bl\t0x179f8", "bl\t0xd428", "bl\t0xd45c",
    "bl\t0xd474", "bl\t0xd980", "bl\t0xd9b4", "bl\t0xddc4",
    "bl\t0xe674", "bl\t0xe6a8", "bl\t0x14ef8", "bl\t0x15104",
):
    assert call in stage2, call
assert "cbe94: 17fd2155" in ARM and "b\t0x143e8" in ARM

for immediate in (
    "$0x10000000000200", "$0x80020000000000",
    "$0x100040000000000", "$0x1181c000010e",
    "$0x3dffe800", "$0x2001000", "$0x800800000000000",
):
    assert immediate in X64, immediate

for symbol in (
    "runRecoveredNativeContextInitStage1",
    "runRecoveredNativeContextInitStage2",
    "runRecoveredEnvironmentDispatcherTail",
    "runRecoveredContextPostStage14ef8",
    "applyProtectedContextFallbackMaskStage",
    "applyProtectedContextMask0800800000000000",
):
    assert symbol in CPP, symbol

print("NATIVE_CONTEXT_INIT_AUDIT_PASS")
