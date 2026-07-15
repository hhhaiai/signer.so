#!/usr/bin/env python3
"""Static cross-ABI checks for libsigner.so+0x16b7c and +0x95020."""

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


producer = section(ARM, "   16b7c:", "   1709c:")
for evidence in (
    "bl\t0xb3230", "bl\t0x92b24", "bl\t0x139e20 <malloc@plt>",
    "bl\t0x95020", "ldr\tx8, [x8, #0xb8]", "mov\tw10, #0x2",
):
    assert evidence in producer, evidence
assert producer.index("bl\t0xb3230") < producer.index("bl\t0x92b24")
assert producer.index("bl\t0x92b24") < producer.index("bl\t0x139e20")
assert producer.index("bl\t0x139e20") < producer.index("bl\t0x95020")

release = section(ARM, "   95020:", "   95110:")
assert "cmp\tx2, #0x0" in release
assert "ccmp\tx1, #0x0" in release
assert "ldr\tx8, [x8, #0x550]" in release

x64 = section(X64, "   18473:", "   18909:")
for evidence in (
    "callq\t0xaae64", "callq\t0x96ae0", "callq\t0x132850 <malloc@plt>",
    "callq\t0x98081", "callq\t*0xb8(%rax)", "movl\t$0x2",
):
    assert evidence in x64, evidence

for symbol in (
    "runRecoveredOwnedPointer108Producer",
    "runRecoveredReleaseStringUtfChars",
    "stageB3230",
    "stage92b24",
    "deleteLocalRef",
):
    assert symbol in CPP, symbol

print("OWNED_POINTER108_PRODUCER_AUDIT_PASS")
