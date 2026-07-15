#!/usr/bin/env python3
"""Cross-ABI static proof for the 16x16 correction-basis transpose."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
ARM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace")
X64 = (ROOT / ".omx/static-audit-20260713/x86_64-full-objdump.txt").read_text(
    errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


# ARM64 0x135050 zeroes a 32-byte local matrix, reads source halfwords,
# constructs MSB-first row masks, conditionally ORs them into local columns,
# and copies all sixteen halfwords back.
require(ARM, r"135170:.*stp\s+q0, q0, \[sp\]", "ARM local matrix zero")
require(ARM, r"1352c4:.*sub\s+w23, w16, w20", "ARM source row bit index")
require(ARM, r"1352c8:.*ldrh\s+w22, \[x0, x20, lsl #1\]", "ARM source halfword read")
require(ARM, r"1352dc:.*lsl\s+w23, w17, w23", "ARM source row mask")
require(ARM, r"135220:.*sub\s+w27, w16, w24", "ARM destination column bit index")
require(ARM, r"135224:.*lsr\s+w27, w22, w27", "ARM source bit extraction")
require(ARM, r"13524c:.*ldrh\s+w27, \[x6, x24, lsl #1\]", "ARM local column read")
require(ARM, r"135250:.*orr\s+w27, w27, w23", "ARM conditional row-bit OR")
require(ARM, r"135254:.*strh\s+w27, \[x6, x24, lsl #1\]", "ARM local column write")
require(ARM, r"13526c:.*ldrh\s+w27, \[x6, x26, lsl #1\]", "ARM copy source")
require(ARM, r"135284:.*strh\s+w27, \[x0, x26, lsl #1\]", "ARM copy destination")

# The x86_64 implementation at 0x12f21b exposes the same two 16-iteration
# loops without relying on ARM flattened-register interpretation.
require(X64, r"12f250:.*xorps\s+%xmm0, %xmm0", "x64 local matrix zero")
require(X64, r"12f43a:.*subb\s+%r10b, %cl", "x64 source row bit index")
require(X64, r"12f44b:.*movzwl\s+\(%rcx,%r10,2\), %ecx", "x64 source halfword read")
require(X64, r"12f36a:.*subb\s+%sil, %cl", "x64 destination column bit index")
require(X64, r"12f375:.*btl\s+%ecx, %r8d", "x64 source bit test")
require(X64, r"12f3a1:.*orw\s+%cx, 0x20\(%rsp,%rsi,2\)", "x64 local column OR")
require(X64, r"12f3c3:.*movzwl\s+0x20\(%rsp,%rdx,2\), %ecx", "x64 copy source")
require(X64, r"12f3cd:.*movw\s+%cx, \(%r8,%rdx,2\)", "x64 copy destination")


def transpose(words: list[int]) -> list[int]:
    output = [0] * 16
    for source in range(16):
        destination_bit = 1 << (15 - source)
        for destination in range(16):
            source_bit = 1 << (15 - destination)
            if words[source] & source_bit:
                output[destination] |= destination_bit
    return output


sample = [
    0x1234, 0xabcd, 0x0000, 0xffff,
    0x8001, 0x00ff, 0xff00, 0x5555,
    0xaaaa, 0x1357, 0x2468, 0xdead,
    0xbeef, 0xcafe, 0xbabe, 0x0f0f,
]
expected = [
    0x5a9e, 0x1314, 0x52aa, 0x935a,
    0x529f, 0x1339, 0xd2df, 0x5341,
    0x549e, 0x556c, 0x94be, 0x9546,
    0x54bf, 0xd55f, 0x14cf, 0x5d59,
]
assert transpose(sample) == expected
assert transpose(expected) == sample

for symbol in (
        "recoveredCorrectionBasisTranspose135050",
        "recoveredCorrectionBasisTranspose135050Regression"):
    if symbol not in CPP:
        raise AssertionError(f"missing C++ evidence: {symbol}")

print("arm64/x86_64 correction-basis transpose 0x135050: PASS")
