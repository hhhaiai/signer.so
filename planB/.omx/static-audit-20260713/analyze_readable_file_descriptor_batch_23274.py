#!/usr/bin/env python3
"""Prove the readable-file descriptor batch at ARM64 0x23274."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM64 = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, label: str) -> None:
    if re.search(pattern, ARM64, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


for pattern, label in (
    (r"232b8:.*add\s+x0, sp, #0x6c.*232bc:.*mov\s+w1, wzr.*232c0:.*mov\s+w2, #0x801.*232fc:.*bl\s+0x139e10", "initial 0x801-byte zeroing"),
    (r"236cc:.*mov\s+w8, #0x800.*236d8:.*add\s+x22, sp, #0x6c", "per-record 0x800 clear setup"),
    (r"23664:.*ldp\s+x22, x8, \[sp, #0x28\].*23678:.*sub\s+x8, x8, #0x1.*2367c:.*strb\s+wzr, \[x22\], #0x1", "per-record byte clear loop"),
    (r"23688:.*ldr\s+x8, \[sp, #0x60\].*2369c:.*add\s+x8, x8, x23, lsl #8.*236a4:.*add\s+x8, x8, #0xf8", "0x100 record stride and count field"),
    (r"235ac:.*lsl\s+x8, x23, #8.*235b8:.*mov\s+w1, #0x801.*235bc:.*ldr\s+x0, \[x9, x8\].*235c0:.*bl\s+0xd6a2c", "readable-file helper call"),
    (r"23528:.*add\s+x8, x8, x23, lsl #8.*23534:.*ldr\s+x1, \[x9, #0x8\].*23538:.*ldr\s+w2, \[x8, #0xa8\].*2353c:.*bl\s+0x23730", "parallel descriptor and kind call"),
    (r"234f8:.*ldr\s+x10, \[sp, #0x20\].*23508:.*ldrh\s+w8, \[x10\].*23510:.*add\s+w8, w8, #0x1.*23514:.*strh\s+w8, \[x10\]", "uint16 match increment"),
    (r"23590:.*tst\s+w0, #0x1", "predicate first-match branch"),
    (r"23630:.*ldr\s+x8, \[sp, #0x18\].*23648:.*cmp\s+x23, x8", "record-count bound"),
):
    require(pattern, label)

for symbol in (
    "runRecoveredReadableFileDescriptorBatch23274",
    "recoveredReadableFileDescriptorBatch23274Regression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("READABLE_FILE_DESCRIPTOR_BATCH_23274_STATIC_OK")
