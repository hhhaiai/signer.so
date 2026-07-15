#!/usr/bin/env python3
"""Prove the 0x100-byte descriptor-record batch matcher at 0x24444."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, label: str) -> None:
    if re.search(pattern, DISASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


for pattern, label in (
    (r"24464:.*stp\s+x1, x2, \[sp, #0x10\]", "record count/counter save"),
    (r"2446c:.*stp\s+xzr, x0, \[sp, #0x38\]", "outer index/base save"),
    (r"246f4:.*mov\s+w24, #0x5c", "92-byte source size"),
    (r"24764:.*strb\s+wzr, \[x26\], #0x1", "source byte zeroing"),
    (r"247a0:.*add\s+x8, x8, x9, lsl #8", "0x100 record stride"),
    (r"247a4:.*ldr\s+x0, \[x8\], #0xf8", "property name and count offset"),
    (r"247ac:.*bl\s+0xd4678", "system property reader call"),
    (r"2462c:.*ldr\s+x8, \[x8\]", "uint64 descriptor count load"),
    (r"24660:.*add\s+x9, x8, x19, lsl #3", "descriptor pointer stride"),
    (r"24664:.*add\s+x8, x8, x19, lsl #2", "descriptor kind stride"),
    (r"24668:.*ldr\s+x1, \[x9, #0x8\]", "descriptor pointer load"),
    (r"2466c:.*ldr\s+w2, \[x8, #0xa8\]", "descriptor kind load"),
    (r"24670:.*bl\s+0x23730", "descriptor predicate call"),
    (r"24644:.*ldrh\s+w8, \[x11\]", "match counter load"),
    (r"24648:.*add\s+w8, w8, #0x1", "match counter increment"),
    (r"2464c:.*strh\s+w8, \[x11\]", "match counter wrapped store"),
):
    require(pattern, label)

for symbol in (
    "RecoveredDescriptorBatchRecord24444",
    "runRecoveredDescriptorBatch24444",
    "recoveredDescriptorBatch24444Regression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("DESCRIPTOR_BATCH_24444_STATIC_OK")
