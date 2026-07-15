#!/usr/bin/env python3
"""Prove the path-existence array counter at ARM64 0x1f95c."""

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
    (r"1fa00:.*stur\s+x2, \[x29, #-0x8\]", "uint16 counter save"),
    (r"1fa04:.*stp\s+x0, x1, \[sp, #0x8\]", "array/count save"),
    (r"1fab4:.*mov\s+x23, x21", "current index publication"),
    (r"1fab8:.*cmp\s+x21, x8", "index/count comparison"),
    (r"1fa88:.*ldr\s+x0, \[x8, x23, lsl #3\]", "path pointer load"),
    (r"1fa8c:.*bl\s+0xd7890", "path existence call"),
    (r"1fa64:.*ldrh\s+w8, \[x10\]", "uint16 load"),
    (r"1fa68:.*add\s+w9, w8, #0x1", "match increment"),
    (r"1fa7c:.*strh\s+w9, \[x10\]", "uint16 wrapped store"),
):
    require(pattern, label)

for symbol in (
    "runRecoveredPathExistenceCounter1f95c",
    "recoveredPathExistenceCounter1f95cRegression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("PATH_EXISTENCE_COUNTER_1F95C_STATIC_OK")
