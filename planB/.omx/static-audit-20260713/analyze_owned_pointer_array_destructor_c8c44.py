#!/usr/bin/env python3
"""Prove the owned pointer-array destructor at ARM64 0xc8c44."""

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
    (r"c8cb8:.*cmp\s+x0, #0x0", "null array gate"),
    (r"c8cfc:.*stp\s+x1, x0, \[sp\]", "count/array save"),
    (r"c8da0:.*ldr\s+x8, \[sp\]", "count load"),
    (r"c8da8:.*cmp\s+x26, x8", "index/count comparison"),
    (r"c8e68:.*ldr\s+x8, \[sp, #0x8\]", "array load"),
    (r"c8e6c:.*add\s+x28, x8, x25, lsl #3", "slot address"),
    (r"c8e70:.*ldr\s+x21, \[x28\]", "element load"),
    (r"c8e74:.*cmp\s+x21, #0x0", "null element gate"),
    (r"c8db4:.*mov\s+x0, x21", "element free argument"),
    (r"c8db8:.*bl\s+0x139de0", "element free"),
    (r"c8dfc:.*str\s+xzr, \[x28\]", "element slot clear"),
    (r"c8e84:.*add\s+x26, x25, #0x1", "index increment"),
    (r"c8e1c:.*ldr\s+x0, \[sp, #0x8\]", "array free argument"),
    (r"c8e20:.*bl\s+0x139de0", "array free"),
):
    require(pattern, label)

for symbol in (
    "runRecoveredOwnedPointerArrayDestroyC8c44",
    "recoveredOwnedPointerArrayDestroyC8c44Regression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("OWNED_POINTER_ARRAY_DESTRUCTOR_C8C44_STATIC_OK")
