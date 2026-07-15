#!/usr/bin/env python3
"""Prove the mapped-file owner destructor at ARM64 0xd3d90."""

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
    (r"d3df4:.*cmp\s+x0, #0x0", "null owner gate"),
    (r"d3f60:.*ldr\s+x20, \[x19, #0x8\]", "mapping load"),
    (r"d3f74:.*add\s+x8, x20, #0x1", "mapping plus one"),
    (r"d3f78:.*cmp\s+x8, #0x2", "nullptr/MAP_FAILED range test"),
    (r"d3f94:.*ldr\s+x1, \[x19, #0x10\]", "mapping length load"),
    (r"d3f98:.*mov\s+x0, x20", "munmap address"),
    (r"d3f9c:.*bl\s+0x139f20", "munmap call"),
    (r"d3f2c:.*ldr\s+w21, \[x19\]", "file descriptor load"),
    (r"d3f48:.*cmp\s+w21, #0x0", "nonnegative fd test"),
    (r"d3fb4:.*mov\s+w0, #0x39", "AArch64 close syscall number 57"),
    (r"d3fb8:.*mov\s+w1, w21", "close fd argument"),
    (r"d3fbc:.*bl\s+0x139e00", "syscall close"),
    (r"d3f10:.*mov\s+x0, x19", "owner free argument"),
    (r"d3f14:.*bl\s+0x139de0", "owner free call"),
):
    require(pattern, label)

for symbol in (
    "RecoveredMappedFileOwnerD3d90",
    "runRecoveredMappedFileDestroyD3d90",
    "recoveredMappedFileDestroyD3d90Regression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("MAPPED_FILE_DESTRUCTOR_D3D90_STATIC_OK")
