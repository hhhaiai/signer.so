#!/usr/bin/env python3
"""Prove the readable-file syscall helper at ARM64 0xd6a2c."""

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
    (r"d6a4c:.*cmp\s+x2, #0x0", "null output gate"),
    (r"d6a58:.*ccmp\s+x0, #0x0, #0x4, ne", "null path gate"),
    (r"d6bb8:.*mov\s+w1, #0x4", "access R_OK argument"),
    (r"d6bbc:.*bl\s+0x139e30", "access call"),
    (r"d6c30:.*mov\s+w0, #0x38", "AArch64 openat syscall 56"),
    (r"d6c34:.*mov\s+w1, #-0x64", "openat AT_FDCWD"),
    (r"d6c3c:.*mov\s+w3, wzr", "openat O_RDONLY flags"),
    (r"d6c40:.*mov\s+w4, wzr", "openat zero mode"),
    (r"d6c44:.*bl\s+0x139e00", "openat syscall call"),
    (r"d6c54:.*cmn\s+w23, #0x1", "low-32-bit open failure test"),
    (r"d6c68:.*mov\s+w0, #0x3f", "AArch64 read syscall 63"),
    (r"d6c78:.*bl\s+0x139e00", "read syscall call"),
    (r"d6c7c:.*cmn\s+x0, #0x1", "exact read minus-one test"),
    (r"d6c84:.*cset\s+w8, ne", "read success boolean"),
    (r"d6bfc:.*add\s+x8, x22, x8", "read-result output address"),
    (r"d6c04:.*sturb\s+wzr, \[x8, #-0x1\]", "output readResult-minus-one terminator"),
    (r"d6c0c:.*mov\s+w0, #0x39", "AArch64 close syscall 57"),
    (r"d6c14:.*bl\s+0x139e00", "close syscall call"),
    (r"d6c94:.*and\s+w0, w19, #0x1", "boolean return"),
):
    require(pattern, label)

for symbol in (
    "RecoveredReadableFileReadOperationsD6a2c",
    "runRecoveredReadableFileReadD6a2c",
    "recoveredReadableFileReadD6a2cRegression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("READABLE_FILE_READER_D6A2C_STATIC_OK")
