#!/usr/bin/env python3
"""Cross-ABI static proof for the urandom/time fallback seed producer."""

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


require(ARM, r"12f3e8:.*cmp\s+x0, #0x0", "ARM null-output gate")
require(ARM, r"12f4b4:.*adr\s+x20, 0x145fd8", "ARM urandom path address")
require(ARM, r"12f934:.*mov\s+x0, x20", "ARM access path")
require(ARM, r"12f938:.*mov\s+w1, #0x4", "ARM access R_OK")
require(ARM, r"12f940:.*str\s+xzr, \[x23\]", "ARM output clear")
require(ARM, r"12f7e4:.*mov\s+w0, #0x38", "ARM openat syscall 56")
require(ARM, r"12f7e8:.*mov\s+w1, #-0x64", "ARM AT_FDCWD")
require(ARM, r"12f7f0:.*mov\s+w3, #0x80000", "ARM O_CLOEXEC")
require(ARM, r"12f840:.*bl\s+0x139f70", "ARM eight-byte read")
require(ARM, r"12f860:.*bl\s+0x139f80", "ARM close after read")
require(ARM, r"12f86c:.*cmp\s+x23, #0x8", "ARM exact read-length gate")
require(ARM, r"12f8ac:.*bl\s+0x13a0b0", "ARM gettimeofday fallback")
require(ARM, r"12f8b0:.*bl\s+0x13a0c0", "ARM getpid fallback")
require(ARM, r"12f8c8:.*eor\s+w8, w8, w0, lsl #16", "ARM pid shift XOR")
require(ARM, r"12f8d0:.*eor\s+w8, w8, w9", "ARM timeval XOR")
require(ARM, r"12f8e4:.*str\s+x8, \[x23\]", "ARM fallback publication")

require(X64, r"129fb8:.*andq\s+\$0x0, \(%rbp\)", "x64 output clear")
require(X64, r"129fc7:.*callq\s+0x132860", "x64 access")
require(X64, r"129e3c:.*callq\s+0x132830", "x64 openat syscall")
require(X64, r"129ea5:.*callq\s+0x1329a0", "x64 read")
require(X64, r"129eb2:.*callq\s+0x1329b0", "x64 close")
require(X64, r"129ef3:.*cmpq\s+\$0x8, %rbp", "x64 exact read-length gate")
require(X64, r"129f32:.*callq\s+0x132ae0", "x64 gettimeofday")
require(X64, r"129f37:.*callq\s+0x132af0", "x64 getpid")
require(X64, r"129f78:.*shll\s+\$0x10, %eax", "x64 pid shift")
require(X64, r"129f7b:.*xorl\s+0x10\(%rsp\), %eax", "x64 seconds XOR")
require(X64, r"129f7f:.*xorl\s+0x18\(%rsp\), %eax", "x64 microseconds XOR")
require(X64, r"129f83:.*movq\s+%rax, \(%rbp\)", "x64 fallback publication")


def fallback(seconds: int, microseconds: int, pid: int) -> int:
    return ((seconds & 0xffffffff)
            ^ (microseconds & 0xffffffff)
            ^ ((pid << 16) & 0xffffffff))


assert fallback(
    0x1122334455667788,
    0x99aabbccddeeff00,
    0x12345678,
) == 0xdef08888

for symbol in (
        "RecoveredEntropySeed12f3acOperations",
        "runRecoveredEntropySeed12f3ac",
        "recoveredEntropySeed12f3acRegression"):
    if symbol not in CPP:
        raise AssertionError(f"missing C++ evidence: {symbol}")

print("arm64/x86_64 entropy seed producer 0x12f3ac: PASS")
