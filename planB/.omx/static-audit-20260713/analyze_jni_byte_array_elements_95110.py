#!/usr/bin/env python3
"""Prove the JNI GetByteArrayElements wrapper at ARM64 0x95110."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM64 = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
X86_64 = (HERE / "x86_64-full-objdump.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


for pattern, label in (
    (r"951a8:.*cmp\s+x2, #0x0", "null array gate"),
    (r"952fc:.*bl\s+0x92ddc", "GetArrayLength wrapper first"),
    (r"953f4:.*ldr\s+x8, \[x8, #0x5c0\]", "GetByteArrayElements vtable slot"),
    (r"953e4:.*mov\s+x2, xzr", "null isCopy pointer"),
    (r"95400:.*str\s+x0, \[x8\]", "elements output publication"),
    (r"9541c:.*bl\s+0x92a20", "pending exception check"),
    (r"952e8:.*mov\s+w8, #0x1c", "status 28"),
    (r"953b0:.*ldur\s+x8, \[x29, #-0x10\].*953b8:.*cmp\s+x8, #0x0", "null elements test"),
    (r"95360:.*ldr\s+x8, \[sp, #0x18\].*95370:.*str\s+wzr, \[x8\].*95374:.*ldur\s+x8, \[x29, #-0x10\].*9537c:.*str\s+xzr, \[x8\]", "paired output cleanup"),
):
    require(ARM64, pattern, label)

for pattern, label in (
    (r"9811d:.*983d4:.*retq", "x86_64 peer function"),
    (r"9827d:.*callq\s+0x96ce4", "x86_64 length wrapper first"),
    (r"9834b:.*callq\s+\*0x5c0\(%rax\)", "x86_64 GetByteArrayElements slot"),
    (r"982c5:.*andl\s+\$0x0, \(%rax\).*982cd:.*andq\s+\$0x0, \(%rax\)", "x86_64 paired cleanup"),
):
    require(X86_64, pattern, label)

for symbol in (
    "RecoveredJniByteArrayElementsOperations95110",
    "runRecoveredJniByteArrayElements95110",
    "recoveredJniByteArrayElements95110Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

print("JNI_BYTE_ARRAY_ELEMENTS_95110_STATIC_OK")
