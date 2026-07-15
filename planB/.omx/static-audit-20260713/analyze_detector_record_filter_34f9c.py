#!/usr/bin/env python3
"""Prove the detector record pointer filter at ARM64 0x34f9c."""

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
    (r"34fcc:.*mov\s+x0, x2.*34fd0:.*mov\s+w1, #0x8.*34ff4:.*bl\s+0x139e50", "calloc count by eight"),
    (r"35294:.*ldr\s+x6, \[x22, x28, lsl #3\]", "ordered input pointer load"),
    (r"3529c:.*ldr\s+x11, \[x6, #0x8\].*352a0:.*cmp\s+x11, #0x0", "required field 08"),
    (r"351e0:.*ldr\s+x11, \[x6, #0x18\].*351e8:.*cmp\s+x11, #0x0", "required field 18"),
    (r"351ac:.*ldr\s+x11, \[x6, #0x20\].*351b4:.*cmp\s+x11, #0x0", "required field 20"),
    (r"351f4:.*ldr\s+x11, \[x6, #0x28\].*351fc:.*cmp\s+x11, #0xa", "kind 10"),
    (r"35208:.*add\s+x30, x27, #0x1.*3520c:.*str\s+x6, \[x0, x27, lsl #3\]", "selected append"),
    (r"35234:.*ldr\s+x3, \[sp\].*35248:.*str\s+x0, \[x3\].*3524c:.*ldr\s+x3, \[sp, #0x8\].*35254:.*str\s+x27, \[x3\]", "success outputs"),
    (r"35260:.*mov\s+w3, #0x2.*35274:.*str\s+w3, \[x23\]", "allocation status 2"),
    (r"352b0:.*cmp\s+x0, #0x0.*352b8:.*cset\s+w0, ne", "allocation boolean return"),
):
    require(ARM64, pattern, label)

for pattern, label in (
    (r"32f7c:.*movq\s+%rdx, %rdi.*32f7f:.*callq\s+0x132880", "x86_64 calloc"),
    (r"331f1:.*cmpq\s+\$0x0, 0x8\(%r15\)", "x86_64 field 08"),
    (r"33109:.*cmpq\s+\$0x0, 0x18\(%r15\)", "x86_64 field 18"),
    (r"330e5:.*cmpq\s+\$0x0, 0x20\(%r15\)", "x86_64 field 20"),
    (r"33126:.*cmpq\s+\$0xa, 0x28\(%r15\)", "x86_64 kind 10"),
    (r"3314a:.*leaq\s+0x1\(%rax\), %rdx.*33152:.*movq\s+%r15, \(%rbx,%rax,8\)", "x86_64 selected append"),
    (r"33198:.*movl\s+\$0x2, \(%rdx\)", "x86_64 status 2"),
):
    require(X86_64, pattern, label)

for symbol in (
    "RecoveredDetectorRecord34f9c",
    "runRecoveredDetectorRecordFilter34f9c",
    "recoveredDetectorRecordFilter34f9cRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

print("DETECTOR_RECORD_FILTER_34F9C_STATIC_OK")
