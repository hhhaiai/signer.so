#!/usr/bin/env python3
"""Statically prove the bounded file-list sequence reader at ARM64 0x12014c."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


def body(start: int, end: int) -> str:
    lines: list[str] = []
    for line in DISASM.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


function = body(0x12014C, 0x1203E4)
for pattern, label in (
    (r"120190:.*str\s+x3, \[sp, #0x18\]", "stream save"),
    (r"120194:.*str\s+w2, \[sp, #0x14\]", "total uint32 save"),
    (r"1201c0:.*stp\s+x8, x1, \[sp\]", "owner save"),
    (r"1201ec:.*mov\s+w20, wzr", "zero offset initialization"),
    (r"120328:.*ldr\s+w8, \[sp, #0x14\]", "total reload"),
    (r"12032c:.*mov\s+w24, w20", "previous offset save"),
    (r"120330:.*cmp\s+w20, w8", "unsigned offset/total comparison"),
    (r"12035c:.*sub\s+x1, x29, #0xc", "record-size destination"),
    (r"120364:.*mov\s+w2, #0x4", "record-size read width"),
    (r"120368:.*mov\s+w3, #0x1", "record-size one-item count"),
    (r"120370:.*bl\s+0x11f89c", "record-size checked read"),
    (r"1202f4:.*ldur\s+w2, \[x29, #-0xc\]", "nested record size argument"),
    (r"1202f8:.*mov\s+x0, x22", "nested status argument"),
    (r"1202fc:.*ldr\s+x1, \[sp, #0x8\]", "nested owner argument"),
    (r"120300:.*ldr\s+x3, \[sp, #0x18\]", "nested stream argument"),
    (r"120304:.*bl\s+0x11fe4c", "nested record reader"),
    (r"120308:.*ldr\s+w8, \[x22\]", "nested status load"),
    (r"12033c:.*ldur\s+w8, \[x29, #-0xc\]", "record size reload"),
    (r"12034c:.*add\s+w8, w24, w8", "uint32 offset plus record size"),
    (r"120354:.*add\s+w20, w8, #0x4", "uint32 prefix advance"),
    (r"1202e4:.*ldr\s+w8, \[sp, #0x14\]", "termination total reload"),
    (r"1202e8:.*cmp\s+w24, w8", "exact-total comparison"),
    (r"1203a0:.*mov\s+w8, #0x8", "overshoot status 8"),
    (r"1203a4:.*str\s+w8, \[x22\]", "overshoot status publication"),
):
    require(function, pattern, label)

for symbol in (
    "runRecoveredFileListReadSequence12014c",
    "recoveredFileListReadSequence12014cRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

require(GENERATOR, r"0x12014C:.*recovered", "0x12014c coverage entry")

print("FILE_LIST_SEQUENCE_READER_12014C_STATIC_OK")
