#!/usr/bin/env python3
"""Statically prove the length-prefixed file-list reader at ARM64 0x11fe4c."""

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


function = body(0x11FE4C, 0x12014C)
for pattern, label in (
    (r"11fe6c:.*stur\s+x3, \[x29, #-0x8\]", "stream save"),
    (r"11fe70:.*mov\s+w22, w2", "expected uint32 size save"),
    (r"11fe78:.*bl\s+0x11fccc", "append before read"),
    (r"11fefc:.*add\s+x8, x0, #0x4", "second header address"),
    (r"120090:.*mov\s+x0, x20", "first header status argument"),
    (r"120094:.*ldr\s+x1, \[sp, #0x10\]", "first header node address"),
    (r"120098:.*mov\s+w2, #0x4", "first header size four"),
    (r"1200a4:.*bl\s+0x11f89c", "first header checked read"),
    (r"1200c8:.*ldr\s+x1, \[sp, #0x8\]", "second header node+4 address"),
    (r"1200cc:.*mov\s+w2, #0x4", "second header size four"),
    (r"1200d8:.*bl\s+0x11f89c", "second header checked read"),
    (r"120050:.*ldr\s+w23, \[x8\]", "payload length load"),
    (r"120054:.*add\s+x8, x23, #0x8", "payload plus header size"),
    (r"120058:.*cmp\s+x8, x9", "zero-extended expected size compare"),
    (r"120008:.*mov\s+w8, #0x8", "size mismatch status 8"),
    (r"1200f8:.*mov\s+w0, #0x1", "payload calloc count one"),
    (r"1200fc:.*mov\s+x1, x23", "payload calloc size"),
    (r"120100:.*bl\s+0x139e50", "payload calloc"),
    (r"120124:.*str\s+x0, \[x8, #0x8\]", "payload pointer publication"),
    (r"120078:.*mov\s+w8, #0x1", "allocation status 1"),
    (r"120020:.*mov\s+x0, x20", "payload read status argument"),
    (r"120024:.*mov\s+x1, x24", "payload read buffer argument"),
    (r"120028:.*mov\s+x2, x23", "payload read exact length"),
    (r"12002c:.*mov\s+w3, #0x1", "payload one-item count"),
    (r"120034:.*bl\s+0x11f89c", "payload checked read"),
):
    require(function, pattern, label)

for symbol in (
    "runRecoveredFileListRecordRead11fe4c",
    "recoveredFileListRecordRead11fe4cRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

require(GENERATOR, r"0x11FE4C:.*recovered", "0x11fe4c coverage entry")

print("FILE_LIST_RECORD_READER_11FE4C_STATIC_OK")
