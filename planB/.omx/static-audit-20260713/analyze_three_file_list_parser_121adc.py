#!/usr/bin/env python3
"""Statically prove the three-section file-list parser at ARM64 0x121adc."""

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


function = body(0x121ADC, 0x122090)
for pattern, label in (
    (r"121afc:.*stur\s+x3, \[x29, #-0x20\]", "stream save"),
    (r"121b04:.*stur\s+w2, \[x29, #-0x24\]", "total uint32 save"),
    (r"121b30:.*add\s+x8, x1, #0x20", "third owner address"),
    (r"121b44:.*stp\s+x8, x1, \[sp, #0x10\]", "third/base owner save"),
    (r"121b48:.*add\s+x8, x1, #0x10", "second owner address"),
    (r"121dd4:.*sub\s+x1, x29, #0x10", "first section-size destination"),
    (r"121dec:.*bl\s+0x11f89c", "first section-size read"),
    (r"121f74:.*add\s+w8, w8, #0x4", "first cumulative prefix"),
    (r"121f78:.*cmp\s+w8, w9", "first cumulative bound"),
    (r"121e1c:.*bl\s+0x12014c", "first section parser"),
    (r"121f34:.*sub\s+x1, x29, #0xc", "second section-size destination"),
    (r"121f48:.*bl\s+0x11f89c", "second section-size read"),
    (r"121fec:.*add\s+w8, w8, w9", "second cumulative length add"),
    (r"121ff4:.*add\s+w8, w8, #0x8", "two-prefix cumulative add"),
    (r"121ff8:.*cmp\s+w8, w9", "second cumulative bound"),
    (r"122034:.*bl\s+0x120858", "second section parser"),
    (r"121f0c:.*sub\s+x1, x29, #0x14", "third section-size destination"),
    (r"121f24:.*bl\s+0x11f89c", "third section-size read"),
    (r"121fa0:.*add\s+w8, w8, w9", "third cumulative length add"),
    (r"121fa8:.*add\s+w8, w8, #0xc", "three-prefix cumulative add"),
    (r"121fb0:.*add\s+w8, w10, w8", "third size cumulative add"),
    (r"121fb4:.*cmp\s+w8, w9", "third cumulative bound"),
    (r"121ea0:.*bl\s+0x120ffc", "third section parser"),
    (r"121db8:.*mov\s+w9, #0x8", "upper-bound status 8"),
    (r"121dc8:.*str\s+w9, \[x22\]", "upper-bound status publication"),
    (r"121e30:.*ldur\s+w8, \[x29, #-0x14\]", "final third size load"),
    (r"121e38:.*add\s+w9, w8, w9", "final cumulative computation"),
    (r"121e60:.*ldur\s+w8, \[x29, #-0x24\]", "final total load"),
    (r"121e74:.*sub\s+w2, w8, w9", "trailing byte count"),
    (r"121e6c:.*mov\s+w3, #0x1", "SEEK_CUR whence"),
    (r"121e78:.*bl\s+0x11f990", "checked trailing seek"),
):
    require(function, pattern, label)

for symbol in (
    "runRecoveredThreeFileListParser121adc",
    "recoveredThreeFileListParser121adcRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

require(GENERATOR, r"0x121ADC:.*recovered", "0x121adc coverage entry")

print("THREE_FILE_LIST_PARSER_121ADC_STATIC_OK")
