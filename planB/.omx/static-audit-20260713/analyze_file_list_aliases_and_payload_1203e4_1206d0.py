#!/usr/bin/env python3
"""Prove the file-list aliases and sized-payload reader through 0x1206d0."""

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


destructor = body(0x1203E4, 0x120550)
append = body(0x120550, 0x1206D0)
reader = body(0x1206D0, 0x120858)

for pattern, label in (
    (r"1204bc:.*ldr\s+x20, \[x19\]", "destructor head load"),
    (r"1204cc:.*ldr\s+x9, \[x20, #0x10\]", "destructor next +0x10"),
    (r"1204d4:.*str\s+x9, \[x19\]", "destructor head advance"),
    (r"12050c:.*ldr\s+x0, \[x20, #0x8\]", "destructor payload +0x08"),
    (r"120510:.*bl\s+0x139de0", "destructor payload free"),
    (r"120514:.*mov\s+x0, x20", "destructor node free argument"),
    (r"120518:.*bl\s+0x139de0", "destructor node free"),
    (r"120530:.*stp\s+xzr, x19, \[x19\]", "destructor owner reset"),
):
    require(destructor, pattern, label)

for pattern, label in (
    (r"120574:.*mov\s+w0, #0x1", "append calloc count one"),
    (r"120578:.*mov\s+w1, #0x18", "append node size 0x18"),
    (r"120598:.*bl\s+0x139e50", "append calloc"),
    (r"120688:.*str\s+w23, \[x20\]", "append status 1"),
    (r"120670:.*stp\s+x0, x10, \[x19\]", "append empty-owner publication"),
    (r"12069c:.*ldr\s+x16, \[x19, #0x8\]", "append tail-slot load"),
    (r"1206b0:.*str\s+x0, \[x16\]", "append tail publication"),
    (r"1206b4:.*str\s+x10, \[x19, #0x8\]", "append node+0x10 advance"),
):
    require(append, pattern, label)

for pattern, label in (
    (r"1206f4:.*stur\s+x3, \[x29, #-0x8\]", "reader stream save"),
    (r"1206fc:.*mov\s+w19, w2", "reader uint32 length save"),
    (r"12070c:.*bl\s+0x120550", "reader append call"),
    (r"120710:.*ldr\s+w8, \[x21\]", "reader post-append status"),
    (r"1207f8:.*str\s+w8, \[x22\]", "reader length publication +0"),
    (r"1207f0:.*mov\s+w0, #0x1", "reader calloc count one"),
    (r"1207f4:.*mov\s+x1, x23", "reader calloc length"),
    (r"1207fc:.*bl\s+0x139e50", "reader payload calloc"),
    (r"12080c:.*str\s+x0, \[x22, #0x8\]", "reader payload publication +8"),
    (r"120828:.*str\s+w9, \[x21\]", "reader allocation status 1"),
    (r"1207c0:.*mov\s+x0, x21", "reader checked-read status"),
    (r"1207c4:.*mov\s+x1, x24", "reader checked-read payload"),
    (r"1207c8:.*mov\s+x2, x23", "reader exact payload length"),
    (r"1207cc:.*mov\s+w3, #0x1", "reader one-item count"),
    (r"1207d4:.*bl\s+0x11f89c", "reader checked-read call"),
):
    require(reader, pattern, label)

for symbol in (
    "runRecoveredFileListDestroy1203e4",
    "runRecoveredFileListAppend120550",
    "runRecoveredFileListSizedPayloadRead1206d0",
    "recoveredFileListAliasAndSizedPayload1203e41205501206d0Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

for address in ("0x1203E4", "0x120550", "0x1206D0"):
    require(GENERATOR, rf"{address}:.*recovered", f"{address} coverage entry")

print("FILE_LIST_ALIASES_PAYLOAD_1203E4_1206D0_STATIC_OK")
