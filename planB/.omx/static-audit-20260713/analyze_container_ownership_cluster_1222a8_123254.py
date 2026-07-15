#!/usr/bin/env python3
"""Prove the simple container ownership functions from 0x1222a8 to 0x123254."""

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


append = body(0x1222A8, 0x122410)
content_destroy = body(0x122410, 0x12243C)
list_destroy = body(0x122BB8, 0x122D24)
alias = body(0x122FE4, 0x122FE8)
aggregate_destroy = body(0x123254, 0x123288)

for pattern, label in (
    (r"1222c4:.*mov\s+w0, #0x1", "container calloc count one"),
    (r"1222c8:.*mov\s+w1, #0x58", "container node size 0x58"),
    (r"1222dc:.*bl\s+0x139e50", "container calloc"),
    (r"12238c:.*str\s+w22, \[x20\]", "container allocation status 1"),
    (r"122334:.*add\s+x9, x0, #0x10", "second owner address"),
    (r"122338:.*add\s+x10, x0, #0x20", "third owner address"),
    (r"12233c:.*add\s+x11, x0, #0x30", "fourth owner address"),
    (r"122340:.*add\s+x13, x0, #0x50", "outer next-field address"),
    (r"1223ac:.*str\s+x0, \[x0, #0x8\]", "first owner tail slot"),
    (r"1223b0:.*str\s+x9, \[x0, #0x18\]", "second owner tail slot"),
    (r"1223b4:.*str\s+x10, \[x0, #0x28\]", "third owner tail slot"),
    (r"1223bc:.*str\s+x11, \[x0, #0x38\]", "fourth owner tail slot"),
    (r"1223cc:.*stp\s+x0, x13, \[x19\]", "empty outer owner publication"),
    (r"1223e0:.*ldr\s+x2, \[x19, #0x8\]", "nonempty tail-slot load"),
    (r"1223f4:.*str\s+x0, \[x2\]", "nonempty tail publication"),
    (r"1223f8:.*str\s+x13, \[x19, #0x8\]", "outer tail advance"),
):
    require(append, pattern, label)

for pattern, label in (
    (r"122420:.*bl\s+0x121aac", "first-three aggregate destruction"),
    (r"122424:.*add\s+x0, x19, #0x30", "fourth list address"),
    (r"122428:.*bl\s+0x121260", "fourth list destruction"),
    (r"12242c:.*add\s+x0, x19, #0x40", "owned buffer address"),
    (r"122438:.*b\s+0x1221b8", "owned buffer tail destruction"),
):
    require(content_destroy, pattern, label)

for pattern, label in (
    (r"122c90:.*ldr\s+x20, \[x19\]", "outer head load"),
    (r"122ca0:.*mov\s+x0, x20", "content destructor node argument"),
    (r"122ca4:.*bl\s+0x122410", "content destructor call"),
    (r"122ca8:.*mov\s+x0, x20", "node free argument"),
    (r"122cac:.*bl\s+0x139de0", "node free call"),
    (r"122cf0:.*ldr\s+x9, \[x20, #0x50\]", "node next +0x50"),
    (r"122cf8:.*str\s+x9, \[x19\]", "outer head advance"),
    (r"122d04:.*stp\s+xzr, x19, \[x19\]", "outer owner reset"),
):
    require(list_destroy, pattern, label)

require(alias, r"122fe4:.*b\s+0x122bb8", "destructor tail alias")

for pattern, label in (
    (r"123264:.*add\s+x0, x0, #0x28", "third list address"),
    (r"123268:.*bl\s+0x120afc", "third list destruction"),
    (r"12326c:.*add\s+x0, x19, #0x10", "second list address"),
    (r"123270:.*bl\s+0x1203e4", "second list destruction"),
    (r"123278:.*str\s+xzr, \[x19, #0x20\]", "borrowed pointer clear"),
    (r"123284:.*b\s+0x11fb60", "first list tail destruction"),
):
    require(aggregate_destroy, pattern, label)

for symbol in (
    "RecoveredContainerNode1222a8",
    "runRecoveredContainerAppend1222a8",
    "runRecoveredContainerNodeContentsDestroy122410",
    "runRecoveredContainerListDestroy122bb8",
    "runRecoveredContainerListDestroy122fe4",
    "runRecoveredThreeListTwoFieldAggregateDestroy123254",
    "recoveredContainerOwnershipCluster1222a8123254Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

for address in (
    "0x1222A8",
    "0x122410",
    "0x122BB8",
    "0x122FE4",
    "0x123254",
):
    require(GENERATOR, rf"{address}:.*recovered", f"{address} coverage entry")

print("CONTAINER_OWNERSHIP_CLUSTER_1222A8_123254_STATIC_OK")
