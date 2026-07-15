#!/usr/bin/env python3
"""Prove the 0x68 large-container ownership helpers."""

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


append = body(0x1238EC, 0x123A54)
content_destroy = body(0x123A54, 0x123A80)
list_destroy = body(0x124608, 0x124774)
alias = body(0x124A20, 0x124A24)

for pattern, label in (
    (r"123908:.*mov\s+w0, #0x1", "calloc count one"),
    (r"12390c:.*mov\s+w1, #0x68", "node size 0x68"),
    (r"123920:.*bl\s+0x139e50", "node calloc"),
    (r"1239d0:.*str\s+w22, \[x20\]", "allocation status 1"),
    (r"123978:.*add\s+x9, x0, #0x10", "second owner address"),
    (r"12397c:.*add\s+x10, x0, #0x28", "third owner address"),
    (r"123980:.*add\s+x11, x0, #0x40", "fourth owner address"),
    (r"123984:.*add\s+x13, x0, #0x60", "next-field address"),
    (r"1239e8:.*str\s+x0, \[x0, #0x8\]", "first tail slot"),
    (r"1239ec:.*str\s+x9, \[x0, #0x18\]", "second tail slot"),
    (r"1239f0:.*str\s+x10, \[x0, #0x30\]", "third tail slot"),
    (r"1239f8:.*str\s+x11, \[x0, #0x48\]", "fourth tail slot"),
    (r"123a08:.*stp\s+x0, x13, \[x19\]", "empty outer publication"),
    (r"123a30:.*str\s+x0, \[x2\]", "nonempty outer publication"),
    (r"123a34:.*str\s+x13, \[x19, #0x8\]", "outer tail advance"),
):
    require(append, pattern, label)

for pattern, label in (
    (r"123a64:.*bl\s+0x123254", "aggregate destruction"),
    (r"123a68:.*add\s+x0, x19, #0x40", "fourth owner address"),
    (r"123a6c:.*bl\s+0x121260", "fourth owner destruction"),
    (r"123a70:.*add\s+x0, x19, #0x50", "buffer address"),
    (r"123a7c:.*b\s+0x1221b8", "buffer tail destruction"),
):
    require(content_destroy, pattern, label)

for pattern, label in (
    (r"1246e0:.*ldr\s+x20, \[x19\]", "outer head load"),
    (r"124708:.*mov\s+x0, x20", "content node argument"),
    (r"12470c:.*bl\s+0x123a54", "content destruction"),
    (r"124714:.*bl\s+0x139de0", "node free"),
    (r"12472c:.*ldr\s+x9, \[x20, #0x60\]", "next +0x60"),
    (r"124734:.*str\s+x9, \[x19\]", "head advance"),
    (r"124754:.*stp\s+xzr, x19, \[x19\]", "owner reset"),
):
    require(list_destroy, pattern, label)

require(alias, r"124a20:.*b\s+0x124608", "tail alias")

for symbol in (
    "RecoveredLargeContainerNode1238ec",
    "runRecoveredLargeContainerAppend1238ec",
    "runRecoveredLargeContainerContentsDestroy123a54",
    "runRecoveredLargeContainerListDestroy124608",
    "runRecoveredLargeContainerListDestroy124a20",
    "recoveredLargeContainerOwnershipCluster1238ec124a20Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

for address in ("0x1238EC", "0x123A54", "0x124608", "0x124A20"):
    require(GENERATOR, rf"{address}:.*recovered", f"{address} coverage entry")

print("LARGE_CONTAINER_OWNERSHIP_1238EC_124A20_STATIC_OK")
