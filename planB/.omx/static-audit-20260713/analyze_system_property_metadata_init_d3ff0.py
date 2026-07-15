#!/usr/bin/env python3
"""Statically prove the ARM64 system-property metadata initializer 0xd3ff0."""

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


function = body(0xD3FF0, 0xD4220)
for pattern, label in (
    (r"d4014:.*mov\s+x19, x0", "status pointer save"),
    (r"d4024:.*bl\s+0xd352c", "temporary source creation"),
    (r"d4028:.*ldr\s+w8, \[x19\]", "post-create status load"),
    (r"d4090:.*mov\s+x20, x0", "temporary source publication"),
    (r"d4144:.*mov\s+w0, #0x1", "calloc count one"),
    (r"d4148:.*mov\s+w1, #0x30", "calloc size 0x30"),
    (r"d414c:.*bl\s+0x139e50", "metadata calloc"),
    (r"d4174:.*mov\s+w8, #0x2", "allocation status 2"),
    (r"d417c:.*str\s+w8, \[x19\]", "allocation status store"),
    (r"d4184:.*ldr\s+x8, \[x20, #0x8\]", "source bytes load"),
    (r"d418c:.*ldr\s+w9, \[x20, #0x2c\]", "source uint32 offset load"),
    (r"d419c:.*add\s+x8, x8, x9", "source cursor derivation"),
    (r"d41a0:.*str\s+x8, \[sp, #0x10\]", "source cursor stack publication"),
    (r"d4190:.*mov\s+x0, x19", "populate status argument"),
    (r"d4194:.*mov\s+x1, x20", "populate source argument"),
    (r"d4198:.*mov\s+x3, x21", "populate metadata argument"),
    (r"d41a4:.*bl\s+0xd28d0", "metadata population call"),
    (r"d41a8:.*ldr\s+w8, \[x19\]", "post-populate status load"),
    (r"d41bc:.*mov\s+x0, x21", "failed metadata free argument"),
    (r"d41c0:.*bl\s+0x139de0", "failed metadata free"),
    (r"d41f0:.*mov\s+x0, x20", "source destructor argument"),
    (r"d41f4:.*bl\s+0xd3d90", "unconditional source destructor"),
    (r"d41f8:.*mov\s+x0, x22", "final metadata return"),
):
    require(function, pattern, label)

for symbol in (
    "RecoveredSystemPropertyMetadataSourceD3ff0",
    "runRecoveredSystemPropertyMetadataInitD3ff0",
    "recoveredSystemPropertyMetadataInitD3ff0Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

require(GENERATOR, r"0x00D3FF0:.*recovered", "0xd3ff0 coverage entry")

print("SYSTEM_PROPERTY_METADATA_INIT_D3FF0_STATIC_OK")
