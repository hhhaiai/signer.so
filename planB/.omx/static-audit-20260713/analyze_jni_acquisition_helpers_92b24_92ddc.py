#!/usr/bin/env python3
"""Statically prove the JNI UTF-char and array-length acquisition helpers."""

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


utf = body(0x92B24, 0x92DDC)
array = body(0x92DDC, 0x93014)

for pattern, label in (
    (r"92b50:.*mov\s+x3, x4", "length output forwarded to 0x927c4"),
    (r"92b78:.*bl\s+0x927c4", "GetStringUTFLength helper call"),
    (r"92d54:.*ldr\s+x8, \[x8, #0x548\]", "GetStringUTFChars slot"),
    (r"92d58:.*blr\s+x8", "GetStringUTFChars call"),
    (r"92d60:.*str\s+x0, \[x8\]", "UTF pointer publication"),
    (r"92d68:.*bl\s+0x92a20", "UTF exception consumer"),
    (r"92d38:.*mov\s+w10, #0x1c", "UTF status 28"),
    (r"92d20:.*str\s+xzr, \[x8\]", "UTF pointer clear"),
    (r"92d2c:.*str\s+xzr, \[x8\]", "UTF length clear"),
    (r"92da8:.*ldur\s+x8, \[x29, #-0x8\]", "UTF output pointer reload"),
    (r"92dac:.*ldr\s+x8, \[x8\]", "UTF null-result load"),
    (r"92db0:.*cmp\s+x8, #0x0", "UTF null-result test"),
):
    require(utf, pattern, label)

for pattern, label in (
    (r"92e58:.*cmp\s+x2, #0x0", "array null test"),
    (r"92f4c:.*ldr\s+x8, \[x8, #0x558\]", "GetArrayLength slot"),
    (r"92f50:.*blr\s+x8", "GetArrayLength call"),
    (r"92f58:.*str\s+w0, \[x8\]", "32-bit jsize publication"),
    (r"92f60:.*bl\s+0x92a20", "array exception consumer"),
    (r"92fb4:.*mov\s+w22, #0x3", "null-array status 3"),
    (r"92fe0:.*mov\s+w22, #0x1c", "array status 28"),
    (r"92fd4:.*str\s+w22, \[x24\]", "array status publication"),
    (r"92fcc:.*str\s+wzr, \[x8\]", "array length clear"),
):
    require(array, pattern, label)

for symbol in (
    "runRecoveredJniStringUtfChars92b24",
    "recoveredJniStringUtfChars92b24Regression",
    "runRecoveredJniArrayLength92ddc",
    "recoveredJniArrayLength92ddcRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

require(GENERATOR, r"0x092B24:.*recovered", "0x92b24 coverage entry")
require(GENERATOR, r"0x092DDC:.*recovered", "0x92ddc coverage entry")

print("JNI_ACQUISITION_HELPERS_92B24_92DDC_STATIC_OK")
