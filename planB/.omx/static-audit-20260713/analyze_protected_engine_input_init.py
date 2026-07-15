#!/usr/bin/env python3
"""Verify the exact nine-descriptor import loop at ARM64 0xf1ec8."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
ASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


def require(pattern: str, label: str) -> None:
    if re.search(pattern, ASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


require(r"f1f48:.*cmp\s+x23, x26", "descriptor-count loop")
require(r"f1f80:.*ldr\s+x27, \[x8\]", "descriptor pointer load")
require(r"f1f84:.*add\s+x9, x20, x23, lsl #3", "lane pointer index")
require(r"f1f90:.*ldr\s+w8, \[x27\]", "descriptor byte length")
require(r"f1fa0:.*ldr\s+x8, \[x27, #0x8\]", "descriptor byte pointer")
require(r"f1fb4:.*rev\s+w3, w8", "complete-word byte swap")
require(r"f1fb8:.*bl\s+0x138318", "complete-word write")
require(r"f1fc4:.*cbz\s+w8, 0xf1f98", "per-word status check")
require(r"f1fd0:.*and\s+w10, w8, #0x3", "remainder classification")
require(r"f1ff4:.*lsl\s+w3, w8, #24", "one-byte tail")
require(r"f2024:.*orr\s+w9, w9, w10, lsl #16", "three-byte tail middle")
require(r"f2028:.*orr\s+w3, w9, w8, lsl #8", "three-byte tail low")
require(r"f2034:.*ldrh\s+w8, \[x9, w8, uxtw\]", "two-byte tail")
require(r"f2038:.*rev\s+w8, w8", "two-byte tail swap")
require(r"f2048:.*bl\s+0x138318", "tail write")
require(r"f2050:.*add\s+x23, x23, #0x1", "next descriptor")
require(r"f2054:.*cbz\s+w8, 0xf1f48", "per-descriptor status check")

for symbol in (
        "RecoveredProtectedEngineDescriptorF1ec8",
        "runRecoveredProtectedEngineInputInitializationF1ec8",
        "protectedWordRead(work->lanes[0], 0) != 0x11223344U",
        "protectedWordRead(work->lanes[1], 0) != 0x55000000U",
        "protectedWordRead(work->lanes[2], 0) != 0x66770000U",
        "protectedWordRead(work->lanes[3], 0) != 0x8899aa00U"):
    if symbol not in CPP:
        raise AssertionError(f"missing C++ evidence: {symbol}")

print("arm64 protected engine 0xf1ec8 descriptor import evidence: PASS")
