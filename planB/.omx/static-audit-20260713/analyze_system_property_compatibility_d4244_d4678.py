#!/usr/bin/env python3
"""Prove the guarded Android system-property compatibility wrappers."""

from __future__ import annotations

import pathlib
import re
import struct


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, label: str) -> None:
    if re.search(pattern, DISASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def virtual_bytes(address: int, size: int) -> bytes:
    image = SO.read_bytes()
    phoff = struct.unpack_from("<Q", image, 0x20)[0]
    phentsize = struct.unpack_from("<H", image, 0x36)[0]
    phnum = struct.unpack_from("<H", image, 0x38)[0]
    for index in range(phnum):
        offset = phoff + index * phentsize
        fields = struct.unpack_from("<IIQQQQQQ", image, offset)
        if fields[0] != 1:
            continue
        file_offset, vaddr, file_size = fields[2], fields[3], fields[5]
        if vaddr <= address and address + size <= vaddr + file_size:
            start = file_offset + address - vaddr
            return image[start : start + size]
    raise AssertionError(f"VMA not mapped: {address:#x}")


decoded_format = bytes(value ^ 0x26 for value in virtual_bytes(0x145880, 23))
assert decoded_format == b"/dev/__properties__/%s\0"

for pattern, label in (
    (r"d4330:.*mov\s+x0, x20", "direct property name"),
    (r"d4334:.*mov\s+x1, x19", "direct property output"),
    (r"d4338:.*bl\s+0x139f30", "direct __system_property_get"),
    (r"d4378:.*add\s+x0, sp, #0x18", "property-area path buffer"),
    (r"d4380:.*mov\s+w2, #0xc8", "200-byte zeroing"),
    (r"d4390:.*bl\s+0xd43e8", "property-area formatter"),
    (r"d4398:.*mov\s+w1, #0x4", "R_OK access mode"),
    (r"d439c:.*bl\s+0x139e30", "property-area access call"),
    (r"d4360:.*strb\s+wzr, \[x19\]", "denied output clear"),
    (r"d4620:.*mov\s+w1, #0xc7", "199-byte vsnprintf bound"),
    (r"d4614:.*adr\s+x2, 0x145880", "decoded path format"),
    (r"d4630:.*bl\s+0x139f40", "vsnprintf call"),
    (r"d46d0:.*ldr\s+w8, \[x9\]", "Android API load"),
    (r"d46c8:.*ldr\s+x25, \[x9, #0x8\]", "metadata cache load"),
    (r"d46f4:.*cmp\s+w8, #0x1b", "API 27 threshold"),
    (r"d4868:.*sub\s+x0, x29, #0xc", "initializer status slot"),
    (r"d4870:.*bl\s+0xd3ff0", "metadata initializer"),
    (r"d4894:.*str\s+x21, \[x8, #0xb10\]", "metadata publication"),
    (r"d485c:.*ldp\s+x0, x1, \[sp, #0x8\]", "direct getter arguments"),
    (r"d4860:.*bl\s+0x139f30", "direct getter call"),
    (r"d489c:.*ldp\s+x1, x2, \[sp, #0x8\]", "guarded getter arguments"),
    (r"d48a4:.*bl\s+0xd4244", "guarded getter call"),
):
    require(pattern, label)

for symbol in (
    "runRecoveredPropertyAreaPathFormatterD43e8",
    "runRecoveredGuardedSystemPropertyGetD4244",
    "runRecoveredSystemPropertyCompatibilityD4678",
    "recoveredSystemPropertyCompatibilityD4244D4678Regression",
):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

print("SYSTEM_PROPERTY_COMPATIBILITY_D4244_D4678_STATIC_OK")
