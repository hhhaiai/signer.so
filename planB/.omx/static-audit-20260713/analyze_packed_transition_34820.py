#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner packed transition predicate.

This script only disassembles local ELF files. It never loads or executes a
target library.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"


def find_objdump() -> str:
    candidates = [
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def disassemble(objdump: str, binary: Path, start: int, stop: int) -> str:
    result = subprocess.run(
        [
            objdump,
            "-d",
            f"--start-address=0x{start:x}",
            f"--stop-address=0x{stop:x}",
            str(binary),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.lower()


def require(disassembly: str, pattern: str, label: str) -> None:
    if re.search(pattern, disassembly) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def packed_transition(first: int, second: int) -> bool:
    return (
        (first & 0x00FFFFFF) == (second & 0x00FFFFFF)
        and (second >> 24) == 1
        and (first >> 24) != 1
    )


def main() -> None:
    objdump = find_objdump()
    arm64 = disassemble(objdump, ARM64_SO, 0x34820, 0x34954)
    x86_64 = disassemble(objdump, X86_64_SO, 0x32955, 0x32A17)

    arm64_patterns = [
        (r"lsr\s+w9,\s*w1,\s*#24", "second high-byte extraction"),
        (r"lsr\s+w10,\s*w0,\s*#24", "first high-byte extraction"),
        (r"cmp\s+w9,\s*#0x?1", "second high byte equals one"),
        (r"ccmp\s+w10,\s*#0x?1,\s*#0x?4,\s*eq", "first high-byte conditional comparison"),
        (r"eor\s+w14,\s*w1,\s*w0", "input XOR"),
        (r"tst\s+w14,\s*#0xffffff", "low-24 equality test"),
        (r"and\s+w0,\s*w17,\s*#0x?1", "boolean return mask"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")

    x86_64_patterns = [
        (r"mov[l]?\s+%esi,\s*%eax", "copy second input"),
        (r"xor[l]?\s+%edi,\s*%eax", "input XOR"),
        (r"and[l]?\s+%ecx,\s*%esi", "second high-byte mask"),
        (r"and[l]?\s+%ecx,\s*%edi", "first high-byte mask"),
        (r"mov[l]?\s+\$0x1000000,\s*%r8d", "high byte equals one constant"),
        (r"test[l]?\s+\$0xffffff,\s*%eax", "low-24 equality test"),
        (r"and[b]?\s+\$0x1,\s*%al", "boolean return mask"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    vectors = [
        (0x00000001, 0x01000001, True),
        (0x01000001, 0x01000001, False),
        (0x02000001, 0x01000001, True),
        (0xFFABCDEF, 0x01ABCDEF, True),
        (0x00000001, 0x02000001, False),
        (0x00000001, 0x01000002, False),
        (0x00000000, 0x01000000, True),
        (0xFFFFFFFF, 0x01FFFFFF, True),
    ]
    for first, second, expected in vectors:
        actual = packed_transition(first, second)
        if actual != expected:
            raise AssertionError(
                f"truth table mismatch: first={first:#010x} "
                f"second={second:#010x} actual={actual} expected={expected}"
            )

    print("ARM64 0x34820..0x34954 instruction evidence: PASS")
    print("x86_64 0x32955..0x32a17 instruction evidence: PASS")
    print("packed transition truth table: PASS")


if __name__ == "__main__":
    main()
