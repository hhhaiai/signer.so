#!/usr/bin/env python3
"""Cross-ABI proof for the fixed unordered uint32-pair matcher at 0x87158."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


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


def run_objdump(objdump: str, args: list[str], binary: Path) -> str:
    result = subprocess.run(
        [objdump, *args, str(binary)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.lower()


def disassemble(objdump: str, binary: Path, start: int, stop: int) -> str:
    return run_objdump(objdump, [
        "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}"
    ], binary)


def data_bytes(objdump: str, binary: Path, address: int, count: int) -> bytes:
    dump = run_objdump(objdump, [
        "-s",
        f"--start-address=0x{address:x}",
        f"--stop-address=0x{address + count:x}",
    ], binary)
    match = re.search(
        rf"^\s*{address:x}\s+((?:[0-9a-f]{{8}}\s*)+)",
        dump,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing data at 0x{address:x}")
    hexadecimal = re.sub(r"\s+", "", match.group(1))[:count * 2]
    return bytes.fromhex(hexadecimal)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0x87158, 0x8746C)
    x86 = disassemble(objdump, X86_64_SO, 0x881EA, 0x88475)

    arm_table = b"".join(data_bytes(objdump, ARM64_SO, address, 16)
                         for address in (0x3010, 0x2FF0, 0x2FC0, 0x2FB0))
    x86_table = b"".join(data_bytes(objdump, X86_64_SO, address, 16)
                         for address in (0x3A70, 0x3980, 0x3800, 0x35C0))
    if arm_table != x86_table:
        raise AssertionError("ARM64/x86_64 fixed-pair table mismatch")
    values = struct.unpack("<16I", arm_table)
    pairs = tuple(zip(values[0::2], values[1::2]))
    expected = (
        (0x0320, 0x029A),
        (0x035C, 0x02DC),
        (0x035C, 0x0300),
        (0x035C, 0x02A0),
        (0x035C, 0x02D0),
        (0x037C, 0x02DC),
        (0x02A0, 0x017A),
        (0x0398, 0x029E),
    )
    if pairs != expected:
        raise AssertionError(pairs)

    for pattern, label in (
        (r"ldr\s+q0,\s*\[x14,\s*#16\]", "ARM64 first table vector"),
        (r"ldr\s+q1,\s*\[x15,\s*#4080\]", "ARM64 second table vector"),
        (r"ldr\s+q0,\s*\[x15,\s*#4032\]", "ARM64 third table vector"),
        (r"ldr\s+q1,\s*\[x16,\s*#4016\]", "ARM64 fourth table vector"),
        (r"mov\s+x9,\s*xzr", "ARM64 index zero"),
        (r"cmp\s+x9,\s*#0x8", "ARM64 eight-pair bound"),
        (r"ldr\s+w24,\s*\[x0,\s*#96\]", "ARM64 field +0x60"),
        (r"ldp\s+w22,\s*w23,\s*\[x23\]", "ARM64 current pair"),
        (r"ldr\s+w25,\s*\[x0,\s*#100\]", "ARM64 field +0x64"),
        (r"add\s+x9,\s*x21,\s*#0x1", "ARM64 next pair"),
        (r"cmp\s+x21,\s*#0x8.*cset\s+w0,\s*cc", "ARM64 found-index return"),
    ):
        require(arm, pattern, label)

    for pattern, label in (
        (r"movaps\s+.*#\s*(?:0x)?3a70", "x86_64 first table vector"),
        (r"movaps\s+.*#\s*(?:0x)?3980", "x86_64 second table vector"),
        (r"movaps\s+.*#\s*(?:0x)?3800", "x86_64 third table vector"),
        (r"movaps\s+.*#\s*(?:0x)?35c0", "x86_64 fourth table vector"),
        (r"xor\s+%esi,\s*%esi", "x86_64 index zero"),
        (r"cmp\s+\$0x8,\s*%r15", "x86_64 eight-pair bound"),
        (r"mov\s+0x60\(%rsi\),\s*%r10d", "x86_64 field +0x60"),
        (r"cmp\s+%r10d,\s*0x64\(%rdi\)", "x86_64 field +0x64"),
        (r"lea\s+0x1\(%r15\),\s*%rsi", "x86_64 next pair"),
        (r"cmp\s+\$0x8,\s*%r15.*setb\s+%al", "x86_64 found-index return"),
    ):
        require(x86, pattern, label)

    for first, second in pairs:
        assert (first, second) in expected
        assert (second, first) != (0, 0)

    for symbol in (
        "displayWidth60",
        "displayHeight64",
        "kRecoveredDetectorUnorderedPairs87158",
        "runRecoveredDetectorUnorderedPairMatcher87158",
        "recoveredDetectorUnorderedPairMatcher87158Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")
    for pattern, label in (
        (r"offsetof\(RecoveredDetectorScratch868b4, displayWidth60\) == 0x60", "C++ width offset"),
        (r"offsetof\(RecoveredDetectorScratch868b4, displayHeight64\) == 0x64", "C++ height offset"),
        (r"scratch->displayWidth60 == pair\[0\].*scratch->displayHeight64 == pair\[1\]", "C++ forward pair"),
        (r"scratch->displayWidth60 == pair\[1\].*scratch->displayHeight64 == pair\[0\]", "C++ reversed pair"),
    ):
        require(CPP, pattern, label)

    require(
        GENERATOR,
        r"0x087158:.*display-dimension unordered-pair predicate.*recovered",
        "0x87158 coverage entry",
    )

    print("ARM64 0x87158 / x86_64 0x881ea fixed table: PASS")
    print("eight display-dimension pairs and width/height +0x60/+0x64 layout: PASS")
    print("forward/reversed pair acceptance and exhausted false: PASS")


if __name__ == "__main__":
    main()
