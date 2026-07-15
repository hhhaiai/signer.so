#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner.so+0x34bf4 record counter."""

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
        [objdump, "-d", f"--start-address=0x{start:x}",
         f"--stop-address=0x{stop:x}", str(binary)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.lower()


def require(disassembly: str, pattern: str, label: str) -> None:
    if re.search(pattern, disassembly) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def main() -> None:
    objdump = find_objdump()
    arm64 = disassemble(objdump, ARM64_SO, 0x34BF4, 0x34F9C)
    x86_64 = disassemble(objdump, X86_64_SO, 0x32C82, 0x32F48)

    arm64_patterns = [
        (r"ldr\s+x28,\s*\[x8,\s*x19,\s*lsl\s*#3\]", "candidate pointer"),
        (r"ldr\s+x8,\s*\[x8\]", "key field load"),
        (r"ldr\s+x9,\s*\[x28,\s*#16\]", "candidate key load"),
        (r"ldr\s+x8,\s*\[x28,\s*#40\]", "candidate +0x28 load"),
        (r"cmp\s+x8,\s*#0x1", "candidate +0x28 equals one"),
        (r"ldr\s+w0,\s*\[x28,\s*#8\]", "packed first low word"),
        (r"ldr\s+w1,\s*\[x28,\s*#24\]", "packed second low word"),
        (r"bl\s+34820", "packed transition helper call"),
        (r"and\s+w8,\s*w0,\s*#0x?1", "helper boolean mask"),
        (r"add\s+w8,\s*w25,\s*w8", "match increment"),
        (r"mov\s+w0,\s*w5", "ARM64 low-word return"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")

    x86_64_patterns = [
        (r"mov\s+\(%rax,%rdx,8\),\s*%rdx", "candidate pointer"),
        (r"cmp\s+0x10\(%rdx\),\s*%rax", "candidate key comparison"),
        (r"cmpq?\s+\$0x1,\s*0x28\(%rax\)", "candidate +0x28 equals one"),
        (r"mov\s+0x8\(%rax\),\s*%edi", "packed first low word"),
        (r"mov\s+0x18\(%rax\),\s*%esi", "packed second low word"),
        (r"call\s+32955", "packed transition helper call"),
        (r"movzbl?\s+%al,\s*%eax", "helper boolean normalization"),
        (r"add\s+%r10d,\s*%eax", "match increment"),
        (r"movzwl?\s+[^,]+,\s*%eax", "zero-extended uint16 return"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    print("ARM64 0x34bf4..0x34f9c packed-counter evidence: PASS")
    print("x86_64 0x32c82..0x32f48 packed-counter evidence: PASS")
    print("counter width: uint16_t modulo 65536")


if __name__ == "__main__":
    main()
