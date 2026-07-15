#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner.so+0x34954 record matching."""

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
    arm64 = disassemble(objdump, ARM64_SO, 0x34954, 0x34BF4)
    x86_64 = disassemble(objdump, X86_64_SO, 0x32A17, 0x32C82)

    arm64_patterns = [
        (r"ldr\s+x14,\s*\[x2,\s*x22,\s*lsl\s*#3\]", "key record pointer"),
        (r"add\s+x24,\s*x14,\s*#0x10", "key field address"),
        (r"ldr\s+x21,\s*\[x0,\s*x25,\s*lsl\s*#3\]", "candidate pointer"),
        (r"ldr\s+x14,\s*\[x24\]", "key field load"),
        (r"ldr\s+x28,\s*\[x21,\s*#16\]", "candidate key load"),
        (r"ldr\s+x14,\s*\[x21,\s*#40\]", "candidate +0x28 load"),
        (r"cmp\s+x14,\s*#0x1", "candidate +0x28 equals one"),
        (r"ldr\s+x14,\s*\[x21,\s*#8\]", "candidate +0x08 load"),
        (r"cinc\s+w28,\s*w26,\s*eq", "conditional match increment"),
        (r"mov\s+w0,\s*w4", "ARM64 low-word return"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")
    if "0x100007f" not in arm64:
        # GNU objdump prints the constant as mov/movk parts on AArch64.
        require(arm64, r"mov\s+w28,\s*#0x7f", "ARM64 low constant part")
        require(arm64, r"movk\s+w28,\s*#0x100,\s*lsl\s*#16",
                "ARM64 high constant part")

    x86_64_patterns = [
        (r"cmpq?\s+\$0x100007f,\s*0x8\(%r13\)", "candidate +0x08 constant"),
        (r"cmpq?\s+\$0x1,\s*0x28\(%r13\)", "candidate +0x28 equals one"),
        (r"mov\s+\(%rdi,%rcx,8\),\s*%r13", "candidate pointer"),
        (r"mov\s+\(%rsi\),\s*%rdi", "key field load"),
        (r"cmp\s+0x10\(%r13\),\s*%rdi", "candidate key comparison"),
        (r"add\s+%r12d,\s*%r14d", "conditional match increment"),
        (r"movzwl?\s+[^,]+,\s*%eax", "zero-extended uint16 return"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    print("ARM64 0x34954..0x34bf4 record-match evidence: PASS")
    print("x86_64 0x32a17..0x32c82 record-match evidence: PASS")
    print("counter width: uint16_t modulo 65536")


if __name__ == "__main__":
    main()
