#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner.so+0xd1a38 slice materializer."""

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
    arm64 = disassemble(objdump, ARM64_SO, 0xD1A38, 0xD1BF4)
    x86_64 = disassemble(objdump, X86_64_SO, 0xBF6D3, 0xBF838)

    arm64_patterns = [
        (r"ldr\s+x8,\s*\[x2\]", "slice cursor load"),
        (r"ldp\s+w23,\s*w22,\s*\[x8\]", "offset/length load"),
        (r"add\s+x9,\s*x8,\s*#0x8", "cursor advance"),
        (r"str\s+x9,\s*\[x2\]", "cursor publication"),
        (r"add\s+x0,\s*x22,\s*#0x1", "uint64 length plus one"),
        (r"ldr\s+x24,\s*\[x1,\s*#8\]", "source data pointer"),
        (r"add\s+x10,\s*x24,\s*x23", "source offset"),
        (r"bl\s+139e20", "malloc call"),
        (r"strb\s+wzr,\s*\[x0,\s*x22\]", "NUL terminator"),
        (r"ldrb\s+w24,\s*\[x17\]", "byte copy load"),
        (r"strb\s+w24,\s*\[x1\]", "byte copy store"),
        (r"str\s+xzr,\s*\[x19\]", "failure output clear"),
        (r"str\s+w16,\s*\[x20\]", "failure status two"),
        (r"str\s+x0,\s*\[x19\]", "success output publication"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")

    x86_64_patterns = [
        (r"mov\s+\(%rdx\),\s*%rax", "slice cursor load"),
        (r"mov\s+\(%rax\),\s*%ecx", "offset load"),
        (r"mov\s+0x4\(%rax\),\s*%edi", "length load"),
        (r"add\s+\$0x8,\s*%rax", "cursor advance"),
        (r"mov\s+%rax,\s*\(%rdx\)", "cursor publication"),
        (r"inc\s+%rdi", "uint64 length plus one"),
        (r"add\s+0x8\(%rsi\),\s*%rcx", "source offset"),
        (r"call\s+132850", "malloc call"),
        (r"movb\s+\$0x0,\s*\(%rax,%r13,1\)", "NUL terminator"),
        (r"mov\s+\(%r11\),\s*%r15b", "byte copy load"),
        (r"mov\s+%r15b,\s*0x0\(%rbp\)", "byte copy store"),
        (r"andq?\s+\$0x0,\s*\(%r15\)", "failure output clear"),
        (r"movl?\s+\$0x2,\s*\(%r15\)", "failure status two"),
        (r"mov\s+%rax,\s*\(%r15\)", "success output publication"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    print("ARM64 0xd1a38..0xd1bf4 slice materializer evidence: PASS")
    print("x86_64 0xbf6d3..0xbf838 slice materializer evidence: PASS")
    print("UINT32_MAX allocation request: 0x100000000 bytes")


if __name__ == "__main__":
    main()
