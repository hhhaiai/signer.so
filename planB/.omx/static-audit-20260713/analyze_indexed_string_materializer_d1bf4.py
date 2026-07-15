#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner.so+0xd1bf4."""

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


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def main() -> None:
    objdump = find_objdump()
    arm64 = disassemble(objdump, ARM64_SO, 0xD1BF4, 0xD2018)
    x86_64 = disassemble(objdump, X86_64_SO, 0xBF838, 0xBFB83)

    arm64_patterns = [
        (r"ldr\s+x8,\s*\[x2\]", "index cursor load"),
        (r"ldr\s+w9,\s*\[x8\],\s*#4", "index load and cursor advance"),
        (r"cmn\s+w9,\s*#0x1", "UINT32_MAX sentinel test"),
        (r"str\s+x8,\s*\[x2\]", "cursor publication"),
        (r"ldr\s+x9,\s*\[x8,\s*#8\]", "source data base"),
        (r"ldr\s+w8,\s*\[x8,\s*#36\]", "source table offset"),
        (r"ldr\s+w10,\s*\[x8,\s*x10,\s*lsl\s*#2\]", "indexed relative offset"),
        (r"add\s+x19,\s*x9,\s*x10", "resolved string pointer"),
        (r"adr\s+x19,\s*3068", "sentinel empty string"),
        (r"ldrb\s+w8,\s*\[x25\],\s*#1", "unbounded NUL scan"),
        (r"sub\s+x8,\s*x8,\s*x23", "string length"),
        (r"add\s+x0,\s*x8,\s*#0x1", "length plus one"),
        (r"bl\s+139e20", "malloc call"),
        (r"strb\s+wzr,\s*\[x0,\s*x9\]", "NUL terminator"),
        (r"str\s+x0,\s*\[x3,\s*#8\]", "success output publication"),
        (r"str\s+xzr,\s*\[x3,\s*#8\]", "failure output clear"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")

    x86_64_patterns = [
        (r"mov\s+\(%rdx\),\s*%rax", "index cursor load"),
        (r"mov\s+\(%rax\),\s*%r8d", "index load"),
        (r"add\s+\$0x4,\s*%rax", "cursor advance"),
        (r"cmp\s+%rsi,\s*%r8", "UINT32_MAX sentinel test"),
        (r"mov\s+%rax,\s*\(%rdx\)", "cursor publication"),
        (r"mov\s+0x8\(%rdx\),\s*%rsi", "source data base"),
        (r"mov\s+0x24\(%rdx\),\s*%edx", "source table offset"),
        (r"mov\s+\(%rdx,%rdi,4\),\s*%edx", "indexed relative offset"),
        (r"add\s+%rsi,\s*%rdx", "resolved string pointer"),
        (r"lea\s+[^#]+#\s*4148", "sentinel empty string"),
        (r"cmpb\s+\$0x0,\s*\(%r15\)", "unbounded NUL scan"),
        (r"sub\s+%r14,\s*%rax", "string length"),
        (r"lea\s+0x1\(%rax\),\s*%rdi", "length plus one"),
        (r"call\s+132850", "malloc call"),
        (r"movb\s+\$0x0,\s*\(%rax,%rdx,1\)", "NUL terminator"),
        (r"mov\s+%rax,\s*0x8\(%rdx\)", "success output publication"),
        (r"andq?\s+\$0x0,\s*0x8\(%rdx\)", "failure output clear"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    arm_empty = run_objdump(objdump, [
        "-s", "--start-address=0x3068", "--stop-address=0x3069"
    ], ARM64_SO)
    x86_empty = run_objdump(objdump, [
        "-s", "--start-address=0x4148", "--stop-address=0x4149"
    ], X86_64_SO)
    require(arm_empty, r"3068\s+00", "ARM64 sentinel NUL byte")
    require(x86_empty, r"4148\s+00", "x86_64 sentinel NUL byte")

    print("ARM64 0xd1bf4..0xd2018 indexed-string evidence: PASS")
    print("x86_64 0xbf838..0xbfb83 indexed-string evidence: PASS")
    print("UINT32_MAX sentinel resolves to static empty string: PASS")
    print("native index/string bounds checks: absent")


if __name__ == "__main__":
    main()
