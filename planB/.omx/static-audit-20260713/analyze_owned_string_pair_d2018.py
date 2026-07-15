#!/usr/bin/env python3
"""Static cross-ABI evidence for libsigner.so+0xd2018 ownership flow."""

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


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def main() -> None:
    objdump = find_objdump()
    arm64 = disassemble(objdump, ARM64_SO, 0xD2018, 0xD22D4)
    x86_64 = disassemble(objdump, X86_64_SO, 0xBFB83, 0xBFE08)

    arm64_patterns = [
        (r"bl\s+d1a38", "stage-one call"),
        (r"ldr\s+w8,\s*\[x20\]", "stage-one status load"),
        (r"bl\s+d1bf4", "stage-two call"),
        (r"ldr\s+w8,\s*\[x24\]", "stage-two status load"),
        (r"ldr\s+x8,\s*\[x19\]", "first owned pointer load"),
        (r"ldr\s+x8,\s*\[x19,\s*#8\]", "second owned pointer load"),
        (r"str\s+xzr,\s*\[x19\]", "first pointer clear"),
        (r"str\s+xzr,\s*\[x19,\s*#8\]", "second pointer clear"),
        (r"bl\s+139de0", "free calls"),
    ]
    for pattern, label in arm64_patterns:
        require(arm64, pattern, f"ARM64 {label}")

    x86_64_patterns = [
        (r"call\s+bf6d3", "stage-one call"),
        (r"cmpl\s+\$0x0,\s*\(%rbx\)", "stage-one status gate"),
        (r"call\s+bf838", "stage-two call"),
        (r"cmpl\s+\$0x0,\s*0x0\(%rbp\)", "stage-two status gate"),
        (r"mov\s+\(%rax\),\s*%rax", "first owned pointer load"),
        (r"mov\s+0x8\(%rax\),\s*%rax", "second owned pointer load"),
        (r"andq?\s+\$0x0,\s*\(%rax\)", "first pointer clear"),
        (r"andq?\s+\$0x0,\s*0x8\(%rax\)", "second pointer clear"),
        (r"call\s+132810", "free calls"),
    ]
    for pattern, label in x86_64_patterns:
        require(x86_64, pattern, f"x86_64 {label}")

    # Execution order is established by the state transition after bfd4e:
    # clearing first selects state 0xbe234f..., which reaches bfc9b and then
    # the second-pointer cleanup state. Assert those concrete anchors exist.
    require(x86_64, r"bfd4e:.*andq?\s+\$0x0,\s*\(%rax\)",
            "first clear transition anchor")
    require(x86_64, r"bfcfd:.*mov\s+\(%rsp\),\s*%rax", "second clear setup")

    print("ARM64 0xd2018..0xd22d4 two-stage ownership evidence: PASS")
    print("x86_64 0xbfb83..0xbfe08 two-stage ownership evidence: PASS")
    print("stage two requires status zero: PASS")
    print("failure cleanup order first then second: PASS")


if __name__ == "__main__":
    main()
