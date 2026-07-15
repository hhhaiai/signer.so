#!/usr/bin/env python3
"""Static cross-ABI proof for detector scratch destructor ARM64 0x8fb44."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X86_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (AUDIT / "generate_arm64_function_inventory.py").read_text()


def find_objdump() -> str:
    for candidate in (
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def disassemble(
        objdump: str, binary: Path, start: int, end: int,
        intel: bool = False) -> str:
    command = [
        objdump,
        "-d",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{end:x}",
    ]
    if intel:
        command.extend(["-M", "intel"])
    command.append(str(binary))
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.lower()


def body(disassembly: str, start: int, end: int) -> str:
    lines = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_absent(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None:
        raise AssertionError(f"unexpected {label}: {pattern}")


def require_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise AssertionError(f"missing/out-of-order {label}: {token}")
        cursor = position + len(token)


def main() -> None:
    objdump = find_objdump()
    arm = body(disassemble(objdump, ARM64_SO, 0x8FB44, 0x90714),
               0x8FB44, 0x90714)
    x86 = body(disassemble(objdump, X86_64_SO, 0x94496, 0x94D5E, True),
               0x94496, 0x94D5E)
    x86_normalized = re.sub(r"\s+", " ", x86)

    require(ARM_EH, r"pc=0008fb44\.\.\.00090714", "ARM64 FDE")
    require(X86_EH, r"pc=00094496\.\.\.00094d5e", "x86_64 FDE")
    require(ARM_FULL, r"\bfc98:\s+[0-9a-f]+\s+bl\s+0x8fb44\b",
            "ARM64 sole caller")
    require(X86_FULL,
            r"\b138eb:\s+(?:[0-9a-f]{2}\s+)+callq?\s+0x94496\b",
            "x86_64 sole caller")
    require(arm, r"cmp\s+x0,\s*#0x0", "ARM64 null input gate")
    require(x86, r"test\s+rdi,rdi", "x86_64 null input gate")
    if len(re.findall(r"\bbl\s+[0-9a-f]+\s+<free@plt>", arm)) != 10:
        raise AssertionError("ARM64 must contain exactly ten free call sites")
    if len(re.findall(r"\bcall\s+[0-9a-f]+\s+<free@plt>", x86)) != 10:
        raise AssertionError("x86_64 must contain exactly ten free call sites")
    print("ARM64/x86_64 FDEs, sole callers, null gate and ten free sites: PASS")

    arm_fixed_loads = {
        0x00: r"ldr\s+x8,\s*\[x19\]",
        0x08: r"ldr\s+x8,\s*\[x19,\s*#8\]",
        0x10: r"ldr\s+x8,\s*\[x19,\s*#16\]",
        0x18: r"ldr\s+x8,\s*\[x19,\s*#24\]",
        0x20: r"ldr\s+x8,\s*\[x19,\s*#32\]",
        0x30: r"ldr\s+x8,\s*\[x19,\s*#48\]",
        0x38: r"ldr\s+x8,\s*\[x19,\s*#56\]",
        0x50: r"ldr\s+x8,\s*\[x19,\s*#80\]",
    }
    arm_fixed_clears = {
        0x00: r"str\s+xzr,\s*\[x19\]",
        0x08: r"str\s+xzr,\s*\[x19,\s*#8\]",
        0x10: r"str\s+xzr,\s*\[x19,\s*#16\]",
        0x18: r"str\s+xzr,\s*\[x19,\s*#24\]",
        0x20: r"str\s+xzr,\s*\[x19,\s*#32\]",
        0x30: r"str\s+xzr,\s*\[x19,\s*#48\]",
        0x38: r"str\s+xzr,\s*\[x19,\s*#56\]",
        0x50: r"str\s+xzr,\s*\[x19,\s*#80\]",
    }
    for offset, pattern in arm_fixed_loads.items():
        require(arm, pattern, f"ARM64 fixed load +0x{offset:x}")
    for offset, pattern in arm_fixed_clears.items():
        require(arm, pattern, f"ARM64 fixed clear +0x{offset:x}")

    for offset in (0x00, 0x08, 0x10, 0x18, 0x20, 0x30, 0x38, 0x50):
        suffix = "0" if offset == 0 else f"{offset:x}"
        require(x86,
                rf"mov\s+rax,qword ptr \[r13\+0x{suffix}\]",
                f"x86_64 fixed load +0x{offset:x}")
        require(x86,
                rf"and\s+qword ptr \[r13\+0x{suffix}\],0x0",
                f"x86_64 fixed clear +0x{offset:x}")
    require_absent(arm, r"\[x19,\s*#64\]", "ARM64 fixedString40 access")
    require_absent(x86, r"\[r13\+0x40\]", "x86_64 fixedString40 access")
    require_absent(arm, r"#2160\]|#0x870\]", "ARM64 stringCount access")
    require_absent(x86, r"\[r13\+0x870\]", "x86_64 stringCount access")
    print("eight fixed fields, field clearing, and untouched +0x40/+0x870: PASS")

    require_order(arm, [
        "add\tx8, x19, x12, lsl #4",
        "ldr\tx9, [x8, #112]!",
        "cmp\tx9, #0x0",
    ], "ARM64 first slot pointer load")
    require(arm, r"ldr\s+x22,\s*\[x8,\s*#120\]",
            "ARM64 second slot pointer load")
    require(arm, r"str\s+xzr,\s*\[x8\]", "ARM64 first slot clear")
    require(arm, r"str\s+xzr,\s*\[x28,\s*#120\]",
            "ARM64 second slot clear")
    require(arm, r"add\s+x8,\s*x8,\s*#0x1",
            "ARM64 sentinel-loop index increment")

    require_order(x86_normalized, [
        "shl rax,0x4",
        "add rax,r13",
        "add rax,0x70",
        "mov rax,qword ptr [rax]",
        "test rax,rax",
    ], "x86_64 first slot pointer load")
    require(x86, r"mov\s+rax,qword ptr \[r13\+rax\*1\+0x78\]",
            "x86_64 second slot pointer load")
    require(x86, r"and\s+qword ptr \[rax\],0x0",
            "x86_64 first slot clear")
    require(x86, r"and\s+qword ptr \[r15\+r13\*1\+0x78\],0x0",
            "x86_64 second slot clear")
    require(x86, r"inc\s+rax", "x86_64 sentinel-loop index increment")
    require_absent(x86, r"cmp\s+[^\n]+,0x80\b",
                   "x86_64 fixed 128-slot loop bound")
    print("all-null sentinel loop and first-before-second slot cleanup: PASS")

    require_order(CPP, [
        "releaseAndClear(scratch->fixedString08);",
        "releaseAndClear(scratch->fixedString18);",
        "releaseAndClear(scratch->fixedString20);",
        "releaseAndClear(scratch->fixedString00);",
        "releaseAndClear(scratch->fixedString30);",
        "releaseAndClear(scratch->fixedString38);",
        "releaseAndClear(scratch->fixedString10);",
        "releaseAndClear(scratch->fixedString50);",
        "while (slot->value != nullptr || slot->secondaryValue08 != nullptr)",
        "releaseAndClear(slot->value);",
        "releaseAndClear(slot->secondaryValue08);",
        "++slot;",
    ], "C++ destructor order")
    require(CPP, r"bool recoveredDetectorScratchContentDestroy8fb44Regression\(\)",
            "C++ regression")
    require(CPP,
            r"if \(!recoveredDetectorScratchContentDestroy8fb44Regression\(\)\)",
            "top-level regression guard")
    require(GENERATOR,
            r"0x08FB44:\s*\(\"detector scratch content destructor\",\s*\"recovered\"",
            "coverage generator entry")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
