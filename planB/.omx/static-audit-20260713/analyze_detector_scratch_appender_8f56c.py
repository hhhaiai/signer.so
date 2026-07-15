#!/usr/bin/env python3
"""Static cross-ABI proof for detector scratch pair appender ARM64 0x8f56c."""

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


def require_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise AssertionError(f"missing/out-of-order {label}: {token}")
        cursor = position + len(token)


def main() -> None:
    objdump = find_objdump()
    arm = body(disassemble(objdump, ARM64_SO, 0x8F56C, 0x8FB44),
               0x8F56C, 0x8FB44)
    x86 = body(disassemble(objdump, X86_64_SO, 0x93F86, 0x94496, True),
               0x93F86, 0x94496)

    require(ARM_EH, r"pc=0008f56c\.\.\.0008fb44", "ARM64 FDE")
    require(X86_EH, r"pc=00093f86\.\.\.00094496", "x86_64 FDE")
    arm_callers = re.findall(r"\bbl\s+0x8f56c\b", ARM_FULL)
    x86_callers = re.findall(r"\bcallq?\s+0x93f86\b", X86_FULL)
    if len(arm_callers) != 1 or len(x86_callers) != 1:
        raise AssertionError(
            f"expected sole callers, got ARM64={len(arm_callers)} "
            f"x86_64={len(x86_callers)}")
    require(ARM_FULL, r"\b8bccc:\s+[0-9a-f]+\s+bl\s+0x8f56c\b",
            "ARM64 caller address")
    require(X86_FULL,
            r"\b92f15:\s+(?:[0-9a-f]{2}\s+)+callq?\s+0x93f86\b",
            "x86_64 caller address")
    print("ARM64/x86_64 FDEs and sole five-argument callers: PASS")

    require(arm, r"ldr\s+x8,\s*\[x0,\s*#2160\]",
            "ARM64 scratch count load")
    require(arm, r"cmp\s+x8,\s*#0x7e", "ARM64 count >126 gate")
    require(x86, r"mov\s+rax,qword ptr \[rdi\+0x870\]",
            "x86_64 scratch count load")
    require(x86, r"cmp\s+rax,0x7f", "x86_64 count >=127 gate")
    require(arm, r"mov\s+w8,\s*#0x26", "ARM64 capacity status 0x26")
    require(x86, r"push\s+0x26", "x86_64 capacity status 0x26")
    print("127-entry capacity gate and reserved all-null slot: PASS")

    if len(re.findall(r"\bbl\s+[0-9a-f]+\s+<malloc@plt>", arm)) != 2:
        raise AssertionError("ARM64 must contain exactly two malloc call sites")
    if len(re.findall(r"\bcall\s+[0-9a-f]+\s+<malloc@plt>", x86)) != 2:
        raise AssertionError("x86_64 must contain exactly two malloc call sites")
    if len(re.findall(r"\bbl\s+[0-9a-f]+\s+<free@plt>", arm)) != 2:
        raise AssertionError("ARM64 must contain exactly two free call sites")
    if len(re.findall(r"\bcall\s+[0-9a-f]+\s+<free@plt>", x86)) != 2:
        raise AssertionError("x86_64 must contain exactly two free call sites")
    require(arm, r"add\s+x8,\s*x2,\s*#0x1", "ARM64 first length+1")
    require(arm, r"add\s+x9,\s*x4,\s*#0x1", "ARM64 second length+1")
    require(x86, r"lea\s+rax,\s*\[rdx\+0x1\]", "x86_64 first length+1")
    require(x86, r"lea\s+rax,\s*\[r8\+0x1\]", "x86_64 second length+1")
    print("two independent malloc(length+1) stages and two cleanup frees: PASS")

    require_order(arm, [
        "8faf4:",
        "stur\tx26, [x29, #-72]",
        "strb\twzr, [x26, x8]",
    ], "ARM64 first input setup and NUL termination")
    require_order(arm, [
        "8fa14:",
        "stp\tx27, x8, [x29, #-48]",
        "strb\twzr, [x27, x8]",
    ], "ARM64 second input setup and NUL termination")
    require(arm, r"ldrb\s+w8,\s*\[x9\],\s*#1.*strb\s+w8,\s*\[x10\],\s*#1",
            "ARM64 forward byte copy loops")
    require(x86,
            r"mov\s+al,byte ptr \[rcx\].*mov\s+byte ptr \[rdx\],al",
            "x86_64 first forward byte copy")
    require(x86,
            r"mov\s+al,byte ptr \[rax\].*mov\s+byte ptr \[rcx\],al",
            "x86_64 second forward byte copy")
    require(x86, r"mov\s+byte ptr \[rcx\+rax\*1\],0x0",
            "x86_64 NUL termination")
    print("forward raw-byte copies and NUL termination for both inputs: PASS")

    require_order(arm, [
        "str\tx26, [x8]",
        "str\tx27, [x8]",
        "str\tx10, [x8, #2160]",
    ], "ARM64 pair publication and count increment")
    require_order(x86, [
        "mov    qword ptr [rax],rcx",
        "mov    qword ptr [rax+0x8],rcx",
        "mov    qword ptr [rax+0x870],rcx",
    ], "x86_64 pair publication and count increment")
    require(arm, r"mov\s+w8,\s*#0x2", "ARM64 allocation status 2")
    require(x86, r"push\s+0x2", "x86_64 allocation status 2")
    require_order(arm, [
        "ldur\tx0, [x29, #-32]",
        "bl\t139de0 <free@plt>",
        "ldur\tx0, [x29, #-24]",
        "bl\t139de0 <free@plt>",
    ], "ARM64 first-before-second cleanup")
    require_order(x86, [
        "mov    rdi,qword ptr [rsp+0x10]",
        "call   132810 <free@plt>",
        "mov    rdi,qword ptr [rsp+0x20]",
        "call   132810 <free@plt>",
    ], "x86_64 first-before-second cleanup")
    print("success-only pair publication and ordered failure rollback: PASS")

    require_order(CPP, [
        "const std::uint64_t index = scratch->stringCount;",
        "if (index > 0x7e) return 0x26;",
        "operations.allocate(firstLength + 1)",
        "first[offset] = firstBytes[offset];",
        "first[firstLength] = 0;",
        "operations.allocate(secondLength + 1)",
        "second[offset] = secondBytes[offset];",
        "second[secondLength] = 0;",
        "operations.release(first);",
        "operations.release(second);",
        "scratch->strings[index].value",
        "scratch->strings[index].secondaryValue08",
        "scratch->stringCount = index + 1;",
    ], "C++ append/rollback order")
    require(CPP,
            r"bool recoveredDetectorScratchOwnedPairAppend8f56cRegression\(\)",
            "C++ regression")
    require(CPP,
            r"if \(!recoveredDetectorScratchOwnedPairAppend8f56cRegression\(\)\)",
            "top-level regression guard")
    require(GENERATOR,
            r"0x08F56C:\s*\(\"detector scratch owned string-pair appender\",\s*\"recovered\"",
            "coverage generator entry")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
