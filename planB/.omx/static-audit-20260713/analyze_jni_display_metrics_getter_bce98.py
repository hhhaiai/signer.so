#!/usr/bin/env python3
"""Static cross-ABI proof for JNI DisplayMetrics getter ARM64 0xbce98."""

from __future__ import annotations

import os
import re
import shutil
import struct
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
    command = [objdump, "-d", f"--start-address=0x{start:x}",
               f"--stop-address=0x{end:x}"]
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


def virtual_bytes(binary: Path, address: int, size: int) -> bytes:
    data = binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError(f"expected little-endian ELF64: {binary}")
    program_offset = struct.unpack_from("<Q", data, 0x20)[0]
    entry_size = struct.unpack_from("<H", data, 0x36)[0]
    entry_count = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(entry_count):
        entry = program_offset + index * entry_size
        program_type, _flags, file_offset, virtual_address, _physical, \
            file_size, _memory_size, _align = struct.unpack_from(
                "<IIQQQQQQ", data, entry)
        if (program_type == 1 and virtual_address <= address
                and address + size <= virtual_address + file_size):
            start = file_offset + address - virtual_address
            return data[start:start + size]
    raise AssertionError(f"virtual range 0x{address:x}+{size} not file-backed")


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
    arm = body(disassemble(objdump, ARM64_SO, 0xBCE98, 0xBD6A8),
               0xBCE98, 0xBD6A8)
    x86 = body(disassemble(objdump, X86_64_SO, 0xB0994, 0xB1071, True),
               0xB0994, 0xB1071)

    require(ARM_EH, r"pc=000bce98\.\.\.000bd6a8", "ARM64 FDE")
    require(X86_EH, r"pc=000b0994\.\.\.000b1071", "x86_64 FDE")
    if len(re.findall(r"\bbl\s+0xbce98\b", ARM_FULL)) != 1:
        raise AssertionError("expected one ARM64 caller")
    if len(re.findall(r"\bcallq?\s+0xb0994\b", X86_FULL)) != 1:
        raise AssertionError("expected one x86_64 caller")
    require(ARM_FULL, r"\b8e9c8:.*\bbl\s+0xbce98\b", "ARM64 caller")
    require(X86_FULL, r"\b90b18:.*\bcallq?\s+0xb0994\b", "x86 caller")
    print("cross-ABI FDEs and sole detector-producer caller: PASS")

    method_name = bytes(value ^ 0x89
                        for value in virtual_bytes(ARM64_SO, 0x145490, 18))
    signature = bytes(value ^ 0xC0
                      for value in virtual_bytes(ARM64_SO, 0x1454B0, 32))
    x86_name = bytes(value ^ 0x74
                     for value in virtual_bytes(X86_64_SO, 0x13DF30, 18))
    x86_signature = bytes(value ^ 0x78
                          for value in virtual_bytes(X86_64_SO, 0x13DF50, 32))
    if method_name != b"getDisplayMetrics\0" or x86_name != method_name:
        raise AssertionError(f"unexpected method decode: {method_name!r}/{x86_name!r}")
    expected_signature = b"()Landroid/util/DisplayMetrics;\0"
    if signature != expected_signature or x86_signature != expected_signature:
        raise AssertionError(
            f"unexpected signature decode: {signature!r}/{x86_signature!r}")
    print("cross-ABI getDisplayMetrics / DisplayMetrics signature: PASS")

    for offset, label in (
        (248, "GetObjectClass"),
        (264, "GetMethodID"),
        (272, "CallObjectMethod"),
        (184, "DeleteLocalRef"),
    ):
        require(arm, rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]", f"ARM64 {label}")
    for register, offset, label in (
        ("rax", "0xf8", "GetObjectClass"),
        ("rax", "0x108", "GetMethodID"),
        ("rcx", "0x110", "CallObjectMethod"),
        ("rax", "0xb8", "DeleteLocalRef"),
    ):
        require(x86, rf"call\s+qword ptr \[{register}\+{offset}\]",
                f"x86 {label}")
    if len(re.findall(r"\bbl\s+92a20\b", arm)) != 3:
        raise AssertionError("ARM64 must consume exceptions exactly three times")
    if len(re.findall(r"\bcall\s+96a44\b", x86)) != 3:
        raise AssertionError("x86_64 must consume exceptions exactly three times")
    print("four JNI vtable methods and three exception stages: PASS")

    require(arm, r"mov\s+w10,\s*#0x3", "ARM64 status 3")
    require(arm, r"mov\s+w(?:8|10),\s*#0x12", "ARM64 status 18")
    require(arm, r"mov\s+w8,\s*#0x1c", "ARM64 status 28")
    require(arm, r"str\s+xzr,\s*\[x8\]", "ARM64 output clearing")
    require(arm, r"ldr\s+x8,\s*\[sp,\s*#32\].*ldr\s+x8,\s*\[x8\].*cmp\s+x8,\s*#0x0",
            "ARM64 null returned-object gate")
    require(x86, r"mov\s+dword ptr \[rax\],0x3", "x86 status 3")
    require(x86, r"push\s+0x12", "x86 status 18")
    require(x86, r"push\s+0x1c", "x86 status 28")
    require(x86, r"and\s+qword ptr \[rax\],0x0", "x86 output clearing")
    require(x86, r"cmp\s+qword ptr \[rax\],0x0", "x86 null result gate")
    require_order(x86, [
        "call   qword ptr [rcx+0x110]",
        "mov    qword ptr [rcx],rax",
        "call   96a44",
    ], "x86 result publication before exception consumption")
    require(x86, r"cmp\s+dword ptr \[rax\],0x0", "x86 final status gate")
    print("statuses 3/18/28, null-result rejection, cleanup and clearing: PASS")

    start = CPP.index("void runRecoveredJniNoArgObjectMethodReaderBce98(")
    end = CPP.index("enum class RecoveredJniNoArgObjectMethodEventBce98", start)
    implementation = CPP[start:end]
    require_order(implementation, [
        "if (object == 0)",
        "*status = 3;",
        "operations.getObjectClass(jniEnvironment, object)",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "operations.getMethodId(",
        "jniEnvironment, objectClass, \"getDisplayMetrics\"",
        "\"()Landroid/util/DisplayMetrics;\")",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "*output = operations.callObjectMethod(jniEnvironment, object, methodId);",
        "operations.consumeException(jniEnvironment)",
        "callException || *output == 0",
        "*status = 28;",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "if (*status != 0) *output = 0;",
    ], "C++ JNI/status/cleanup order")
    require(CPP, r"bool recoveredJniNoArgObjectMethodReaderBce98Regression\(\)",
            "C++ regression")
    require(CPP,
            r"if \(!recoveredJniNoArgObjectMethodReaderBce98Regression\(\)\)",
            "top-level guard")
    require(GENERATOR,
            r"0x0BCE98:\s*\(\"JNI DisplayMetrics getter\",\s*\"recovered\"",
            "coverage entry")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
