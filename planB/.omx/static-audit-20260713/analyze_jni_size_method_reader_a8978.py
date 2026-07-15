#!/usr/bin/env python3
"""Static cross-ABI proof for JNI size() reader ARM64 0xa8978."""

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
        if (program_type == 1 and virtual_address <= address \
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
    arm = body(disassemble(objdump, ARM64_SO, 0xA8978, 0xA948C),
               0xA8978, 0xA948C)
    x86 = body(disassemble(objdump, X86_64_SO, 0xA469C, 0xA4CD9, True),
               0xA469C, 0xA4CD9)

    require(ARM_EH, r"pc=000a8978\.\.\.000a948c", "ARM64 FDE")
    require(X86_EH, r"pc=000a469c\.\.\.000a4cd9", "x86_64 FDE")
    if len(re.findall(r"\bbl\s+0xa8978\b", ARM_FULL)) != 1:
        raise AssertionError("expected one ARM64 caller")
    if len(re.findall(r"\bcallq?\s+0xa469c\b", X86_FULL)) != 1:
        raise AssertionError("expected one x86_64 caller")
    require(ARM_FULL, r"\b8da60:.*\bbl\s+0xa8978\b", "ARM64 caller")
    require(X86_FULL, r"\b91bc8:.*\bcallq?\s+0xa469c\b", "x86 caller")
    print("cross-ABI FDEs and sole detector-producer caller: PASS")

    method_name = bytes(value ^ 0xE8
                        for value in virtual_bytes(ARM64_SO, 0x144FB0, 5))
    signature = bytes(value ^ 0xC9
                      for value in virtual_bytes(ARM64_SO, 0x144FB8, 4))
    x86_name = bytes(value ^ 0x16
                     for value in virtual_bytes(X86_64_SO, 0x13DA50, 5))
    x86_signature = bytes(value ^ 0x39
                          for value in virtual_bytes(X86_64_SO, 0x13DA58, 4))
    if method_name != b"size\0" or x86_name != b"size\0":
        raise AssertionError(f"unexpected method decode: {method_name!r}/{x86_name!r}")
    if signature != b"()I\0" or x86_signature != b"()I\0":
        raise AssertionError(
            f"unexpected signature decode: {signature!r}/{x86_signature!r}")
    print("cross-ABI size / ()I once-decoded constants: PASS")

    for offset, label in (
        (248, "GetObjectClass"),
        (264, "GetMethodID"),
        (392, "CallIntMethod"),
        (184, "DeleteLocalRef"),
    ):
        require(arm, rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]", f"ARM64 {label}")
    for offset, label in (
        ("0xf8", "GetObjectClass"),
        ("0x108", "GetMethodID"),
        ("0x188", "CallIntMethod"),
        ("0xb8", "DeleteLocalRef"),
    ):
        require(x86, rf"call\s+qword ptr \[(?:rax|rcx)\+{offset}\]",
                f"x86 {label}")
    if len(re.findall(r"\bbl\s+92a20\b", arm)) != 3:
        raise AssertionError("ARM64 must consume exceptions exactly three times")
    if len(re.findall(r"\bcall\s+96a44\b", x86)) != 3:
        raise AssertionError("x86_64 must consume exceptions exactly three times")
    print("four JNI vtable methods and three exception-consumer calls: PASS")

    require(arm, r"mov\s+w10,\s*#0x3", "ARM64 status 3")
    require(arm, r"mov\s+w(?:8|10),\s*#0x12", "ARM64 status 18")
    require(arm, r"mov\s+w8,\s*#0x1c", "ARM64 status 28")
    require(arm, r"str\s+wzr,\s*\[x8\]", "ARM64 output clearing")
    require(x86, r"mov\s+dword ptr \[rax\],0x3", "x86 status 3")
    require(x86, r"push\s+0x12", "x86 status 18")
    require(x86, r"push\s+0x1c", "x86 status 28")
    require(x86, r"and\s+dword ptr \[rax\],0x0", "x86 output clearing")
    print("statuses 3/18/28, class cleanup and final output clearing: PASS")

    require_order(CPP, [
        "if (object == 0)",
        "*status = 3;",
        "operations.getObjectClass(jniEnvironment, object)",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "operations.getMethodId(",
        "jniEnvironment, objectClass, \"size\", \"()I\")",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "*output = operations.callIntMethod(jniEnvironment, object, methodId);",
        "operations.consumeException(jniEnvironment)",
        "*status = 28;",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "if (*status != 0) *output = 0;",
    ], "C++ JNI/status/cleanup order")
    require(CPP, r"bool recoveredJniSizeMethodReaderA8978Regression\(\)",
            "C++ regression")
    require(CPP, r"if \(!recoveredJniSizeMethodReaderA8978Regression\(\)\)",
            "top-level guard")
    require(GENERATOR,
            r"0x0A8978:\s*\(\"JNI size-method reader\",\s*\"recovered\"",
            "coverage entry")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
