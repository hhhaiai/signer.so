#!/usr/bin/env python3
"""Static cross-ABI proof for JNI int-field reader ARM64 0xb21b4."""

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


def read_virtual(binary: Path, address: int, size: int) -> bytes:
    data = binary.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError(f"not ELF64 little-endian: {binary}")
    program_offset = struct.unpack_from("<Q", data, 0x20)[0]
    program_size = struct.unpack_from("<H", data, 0x36)[0]
    program_count = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(program_count):
        offset = program_offset + index * program_size
        values = struct.unpack_from("<IIQQQQQQ", data, offset)
        segment_type, _, file_offset, virtual_address, _, file_size, _, _ = values
        if segment_type != 1:
            continue
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return data[start:start + size]
    raise AssertionError(f"virtual range 0x{address:x}+0x{size:x} is not file-backed")


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
    arm = body(disassemble(objdump, ARM64_SO, 0xB21B4, 0xB2978),
               0xB21B4, 0xB2978)
    x86 = body(disassemble(objdump, X86_64_SO, 0xAA362, 0xAA8BB, True),
               0xAA362, 0xAA8BB)

    require(ARM_EH, r"pc=000b21b4\.\.\.000b2978", "ARM64 FDE")
    require(X86_EH, r"pc=000aa362\.\.\.000aa8bb", "x86_64 FDE")
    arm_callers = re.findall(r"\bbl\s+0xb21b4\b", ARM_FULL)
    x86_callers = re.findall(r"\bcallq?\s+0xaa362\b", X86_FULL)
    if len(arm_callers) != 2 or len(x86_callers) != 2:
        raise AssertionError(
            f"expected two producer calls, got ARM64={len(arm_callers)} "
            f"x86_64={len(x86_callers)}")
    for address in ("8c320", "8d564"):
        require(ARM_FULL,
                rf"\b{address}:\s+[0-9a-f]+\s+bl\s+0xb21b4\b",
                f"ARM64 caller {address}")
    for address in ("8e91c", "9374d"):
        require(X86_FULL,
                rf"\b{address}:\s+(?:[0-9a-f]{{2}}\s+)+callq?\s+0xaa362\b",
                f"x86_64 caller {address}")
    print("cross-ABI FDEs and two detector-producer call sites: PASS")

    width = bytes(value ^ 0x65 for value in read_virtual(ARM64_SO, 0x144850, 12))
    height = bytes(value ^ 0x31 for value in read_virtual(ARM64_SO, 0x144860, 13))
    signature = bytes(value ^ 0xF1 for value in read_virtual(X86_64_SO, 0x13DBA4, 2))
    if width != b"widthPixels\0" or height != b"heightPixels\0":
        raise AssertionError(
            f"unexpected DisplayMetrics fields: width={width!r} height={height!r}")
    if signature != b"I\0":
        raise AssertionError(f"unexpected JNI field signature: {signature!r}")
    require(ARM_FULL, r"\b8c2f4:.*adr\s+x3,\s*0x144860\b",
            "heightPixels caller pointer")
    require(ARM_FULL, r"\b8d538:.*adr\s+x3,\s*0x144850\b",
            "widthPixels caller pointer")
    print("heightPixels/widthPixels names and JNI signature I: PASS")

    for offset, name in ((248, "GetObjectClass"), (184, "DeleteLocalRef"),
                         (752, "GetFieldID"), (800, "GetIntField")):
        require(arm, rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]",
                f"ARM64 {name} vtable slot")
    for offset, name in (("f8", "GetObjectClass"), ("b8", "DeleteLocalRef"),
                         ("2f0", "GetFieldID"), ("320", "GetIntField")):
        require(x86, rf"call\s+qword ptr \[rax\+0x{offset}\]",
                f"x86_64 {name} vtable slot")
    if len(re.findall(r"\bbl\s+92a20\b", arm)) != 3:
        raise AssertionError("ARM64 must consume exceptions exactly three times")
    if len(re.findall(r"\bcall\s+96a44\b", x86)) != 3:
        raise AssertionError("x86_64 must consume exceptions exactly three times")
    print("four JNI vtable methods and three exception-consumer calls: PASS")

    require(arm, r"mov\s+w10,\s*#0x3", "ARM64 null status 3")
    require(arm, r"mov\s+w10,\s*#0x12", "ARM64 class/field status 18")
    require(arm, r"mov\s+w8,\s*#0x1c", "ARM64 int exception status 28")
    require(arm, r"str\s+wzr,\s*\[x8\]", "ARM64 final output clear")
    require(x86, r"mov\s+dword ptr \[rax\],0x3", "x86_64 null status 3")
    require(x86, r"mov\s+dword ptr \[rax\],0x12", "x86_64 status 18")
    require(x86, r"push\s+0x1c", "x86_64 status 28")
    require(x86, r"and\s+dword ptr \[rax\],0x0", "x86_64 final output clear")
    require_order(x86, [
        "call   qword ptr [rax+0x320]",
        "mov    dword ptr [rcx],eax",
        "call   96a44",
    ], "x86_64 result publication before exception consumption")
    require(x86, r"test\s+r12,r12.*sete\s+byte ptr \[rsp\+0xb\]",
            "x86_64 class-null tracking")
    require(x86, r"cmp\s+dword ptr \[rax\],0x0",
            "x86_64 final incoming-status gate")
    print("statuses 3/18/28, class-null cleanup gate and output clearing: PASS")

    start = CPP.index("void runRecoveredJniIntFieldReaderB21b4(")
    end = CPP.index("enum class RecoveredJniIntFieldEventB21b4", start)
    implementation = CPP[start:end]
    require_order(implementation, [
        "if (object == 0 || fieldName == nullptr)",
        "*status = 3;",
        "operations.getObjectClass(jniEnvironment, object)",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "operations.getFieldId(",
        "jniEnvironment, objectClass, fieldName, \"I\")",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "*output = operations.getIntField(jniEnvironment, object, fieldId);",
        "operations.consumeException(jniEnvironment)",
        "*status = 28;",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "if (*status != 0) *output = 0;",
    ], "C++ JNI/status/cleanup order")
    require(CPP, r"bool recoveredJniIntFieldReaderB21b4Regression\(\)",
            "C++ regression")
    require(CPP, r"if \(!recoveredJniIntFieldReaderB21b4Regression\(\)\)",
            "top-level regression guard")
    require(CPP, r"state\.seenFieldName != \"heightPixels\"",
            "heightPixels regression")
    require(CPP, r"state\.seenFieldName != \"widthPixels\"",
            "widthPixels regression")
    require(GENERATOR,
            r"0x0B21B4:\s*\(\"JNI int-field reader\",\s*\"recovered\"",
            "coverage generator entry")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
