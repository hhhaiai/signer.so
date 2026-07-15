#!/usr/bin/env python3
"""Cross-ABI proof for JNI Context.getSystemService helper 0xb5828."""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X86_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(errors="replace").lower()
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(errors="replace").lower()
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
    raise SystemExit("GNU objdump not found")


def disassemble(objdump: str, binary: Path, start: int, end: int,
                intel: bool = False) -> str:
    command = [objdump, "-d", f"--start-address=0x{start:x}",
               f"--stop-address=0x{end:x}"]
    if intel:
        command.extend(["-M", "intel"])
    command.append(str(binary))
    return subprocess.run(command, check=True, text=True,
                          stdout=subprocess.PIPE).stdout.lower()


def virtual_bytes(binary: Path, address: int, size: int) -> bytes:
    data = binary.read_bytes()
    program_offset = struct.unpack_from("<Q", data, 0x20)[0]
    entry_size = struct.unpack_from("<H", data, 0x36)[0]
    entry_count = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(entry_count):
        entry = program_offset + index * entry_size
        kind, _flags, file_offset, virtual_address, _physical, file_size, \
            _memory_size, _align = struct.unpack_from("<IIQQQQQQ", data, entry)
        if kind == 1 and virtual_address <= address \
                and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return data[start:start + size]
    raise AssertionError(f"unmapped virtual bytes 0x{address:x}+{size}")


def decoded(binary: Path, address: int, size: int, key: int) -> bytes:
    return bytes(value ^ key for value in virtual_bytes(binary, address, size))


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
    arm = disassemble(objdump, ARM_SO, 0xB5828, 0xB70E4)
    x86 = disassemble(objdump, X86_SO, 0xAC4D5, 0xAD0A5, True)

    require(ARM_EH, r"pc=000b5828\.\.\.000b70e4", "ARM64 FDE")
    require(X86_EH, r"pc=000ac4d5\.\.\.000ad0a5", "x86 FDE")
    require(ARM_FULL, r"\b8af24:.*\bbl\s+0xb5828\b", "ARM64 caller")
    require(X86_FULL, r"\b9089f:.*\bcallq?\s+0xac4d5\b", "x86 caller")
    print("cross-ABI FDE and sole producer caller: PASS")

    constants = [
        (ARM_SO, 0x1451F0, 24, 0x38, b"android/content/Context\0"),
        (X86_SO, 0x13DC90, 24, 0x49, b"android/content/Context\0"),
        (ARM_SO, 0x145210, 17, 0x0A, b"getSystemService\0"),
        (X86_SO, 0x13DCB0, 17, 0x7F, b"getSystemService\0"),
        (ARM_SO, 0x145230, 39, 0x8A,
         b"(Ljava/lang/String;)Ljava/lang/Object;\0"),
        (X86_SO, 0x13DCD0, 39, 0xAE,
         b"(Ljava/lang/String;)Ljava/lang/Object;\0"),
        (ARM_SO, 0x145110, 19, 0xAF, b"Ljava/lang/String;\0"),
        (X86_SO, 0x13DBB0, 19, 0xEA, b"Ljava/lang/String;\0"),
    ]
    for binary, address, size, key, expected in constants:
        actual = decoded(binary, address, size, key)
        if actual != expected:
            raise AssertionError(
                f"decode mismatch {binary.name}@0x{address:x}: {actual!r}")
    print("Context, method and two JNI signatures decoded cross-ABI: PASS")

    for offset, operation in (
        (48, "FindClass"),
        (264, "GetMethodID"),
        (1152, "GetStaticFieldID"),
        (1160, "GetStaticObjectField"),
        (272, "CallObjectMethod"),
        (184, "DeleteLocalRef"),
    ):
        require(arm, rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]",
                f"ARM64 {operation}")
    if len(re.findall(r"ldr\s+x8,\s*\[x8,\s*#184\]", arm)) != 2:
        raise AssertionError("ARM64 must contain two local-ref cleanup sites")
    if len(re.findall(r"\bbl\s+92a20\b", arm)) != 5:
        raise AssertionError("ARM64 must consume exceptions five times")
    if len(re.findall(r"\bcall\s+96a44\b", x86)) != 5:
        raise AssertionError("x86 must consume exceptions five times")
    for offset in ("0x30", "0x108", "0x480", "0x488", "0x110", "0xb8"):
        require(x86, rf"call\s+qword ptr \[(?:rax|r8)\+{offset}\]",
                f"x86 JNI slot {offset}")
    print("six JNI operations, five exception stages and two cleanup sites: PASS")

    require(arm, r"cmp\s+x3,\s*#0x0.*ccmp\s+x2,\s*#0x0",
            "field-name/context null input gate")
    require(arm, r"mov\s+w\d+,\s*#0x3\b", "status 3")
    require(arm, r"mov\s+w\d+,\s*#0x12\b", "status 18")
    require(arm, r"mov\s+w\d+,\s*#0x1c\b", "status 28")
    require(arm, r"str\s+xzr,\s*\[x8\]", "output clearing")
    require_order(arm, [
        "ldr\tx8, [x8, #272]",
        "blr\tx8",
        "str\tx0, [x8]",
        "bl\t92a20",
    ], "CallObjectMethod result publication before exception consumption")
    require(x86, r"push\s+0x3", "x86 status 3")
    require(x86, r"push\s+0x12", "x86 status 18")
    require(x86, r"mov\s+dword ptr \[rax\],0x1c", "x86 status 28")
    print("input gate, statuses 3/18/28 and result clearing: PASS")

    start = CPP.index("void runRecoveredJniSystemServiceGetterB5828(")
    end = CPP.index("enum class RecoveredJniSystemServiceEventB5828", start)
    implementation = CPP[start:end]
    require_order(implementation, [
        "if (context == 0 || serviceFieldName == nullptr)",
        "*status = 3;",
        "operations.findClass(",
        "jniEnvironment, \"android/content/Context\")",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "operations.getMethodId(",
        "\"getSystemService\"",
        "\"(Ljava/lang/String;)Ljava/lang/Object;\"",
        "operations.consumeException(jniEnvironment)",
        "operations.getStaticFieldId(",
        "serviceFieldName",
        "\"Ljava/lang/String;\"",
        "operations.consumeException(jniEnvironment)",
        "operations.getStaticObjectField(",
        "operations.consumeException(jniEnvironment)",
        "*status = 28;",
        "*output = operations.callObjectMethod(",
        "operations.consumeException(jniEnvironment)",
        "callException || *output == 0",
        "operations.deleteLocalRef(jniEnvironment, serviceName);",
        "operations.deleteLocalRef(jniEnvironment, contextClass);",
        "if (*status != 0) *output = 0;",
    ], "C++ JNI/status/ownership order")
    require(CPP, r"bool recoveredJniSystemServiceGetterB5828Regression\(\)",
            "regression")
    require(CPP, r"if \(!recoveredJniSystemServiceGetterB5828Regression\(\)\)",
            "main guard")
    require(GENERATOR,
            r"0x0B5828:\s*\(\"JNI Context.getSystemService getter\",\s*\"recovered\"",
            "coverage entry")
    print("C++ implementation, regression and coverage entry: PASS")


if __name__ == "__main__":
    main()
