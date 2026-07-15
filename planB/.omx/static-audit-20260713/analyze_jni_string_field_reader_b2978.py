#!/usr/bin/env python3
"""Prove the caller-selected JNI String-field reader at ARM64 0xb2978."""

from __future__ import annotations

import csv
import re
import struct
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_FRAMES = (HERE / "arm64-eh-frame.txt").read_text(errors="replace")
X86_FRAMES = (HERE / "x86_64-eh-frame.txt").read_text(errors="replace")
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_FULL = (HERE / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()
SOURCE = ROOT / "native-reimplementation/recovered_primitives.cpp"
GENERATOR = HERE / "generate_arm64_function_inventory.py"
INVENTORY = HERE / "arm64-function-inventory.csv"
DYNAMIC_LOG = HERE / "current-b2978-original-dynamic.log"


def require(condition: bool, description: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {description}")


def objdump(path: Path, start: int, end: int) -> str:
    return subprocess.run(
        [
            "/usr/bin/objdump", "-d", "--no-show-raw-insn",
            f"--start-address={start:#x}", f"--stop-address={end:#x}",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.lower()


def read_virtual(binary: Path, address: int, size: int) -> bytes:
    data = binary.read_bytes()
    require(data[:6] == b"\x7fELF\x02\x01",
            f"ELF64 little-endian {binary}")
    program_offset = struct.unpack_from("<Q", data, 0x20)[0]
    program_size = struct.unpack_from("<H", data, 0x36)[0]
    program_count = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(program_count):
        offset = program_offset + index * program_size
        values = struct.unpack_from("<IIQQQQQQ", data, offset)
        segment_type, _, file_offset, virtual_address, _, file_size, _, _ = (
            values)
        if segment_type != 1:
            continue
        if (virtual_address <= address
                and address + size <= virtual_address + file_size):
            start = file_offset + address - virtual_address
            return data[start:start + size]
    raise SystemExit(f"FAIL: non-file-backed VMA {address:#x}+{size:#x}")


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def require_order(text: str, tokens: list[str], description: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        require(position >= 0, f"{description}: {token}")
        cursor = position + len(token)


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm = objdump(ARM_SO, 0xB2978, 0xB3230)
    x86 = objdump(X86_SO, 0xAA8BB, 0xAAE64)
    source = SOURCE.read_text()
    generator = GENERATOR.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=000b2978...000b3230" in ARM_FRAMES,
            "ARM64 String-field FDE")
    require("pc=000aa8bb...000aae64" in X86_FRAMES,
            "x86_64 String-field FDE")
    arm_callers = re.findall(r"\bbl\s+0xb2978\b", ARM_FULL)
    x86_callers = re.findall(r"\bcallq?\s+0xaa8bb\b", X86_FULL)
    require(len(arm_callers) == 1 and len(x86_callers) == 1,
            f"single cross-ABI caller ARM={len(arm_callers)} "
            f"x86={len(x86_callers)}")
    require_pattern(
        ARM_FULL,
        r"\b181c0:.*\bbl\s+0xb2978\b",
        "ARM64 publicSourceDir producer caller",
    )
    require_pattern(
        X86_FULL,
        r"\b19728:.*\bcallq?\s+0xaa8bb\b",
        "x86_64 publicSourceDir producer caller",
    )
    print("cross-ABI FDEs and sole publicSourceDir producer caller: PASS")

    arm_signature = bytes(
        value ^ 0xAF for value in read_virtual(ARM_SO, 0x145110, 19))
    x86_signature = bytes(
        value ^ 0xEA for value in read_virtual(X86_SO, 0x13DBB0, 19))
    expected_signature = b"Ljava/lang/String;\0"
    require(arm_signature == expected_signature,
            f"ARM64 String signature {arm_signature!r}")
    require(x86_signature == expected_signature,
            f"x86_64 String signature {x86_signature!r}")
    require_pattern(
        ARM_FULL,
        r"\b181ac:.*add\s+x3,\s*x3,\s*#0xf0.*"
        r"\b181c0:.*\bbl\s+0xb2978\b",
        "ARM64 decoded publicSourceDir pointer forwarding",
    )
    print("cross-ABI Ljava/lang/String; and publicSourceDir forwarding: PASS")

    for offset, name in (
            ("0xf8", "GetObjectClass"),
            ("0x2f0", "GetFieldID"),
            ("0x2f8", "GetObjectField"),
            ("0xb8", "DeleteLocalRef")):
        require(offset in arm, f"ARM64 {name} vtable slot")
    for offset, name in (
            ("0xf8", "GetObjectClass"),
            ("0x2f0", "GetFieldID"),
            ("0x2f8", "GetObjectField"),
            ("0xb8", "DeleteLocalRef")):
        require_pattern(
            x86,
            rf"callq\s+\*{offset}\(%rax\)",
            f"x86_64 {name} vtable slot",
        )
    require(len(re.findall(r"\bbl\s+0x92a20\b", arm)) == 3,
            "ARM64 three exception consumers")
    require(len(re.findall(r"\bcallq\s+0x96a44\b", x86)) == 3,
            "x86_64 three exception consumers")
    print("GetObjectClass/GetFieldID/GetObjectField and cleanup flow: PASS")

    for token, description in (
            ("mov\tw10, #0x3", "ARM64 null status 3"),
            ("mov\tw10, #0x12", "ARM64 status 18"),
            ("mov\tw8, #0x1c", "ARM64 status 28"),
            ("str\tx0, [x8]", "ARM64 result publication"),
            ("str\txzr, [x8]", "ARM64 output clear")):
        require(token in arm, description)
    require_pattern(
        arm,
        r"b2f88:.*ldur\s+x8, \[x29, #-0x18\].*"
        r"b2f8c:.*ldr\s+x8, \[x8\].*b2f90:.*cmp\s+x8, #0x0",
        "ARM64 null object-field result gate",
    )
    for pattern, description in (
            (r"movl\s+\$0x3, \(%rax\)", "x86_64 null status 3"),
            (r"movl\s+\$0x12, \(%rax\)", "x86_64 status 18"),
            (r"pushq\s+\$0x1c", "x86_64 status 28"),
            (r"movq\s+%rax, \(%rcx\)", "x86_64 result publication"),
            (r"cmpq\s+\$0x0, \(%rax\)", "x86_64 null-result gate"),
            (r"andq\s+\$0x0, \(%rax\)", "x86_64 output clear")):
        require_pattern(x86, pattern, description)
    print("statuses 3/18/28, null-result failure and output clearing: PASS")

    start = source.index("void runRecoveredJniStringFieldReaderB2978(")
    end = source.index(
        "enum class RecoveredJniStringFieldEventB2978", start)
    implementation = source[start:end]
    require_order(implementation, [
        "if (object == 0 || fieldName == nullptr)",
        "*status = 3;",
        "operations.getObjectClass(jniEnvironment, object)",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "operations.getFieldId(",
        "fieldName, \"Ljava/lang/String;\")",
        "operations.consumeException(jniEnvironment)",
        "*status = 18;",
        "*outputString = operations.getObjectField(",
        "operations.consumeException(jniEnvironment)",
        "*status = 28;",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "if (*status != 0) *outputString = 0;",
    ], "C++ JNI/status/ownership order")
    for token in (
            "bool recoveredJniStringFieldReaderB2978Regression()",
            "if (!recoveredJniStringFieldReaderB2978Regression())",
            "JNI String-field reader 0xb2978 regression failed"):
        require(token in source, f"C++ token {token}")
    require_pattern(
        generator,
        r"0x0B2978:\s*\(\"JNI caller-selected String-field reader\","
        r"\s*\"recovered\"",
        "coverage generator recovered entry",
    )

    row = inventory_rows()[0xB2978]
    require(row["status"] == "recovered", "0xb2978 recovered coverage")
    require(row["reachable"] == "yes", "0xb2978 JNI reachable")
    print("C++ implementation, regression and recovered coverage: PASS")

    for token in (
            "b2978 entries=1 status=0->0 field=publicSourceDir "
            "signature=Ljava/lang/String;",
            "exceptions=[0, 0, 0] cleanup=class",
            "path=/data/app/~~audit/com.adjust.test-audit/base-public.apk",
            "Tests run: 1, Failures: 0, Errors: 0, Skipped: 0",
            "BUILD SUCCESS"):
        require(token in dynamic_log, f"original-SO dynamic token {token}")
    print("original-SO natural observation-only String-field flow: PASS")


if __name__ == "__main__":
    main()
