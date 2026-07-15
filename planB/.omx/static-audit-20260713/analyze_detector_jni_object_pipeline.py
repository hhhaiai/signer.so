#!/usr/bin/env python3
"""Cross-ABI proof for four detector-producer JNI object helpers."""

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
    ranges = {
        "resources": (0xBB5A0, 0xBC3AC, 0xAFB26, 0xB02C7),
        "name": (0xBEA74, 0xBF5FC, 0xB1A13, 0xB20C2),
        "vendor": (0xBF5FC, 0xC0180, 0xB20C2, 0xB278E),
        "list": (0xC0180, 0xC0D84, 0xB278E, 0xB2E55),
    }
    arm = {}
    x86 = {}
    for label, (arm_start, arm_end, x86_start, x86_end) in ranges.items():
        arm[label] = disassemble(objdump, ARM_SO, arm_start, arm_end)
        x86[label] = disassemble(objdump, X86_SO, x86_start, x86_end, True)
        require(ARM_EH, rf"pc=000{arm_start:x}\.\.\.000{arm_end:x}",
                f"ARM64 {label} FDE")
        require(X86_EH, rf"pc=000{x86_start:x}\.\.\.000{x86_end:x}",
                f"x86 {label} FDE")
    for address, target in ((0x8C2A0, 0xBB5A0), (0x8BF60, 0xBEA74),
                            (0x8CA74, 0xBF5FC), (0x8CC60, 0xC0180)):
        require(ARM_FULL, rf"\b{address:x}:.*\bbl\s+0x{target:x}\b",
                f"ARM64 caller 0x{address:x}")
    for address, target in ((0x8F5CA, 0xAFB26), (0x91CB6, 0xB1A13),
                            (0x91EEA, 0xB20C2), (0x91510, 0xB278E)):
        require(X86_FULL, rf"\b{address:x}:.*\bcallq?\s+0x{target:x}\b",
                f"x86 caller 0x{address:x}")
    print("four cross-ABI FDE/caller pairs: PASS")

    constants = [
        (ARM_SO, 0x145400, 30, 0x23, b"android/content/res/Resources\0"),
        (X86_SO, 0x13DEA0, 30, 0xC0, b"android/content/res/Resources\0"),
        (ARM_SO, 0x145420, 10, 0x08, b"getSystem\0"),
        (X86_SO, 0x13DEC0, 10, 0xB3, b"getSystem\0"),
        (ARM_SO, 0x145430, 34, 0x30, b"()Landroid/content/res/Resources;\0"),
        (X86_SO, 0x13DED0, 34, 0x53, b"()Landroid/content/res/Resources;\0"),
        (ARM_SO, 0x145508, 8, 0x0B, b"getName\0"),
        (X86_SO, 0x13DFA8, 8, 0xF7, b"getName\0"),
        (ARM_SO, 0x145510, 10, 0xFD, b"getVendor\0"),
        (X86_SO, 0x13DFB0, 10, 0x59, b"getVendor\0"),
        (ARM_SO, 0x144AF0, 21, 0x47, b"()Ljava/lang/String;\0"),
        (X86_SO, 0x13D590, 21, 0x2A, b"()Ljava/lang/String;\0"),
        (ARM_SO, 0x145520, 14, 0xCD, b"getSensorList\0"),
        (X86_SO, 0x13DFC0, 14, 0xC1, b"getSensorList\0"),
        (ARM_SO, 0x145530, 20, 0x47, b"(I)Ljava/util/List;\0"),
        (X86_SO, 0x13DFD0, 20, 0x02, b"(I)Ljava/util/List;\0"),
    ]
    for binary, address, size, key, expected in constants:
        actual = decoded(binary, address, size, key)
        if actual != expected:
            raise AssertionError(
                f"decode mismatch {binary.name}@0x{address:x}: {actual!r}")
    print("class/method/signature constants decoded across both ABIs: PASS")

    for label in ("name", "vendor", "list"):
        for offset, operation in ((248, "GetObjectClass"), (264, "GetMethodID"),
                                  (272, "CallObjectMethod"), (184, "DeleteLocalRef")):
            require(arm[label], rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]",
                    f"ARM64 {label} {operation}")
        if len(re.findall(r"\bbl\s+92a20\b", arm[label])) != 3:
            raise AssertionError(f"ARM64 {label} exception count")
    for offset, operation in ((48, "FindClass"), (904, "GetStaticMethodID"),
                              (912, "CallStaticObjectMethod"), (184, "DeleteLocalRef")):
        require(arm["resources"], rf"ldr\s+x8,\s*\[x8,\s*#{offset}\]",
                f"ARM64 resources {operation}")
    if len(re.findall(r"\bbl\s+92a20\b", arm["resources"])) != 3:
        raise AssertionError("ARM64 Resources exception count")
    print("JNI vtable surfaces and three-stage exception handling: PASS")

    for label in ("name", "vendor"):
        for status in ("0x3", "0x12", "0x1c"):
            require(arm[label], rf"mov\s+w\d+,\s*#{status}\b",
                    f"ARM64 {label} status {status}")
    require(arm["resources"], r"mov\s+w\d+,\s*#0x12\b",
            "Resources status 18")
    require(arm["resources"], r"mov\s+w\d+,\s*#0x1c\b",
            "Resources status 28")
    require(arm["list"], r"mov\s+w\d+,\s*#0x3\b", "sensor list status 3")
    require(arm["list"], r"mov\s+w\d+,\s*#0x12\b", "sensor list status 18")
    if re.search(r"mov\s+w\d+,\s*#0x1c\b", arm["list"]):
        raise AssertionError("SensorManager.getSensorList must not use status 28")
    require(arm["list"], r"ldr\s+w3,\s*\[sp,\s*#8\].*ldr\s+x8,\s*\[x8,\s*#272\]",
            "sensor type forwarded to CallObjectMethod")
    print("status split including getSensorList call/null status 18: PASS")

    require_order(CPP, [
        "void runRecoveredJniSystemResourcesGetterBb5a0(",
        "\"android/content/res/Resources\"",
        "\"getSystem\"",
        "\"()Landroid/content/res/Resources;\"",
        "*status = 28;",
        "bool recoveredJniSystemResourcesGetterBb5a0Regression()",
        "void runRecoveredJniSensorNameGetterBea74(",
        "\"getName\"",
        "void runRecoveredJniSensorVendorGetterBf5fc(",
        "\"getVendor\"",
        "bool recoveredJniSensorStringGettersRegression()",
        "void runRecoveredJniSensorListGetterC0180(",
        "\"getSensorList\"",
        "\"(I)Ljava/util/List;\"",
        "bool recoveredJniSensorListGetterC0180Regression()",
    ], "C++ implementations and regressions")
    for address, name in (
        ("0x0BB5A0", "JNI Resources.getSystem getter"),
        ("0x0BEA74", "JNI Sensor.getName getter"),
        ("0x0BF5FC", "JNI Sensor.getVendor getter"),
        ("0x0C0180", "JNI SensorManager.getSensorList getter"),
    ):
        require(GENERATOR, rf"{address}:\s*\(\"{re.escape(name)}\",\s*\"recovered\"",
                f"coverage {address}")
    for regression in (
        "recoveredJniSystemResourcesGetterBb5a0Regression",
        "recoveredJniSensorStringGettersRegression",
        "recoveredJniSensorListGetterC0180Regression",
    ):
        require(CPP, rf"if \(!{regression}\(\)\)", f"main guard {regression}")
    print("C++ source, regression guards and coverage entries: PASS")


if __name__ == "__main__":
    main()
