#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
ARM_FRAMES = Path(__file__).with_name("arm64-eh-frame.txt")
SOURCE = ROOT / "native-reimplementation/recovered_primitives.cpp"
INVENTORY = Path(__file__).with_name("arm64-function-inventory.csv")


def require(condition: bool, description: str) -> None:
    if not condition:
        raise SystemExit(f"missing proof: {description}")


def body(text: str, start: int, end: int) -> str:
    selected: list[str] = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and start <= int(match.group(1), 16) < end:
            selected.append(line)
    require(bool(selected), f"disassembly body {start:#x}..{end:#x}")
    return "\n".join(selected)


def decoded(blob: bytes, vma: int, length: int, key: int) -> bytes:
    raw = blob[vma - 0x8000 : vma - 0x8000 + length]
    require(len(raw) == length, f"bytes at VMA {vma:#x}")
    return bytes(value ^ key for value in raw)


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def objdump(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/objdump", *arguments, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm_text = ARM_DISASSEMBLY.read_text(errors="replace")
    x86_text = objdump(X86_SO, "-d")
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = objdump(X86_SO, "--dwarf=frames")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()

    arm_function = body(arm_text, 0xB9424, 0xB9CC8)
    x86_function = body(x86_text, 0xAE5F4, 0xAECE3)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000b9424...000b9cc8" in arm_frames, "ARM64 FDE")
    require("pc=000ae5f4...000aece3" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_field": (decoded(arm_blob, 0x145310, 12, 0x8B),
                      b"signingInfo\0"),
        "arm_signature": (decoded(arm_blob, 0x145320, 33, 0xDC),
                          b"Landroid/content/pm/SigningInfo;\0"),
        "x86_field": (decoded(x86_blob, 0x13DDB0, 12, 0xFF),
                      b"signingInfo\0"),
        "x86_signature": (decoded(x86_blob, 0x13DDC0, 33, 0x2A),
                          b"Landroid/content/pm/SigningInfo;\0"),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI PackageInfo.signingInfo constants: PASS")

    for pattern, description in [
        (r"b9460:.*cmp\s+x2, #0x0", "ARM caller-object null gate"),
        (r"b9c30:.*\[x8, #0xf8\].*b9c34:.*blr", "ARM GetObjectClass"),
        (r"b9c50:.*0x92a20", "ARM class exception consumer"),
        (r"b9acc:.*0x145310.*b9ad4:.*0x145320",
         "ARM field/signature pointers"),
        (r"b9aec:.*\[x8, #0x2f0\].*b9af0:.*blr", "ARM GetFieldID"),
        (r"b9b0c:.*0x92a20", "ARM field exception consumer"),
        (r"b9a1c:.*\[x8, #0x2f8\].*b9a20:.*blr", "ARM GetObjectField"),
        (r"b9a28:.*str\s+x0, \[x8\]", "ARM object-result publication"),
        (r"b9a40:.*0x92a20", "ARM object-field exception consumer"),
        (r"b99a0:.*ldr\s+x8, \[x8\].*b99a8:.*cmp\s+x8, #0x0",
         "ARM null object-result check"),
        (r"b99d0:.*\[x8, #0xb8\].*b99d4:.*blr", "ARM DeleteLocalRef"),
        (r"b99e8:.*ldr\s+w8, \[x8\].*b99f0:.*cmp\s+w8, #0x0",
         "ARM incoming/final-status check"),
        (r"b9904:.*str\s+xzr, \[x8\]", "ARM nonzero-status output clear"),
        (r"b9bdc:.*#0x3\b", "ARM null-input status 3"),
        (r"b9824:.*#0x12\b.*b9bf8:.*#0x12\b",
         "ARM class/field status 18"),
        (r"b981c:.*#0x1c\b", "ARM object-result status 28"),
        (r"b986c:.*0x1469b0.*b9870:.*0x139800",
         "ARM field-name once-lock acquire"),
        (r"b9ad8:.*stlrb", "ARM field-name once-lock release"),
        (r"b9a8c:.*0x1469b4.*b9a90:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"b9858:.*stlrb", "ARM signature once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"ae652:.*testq\s+%rdx", "x86 caller-object null gate"),
        (r"aec37:.*\*0xf8", "x86 GetObjectClass"),
        (r"aec53:.*0x96a44", "x86 class exception consumer"),
        (r"aeb1b:.*0x13ddb0.*aeb22:.*0x13ddc0",
         "x86 field/signature pointers"),
        (r"aeb29:.*\*0x2f0", "x86 GetFieldID"),
        (r"aeb3f:.*0x96a44", "x86 field exception consumer"),
        (r"aea69:.*\*0x2f8", "x86 GetObjectField"),
        (r"aea74:.*movq\s+%rax, \(%rcx\)", "x86 object-result publication"),
        (r"aea84:.*0x96a44", "x86 object-field exception consumer"),
        (r"ae9be:.*cmpq\s+\$0x0, \(%rax\)", "x86 null object-result check"),
        (r"ae9ec:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"aea33:.*cmpl\s+\$0x0, \(%rax\)",
         "x86 incoming/final-status check"),
        (r"ae946:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"aebeb:.*\$0x3", "x86 null-input status 3"),
        (r"ae8d4:.*\$0x12.*aebfe:.*\$0x12",
         "x86 class/field status 18"),
        (r"ae8d0:.*\$0x1c", "x86 object-result status 28"),
        (r"ae8f7:.*cmpxchgb.*0x13f040", "x86 field-name lock acquire"),
        (r"aeb03:.*\$0x0.*0x13f040", "x86 field-name lock release"),
        (r"aeae9:.*cmpxchgb.*0x13f042", "x86 signature lock acquire"),
        (r"ae8e3:.*\$0x0.*0x13f042", "x86 signature lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e43c:.*x2.*1e440:.*x3.*1e444:.*x0, x23.*"
        r"1e448:.*x1, x22.*1e44c:.*0xb9424",
        "ARM status/JNIEnv/object/output caller forwarding",
    )
    require_pattern(
        x86_caller,
        r"23239:.*%rdx.*2323e:.*%r13.*23242:.*%rdi.*"
        r"23245:.*%rsi.*23248:.*%rcx.*2324d:.*0xae5f4",
        "x86 status/JNIEnv/object/output caller forwarding",
    )
    print("cross-ABI signingInfo JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniObjectFieldReaderOperationsB9424",
        "runRecoveredJniSigningInfoFieldReaderB9424",
        "recoveredJniSigningInfoFieldReaderB9424Regression",
        '"signingInfo",',
        '"Landroid/content/pm/SigningInfo;"',
        "operations.getObjectField(",
        "operations.deleteLocalRef(jniEnvironment, packageInfoClass);",
        "if (*status != 0) *outputSigningInfo = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI PackageInfo.signingInfo field reader 0xb9424 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xB9424]
    require(row["status"] == "recovered", "0xb9424 recovered coverage")
    require(row["reachable"] == "yes", "0xb9424 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
