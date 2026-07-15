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
    return subprocess.run(
        ["/usr/bin/objdump", *arguments, str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


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

    arm_function = body(arm_text, 0xB8830, 0xB9424)
    x86_function = body(x86_text, 0xADF2E, 0xAE5F4)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000b8830...000b9424" in arm_frames, "ARM64 FDE")
    require("pc=000adf2e...000ae5f4" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_field": (
            decoded(arm_blob, 0x1452E0, 11, 0x1F),
            b"signatures\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x1452F0, 32, 0x0B),
            b"[Landroid/content/pm/Signature;\0",
        ),
        "x86_field": (
            decoded(x86_blob, 0x13DD80, 11, 0x40),
            b"signatures\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13DD90, 32, 0x5C),
            b"[Landroid/content/pm/Signature;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI legacy PackageInfo.signatures constants: PASS")

    for pattern, description in [
        (r"b8880:.*cmp\s+x2, #0x0", "ARM PackageInfo null gate"),
        (r"b8f44:.*\[x8, #0xf8\].*b8f48:.*blr", "ARM GetObjectClass"),
        (r"b8f64:.*0x92a20", "ARM class exception consumer"),
        (r"b9238:.*0x1452e0.*b9240:.*0x1452f0",
         "ARM field/signature pointers"),
        (r"b9258:.*\[x8, #0x2f0\].*b925c:.*blr", "ARM GetFieldID"),
        (r"b9278:.*0x92a20", "ARM field exception consumer"),
        (r"b8d34:.*\[x8, #0x2f8\].*b8d38:.*blr", "ARM GetObjectField"),
        (r"b8d40:.*str\s+x0, \[x8\]", "ARM Signature-array publication"),
        (r"b8d58:.*0x92a20", "ARM object-field exception consumer"),
        (r"b9368:.*ldr\s+x8, \[sp, #0x28\].*"
         r"b936c:.*ldr\s+x8, \[x8\].*b9370:.*cmp\s+x8, #0x0",
         "ARM null object-result check"),
        (r"b90e8:.*\[x8, #0xb8\].*b90ec:.*blr", "ARM DeleteLocalRef"),
        (r"b9108:.*ldr\s+w8, \[x8\].*b9120:.*cmp\s+w8, #0x0",
         "ARM incoming/final status check"),
        (r"b93cc:.*str\s+xzr, \[x8\]", "ARM nonzero-status output clear"),
        (r"b8d0c:.*#0x3\b", "ARM null-input status 3"),
        (r"b8f18:.*#0x12\b.*b93d8:.*#0x12\b",
         "ARM class/field status 18"),
        (r"b8c08:.*#0x1c\b", "ARM object-result status 28"),
        (r"b8c1c:.*0x1469a8.*b8c20:.*0x139800",
         "ARM field-name once-lock acquire"),
        (r"b9230:.*0x1469a8.*b9244:.*stlrb",
         "ARM field-name once-lock release"),
        (r"b8e44:.*0x1469ac.*b8e48:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"b90b4:.*0x1469ac.*b90c4:.*stlrb",
         "ARM signature once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"adf8c:.*testq\s+%rdx", "x86 PackageInfo null gate"),
        (r"ae318:.*\*0xf8", "x86 GetObjectClass"),
        (r"ae331:.*0x96a44", "x86 class exception consumer"),
        (r"ae4af:.*0x13dd80.*ae4b6:.*0x13dd90",
         "x86 field/signature pointers"),
        (r"ae4bd:.*\*0x2f0", "x86 GetFieldID"),
        (r"ae4d3:.*0x96a44", "x86 field exception consumer"),
        (r"ae255:.*\*0x2f8", "x86 GetObjectField"),
        (r"ae260:.*movq\s+%rax, \(%rcx\)",
         "x86 Signature-array publication"),
        (r"ae270:.*0x96a44", "x86 object-field exception consumer"),
        (r"ae549:.*movq.*ae54e:.*cmpq\s+\$0x0, \(%rax\)",
         "x86 null object-result check"),
        (r"ae3fc:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"ae443:.*cmpl\s+\$0x0, \(%rax\)",
         "x86 incoming/final status check"),
        (r"ae5ac:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"ae22b:.*\$0x3", "x86 null-input status 3"),
        (r"ae2f9:.*\$0x12.*ae5bd:.*\$0x12",
         "x86 class/field status 18"),
        (r"ae1dc:.*\$0x1c", "x86 object-result status 28"),
        (r"ae1e8:.*cmpxchgb.*0x13f03c", "x86 field-name lock acquire"),
        (r"ae498:.*\$0x0.*0x13f03c", "x86 field-name lock release"),
        (r"ae2d5:.*cmpxchgb.*0x13f03e", "x86 signature lock acquire"),
        (r"ae3cd:.*\$0x0.*0x13f03e", "x86 signature lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e368:.*x2.*1e36c:.*x0, x23.*1e370:.*x1, x22.*"
        r"1e374:.*x3.*1e378:.*0xb8830",
        "ARM status/JNIEnv/PackageInfo/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"2315f:.*%rdx.*23164:.*%rdi.*23168:.*%rsi.*"
        r"2316b:.*%rcx.*23170:.*0xadf2e",
        "x86 status/JNIEnv/PackageInfo/output forwarding",
    )
    print("cross-ABI legacy signatures JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniLegacySignaturesFieldOperationsB8830",
        "runRecoveredJniLegacySignaturesFieldReaderB8830",
        "recoveredJniLegacySignaturesFieldReaderB8830Regression",
        '"signatures",',
        '"[Landroid/content/pm/Signature;"',
        "operations.getObjectField(",
        "operations.deleteLocalRef(jniEnvironment, packageInfoClass);",
        "if (*status != 0) *outputSignatures = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI PackageInfo.signatures field reader 0xb8830 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xB8830]
    require(row["status"] == "recovered", "0xb8830 recovered coverage")
    require(row["reachable"] == "yes", "0xb8830 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
