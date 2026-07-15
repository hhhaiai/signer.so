#!/usr/bin/env python3
"""Prove the Signature.toByteArray JNI helper at ARM64 0xc2248."""

from __future__ import annotations

import csv
import re
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_FRAMES = HERE / "arm64-eh-frame.txt"
X86_FRAMES = HERE / "x86_64-eh-frame.txt"
SOURCE = ROOT / "native-reimplementation/recovered_primitives.cpp"
INVENTORY = HERE / "arm64-function-inventory.csv"
DYNAMIC_LOG = HERE / "current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log"


def require(condition: bool, description: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {description}")


def objdump(path: Path, start: int, end: int) -> str:
    return subprocess.run(
        [
            "/usr/bin/objdump",
            "-d",
            "--no-show-raw-insn",
            f"--start-address={start:#x}",
            f"--stop-address={end:#x}",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def decoded(blob: bytes, vma: int, length: int, key: int) -> bytes:
    raw = blob[vma - 0x8000:vma - 0x8000 + length]
    require(len(raw) == length, f"bytes at VMA {vma:#x}")
    return bytes(value ^ key for value in raw)


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm = objdump(ARM_SO, 0xC2248, 0xC2B78)
    x86 = objdump(X86_SO, 0xB392F, 0xB3FF9)
    arm_caller = objdump(ARM_SO, 0x1E578, 0x1F058)
    x86_caller = objdump(X86_SO, 0x2335E, 0x23D51)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=000c2248...000c2b78" in arm_frames, "ARM64 FDE")
    require("pc=000b392f...000b3ff9" in x86_frames, "x86_64 FDE")
    require("pc=0001e578...0001f058" in arm_frames, "ARM64 caller FDE")
    require("pc=0002335e...00023d51" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_method": (decoded(arm_blob, 0x144948, 12, 0xE2),
                       b"toByteArray\0"),
        "arm_signature": (decoded(arm_blob, 0x144954, 5, 0xB6), b"()[B\0"),
        "x86_method": (decoded(x86_blob, 0x13D3E8, 12, 0xC6),
                       b"toByteArray\0"),
        "x86_signature": (decoded(x86_blob, 0x13D3F4, 5, 0x1C), b"()[B\0"),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI Signature.toByteArray constants: PASS")

    for pattern, description in [
        (r"c2284:.*cmp\s+x2, #0x0", "ARM Signature null gate"),
        (r"c26f8:.*\[x28\].*c2700:.*\[x8, #0xf8\].*c2704:.*blr",
         "ARM GetObjectClass"),
        (r"c2720:.*0x92a20", "ARM class exception consumer"),
        (r"c295c:.*0x144948.*c2964:.*0x144954",
         "ARM method/signature pointers"),
        (r"c297c:.*\[x8, #0x108\].*c2980:.*blr", "ARM GetMethodID"),
        (r"c299c:.*0x92a20", "ARM method exception consumer"),
        (r"c28c8:.*c28cc:.*\[x8, #0x110\].*c28d0:.*blr",
         "ARM CallObjectMethod"),
        (r"c28d4:.*ldr.*c28d8:.*str\s+x0, \[x8\]",
         "ARM returned byte-array publication"),
        (r"c28f0:.*0x92a20", "ARM call exception consumer"),
        (r"c2854:.*c2860:.*\[x8, #0xb8\].*c2864:.*blr",
         "ARM DeleteLocalRef"),
        (r"c2b34:.*#0x3\b.*c2b4c:.*str\s+w10", "ARM status 3"),
        (r"c2638:.*#0x12\b.*c2784:.*#0x12\b", "ARM status 18"),
        (r"c2630:.*#0x1c\b", "ARM status 28"),
        (r"c2a90:.*c2aa4:.*str\s+xzr, \[x8\]",
         "ARM nonzero-status output clear"),
    ]:
        require_pattern(arm, pattern, description)

    for pattern, description in [
        (r"b3c82:.*\*0xf8", "x86 GetObjectClass"),
        (r"b3c98:.*0x96a44", "x86 class exception consumer"),
        (r"b3e8c:.*0x13d3e8.*b3e93:.*0x13d3f4",
         "x86 method/signature pointers"),
        (r"b3e9a:.*\*0x108", "x86 GetMethodID"),
        (r"b3eb0:.*0x96a44", "x86 method exception consumer"),
        (r"b3df9:.*\*0x110", "x86 CallObjectMethod"),
        (r"b3dff:.*b3e04:.*movq\s+%rax, \(%rcx\)",
         "x86 returned byte-array publication"),
        (r"b3e14:.*0x96a44", "x86 call exception consumer"),
        (r"b3d81:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"b3fdc:.*\$0x3", "x86 status 3"),
        (r"b3c16:.*\$0x12.*b3d02:.*\$0x12", "x86 status 18"),
        (r"b3c0a:.*\$0x1c", "x86 status 28"),
    ]:
        require_pattern(x86, pattern, description)

    require_pattern(
        arm_caller,
        r"1eeb0:.*1eeb8:.*x1, x20.*1eebc:.*\[sp, #0x18\].*"
        r"1eec0:.*x0, x23.*1eec4:.*0xc2248",
        "ARM status/JNIEnv/Signature/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"23bf9:.*%r15, %rdi.*23bfc:.*%rsi.*23c01:.*%rdx.*"
        r"23c06:.*%rcx.*23c0b:.*0xb392f",
        "x86 status/JNIEnv/Signature/output forwarding",
    )
    print("cross-ABI Signature.toByteArray JNI/status/ownership flow: PASS")

    for token in [
        "Signature.toByteArray()[B",
        "libsigner.so]0xc2984",
        "libsigner.so]0xc28d4",
    ]:
        require(token in dynamic_log, f"original-SO observation token {token}")
    print("original-SO Signature.toByteArray natural JNI path: PASS")

    for token in [
        "RecoveredJniSignatureToByteArrayOperationsC2248",
        "runRecoveredJniSignatureToByteArrayC2248",
        "recoveredJniSignatureToByteArrayC2248Regression",
        "runRecoveredJniToByteArray93fd0(",
        '"JNI Signature.toByteArray helper 0xc2248 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0xC2248]
    require(row["status"] == "recovered", "0xc2248 recovered coverage")
    require(row["reachable"] == "yes", "0xc2248 JNI-reachable classification")
    print("C++ shared implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
