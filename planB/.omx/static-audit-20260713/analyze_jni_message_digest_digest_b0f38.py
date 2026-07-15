#!/usr/bin/env python3
"""Prove the MessageDigest.digest overload helper at ARM64 0xb0f38."""

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
            "/usr/bin/objdump", "-d", "--no-show-raw-insn",
            f"--start-address={start:#x}", f"--stop-address={end:#x}",
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
    arm = objdump(ARM_SO, 0xB0F38, 0xB1E40)
    x86 = objdump(X86_SO, 0xA9783, 0xAA064)
    arm_caller = objdump(ARM_SO, 0x1E578, 0x1F058)
    x86_caller = objdump(X86_SO, 0x2335E, 0x23D51)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=000b0f38...000b1e40" in arm_frames, "ARM64 digest FDE")
    require("pc=000a9783...000aa064" in x86_frames, "x86_64 digest FDE")
    require("pc=0001e578...0001f058" in arm_frames, "ARM64 caller FDE")
    require("pc=0002335e...00023d51" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_method": (decoded(arm_blob, 0x1450E4, 7, 0xDF), b"digest\0"),
        "arm_noarg_signature": (
            decoded(arm_blob, 0x144954, 5, 0xB6), b"()[B\0"),
        "arm_byte_array_signature": (
            decoded(arm_blob, 0x144A20, 7, 0x90), b"([B)[B\0"),
        "x86_method": (decoded(x86_blob, 0x13DB84, 7, 0x59), b"digest\0"),
        "x86_noarg_signature": (
            decoded(x86_blob, 0x13D3F4, 5, 0x1C), b"()[B\0"),
        "x86_byte_array_signature": (
            decoded(x86_blob, 0x13D4C0, 7, 0x6C), b"([B)[B\0"),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI MessageDigest.digest overload constants: PASS")

    for pattern, description in [
        (r"b0f70:.*cmp\s+x2, #0x0", "ARM MessageDigest null gate"),
        (r"b0f90:.*cmp\s+x3, #0x0.*b0fa4:.*csel",
         "ARM optional byte-array overload selection"),
        (r"b1454:.*b1464:.*\[x8, #0xf8\].*b1468:.*blr",
         "ARM GetObjectClass"),
        (r"b1478:.*0x92a20", "ARM class exception consumer"),
        (r"b1968:.*b1974:.*0x1450e4.*b1984:.*\[sp, #0x8\].*"
         r"b1990:.*\[x8, #0x108\].*b1994:.*blr",
         "ARM GetMethodID digest with selected signature"),
        (r"b19a4:.*0x92a20", "ARM method exception consumer"),
        (r"b17e8:.*b17f0:.*\[sp, #0x30\].*b17f4:.*blr",
         "ARM no-argument CallObjectMethod"),
        (r"b153c:.*b1544:.*\[sp, #0x30\].*b1548:.*\[sp, #0x10\].*"
         r"b154c:.*blr", "ARM byte-array CallObjectMethod"),
        (r"b1674:.*b1680:.*str\s+x9, \[x8\].*b1684:.*0x92a20",
         "ARM output publication then call exception consumer"),
        (r"b1890:.*b1894:.*ldr\s+x8, \[x8\].*b1898:.*cmp\s+x8, #0x0",
         "ARM null digest result check"),
        (r"b18b4:.*b18c0:.*\[x8, #0xb8\].*b18c4:.*blr",
         "ARM object-class DeleteLocalRef"),
        (r"b1ca4:.*#0x3\b.*b1cb8:.*str\s+w8", "ARM status 3"),
        (r"b1574:.*#0x12\b.*b1d04:.*#0x12\b", "ARM status 18"),
        (r"b144c:.*#0x1c\b", "ARM status 28"),
        (r"b1d44:.*b1d58:.*str\s+xzr, \[x8\]",
         "ARM nonzero-status output clear"),
    ]:
        require_pattern(arm, pattern, description)

    for pattern, description in [
        (r"a97af:.*testq\s+%rdx", "x86 MessageDigest null gate"),
        (r"a97d7:.*testq\s+%rcx.*a97da:.*0x13d3f4.*"
         r"a97e1:.*0x13d4c0.*a97e8:.*cmoveq",
         "x86 optional byte-array overload selection"),
        (r"a9b30:.*a9b41:.*\*0xf8.*a9b56:.*0x96a44",
         "x86 GetObjectClass and exception consumer"),
        (r"a9e42:.*a9e53:.*0x13db84.*a9e5f:.*\*0x108.*"
         r"a9e6b:.*0x96a44", "x86 GetMethodID and exception consumer"),
        (r"a9d2f:.*a9d40:.*\*0x50", "x86 no-argument CallObjectMethod"),
        (r"a9bde:.*a9bed:.*%rcx.*a9bf4:.*\*0x50",
         "x86 byte-array CallObjectMethod"),
        (r"a9c80:.*a9c8a:.*movq\s+%rcx, \(%rax\).*"
         r"a9c92:.*0x96a44", "x86 output publication and exception consumer"),
        (r"a9d97:.*cmpq\s+\$0x0, \(%rax\)", "x86 null result check"),
        (r"a9dbd:.*a9dca:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"a9fa0:.*\$0x3", "x86 status 3"),
        (r"a9c11:.*\$0x12.*a9fe1:.*\$0x12", "x86 status 18"),
        (r"a9b29:.*\$0x1c", "x86 status 28"),
        (r"aa014:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
    ]:
        require_pattern(x86, pattern, description)

    require_pattern(
        arm_caller,
        r"1edc8:.*1edd0:.*\[x29, #-0x28\].*1edd4:.*x1, x20.*"
        r"1edd8:.*x3, xzr.*1eddc:.*x0, x23.*1ede0:.*0xb0f38",
        "ARM parent selects no-argument digest overload",
    )
    require_pattern(
        x86_caller,
        r"23a59:.*23a5e:.*%r15, %rdi.*23a61:.*%rsi.*"
        r"23a66:.*xorl\s+%ecx, %ecx.*23a68:.*%r8.*23a6d:.*0xa9783",
        "x86 parent selects no-argument digest overload",
    )
    print("cross-ABI digest JNI/status/ownership and caller flow: PASS")

    for token in [
        "MessageDigest$Delegate.digest()[B",
        "libsigner.so]0xb1998",
        "libsigner.so]0xb17f8",
    ]:
        require(token in dynamic_log, f"original-SO observation token {token}")
    print("original-SO MessageDigest.digest natural no-arg path: PASS")

    for token in [
        "RecoveredJniMessageDigestOperationsB0f38",
        "runRecoveredJniMessageDigestB0f38",
        "recoveredJniMessageDigestB0f38Regression",
        '"digest"',
        '"([B)[B"',
        '"JNI MessageDigest.digest helper 0xb0f38 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0xB0F38]
    require(row["status"] == "recovered", "0xb0f38 recovered coverage")
    require(row["reachable"] == "yes", "0xb0f38 JNI-reachable classification")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
