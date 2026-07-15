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

    arm_function = body(arm_text, 0xC2B78, 0xC375C)
    x86_function = body(x86_text, 0xB3FF9, 0xB46D8)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000c2b78...000c375c" in arm_frames, "ARM64 FDE")
    require("pc=000b3ff9...000b46d8" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x1455A0, 22, 0x5A),
            b"getApkContentsSigners\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x1455C0, 34, 0x0C),
            b"()[Landroid/content/pm/Signature;\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13E040, 22, 0x94),
            b"getApkContentsSigners\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13E060, 34, 0x49),
            b"()[Landroid/content/pm/Signature;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI SigningInfo APK-content-signers constants: PASS")

    for pattern, description in [
        (r"c2bb0:.*cmp\s+x2, #0x0", "ARM SigningInfo null gate"),
        (r"c3568:.*\[x8, #0xf8\].*c356c:.*blr", "ARM GetObjectClass"),
        (r"c3588:.*0x92a20", "ARM class exception consumer"),
        (r"c32c0:.*0x1455a0.*c32c8:.*0x1455c0",
         "ARM method/signature pointers"),
        (r"c32e0:.*\[x8, #0x108\].*c32e4:.*blr", "ARM GetMethodID"),
        (r"c3300:.*0x92a20", "ARM method exception consumer"),
        (r"c31c0:.*\[x8, #0x110\].*c31c4:.*blr", "ARM CallObjectMethod"),
        (r"c31cc:.*str\s+x0, \[x8\]", "ARM Signature-array publication"),
        (r"c31e4:.*0x92a20", "ARM call exception consumer"),
        (r"c3534:.*ldr\s+x8, \[sp, #0x20\].*"
         r"c3538:.*ldr\s+x8, \[x8\].*c353c:.*cmp\s+x8, #0x0",
         "ARM null result check"),
        (r"c2f74:.*\[x8, #0xb8\].*c2f78:.*blr", "ARM DeleteLocalRef"),
        (r"c2f94:.*ldr\s+w8, \[x8\].*c2fac:.*cmp\s+w8, #0x0",
         "ARM incoming/final status check"),
        (r"c3720:.*str\s+xzr, \[x8\]", "ARM nonzero-status output clear"),
        (r"c36a0:.*#0x3\b", "ARM null-input status 3"),
        (r"c3070:.*#0x12\b.*c3680:.*#0x12\b",
         "ARM class/method status 18"),
        (r"c2f60:.*#0x1c\b", "ARM call/null-result status 28"),
        (r"c3098:.*0x146a04.*c309c:.*0x139800",
         "ARM method-name once-lock acquire"),
        (r"c32b8:.*0x146a04.*c32cc:.*stlrb",
         "ARM method-name once-lock release"),
        (r"c3470:.*0x146a08.*c3474:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"c3198:.*0x146a08.*c31a8:.*stlrb",
         "ARM signature once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"b404d:.*testq\s+%rdx", "x86 SigningInfo null gate"),
        (r"b4576:.*\*0xf8", "x86 GetObjectClass"),
        (r"b4588:.*0x96a44", "x86 class exception consumer"),
        (r"b4440:.*0x13e040.*b4447:.*0x13e060",
         "x86 method/signature pointers"),
        (r"b444e:.*\*0x108", "x86 GetMethodID"),
        (r"b445a:.*0x96a44", "x86 method exception consumer"),
        (r"b43b3:.*\*0x110", "x86 CallObjectMethod"),
        (r"b43be:.*movq\s+%rax, \(%rcx\)",
         "x86 Signature-array publication"),
        (r"b43c4:.*0x96a44", "x86 call exception consumer"),
        (r"b4540:.*movq.*b4545:.*cmpq\s+\$0x0, \(%rax\)",
         "x86 null result check"),
        (r"b42c3:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"b430f:.*cmpl\s+\$0x0, \(%rax\)",
         "x86 incoming/final status check"),
        (r"b4692:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"b4639:.*\$0x3", "x86 null-input status 3"),
        (r"b4331:.*\$0x12.*b4613:.*\$0x12",
         "x86 class/method status 18"),
        (r"b42b2:.*\$0x1c", "x86 call/null-result status 28"),
        (r"b4345:.*cmpxchgb.*0x13f06a", "x86 method-name lock acquire"),
        (r"b4429:.*\$0x0.*0x13f06a", "x86 method-name lock release"),
        (r"b451c:.*cmpxchgb.*0x13f06c", "x86 signature lock acquire"),
        (r"b438d:.*\$0x0.*0x13f06c", "x86 signature lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e4b8:.*x0, x23.*1e4bc:.*x1, x22.*"
        r"1e4c0:.*x2.*1e4c4:.*x3.*1e4c8:.*0xc2b78",
        "ARM status/JNIEnv/SigningInfo/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"232ce:.*%rdi.*232d2:.*%rsi.*232d5:.*%rdx.*"
        r"232da:.*%rcx.*232df:.*0xb3ff9",
        "x86 status/JNIEnv/SigningInfo/output forwarding",
    )
    print("cross-ABI APK-content-signers JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniApkContentsSignersOperationsC2b78",
        "runRecoveredJniApkContentsSignersC2b78",
        "recoveredJniApkContentsSignersC2b78Regression",
        '"getApkContentsSigners"',
        '"()[Landroid/content/pm/Signature;"',
        "operations.callObjectMethod(",
        "operations.deleteLocalRef(jniEnvironment, signingInfoClass);",
        "if (*status != 0) *outputSignatures = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI SigningInfo.getApkContentsSigners reader 0xc2b78 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xC2B78]
    require(row["status"] == "recovered", "0xc2b78 recovered coverage")
    require(row["reachable"] == "yes", "0xc2b78 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
