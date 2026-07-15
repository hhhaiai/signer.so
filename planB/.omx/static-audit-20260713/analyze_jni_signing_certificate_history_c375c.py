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

    arm_function = body(arm_text, 0xC375C, 0xC4064)
    x86_function = body(x86_text, 0xB46D8, 0xB4DAD)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000c375c...000c4064" in arm_frames, "ARM64 FDE")
    require("pc=000b46d8...000b4dad" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x1455F0, 29, 0x34),
            b"getSigningCertificateHistory\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x1455C0, 34, 0x0C),
            b"()[Landroid/content/pm/Signature;\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13E090, 29, 0x3A),
            b"getSigningCertificateHistory\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13E060, 34, 0x49),
            b"()[Landroid/content/pm/Signature;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI SigningInfo certificate-history constants: PASS")

    for pattern, description in [
        (r"c37f8:.*cmp\s+x2, #0x0", "ARM SigningInfo null gate"),
        (r"c3cec:.*\[x8, #0xf8\].*c3cf0:.*blr", "ARM GetObjectClass"),
        (r"c3d0c:.*0x92a20", "ARM class exception consumer"),
        (r"c3d7c:.*0x1455f0.*c3d84:.*0x1455c0",
         "ARM method/signature pointers"),
        (r"c3d9c:.*\[x8, #0x108\].*c3da0:.*blr", "ARM GetMethodID"),
        (r"c3dbc:.*0x92a20", "ARM method exception consumer"),
        (r"c3c78:.*\[x8, #0x110\].*c3c7c:.*blr", "ARM CallObjectMethod"),
        (r"c3c84:.*str\s+x0, \[x8\]", "ARM Signature-array publication"),
        (r"c3c9c:.*0x92a20", "ARM call exception consumer"),
        (r"c3e20:.*ldr\s+x8, \[x8\].*c3e24:.*cmp\s+x8, #0x0",
         "ARM null result check"),
        (r"c3bb8:.*\[x8, #0xb8\].*c3bbc:.*blr", "ARM DeleteLocalRef"),
        (r"c3bd8:.*ldr\s+w8, \[x8\].*c3bf0:.*cmp\s+w8, #0x0",
         "ARM incoming/final status check"),
        (r"c3e54:.*str\s+xzr, \[x8\]", "ARM nonzero-status output clear"),
        (r"c3e64:.*#0x3\b", "ARM null-input status 3"),
        (r"c3f04:.*#0x12\b.*c3fb0:.*#0x12\b",
         "ARM class/method status 18"),
        (r"c3b54:.*#0x1c\b", "ARM call/null-result status 28"),
        (r"c3b68:.*0x146a08.*c3b6c:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"c3d74:.*0x146a08.*c3d88:.*stlrb",
         "ARM signature once-lock release"),
        (r"c3fec:.*0x146a0c.*c3ff0:.*0x139800",
         "ARM method-name once-lock acquire"),
        (r"c3eec:.*0x146a0c.*c3efc:.*stlrb",
         "ARM method-name once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"b472c:.*testq\s+%rdx", "x86 SigningInfo null gate"),
        (r"b4b19:.*\*0xf8", "x86 GetObjectClass"),
        (r"b4b38:.*0x96a44", "x86 class exception consumer"),
        (r"b4bb9:.*0x13e090.*b4bc0:.*0x13e060",
         "x86 method/signature pointers"),
        (r"b4bc7:.*\*0x108", "x86 GetMethodID"),
        (r"b4bdd:.*0x96a44", "x86 method exception consumer"),
        (r"b4a98:.*\*0x110", "x86 CallObjectMethod"),
        (r"b4aa3:.*movq\s+%rax, \(%rcx\)",
         "x86 Signature-array publication"),
        (r"b4ab3:.*0x96a44", "x86 call exception consumer"),
        (r"b4c3d:.*cmpq\s+\$0x0, \(%rax\)", "x86 null result check"),
        (r"b49de:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"b4a1b:.*cmpl\s+\$0x0, \(%rax\)",
         "x86 incoming/final status check"),
        (r"b4c59:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"b4c71:.*\$0x3", "x86 null-input status 3"),
        (r"b4cdf:.*\$0x12.*b4d4d:.*\$0x12",
         "x86 class/method status 18"),
        (r"b49a1:.*\$0x1c", "x86 call/null-result status 28"),
        (r"b49ad:.*cmpxchgb.*0x13f06c", "x86 signature lock acquire"),
        (r"b4ba2:.*\$0x0.*0x13f06c", "x86 signature lock release"),
        (r"b4d7a:.*cmpxchgb.*0x13f06e", "x86 method lock acquire"),
        (r"b4cd0:.*\$0x0.*0x13f06e", "x86 method lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e210:.*x0, x23.*1e214:.*x1, x22.*1e218:.*x2.*"
        r"1e21c:.*x3.*1e220:.*0xc375c",
        "ARM status/JNIEnv/SigningInfo/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"2303f:.*%rdi.*23043:.*%rsi.*23046:.*%rdx.*"
        r"2304b:.*%rcx.*23050:.*0xb46d8",
        "x86 status/JNIEnv/SigningInfo/output forwarding",
    )
    print("cross-ABI certificate-history JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniSigningCertificateHistoryOperationsC375c",
        "runRecoveredJniSigningCertificateHistoryC375c",
        "recoveredJniSigningCertificateHistoryC375cRegression",
        '"getSigningCertificateHistory"',
        '"()[Landroid/content/pm/Signature;"',
        "operations.callObjectMethod(",
        "operations.deleteLocalRef(jniEnvironment, signingInfoClass);",
        "if (*status != 0) *outputSignatures = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI SigningInfo certificate-history reader 0xc375c regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xC375C]
    require(row["status"] == "recovered", "0xc375c recovered coverage")
    require(row["reachable"] == "yes", "0xc375c JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
