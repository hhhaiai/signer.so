#!/usr/bin/env python3
"""Prove MessageDigest.getInstance(String) at ARM64 0xaf438."""

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
    arm = objdump(ARM_SO, 0xAF438, 0xB081C)
    x86 = objdump(X86_SO, 0xA87CF, 0xA91A3)
    arm_caller = objdump(ARM_SO, 0x1E578, 0x1F058)
    x86_caller = objdump(X86_SO, 0x2335E, 0x23D51)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=000af438...000b081c" in arm_frames,
            "ARM64 getInstance FDE")
    require("pc=000a87cf...000a91a3" in x86_frames,
            "x86_64 getInstance FDE")

    constants = {
        "arm_class": (
            decoded(arm_blob, 0x145090, 28, 0xEA),
            b"java/security/MessageDigest\0",
        ),
        "arm_method": (
            decoded(arm_blob, 0x1449A8, 12, 0x1E), b"getInstance\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x1450B0, 50, 0x38),
            b"(Ljava/lang/String;)Ljava/security/MessageDigest;\0",
        ),
        "arm_algorithm": (
            decoded(arm_blob, 0x143144, 5, 0xDC), b"SHA1\0",
        ),
        "x86_class": (
            decoded(x86_blob, 0x13DB30, 28, 0xE7),
            b"java/security/MessageDigest\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13D448, 12, 0xCA), b"getInstance\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13DB50, 50, 0x6B),
            b"(Ljava/lang/String;)Ljava/security/MessageDigest;\0",
        ),
        "x86_algorithm": (
            decoded(x86_blob, 0x13BB14, 5, 0x38), b"SHA1\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI MessageDigest/getInstance/SHA1 constants: PASS")

    for pattern, description in [
        (r"af488:.*str\s+x2, \[sp\].*af48c:.*cmp\s+x2, #0x0",
         "ARM null algorithm gate"),
        (r"b02b0:.*0x145090.*b02c4:.*\[x8, #0x30\].*b02c8:.*blr.*"
         r"b02e4:.*0x92a20", "ARM FindClass and exception consume"),
        (r"afe74:.*0x1449a8.*afe7c:.*0x1450b0.*"
         r"afe94:.*\[x8, #0x388\].*afe98:.*blr.*afeb4:.*0x92a20",
         "ARM GetStaticMethodID and exception consume"),
        (r"b0158:.*ldr\s+x1, \[sp\].*b0164:.*\[x8, #0x538\].*"
         r"b0168:.*blr.*b0184:.*0x92a20",
         "ARM NewStringUTF and exception consume"),
        (r"b0430:.*x3, x23.*b0434:.*\[sp, #0x28\].*"
         r"b0438:.*\[sp, #0x18\].*b0444:.*\[x8, #0x390\].*"
         r"b0448:.*blr.*b044c:.*\[sp, #0x20\].*b0450:.*str\s+x0.*"
         r"b0468:.*0x92a20", "ARM call, publication and exception consume"),
        (r"afff8:.*#0x3\b.*b000c:.*str\s+w11", "ARM status 3"),
        (r"b0130:.*#0x12\b.*b07cc:.*#0x12\b", "ARM status 18"),
        (r"af998:.*#0x1b\b", "ARM NewStringUTF status 27"),
        (r"afac4:.*#0x1c\b", "ARM call status 28"),
        (r"afb2c:.*\[sp, #0x28\].*\[x8, #0xb8\].*afb3c:.*blr",
         "ARM MessageDigest class cleanup block"),
        (r"b0014:.*\[sp, #0x8\].*\[x8, #0xb8\].*b0024:.*blr",
         "ARM Java String cleanup block"),
        (r"afcc0:.*\[sp, #0x30\].*ldr\s+w8, \[x8\].*"
         r"b057c:.*\[sp, #0x20\].*str\s+xzr",
         "ARM incoming-status output clear"),
    ]:
        require_pattern(arm, pattern, description)

    for pattern, description in [
        (r"a881e:.*%rdx, 0x40\(%rsp\).*a8823:.*testq\s+%rdx",
         "x86 null algorithm gate"),
        (r"a8f65:.*0x13db30.*a8f6c:.*\*0x30.*a8f85:.*0x96a44",
         "x86 FindClass and exception consume"),
        (r"a8dcc:.*0x30\(%rsp\).*a8dd1:.*0x13d448.*"
         r"a8dd8:.*0x13db50.*a8ddf:.*\*0x388.*a8df5:.*0x96a44",
         "x86 GetStaticMethodID and exception consume"),
        (r"a8edf:.*0x40\(%rsp\).*a8ee4:.*\*0x538.*a8efa:.*0x96a44",
         "x86 NewStringUTF and exception consume"),
        (r"a9006:.*0x30\(%rsp\).*a900b:.*0x50\(%rsp\).*"
         r"a9010:.*0x10\(%rsp\).*a9017:.*\*0x390.*"
         r"a9023:.*\(%rcx\).*a9033:.*0x96a44",
         "x86 call, publication and exception consume"),
        (r"a8e52:.*\$0x3", "x86 status 3"),
        (r"a8ec4:.*\$0x12.*a9169:.*\$0x12", "x86 status 18"),
        (r"a8bc1:.*\$0x1b", "x86 NewStringUTF status 27"),
        (r"a8bfa:.*\$0x1c", "x86 call status 28"),
        (r"a8c55:.*0x30\(%rsp\).*a8c5a:.*\*0xb8",
         "x86 MessageDigest class cleanup block"),
        (r"a8e72:.*0x48\(%rsp\).*a8e77:.*\*0xb8",
         "x86 Java String cleanup block"),
        (r"a8d3b:.*0x18\(%rsp\).*cmpl\s+\$0x0.*"
         r"a9085:.*0x28\(%rsp\).*andq\s+\$0x0",
         "x86 incoming-status output clear"),
    ]:
        require_pattern(x86, pattern, description)
    print("cross-ABI getInstance JNI/status/ownership: PASS")

    require_pattern(
        arm_caller,
        r"1eb20:.*#0x144.*1eb24:.*#0xdc.*"
        r"1ec00:.*0x143000.*1ec04:.*#0x144.*1ec14:.*0xaf438",
        "ARM parent decodes and forwards SHA1",
    )
    require_pattern(
        x86_caller,
        r"237b8:.*0x38383838.*13bb14.*237c2:.*\$0x38.*"
        r"2384d:.*0x13bb14.*23859:.*0xa87cf",
        "x86 parent decodes and forwards SHA1",
    )
    print("cross-ABI parent SHA1 forwarding: PASS")

    for token in [
        "FindClass(java/security/MessageDigest)",
        "MessageDigest.getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;",
        'NewStringUTF("SHA1")',
        'getInstance("SHA1") => java.security.MessageDigest$Delegate',
        "libsigner.so]0xb02cc",
        "libsigner.so]0xafe9c",
        "libsigner.so]0xb016c",
        "libsigner.so]0xb044c",
    ]:
        require(token in dynamic_log, f"original-SO observation token {token}")
    print("original-SO MessageDigest.getInstance natural path: PASS")

    for token in [
        "RecoveredJniMessageDigestGetInstanceOperationsAf438",
        "runRecoveredJniMessageDigestGetInstanceAf438",
        "recoveredJniMessageDigestGetInstanceAf438Regression",
        '"java/security/MessageDigest"',
        '"getInstance"',
        '"(Ljava/lang/String;)Ljava/security/MessageDigest;"',
        '"JNI MessageDigest.getInstance helper 0xaf438 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0xAF438]
    require(row["status"] == "recovered", "0xaf438 recovered coverage")
    require(row["reachable"] == "yes", "0xaf438 JNI-reachable classification")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
