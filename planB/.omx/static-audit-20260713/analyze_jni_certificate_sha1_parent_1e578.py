#!/usr/bin/env python3
"""Prove the certificate Signature[0] -> SHA1 parent at ARM64 0x1e578."""

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
JNI_LOG = HERE / "current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log"
DYNAMIC_LOG = HERE / "current-342-46-1e578-original-dynamic-probe.log"


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


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm = objdump(ARM_SO, 0x1E578, 0x1F058)
    x86 = objdump(X86_SO, 0x2335E, 0x23D51)
    arm_caller = objdump(ARM_SO, 0xCC300, 0xCC3D0)
    x86_caller = objdump(X86_SO, 0xBB430, 0xBB4D0)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    source = SOURCE.read_text()
    jni_log = JNI_LOG.read_text(errors="replace")
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=0001e578...0001f058" in arm_frames,
            "ARM64 certificate SHA1 parent FDE")
    require("pc=0002335e...00023d51" in x86_frames,
            "x86_64 certificate SHA1 parent FDE")

    require_pattern(
        arm_caller,
        r"cc388:.*ldp\s+x2, x1.*cc38c:.*x0, sp, #0x84.*"
        r"cc390:.*w3.*cc394:.*x4.*cc398:.*0x1e578",
        "ARM caller forwards status/env/context/API/output",
    )
    require_pattern(
        x86_caller,
        r"bb46b:.*%ecx.*bb472:.*%r15, %rdi.*bb475:.*%rsi.*"
        r"bb47a:.*%rdx.*bb47f:.*%r8.*bb487:.*0x2335e",
        "x86 caller forwards status/env/context/API/output",
    )

    for pattern, description in [
        (r"1e5ac:.*x4, x29, #0xc.*1e5b0:.*x5, x29, #0x18.*"
         r"1e5ec:.*0x1dde0", "ARM certificate-array selector"),
        (r"1ef10:.*\[x29, #-0x18\].*1ef14:.*w2, wzr.*"
         r"1ef18:.*\[x8, #0x568\].*1ef1c:.*blr.*1ef28:.*0x92a20",
         "ARM Signature[0] selection and exception consume"),
        (r"1eebc:.*\[sp, #0x18\].*1eec4:.*0xc2248",
         "ARM Signature.toByteArray"),
        (r"1ec00:.*0x143000.*1ec04:.*#0x144.*1ec14:.*0xaf438",
         "ARM MessageDigest.getInstance SHA1"),
        (r"1ee1c:.*ldp\s+x2, x3, \[x29, #-0x28\].*"
         r"1ee24:.*0xb081c", "ARM MessageDigest.update forwarding"),
        (r"1edd0:.*\[x29, #-0x28\].*1edd8:.*x3, xzr.*"
         r"1ede0:.*0xb0f38", "ARM no-argument MessageDigest.digest"),
        (r"1efb4:.*\[x29, #-0x30\].*1efc4:.*0x95110",
         "ARM digest byte-array elements"),
        (r"1eac4:.*\[x29, #-0x3c\].*1ead4:.*#0x14",
         "ARM exact 20-byte length check"),
        (r"1ee58:.*\[x29, #-0x38\].*1ee6c:.*ldr\s+q0.*"
         r"1ee74:.*\[x8, #0x10\].*1ee7c:.*str\s+q0.*"
         r"1ee80:.*#0x10", "ARM 16 plus 4 byte publication"),
        (r"1ec80:.*\[x29, #-0x30\].*1ec88:.*\[sp, #0x20\].*"
         r"1ec8c:.*0x95834", "ARM element release"),
        (r"1ed14:.*#0x14\b", "ARM status 20 on digest length"),
        (r"1ed70:.*#0x1c\b", "ARM status 28 on array element"),
    ]:
        require_pattern(arm, pattern, description)

    arm_delete_blocks = re.findall(r"ldr\s+x8, \[x8, #0xb8\]", arm)
    require(len(arm_delete_blocks) == 4,
            f"ARM parent has four direct DeleteLocalRef calls: {len(arm_delete_blocks)}")
    for address, stack_offset, description in [
        ("1eb04", "0x40", "MessageDigest cleanup"),
        ("1ee98", "0x38", "certificate byte-array cleanup"),
        ("1ecd0", "0x30", "digest byte-array cleanup"),
        ("1f008", "0x28", "Signature-array cleanup"),
    ]:
        require_pattern(
            arm,
            rf"{int(address, 16) - 16:x}:.*\[sp, #{stack_offset}\].*"
            rf"{address}:.*blr",
            f"ARM {description}",
        )

    for pattern, description in [
        (r"23403:.*0x22cf9", "x86 certificate-array selector"),
        (r"23b54:.*0x80\(%rsp\).*23b5f:.*xorl\s+%edx.*"
         r"23b61:.*\*0x568.*23b6d:.*0x96a44",
         "x86 Signature[0] selection and exception consume"),
        (r"23c01:.*0x30\(%rsp\).*23c0b:.*0xb392f",
         "x86 Signature.toByteArray"),
        (r"2384d:.*0x13bb14.*23859:.*0xa87cf",
         "x86 MessageDigest.getInstance SHA1"),
        (r"23a95:.*0x70\(%rsp\).*23a9a:.*0x78\(%rsp\).*"
         r"23aa7:.*0xa91a3", "x86 MessageDigest.update forwarding"),
        (r"23a59:.*0x70\(%rsp\).*23a66:.*xorl\s+%ecx.*"
         r"23a6d:.*0xa9783", "x86 no-argument MessageDigest.digest"),
        (r"23c52:.*0x68\(%rsp\).*23c64:.*0x5c\(%rsp\).*"
         r"23c69:.*0x9811d", "x86 digest byte-array elements"),
        (r"2373d:.*\$0x14, 0x5c\(%rsp\)",
         "x86 exact 20-byte length check"),
        (r"23ad4:.*0x10\(%rdx\).*23adc:.*0x10\(%rcx\).*"
         r"23ae4:.*\(%rdx\).*23ae7:.*\(%rcx\)",
         "x86 16 plus 4 byte publication"),
        (r"238bd:.*0x68\(%rsp\).*238c7:.*0x28\(%rsp\).*"
         r"238cc:.*0x98686", "x86 element release"),
        (r"239c3:.*\$0x14", "x86 status 20 on digest length"),
        (r"239d6:.*\$0x1c", "x86 status 28 on array element"),
    ]:
        require_pattern(x86, pattern, description)

    x86_delete_blocks = re.findall(r"callq\s+\*0xb8", x86)
    require(len(x86_delete_blocks) == 4,
            f"x86 parent has four direct DeleteLocalRef calls: {len(x86_delete_blocks)}")
    print("cross-ABI certificate SHA1 call/status/publication flow: PASS")

    for token in [
        "GetObjectArrayElement(",
        "libsigner.so]0x1ef20",
        "Signature.toByteArray()[B",
        "MessageDigest.getInstance",
        'NewStringUTF("SHA1")',
        "MessageDigest$Delegate.update([B)V",
        "MessageDigest$Delegate.digest()[B",
        "GetArrayLength(",
        "=> 20) was called from RX@",
        "GetByteArrayElements(false)",
    ]:
        require(token in jni_log, f"natural JNI token {token}")

    for token in [
        "1e578 status=0->0 api=35",
        "length=20 sha1=c0cfa6f8ecb636b7d03915227b2ce6517c514ef6",
        "events=[copy20, release-elements, delete-1eb04, delete-1ee98, "
        "delete-1ecd0, delete-1f008]",
        "Tests run: 1, Failures: 0, Errors: 0, Skipped: 0",
        "BUILD SUCCESS",
    ]:
        require(token in dynamic_log, f"parent dynamic token {token}")
    print("original-SO 20-byte publication and ownership order: PASS")

    for token in [
        "RecoveredJniCertificateSha1Operations1e578",
        "runRecoveredJniCertificateSha11e578",
        "recoveredJniCertificateSha11e578Regression",
        '"SHA1"',
        '"JNI certificate SHA1 parent 0x1e578 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0x1E578]
    require(row["status"] == "recovered", "0x1e578 recovered coverage")
    require(row["reachable"] == "yes", "0x1e578 JNI-reachable classification")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
