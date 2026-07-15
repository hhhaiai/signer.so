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

    arm_function = body(arm_text, 0xC4064, 0xC4AE4)
    x86_function = body(x86_text, 0xB4DAD, 0xB5413)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000c4064...000c4ae4" in arm_frames, "ARM64 FDE")
    require("pc=000b4dad...000b5413" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames,
            "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x145610, 19, 0xDF),
            b"hasMultipleSigners\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x145624, 4, 0x0F),
            b"()Z\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13E0B0, 19, 0xA0),
            b"hasMultipleSigners\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13E0C4, 4, 0xDE),
            b"()Z\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI SigningInfo.hasMultipleSigners constants: PASS")

    for pattern, description in [
        (r"c40a0:.*cmp\s+x2, #0x0", "ARM SigningInfo null gate"),
        (r"c4568:.*\[x8, #0xf8\].*c456c:.*blr",
         "ARM GetObjectClass"),
        (r"c4588:.*0x92a20", "ARM class exception consumer"),
        (r"c4458:.*0x145610.*c4460:.*0x145624",
         "ARM method/signature pointers"),
        (r"c4478:.*\[x8, #0x108\].*c447c:.*blr",
         "ARM GetMethodID"),
        (r"c4498:.*0x92a20", "ARM method exception consumer"),
        (r"c46d0:.*\[x8, #0x128\].*c46d4:.*blr",
         "ARM CallBooleanMethod"),
        (r"c46dc:.*strb\s+w0, \[x8\]", "ARM boolean publication"),
        (r"c46f4:.*0x92a20", "ARM call exception consumer"),
        (r"c48f0:.*\[x8, #0xb8\].*c48f4:.*blr",
         "ARM DeleteLocalRef"),
        (r"c46b4:.*#0x3\b", "ARM null-input status 3"),
        (r"c464c:.*#0x12\b.*c4674:.*#0x12\b",
         "ARM class/method status 18"),
        (r"c48c8:.*#0x1c\b", "ARM call-exception status 28"),
        (r"c4668:.*strb\s+wzr, \[x8\]", "ARM output clearing"),
        (r"c4910:.*ldr\s+w8, \[x8\].*c4974:.*cmp\s+w8, #0x0",
         "ARM final status check"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"b4df7:.*testq\s+%rdx", "x86 SigningInfo null gate"),
        (r"b5114:.*\*0xf8", "x86 GetObjectClass"),
        (r"b5120:.*0x96a44", "x86 class exception consumer"),
        (r"b5074:.*0x13e0b0.*b507b:.*0x13e0c4",
         "x86 method/signature pointers"),
        (r"b5082:.*\*0x108", "x86 GetMethodID"),
        (r"b508e:.*0x96a44", "x86 method exception consumer"),
        (r"b5245:.*\*0x128", "x86 CallBooleanMethod"),
        (r"b5250:.*movb\s+%al, \(%rcx\)", "x86 boolean publication"),
        (r"b5255:.*0x96a44", "x86 call exception consumer"),
        (r"b5351:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"b5220:.*\$0x3", "x86 null-input status 3"),
        (r"b51ac:.*\$0x12.*b51cf:.*\$0x12",
         "x86 class/method status 18"),
        (r"b532e:.*\$0x1c", "x86 call-exception status 28"),
        (r"b51b8:.*movb\s+\$0x0, \(%rax\)", "x86 output clearing"),
        (r"b53a2:.*cmpl\s+\$0x0, \(%rax\)", "x86 final status check"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e1dc:.*x2.*1e1e0:.*x0, x23.*1e1e4:.*x1, x22.*"
        r"1e1e8:.*x3.*1e1ec:.*0xc4064",
        "ARM status/JNIEnv/SigningInfo/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"23001:.*%rdx.*23006:.*%r13.*2300a:.*%r13, %rdi.*"
        r"2300d:.*%r12, %rsi.*23010:.*%rcx.*23015:.*0xb4dad",
        "x86 status/JNIEnv/SigningInfo/output forwarding",
    )
    print("cross-ABI hasMultipleSigners JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniNoArgBooleanMethodOperationsC4064",
        "runRecoveredJniHasMultipleSignersC4064",
        "recoveredJniHasMultipleSignersC4064Regression",
        '"hasMultipleSigners"',
        '"()Z"',
        "operations.callBooleanMethod(",
        "operations.deleteLocalRef(jniEnvironment, signingInfoClass);",
        "if (*status != 0) *outputHasMultipleSigners = 0;",
        "state.booleanResult = 0;",
        "status = 0x55;",
        "state.exceptions[2] = 1;",
        '"JNI SigningInfo.hasMultipleSigners reader 0xc4064 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xC4064]
    require(row["status"] == "recovered", "0xc4064 recovered coverage")
    require(row["reachable"] == "yes", "0xc4064 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
