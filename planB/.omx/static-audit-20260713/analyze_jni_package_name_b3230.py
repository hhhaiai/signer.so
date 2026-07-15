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

    arm_function = body(arm_text, 0xB3230, 0xB3BF4)
    x86_function = body(x86_text, 0xAAE64, 0xAB508)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000b3230...000b3bf4" in arm_frames, "ARM64 FDE")
    require("pc=000aae64...000ab508" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames,
            "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x145128, 15, 0xF5),
            b"getPackageName\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x144AF0, 21, 0x47),
            b"()Ljava/lang/String;\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13DBC8, 15, 0x81),
            b"getPackageName\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13D590, 21, 0x2A),
            b"()Ljava/lang/String;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI Context.getPackageName constants: PASS")

    for pattern, description in [
        (r"b32e4:.*cmp\s+x2, #0x0", "ARM Context null gate"),
        (r"b3778:.*\[x8, #0xf8\].*b377c:.*blr",
         "ARM GetObjectClass"),
        (r"b3798:.*0x92a20", "ARM class exception consumer"),
        (r"b3a2c:.*0x145128.*b3a34:.*0x144af0",
         "ARM method/signature pointers"),
        (r"b3a4c:.*\[x8, #0x108\].*b3a50:.*blr",
         "ARM GetMethodID"),
        (r"b3a6c:.*0x92a20", "ARM method exception consumer"),
        (r"b3924:.*\[x8, #0x110\].*b3928:.*blr",
         "ARM CallObjectMethod"),
        (r"b3930:.*str\s+x0, \[x8\]", "ARM String publication"),
        (r"b3948:.*0x92a20", "ARM call exception consumer"),
        (r"b3b38:.*ldr\s+x8, \[x8\].*b3b40:.*cmp\s+x8, #0x0",
         "ARM null result check"),
        (r"b39c4:.*\[x8, #0xb8\].*b39c8:.*blr",
         "ARM DeleteLocalRef"),
        (r"b39e4:.*ldr\s+w8, \[x8\].*b3a04:.*cmp\s+w8, #0x0",
         "ARM incoming/final status check"),
        (r"b3af0:.*str\s+xzr, \[x8\]",
         "ARM nonzero-status output clear"),
        (r"b375c:.*#0x3\b", "ARM null-input status 3"),
        (r"b3630:.*#0x12\b.*b3ba8:.*#0x12\b",
         "ARM class/method status 18"),
        (r"b3628:.*#0x1c\b", "ARM call/null-result status 28"),
        (r"b36e4:.*0x1468b8.*b36e8:.*0x139800",
         "ARM method-name once-lock acquire"),
        (r"b3a24:.*0x1468b8.*b3a38:.*stlrb",
         "ARM method-name once-lock release"),
        (r"b3838:.*0x146978.*b383c:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"b3b20:.*0x146978.*b3b30:.*stlrb",
         "ARM signature once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"aaeae:.*testq\s+%rdx", "x86 Context null gate"),
        (r"ab1e3:.*\*0xf8", "x86 GetObjectClass"),
        (r"ab1fc:.*0x96a44", "x86 class exception consumer"),
        (r"ab3c7:.*0x13dbc8.*ab3ce:.*0x13d590",
         "x86 method/signature pointers"),
        (r"ab3d5:.*\*0x108", "x86 GetMethodID"),
        (r"ab3eb:.*0x96a44", "x86 method exception consumer"),
        (r"ab2e8:.*\*0x110", "x86 CallObjectMethod"),
        (r"ab2f3:.*movq\s+%rax, \(%rcx\)",
         "x86 String publication"),
        (r"ab303:.*0x96a44", "x86 call exception consumer"),
        (r"ab46c:.*cmpq\s+\$0x0, \(%rax\)", "x86 null result check"),
        (r"ab35c:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"ab38f:.*cmpl\s+\$0x0, \(%rax\)",
         "x86 incoming/final status check"),
        (r"ab432:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"ab1c4:.*\$0x3", "x86 null-input status 3"),
        (r"ab12d:.*\$0x12.*ab4d1:.*\$0x12",
         "x86 class/method status 18"),
        (r"ab129:.*\$0x1c", "x86 call/null-result status 28"),
        (r"ab19b:.*cmpxchgb.*0x13efc4",
         "x86 method-name lock acquire"),
        (r"ab3af:.*\$0x0.*0x13efc4",
         "x86 method-name lock release"),
        (r"ab26b:.*cmpxchgb.*0x13f024",
         "x86 signature lock acquire"),
        (r"ab45d:.*\$0x0.*0x13f024",
         "x86 signature lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1de1c:.*x3.*1de24:.*x22, x1.*1de2c:.*x23, x0.*"
        r"1de40:.*x2.*1de44:.*0xb3230",
        "ARM status/JNIEnv/Context/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"22d14:.*%rsi, %r12.*22d17:.*%rdi, %rbx.*"
        r"22d46:.*%rcx.*22d6a:.*%rdx.*22d6f:.*0xaae64",
        "x86 status/JNIEnv/Context/output forwarding",
    )
    print("cross-ABI getPackageName JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniPackageNameOperationsB3230",
        "runRecoveredJniPackageNameB3230",
        "recoveredJniPackageNameB3230Regression",
        '"getPackageName"',
        '"()Ljava/lang/String;"',
        "operations.callObjectMethod(",
        "operations.deleteLocalRef(jniEnvironment, contextClass);",
        "if (*status != 0) *outputPackageName = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI Context.getPackageName reader 0xb3230 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xB3230]
    require(row["status"] == "recovered", "0xb3230 recovered coverage")
    require(row["reachable"] == "yes", "0xb3230 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
