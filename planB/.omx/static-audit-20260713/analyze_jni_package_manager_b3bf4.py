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

    arm_function = body(arm_text, 0xB3BF4, 0xB479C)
    x86_function = body(x86_text, 0xAB508, 0xABBD8)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000b3bf4...000b479c" in arm_frames, "ARM64 FDE")
    require("pc=000ab508...000abbd8" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames,
            "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x145140, 18, 0x42),
            b"getPackageManager\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x145160, 38, 0x03),
            b"()Landroid/content/pm/PackageManager;\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13DBE0, 18, 0xD3),
            b"getPackageManager\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13DC00, 38, 0xF2),
            b"()Landroid/content/pm/PackageManager;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI Context.getPackageManager constants: PASS")

    for pattern, description in [
        (r"b3c40:.*cmp\s+x2, #0x0", "ARM Context null gate"),
        (r"b463c:.*\[x8, #0xf8\].*b4640:.*blr",
         "ARM GetObjectClass"),
        (r"b465c:.*0x92a20", "ARM class exception consumer"),
        (r"b431c:.*0x145140.*b4324:.*0x145160",
         "ARM method/signature pointers"),
        (r"b433c:.*\[x8, #0x108\].*b4340:.*blr",
         "ARM GetMethodID"),
        (r"b435c:.*0x92a20", "ARM method exception consumer"),
        (r"b4504:.*\[x8, #0x110\].*b4508:.*blr",
         "ARM CallObjectMethod"),
        (r"b4510:.*str\s+x0, \[x8\]", "ARM PackageManager publication"),
        (r"b4528:.*0x92a20", "ARM call exception consumer"),
        (r"b4244:.*\[x8, #0xb8\].*b4248:.*blr",
         "ARM DeleteLocalRef"),
        (r"b41ec:.*#0x3\b", "ARM null-input status 3"),
        (r"b4770:.*#0x12\b", "ARM failure status 18"),
        (r"b4034:.*ldr\s+x8, \[x8\].*b403c:.*cmp\s+x8, #0x0",
         "ARM null PackageManager result check"),
        (r"b420c:.*str\s+xzr, \[x8\]", "ARM output clearing"),
        (r"b4264:.*ldr\s+w8, \[x8\].*b427c:.*cmp\s+w8, #0x0",
         "ARM final status check"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"ab566:.*testq\s+%rdx", "x86 Context null gate"),
        (r"abb0b:.*\*0xf8", "x86 GetObjectClass"),
        (r"abb21:.*0x96a44", "x86 class exception consumer"),
        (r"ab91e:.*0x13dbe0.*ab925:.*0x13dc00",
         "x86 method/signature pointers"),
        (r"ab92c:.*\*0x108", "x86 GetMethodID"),
        (r"ab942:.*0x96a44", "x86 method exception consumer"),
        (r"aba47:.*\*0x110", "x86 CallObjectMethod"),
        (r"aba52:.*movq\s+%rax, \(%rcx\)",
         "x86 PackageManager publication"),
        (r"aba62:.*0x96a44", "x86 call exception consumer"),
        (r"ab896:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"ab846:.*\$0x3", "x86 null-input status 3"),
        (r"ab9b7:.*\$0x12.*abba1:.*\$0x12",
         "x86 failure status 18"),
        (r"ab7d8:.*cmpq\s+\$0x0, \(%rax\)",
         "x86 null PackageManager result check"),
        (r"ab859:.*andq\s+\$0x0, \(%rax\)", "x86 output clearing"),
        (r"ab8e7:.*cmpl\s+\$0x0, \(%rax\)", "x86 final status check"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e408:.*x3.*1e40c:.*x0, x23.*1e410:.*x1, x22.*"
        r"1e414:.*x2.*1e418:.*0xb3bf4",
        "ARM status/JNIEnv/Context/output forwarding",
    )
    require_pattern(
        x86_caller,
        r"231f4:.*%r13.*231f8:.*%r13, %rdi.*231fb:.*%r12, %rsi.*"
        r"231fe:.*%rdx.*23203:.*%rcx.*23208:.*0xab508",
        "x86 status/JNIEnv/Context/output forwarding",
    )
    print("cross-ABI getPackageManager JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniPackageManagerOperationsB3bf4",
        "runRecoveredJniPackageManagerB3bf4",
        "recoveredJniPackageManagerB3bf4Regression",
        '"getPackageManager"',
        '"()Landroid/content/pm/PackageManager;"',
        "operations.callObjectMethod(",
        "operations.deleteLocalRef(jniEnvironment, contextClass);",
        "if (*status != 0) *outputPackageManager = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        '"JNI Context.getPackageManager reader 0xb3bf4 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xB3BF4]
    require(row["status"] == "recovered", "0xb3bf4 recovered coverage")
    require(row["reachable"] == "yes", "0xb3bf4 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
