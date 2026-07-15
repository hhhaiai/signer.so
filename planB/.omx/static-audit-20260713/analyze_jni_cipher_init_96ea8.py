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

    arm_function = body(arm_text, 0x96EA8, 0x975F0)
    x86_function = body(x86_text, 0x997A5, 0x99DE0)
    arm_caller = body(arm_text, 0xCAC40, 0xCBA84)
    x86_caller = body(x86_text, 0xBA02D, 0xBAC93)

    require("pc=00096ea8...000975f0" in arm_frames, "ARM64 FDE")
    require("pc=000997a5...00099de0" in x86_frames, "x86_64 FDE")
    require("pc=000cac40...000cba84" in arm_frames, "ARM64 caller FDE")
    require("pc=000ba02d...000bac93" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_method": (decoded(arm_blob, 0x1449EC, 5, 0x3B), b"init\0"),
        "arm_signature": (
            decoded(arm_blob, 0x144A00, 24, 0x30),
            b"(ILjava/security/Key;)V\0",
        ),
        "x86_method": (decoded(x86_blob, 0x13D48C, 5, 0x6B), b"init\0"),
        "x86_signature": (
            decoded(x86_blob, 0x13D4A0, 24, 0x14),
            b"(ILjava/security/Key;)V\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI Cipher.init(int,Key) constants: PASS")

    for pattern, description in [
        (r"96ecc:.*cmp\s+x4, #0x0.*96ed8:.*ccmp\s+x2, #0x0",
         "ARM cipher/key null gate"),
        (r"972c0:.*\[x8, #0xf8\].*972c4:.*blr", "ARM GetObjectClass"),
        (r"972d0:.*0x92a20", "ARM class exception consumer"),
        (r"9740c:.*0x1449ec.*97414:.*0x144a00",
         "ARM method/signature pointers"),
        (r"97424:.*\[x8, #0x108\].*97428:.*blr", "ARM GetMethodID"),
        (r"97438:.*0x92a20", "ARM method exception consumer"),
        (r"97598:.*\[x8, #0x1e8\].*975a4:.*blr", "ARM CallVoidMethod"),
        (r"975ac:.*0x92a20", "ARM call exception consumer"),
        (r"97560:.*\[x8, #0xb8\].*97564:.*blr", "ARM DeleteLocalRef"),
        (r"9753c:.*#0x3\b.*9754c:.*str\s+w10", "ARM null-input status 3"),
        (r"97270:.*#0x12\b.*97284:.*#0x12\b.*972ac:.*str\s+w10",
         "ARM class/method status 18"),
        (r"97324:.*#0x29\b", "ARM call-exception status 41"),
        (r"97220:.*0x14688c.*97230:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"973e4:.*0x14688c.*973f4:.*stlrb",
         "ARM signature once-lock release"),
        (r"9748c:.*0x146888.*9749c:.*0x139800",
         "ARM method-name once-lock acquire"),
        (r"97400:.*0x146888.*97418:.*stlrb",
         "ARM method-name once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"997f8:.*testq\s+%r8.*9981b:.*testq\s+%rdx",
         "x86 cipher/key null gate"),
        (r"99aa1:.*\*0xf8", "x86 GetObjectClass"),
        (r"99abd:.*0x96a44", "x86 class exception consumer"),
        (r"99bc2:.*0x13d48c.*99bc9:.*0x13d4a0",
         "x86 method/signature pointers"),
        (r"99bd0:.*\*0x108", "x86 GetMethodID"),
        (r"99be6:.*0x96a44", "x86 method exception consumer"),
        (r"99d64:.*\*0x1e8", "x86 CallVoidMethod"),
        (r"99d78:.*0x96a44", "x86 call exception consumer"),
        (r"99cf3:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"99cd1:.*\$0x3", "x86 null-input status 3"),
        (r"99a64:.*\$0x12.*99a70:.*\$0x12", "x86 class/method status 18"),
        (r"99b31:.*\$0x29", "x86 call-exception status 41"),
        (r"99a3b:.*cmpxchgb.*0x13efae", "x86 signature once-lock acquire"),
        (r"99b9c:.*\$0x0.*0x13efae", "x86 signature once-lock release"),
        (r"99c48:.*cmpxchgb.*0x13efac", "x86 method-name once-lock acquire"),
        (r"99bab:.*\$0x0.*0x13efac", "x86 method-name once-lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"cb1c4:.*#0x2\b.*cb1cc:.*x1.*cb1d0:.*x2.*"
        r"cb1d8:.*x0, x22.*cb1dc:.*x4.*cb1e0:.*0x96ea8",
        "ARM DECRYPT_MODE caller argument forwarding and edge",
    )
    require_pattern(
        x86_caller,
        r"ba41f:.*%rdi.*ba422:.*%rsi.*ba426:.*\$0x2.*"
        r"ba429:.*0x997a5",
        "x86 DECRYPT_MODE caller argument forwarding and edge",
    )
    print("cross-ABI Cipher.init JNI/status/cleanup flow: PASS")

    for required in [
        "RecoveredJniIntKeyInitOperations96ea8",
        "runRecoveredJniIntKeyInit96ea8",
        "recoveredJniIntKeyInit96ea8Regression",
        '"init", "(ILjava/security/Key;)V"',
        "operations.callVoidMethod(",
        "*status = 41;",
        "status = 0x55;",
        "status != 0x55",
        '"JNI init(int, Key) helper 0x96ea8 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0x96EA8]
    require(row["status"] == "recovered", "0x96ea8 recovered coverage")
    require(row["reachable"] == "yes", "0x96ea8 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
