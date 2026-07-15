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

    arm_function = body(arm_text, 0xB081C, 0xB0F38)
    x86_function = body(x86_text, 0xA91A3, 0xA9783)
    arm_caller = body(arm_text, 0x1E578, 0x1F058)
    x86_caller = body(x86_text, 0x2335E, 0x23D51)

    require("pc=000b081c...000b0f38" in arm_frames, "ARM64 FDE")
    require("pc=000a91a3...000a9783" in x86_frames, "x86_64 FDE")
    require("pc=0001e578...0001f058" in arm_frames, "ARM64 caller FDE")
    require("pc=0002335e...00023d51" in x86_frames, "x86_64 caller FDE")

    constants = {
        "arm_method": (decoded(arm_blob, 0x145048, 7, 0xA5), b"update\0"),
        "arm_signature": (decoded(arm_blob, 0x145050, 6, 0x7B), b"([B)V\0"),
        "x86_method": (decoded(x86_blob, 0x13DAE8, 7, 0x55), b"update\0"),
        "x86_signature": (decoded(x86_blob, 0x13DAF0, 6, 0x5E), b"([B)V\0"),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI update([B)V constants: PASS")

    for pattern, description in [
        (r"b083c:.*cmp\s+x3, #0x0.*b0850:.*ccmp\s+x2, #0x0",
         "ARM object/byte-array null gate"),
        (r"b0ba4:.*\[x8, #0xf8\].*b0ba8:.*blr", "ARM GetObjectClass"),
        (r"b0bb8:.*0x92a20", "ARM class exception consumer"),
        (r"b0e18:.*0x145048.*b0e20:.*0x145050",
         "ARM method/signature pointers"),
        (r"b0e30:.*\[x8, #0x108\].*b0e34:.*blr", "ARM GetMethodID"),
        (r"b0e40:.*0x92a20", "ARM method exception consumer"),
        (r"b0e9c:.*\[x8, #0x1e8\].*b0ea4:.*blr", "ARM CallVoidMethod"),
        (r"b0eac:.*0x92a20", "ARM call exception consumer"),
        (r"b0d00:.*\[x8, #0xb8\].*b0d04:.*blr", "ARM DeleteLocalRef"),
        (r"b0ec4:.*#0x3\b.*b0ed4:.*str\s+w10", "ARM null-input status 3"),
        (r"b0de0:.*#0x12\b.*b0edc:.*#0x12\b",
         "ARM class/method status 18"),
        (r"b0c20:.*#0x1c\b", "ARM call-exception status 28"),
        (r"b0b68:.*0x146954.*b0b78:.*0x139800",
         "ARM signature once-lock acquire"),
        (r"b0d1c:.*0x146950.*b0d2c:.*0x139800",
         "ARM method-name once-lock acquire"),
        (r"b0e0c:.*0x146950.*b0e24:.*stlrb",
         "ARM method-name once-lock release"),
        (r"b0f00:.*0x146954.*b0f10:.*stlrb",
         "ARM signature once-lock release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"a91e8:.*testq\s+%rcx", "x86 byte-array null gate"),
        (r"a9456:.*\*0xf8", "x86 GetObjectClass"),
        (r"a946f:.*0x96a44", "x86 class exception consumer"),
        (r"a9664:.*0x13dae8.*a966b:.*0x13daf0",
         "x86 method/signature pointers"),
        (r"a9672:.*\*0x108", "x86 GetMethodID"),
        (r"a9688:.*0x96a44", "x86 method exception consumer"),
        (r"a96dc:.*\*0x1e8", "x86 CallVoidMethod"),
        (r"a96f0:.*0x96a44", "x86 call exception consumer"),
        (r"a9585:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"a970f:.*\$0x3", "x86 null-input status 3"),
        (r"a962b:.*\$0x12.*a974f:.*\$0x12",
         "x86 class/method status 18"),
        (r"a94fd:.*\$0x1c", "x86 call-exception status 28"),
        (r"a9423:.*cmpxchgb.*0x13f012", "x86 signature once-lock acquire"),
        (r"a95cf:.*cmpxchgb.*0x13f010", "x86 method-name once-lock acquire"),
        (r"a964c:.*\$0x0.*0x13f010", "x86 method-name once-lock release"),
        (r"a9765:.*\$0x0.*0x13f012", "x86 signature once-lock release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1ee18:.*mov\s+x1, x20.*1ee1c:.*ldp\s+x2, x3.*"
        r"1ee20:.*mov\s+x0, x23.*1ee24:.*0xb081c",
        "ARM caller argument forwarding and edge",
    )
    require_pattern(
        x86_caller,
        r"23a95:.*%rdx.*23a9a:.*%rcx.*23a9f:.*%rdi.*"
        r"23aa2:.*%rsi.*23aa7:.*0xa91a3",
        "x86 caller argument forwarding and edge",
    )
    print("cross-ABI update JNI/status/cleanup flow: PASS")

    for required in [
        "RecoveredJniByteArrayUpdateOperationsB081c",
        "runRecoveredJniByteArrayUpdateB081c",
        "recoveredJniByteArrayUpdateB081cRegression",
        '"update", "([B)V"',
        "operations.callVoidMethod(",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "status = 0x55;",
        "status != 0x55",
        "state.exceptions[2] = 1;",
        '"JNI update([B)V helper 0xb081c regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xB081C]
    require(row["status"] == "recovered", "0xb081c recovered coverage")
    require(row["reachable"] == "yes", "0xb081c JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
