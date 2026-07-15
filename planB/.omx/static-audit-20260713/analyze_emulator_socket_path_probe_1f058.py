#!/usr/bin/env python3
"""Prove the QEMU/Genymotion socket-path probe at ARM64 0x1f058."""

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
DYNAMIC_LOG = HERE / "current-344-44-1f058-original-dynamic.log"


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
    arm = objdump(ARM_SO, 0x1F058, 0x1F95C)
    x86 = objdump(X86_SO, 0x23D51, 0x2422E)
    arm_caller = objdump(ARM_SO, 0xFA80, 0xFAD0)
    x86_caller = objdump(X86_SO, 0x136F0, 0x13740)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=0001f058...0001f95c" in arm_frames,
            "ARM64 emulator socket-path probe FDE")
    require("pc=00023d51...0002422e" in x86_frames,
            "x86_64 emulator socket-path probe FDE")

    expected_paths = [
        b"/dev/socket/qemud\0",
        b"/dev/qemu_pipe\0",
        b"/dev/socket/genyd\0",
        b"/dev/socket/baseband_genyd\0",
    ]
    arm_constants = [
        decoded(arm_blob, 0x143150, 18, 0xDD),
        decoded(arm_blob, 0x143168, 15, 0x03),
        decoded(arm_blob, 0x143180, 18, 0x3D),
        decoded(arm_blob, 0x1431A0, 27, 0x4D),
    ]
    x86_constants = [
        decoded(x86_blob, 0x13BB20, 18, 0x0D),
        decoded(x86_blob, 0x13BB38, 15, 0x5A),
        decoded(x86_blob, 0x13BB50, 18, 0xF9),
        decoded(x86_blob, 0x13BB70, 27, 0xA9),
    ]
    require(arm_constants == expected_paths,
            f"ARM64 decoded emulator paths: {arm_constants!r}")
    require(x86_constants == expected_paths,
            f"x86_64 decoded emulator paths: {x86_constants!r}")
    print("cross-ABI QEMU/Genymotion socket paths: PASS")

    require_pattern(
        arm,
        r"1f8e0:.*0x146000.*1f8ec:.*#0x738.*"
        r"1f8f4:.*#0x2.*1f908:.*stp\s+x8, x26, \[x0\].*"
        r"1f918:.*str\s+x8, \[x19, #0x10\]!.*"
        r"1f924:.*str\s+x8, \[x0, #0x18\].*"
        r"1f928:.*bl\s+0x1f95c.*1f92c:.*x0, x19.*"
        r"1f934:.*w1, #0x2.*1f958:.*b\s+0x1f95c",
        "ARM four-pointer table and two two-path counter calls",
    )
    require_pattern(
        x86,
        r"241b9:.*0x13bb20.*241c0:.*0x13ebc0.*"
        r"241ce:.*0x13bb38.*241d5:.*0x13ebc8.*"
        r"241dc:.*0x13bb50.*241e3:.*0x13ebd0.*"
        r"241f1:.*0x13bb70.*241f8:.*0x13ebd8.*"
        r"24203:.*%r15, %rsi.*2420d:.*0x2422e.*"
        r"24212:.*%r14, %rdi.*24229:.*0x2422e",
        "x86 four-pointer table and two two-path counter calls",
    )
    print("cross-ABI two-group path-counter orchestration: PASS")

    require_pattern(
        arm_caller,
        r"faa4:.*x0, sp, #0x34.*faa8:.*0x1f058.*"
        r"faac:.*ldrh\s+w8, \[sp, #0x34\].*fabc:.*w8, #0x0",
        "ARM environment stage consumes nonzero uint16 count",
    )
    require_pattern(
        x86_caller,
        r"1370a:.*0x36\(%rsp\), %rdi.*1370f:.*0x23d51.*"
        r"13714:.*\$0x0, 0x36\(%rsp\)",
        "x86 environment stage consumes nonzero uint16 count",
    )
    print("cross-ABI environment correction-0x01 caller gate: PASS")

    for token in [
        "1f058 entries=1 count=0->0->0 groups=[2,2]",
        "paths=[/dev/socket/qemud, /dev/qemu_pipe, /dev/socket/genyd, "
        "/dev/socket/baseband_genyd]",
        "Tests run: 1, Failures: 0, Errors: 0, Skipped: 0",
        "BUILD SUCCESS",
    ]:
        require(token in dynamic_log, f"original-SO dynamic token {token}")
    print("original-SO two-group path observation: PASS")

    for token in [
        "runRecoveredEmulatorSocketPathProbe1f058",
        "recoveredEmulatorSocketPathProbe1f058Regression",
        '"/dev/socket/qemud"',
        '"/dev/qemu_pipe"',
        '"/dev/socket/genyd"',
        '"/dev/socket/baseband_genyd"',
        '"emulator socket-path probe 0x1f058 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0x1F058]
    require(row["status"] == "recovered", "0x1f058 recovered coverage")
    require(row["reachable"] == "yes", "0x1f058 JNI-reachable classification")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
