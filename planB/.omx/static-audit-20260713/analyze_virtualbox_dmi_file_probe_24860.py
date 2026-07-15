#!/usr/bin/env python3
"""Prove the VirtualBox DMI file-content probe at ARM64 0x24860."""

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
DYNAMIC_LOG = HERE / "current-345-43-24860-original-dynamic.log"


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
    arm = objdump(ARM_SO, 0x24860, 0x25068)
    x86 = objdump(X86_SO, 0x27397, 0x278F6)
    arm_caller = objdump(ARM_SO, 0xFBC0, 0xFC08)
    x86_caller = objdump(X86_SO, 0x13830, 0x13875)
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = X86_FRAMES.read_text(errors="replace")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()
    dynamic_log = DYNAMIC_LOG.read_text(errors="replace")

    require("pc=00024860...00025068" in arm_frames,
            "ARM64 VirtualBox DMI probe FDE")
    require("pc=00027397...000278f6" in x86_frames,
            "x86_64 VirtualBox DMI probe FDE")

    expected = [
        b"/sys/devices/virtual/dmi/id/product_name\0",
        b"VirtualBox\0",
        b"/sys/devices/virtual/dmi/id/sys_vendor\0",
        b"innotek\0",
    ]
    arm_constants = [
        decoded(arm_blob, 0x143440, 41, 0x6B),
        decoded(arm_blob, 0x143470, 11, 0xBA),
        decoded(arm_blob, 0x143480, 39, 0xDF),
        decoded(arm_blob, 0x1434A8, 8, 0x40),
    ]
    x86_constants = [
        decoded(x86_blob, 0x13BE10, 41, 0x42),
        decoded(x86_blob, 0x13BE40, 11, 0x72),
        decoded(x86_blob, 0x13BE50, 39, 0xEB),
        decoded(x86_blob, 0x13BE78, 8, 0x88),
    ]
    require(arm_constants == expected,
            f"ARM64 VirtualBox DMI constants: {arm_constants!r}")
    require(x86_constants == expected,
            f"x86 VirtualBox DMI constants: {x86_constants!r}")
    print("cross-ABI VirtualBox DMI paths and markers: PASS")

    require_pattern(
        arm,
        r"24fd8:.*x8, sp.*24fdc:.*x0, x8, #0x200.*"
        r"24fe8:.*#0x440.*24ff0:.*#0x470.*"
        r"24ff4:.*w9, #0x3.*24ff8:.*w1, #0x2.*"
        r"25000:.*stp\s+x11, x10, \[x0\].*"
        r"25010:.*str\s+w9, \[x0, #0xa8\].*"
        r"25014:.*str\s+x10, \[x0, #0xf8\].*"
        r"25018:.*stp\s+x22, x11, \[x8, #-0x100\].*"
        r"2501c:.*stur\s+w9, \[x8, #-0x58\].*"
        r"25020:.*stur\s+x10, \[x8, #-0x8\].*"
        r"25024:.*bl\s+0x23274",
        "ARM two 0x100 records with kind 3/count 1 and readable-file batch",
    )
    require_pattern(
        x86,
        r"27868:.*%rsp, %rax.*2786b:.*-0x200\(%rax\), %rdi.*"
        r"27875:.*0x13be10.*2787c:.*-0x200\(%rax\).*"
        r"27883:.*0x13be40.*2788a:.*-0x1f8\(%rax\).*"
        r"27894:.*-0x158\(%rax\).*2789d:.*-0x108\(%rax\).*"
        r"278a4:.*0x13be50.*278ab:.*-0x100\(%rax\).*"
        r"278b2:.*0x13be78.*278b9:.*-0xf8\(%rax\).*"
        r"278c0:.*-0x58\(%rax\).*278c3:.*-0x8\(%rax\).*"
        r"278c7:.*\$0x2.*278ce:.*0x26286",
        "x86 two 0x100 records with kind 3/count 1 and readable-file batch",
    )
    print("cross-ABI two-record kind-3 readable-file orchestration: PASS")

    require_pattern(
        arm_caller,
        r"fbcc:.*x0, sp, #0x34.*fbd0:.*strh\s+wzr.*"
        r"fbd4:.*0x24860.*fbd8:.*ldrh\s+w8.*fbe8:.*w8, #0x0",
        "ARM flattened caller zeroes and consumes uint16 count",
    )
    require_pattern(
        x86_caller,
        r"13840:.*andw\s+\$0x0, 0x36\(%rsp\).*"
        r"13846:.*0x36\(%rsp\), %rdi.*1384b:.*0x27397.*"
        r"13850:.*\$0x0, 0x36\(%rsp\)",
        "x86 flattened caller zeroes and consumes uint16 count",
    )
    print("cross-ABI flattened caller count flow: PASS")

    for token in [
        "24860 entries=1 count=0->0 records=2",
        "paths=[/sys/devices/virtual/dmi/id/product_name, "
        "/sys/devices/virtual/dmi/id/sys_vendor]",
        "markers=[VirtualBox, innotek]",
        "kinds=[3, 3] descriptorCounts=[1, 1]",
        "Tests run: 1, Failures: 0, Errors: 0, Skipped: 0",
        "BUILD SUCCESS",
    ]:
        require(token in dynamic_log, f"original-SO dynamic token {token}")
    print("original-SO direct two-record observation: PASS")

    for token in [
        "runRecoveredVirtualBoxDmiFileProbe24860",
        "recoveredVirtualBoxDmiFileProbe24860Regression",
        '"/sys/devices/virtual/dmi/id/product_name"',
        '"VirtualBox"',
        '"/sys/devices/virtual/dmi/id/sys_vendor"',
        '"innotek"',
        '"VirtualBox DMI file probe 0x24860 regression failed',
    ]:
        require(token in source, f"C++ source token {token}")

    row = inventory_rows()[0x24860]
    require(row["status"] == "recovered", "0x24860 recovered coverage")
    require(row["reachable"] == "yes", "0x24860 JNI-reachable classification")
    print("C++ implementation, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
