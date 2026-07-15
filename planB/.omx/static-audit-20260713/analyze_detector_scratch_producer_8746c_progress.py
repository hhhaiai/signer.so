#!/usr/bin/env python3
"""Static closure guard for the recovered detector scratch producer 0x8746c."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM = (AUDIT / "disasm-8746c-8f56c.txt").read_text(errors="replace").lower()
X86 = (AUDIT / "disasm-x86-88475-93f86.txt").read_text(
    errors="replace").lower()
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X86_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()
GENERATOR = (AUDIT / "generate_arm64_function_inventory.py").read_text()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def call_counter(text: str, mnemonic: str) -> Counter[int]:
    return Counter(int(match, 16) for match in re.findall(
        rf"\b{mnemonic}\s+([0-9a-f]+)\s+<", text))


def main() -> None:
    require(ARM_EH, r"pc=0008746c\.\.\.0008f56c", "ARM64 FDE")
    require(X86_EH, r"pc=00088475\.\.\.00093f86", "x86_64 FDE")
    require(ARM_FULL, r"\bf3bc:\s+[0-9a-f]+\s+bl\s+0x8746c\b",
            "ARM64 sole caller")
    require(X86_FULL,
            r"\b1318a:\s+(?:[0-9a-f]{2}\s+)+callq?\s+0x88475\b",
            "x86_64 sole caller")
    require(ARM_FULL, r"\bf36c:.*add\s+x0,\s*sp,\s*#0x38",
            "ARM64 scratch memset pointer")
    require(ARM_FULL, r"\bf374:.*mov\s+w2,\s*#0x878",
            "ARM64 scratch memset size")
    require(ARM_FULL, r"\bf3a8:.*bl\s+0x139e10\s+<memset@plt>",
            "ARM64 scratch memset call")
    require(ARM_FULL, r"\bf3ac:.*add\s+x2,\s*sp,\s*#0x38",
            "ARM64 scratch producer argument")
    require(X86_FULL, r"\b1316a:.*leaq\s+0x38\(%rsp\),\s*%rdi",
            "x86_64 scratch memset pointer")
    require(X86_FULL, r"\b1316f:.*movl\s+\$0x878,\s*%edx",
            "x86_64 scratch memset size")
    require(X86_FULL, r"\b13176:.*callq\s+0x132840\s+<memset@plt>",
            "x86_64 scratch memset call")
    require(X86_FULL, r"\b13185:.*leaq\s+0x38\(%rsp\),\s*%rdx",
            "x86_64 scratch producer argument")
    print("cross-ABI FDE, sole caller and {JNIEnv,Context,scratch} signature: PASS")

    arm_calls = call_counter(ARM, "bl")
    x86_calls = call_counter(X86, "call")
    expected_pairs = [
        (0x8F56C, 0x93F86, 1),
        (0x92B24, 0x96AE0, 2),
        (0x95020, 0x98081, 2),
        (0xA8978, 0xA469C, 1),
        (0xA948C, 0xA4CD9, 1),
        (0xB21B4, 0xAA362, 2),
        (0xB5828, 0xAC4D5, 1),
        (0xBB5A0, 0xAFB26, 1),
        (0xBCE98, 0xB0994, 1),
        (0xBEA74, 0xB1A13, 1),
        (0xBF5FC, 0xB20C2, 1),
        (0xC0180, 0xB278E, 1),
        (0xD4678, 0xC1A02, 13),
    ]
    for arm_target, x86_target, count in expected_pairs:
        if arm_calls[arm_target] != count or x86_calls[x86_target] != count:
            raise AssertionError(
                f"callee mismatch ARM64 0x{arm_target:x}={arm_calls[arm_target]} "
                f"x86_64 0x{x86_target:x}={x86_calls[x86_target]} expected={count}")
    if arm_calls[0x139800] != 16:
        raise AssertionError("ARM64 must call acquire-byte CAS helper 16 times")
    if len(re.findall(r"lock\s+cmpxchg", X86)) != 16:
        raise AssertionError("x86_64 must inline sixteen lock cmpxchg sites")
    print("cross-ABI 13-helper mapping and sixteen once-init locks: PASS")

    if arm_calls[0x139E20] != 13 or x86_calls[0x132850] != 13:
        raise AssertionError("expected thirteen malloc call sites per ABI")
    if arm_calls[0xD4678] != 13 or x86_calls[0xC1A02] != 13:
        raise AssertionError("expected thirteen property-dispatch calls per ABI")
    if arm_calls[0x8F56C] != 1 or x86_calls[0x93F86] != 1:
        raise AssertionError("expected one recovered pair-appender call per ABI")
    print("thirteen property/malloc stages and one pair-appender dependency: PASS")

    recovered_dependencies = {
        0xA8978: "JNI size-method reader",
        0xA948C: "JNI indexed object-method reader",
        0xB21B4: "JNI int-field reader",
        0xB5828: "JNI Context.getSystemService getter",
        0xBB5A0: "JNI Resources.getSystem getter",
        0xBCE98: "JNI DisplayMetrics getter",
        0xBEA74: "JNI Sensor.getName getter",
        0xBF5FC: "JNI Sensor.getVendor getter",
        0xC0180: "JNI SensorManager.getSensorList getter",
    }
    for address, name in recovered_dependencies.items():
        require(GENERATOR,
                rf"0x0*{address:X}:\s*\(\"{re.escape(name)}\",\s*\"recovered\"",
                f"recovered dependency 0x{address:x}")
    print("all direct JNI producer dependencies are recovered and explicit: PASS")

    require(GENERATOR,
            r"0x0*8746C:\s*\(\"detector property/sensor/display scratch "
            r"producer\",\s*\"recovered\"",
            "recovered producer coverage entry")
    print("producer coverage generator entry is recovered: PASS")


if __name__ == "__main__":
    main()
