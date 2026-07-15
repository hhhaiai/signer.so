#!/usr/bin/env python3
"""Static proof for the ARM64 CPU-feature constructor wrapper 0x139d04."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
WINDOW = DISASM[
    DISASM.index("  139d04:"):DISASM.index("  139d98:") + 80
]
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text().lower()
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text().lower()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def main() -> None:
    blob = SO.read_bytes()
    if blob[0x3060:0x3068] != b"ro.arch\0":
        raise AssertionError("unexpected ro.arch bytes at VMA/file offset 0x3060")
    if blob[0x3069:0x3074] != b"exynos9810\0":
        raise AssertionError("unexpected exynos9810 bytes at 0x3069")
    print("fixed ro.arch and exynos9810 constructor strings: PASS")

    require(WINDOW,
            r"139d10:.*adrp\s+x8,\s*0x146000.*"
            r"139d14:.*ldr\s+x8,\s*\[x8,\s*#0xbb8\].*"
            r"139d18:.*cbz\s+x8,\s*0x139d2c.*"
            r"139d1c:.*ldp\s+x30,\s*x19.*"
            r"139d28:.*ret",
            "nonzero published-feature early return")
    require(WINDOW,
            r"139d2c:.*adrp\s+x0,\s*0x3000.*"
            r"139d30:.*add\s+x0,\s*x0,\s*#0x60.*"
            r"139d34:.*add\s+x1,\s*sp,\s*#0x24.*"
            r"139d38:.*bl\s+0x139f30\s+<__system_property_get@plt>.*"
            r"139d3c:.*cmp\s+w0,\s*#0x1.*"
            r"139d40:.*b\.lt\s+0x139d5c",
            "ro.arch read and missing-property branch")
    require(WINDOW,
            r"139d44:.*adrp\s+x1,\s*0x3000.*"
            r"139d48:.*add\s+x1,\s*x1,\s*#0x69.*"
            r"139d4c:.*add\s+x0,\s*sp,\s*#0x24.*"
            r"139d50:.*mov\s+w2,\s*#0xa.*"
            r"139d54:.*bl\s+0x139ef0\s+<strncmp@plt>.*"
            r"139d58:.*cbz\s+w0,\s*0x139d1c",
            "ten-byte exynos9810 prefix skip")
    require(WINDOW,
            r"139d5c:.*mov\s+w0,\s*#0x10.*"
            r"139d60:.*bl\s+0x13a160\s+<getauxval@plt>.*"
            r"139d64:.*mov\s+x19,\s*x0.*"
            r"139d68:.*mov\s+w0,\s*#0x1a.*"
            r"139d6c:.*bl\s+0x13a160\s+<getauxval@plt>",
            "ordered AT_HWCAP and AT_HWCAP2 reads")
    require(WINDOW,
            r"139d70:.*orr\s+x8,\s*x19,\s*#0x4000000000000000.*"
            r"139d74:.*mov\s+w9,\s*#0x18.*"
            r"139d78:.*str\s+x0,\s*\[sp,\s*#0x18\].*"
            r"139d7c:.*add\s+x1,\s*sp,\s*#0x8.*"
            r"139d80:.*mov\s+x0,\s*x8.*"
            r"139d84:.*stp\s+x9,\s*x19,\s*\[sp,\s*#0x8\].*"
            r"139d88:.*bl\s+0x1398cc",
            "tagged HWCAP and three-word descriptor call")
    print("constructor gate, property prefix and aux descriptor flow: PASS")

    for symbol in (
            "recoveredcpufeatureconstructoroperations139d04",
            "runrecoveredcpufeatureconstructor139d04",
            "recoveredcpufeatureconstructor139d04regression"):
        require(CPP, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    require(CPP,
            r"if \(!recoveredcpufeatureconstructor139d04regression\(\)\)",
            "top-level regression guard")
    require(COVERAGE,
            r"`0x139d04\.\.0x139d9c`.*\*\*recovered\*\*",
            "recovered coverage row")
    require(COVERAGE,
            r"`0x1398cc\.\.0x139d04`.*\*\*recovered\*\*",
            "separately recovered feature decoder row")
    print("C++ wrapper model, regression and separate recovered callee: PASS")


if __name__ == "__main__":
    main()
