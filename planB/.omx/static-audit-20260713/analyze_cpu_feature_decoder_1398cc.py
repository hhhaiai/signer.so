#!/usr/bin/env python3
"""Static proof for the ARM64 CPU-feature decoder 0x1398cc."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
WINDOW = DISASM[
    DISASM.index("  1398cc:"):DISASM.index("  139d04:")
]
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
CPP_LOWER = CPP.lower()
CPP_WINDOW = CPP_LOWER[
    CPP_LOWER.index("enum class recoveredcpufeaturedecoderstatus1398cc"):
    CPP_LOWER.index("struct recoveredcpufeatureconstructoroperations139d04")
]
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text(
    errors="replace").lower()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def main() -> None:
    require(WINDOW,
            r"1398dc:.*adrp\s+x8,\s*0x146000.*"
            r"1398e0:.*ldr\s+x9,\s*\[x8,\s*#0xbb8\].*"
            r"1398e4:.*cbz\s+x9,\s*0x1398f8.*"
            r"1398f4:.*ret",
            "published-feature early return")
    require(WINDOW,
            r"1398f8:.*tbnz\s+x0,\s*#0x3e,\s*0x139904.*"
            r"1398fc:.*mov\s+x9,\s*xzr.*"
            r"139904:.*ldr\s+x9,\s*\[x1,\s*#0x10\]",
            "bit-62 descriptor tag and HWCAP2 selection")
    require(WINDOW,
            r"139af8:.*str\s+x11,\s*\[x8,\s*#0xbb8\].*"
            r"139b60:.*tbnz\s+w0,\s*#0xb,\s*0x139bdc",
            "first publication and HWCAP-bit-11 branch")
    require(WINDOW,
            r"139b9c:.*str\s+x11,\s*\[x8,\s*#0xbb8\].*"
            r"139bbc:.*tst\s+x9,\s*#0x2.*"
            r"139bc0:.*and\s+x9,\s*x0,\s*#0x400000.*"
            r"139bd4:.*csel\s+x9,\s*x9,\s*x11,\s*eq",
            "non-system-register publication and joint HWCAP/HWCAP2 gate")
    for address, register in (
            ("139bdc", "id_aa64pfr1_el1"),
            ("139c10", "id_aa64pfr0_el1"),
            ("139c30", "id_aa64zfr0_el1"),
            ("139c5c", "id_aa64isar0_el1"),
            ("139c6c", "id_aa64isar1_el1")):
        require(WINDOW, rf"{address}:.*mrs\s+x\d+,\s*{register}",
                f"{register} read")
    require(WINDOW,
            r"139bec:.*str\s+x11,\s*\[x8,\s*#0xbb8\].*"
            r"139c88:.*str\s+x10,\s*\[x8,\s*#0xbb8\].*"
            r"139cd0:.*orr\s+x9,\s*x10,\s*#0x400000000000000.*"
            r"139cd4:.*str\s+x9,\s*\[x8,\s*#0xbb8\].*"
            r"139ce8:.*orr\s+x10,\s*x10,\s*#0x8000000000000.*"
            r"139cf0:.*str\s+x9,\s*\[x8,\s*#0xbb8\]",
            "ordered system-register publications and final bit 58")
    print("ARM64 global gate, descriptor, feature inputs and publications: PASS")

    for symbol in (
            "recoveredcpufeaturedecoderstatus1398cc",
            "recoveredcpufeaturedecoderinput1398cc",
            "recoveredcpufeaturedecoderoutput1398cc",
            "runrecoveredcpufeaturedecoder1398cc",
            "recoveredcpufeaturedecoder1398ccregression"):
        require(CPP_WINDOW, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    for presence in (
            "publishedfeaturesprovided",
            "taggedhwcapprovided",
            "auxdescriptorprovided",
            "idaa64pfr1provided",
            "idaa64pfr0provided",
            "idaa64zfr0provided",
            "idaa64isar0provided",
            "idaa64isar1provided"):
        require(CPP_WINDOW, rf"\b{presence}\b", f"caller presence gate {presence}")
    require(CPP_WINDOW,
            r"descriptortagged\s*&&\s*!input\.auxdescriptorprovided",
            "lazy descriptor validation")
    require(CPP_WINDOW,
            r"input\.idaa64pfr0\s*&\s*0xf00000000ull.*"
            r"!input\.idaa64zfr0provided",
            "conditional ZFR0 presence validation")
    require(CPP_WINDOW,
            r"const auto publish.*output\.publications\.push_back",
            "ordered publication capture")
    if "getauxval" in CPP_WINDOW or "__system_property_get" in CPP_WINDOW \
            or re.search(r"\bmrs\b", CPP_WINDOW):
        raise AssertionError("decoder must not read host auxv, properties or system registers")
    require(CPP_LOWER,
            r"if \(!recoveredcpufeaturedecoder1398ccregression\(\)\)",
            "top-level regression guard")
    require(COVERAGE,
            r"`0x1398cc\.\.0x139d04`.*aarch64 cpu-feature word decoder.*"
            r"\*\*recovered\*\*",
            "recovered coverage row")
    print("caller-only input surface, presence gates, regression and coverage: PASS")


if __name__ == "__main__":
    main()
