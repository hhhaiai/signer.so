#!/usr/bin/env python3
"""Static proof for ARM64 module runtime scaffolding at 0x8070..0x80c0."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
RUNTIME = DISASM[
    DISASM.index("    8070:"):DISASM.index("    80c0:")
]
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text().lower()
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text().lower()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def main() -> None:
    require(RUNTIME,
            r"8070:.*bti\s+c.*"
            r"8074:.*adrp\s+x0,\s*0x13e000.*"
            r"8078:.*add\s+x0,\s*x0,\s*#0x170.*"
            r"807c:.*b\s+0x139dc0\s+<__cxa_finalize@plt>",
            "0x8070 DSO finalizer wrapper")
    require(RUNTIME,
            r"8080:.*bti\s+c.*8084:.*ret",
            "0x8080 no-op callback")
    require(RUNTIME,
            r"8088:.*bti\s+c.*808c:.*b\s+0x8080",
            "0x8088 no-op tail alias")
    require(RUNTIME,
            r"8090:.*bti\s+c.*"
            r"8094:.*cbz\s+x0,\s*0x80a0.*"
            r"8098:.*mov\s+x16,\s*x0.*"
            r"809c:.*br\s+x16.*"
            r"80a0:.*ret",
            "0x8090 nullable callback dispatcher")
    require(RUNTIME,
            r"80a4:.*bti\s+c.*"
            r"80a8:.*mov\s+x1,\s*x0.*"
            r"80ac:.*nop.*"
            r"80b0:.*adr\s+x0,\s*0x8090.*"
            r"80b4:.*adrp\s+x2,\s*0x13e000.*"
            r"80b8:.*add\s+x2,\s*x2,\s*#0x170.*"
            r"80bc:.*b\s+0x139dd0\s+<__cxa_atexit@plt>",
            "0x80a4 atexit registration")
    print("five exact ARM64 module runtime FDE bodies: PASS")

    for symbol in (
            "runrecoveredmodulefinalize8070",
            "runrecoveredmodulenoop8080",
            "runrecoveredmodulenoopalias8088",
            "runrecoveredmoduleexitdispatcher8090",
            "runrecoveredmoduleatexitregistration80a4",
            "recoveredmoduleruntimescaffolding8070regression"):
        require(CPP, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    require(CPP,
            r"if \(!recoveredmoduleruntimescaffolding8070regression\(\)\)",
            "top-level regression guard")
    for address in (0x8070, 0x8080, 0x8088, 0x8090, 0x80A4):
        require(COVERAGE,
                rf"`0x{address:x}\.\.[^`]+`.*\*\*recovered\*\*",
                f"coverage 0x{address:x}")
    print("C++ runtime callbacks, regression and recovered coverage: PASS")


if __name__ == "__main__":
    main()
