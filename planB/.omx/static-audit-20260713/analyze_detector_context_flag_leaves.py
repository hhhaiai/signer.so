#!/usr/bin/env python3
"""Static proof for ARM64 detector context-flag and no-op FDE leaves."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text().lower()
GENERATOR = (AUDIT / "generate_arm64_function_inventory.py").read_text().lower()
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text().lower()


FLAG_LEAVES = {
    0x008AD4: 0x0200080000000000,
    0x016B64: 0x1000000000000000,
    0x040FEC: 0x0000000000000800,
    0x0418D8: 0x0000000000002000,
    0x0421CC: 0x0000000000004000,
    0x0430F4: 0x0000000000008000,
    0x043998: 0x0000000000010000,
    0x0442DC: 0x0000000000020000,
    0x044C28: 0x0000000000040000,
    0x044DA0: 0x0000000000080000,
    0x0456A8: 0x0000000000100000,
    0x047778: 0x0000000000200000,
    0x047F84: 0x0000000000400000,
    0x0490E0: 0x0000000000800000,
    0x04AFD4: 0x0000000001000000,
    0x04AFF0: 0x0000000020000000,
    0x04B000: 0x0000000004000000,
    0x04B010: 0x0000000008000000,
    0x04D9AC: 0x0000000010000000,
    0x0927AC: 0x0001000000000000,
}

NO_OP_LEAVES = (0x04AFE4, 0x04AFE8, 0x04AFEC)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def instruction(address: int) -> str:
    match = re.search(
        rf"^\s*{address:x}:\s+[0-9a-f]+\s+([^\n]+)$", DISASM, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing instruction 0x{address:x}")
    text = match.group(1).split("//", 1)[0].strip()
    return re.sub(r"\s+", " ", text)


def verify_simple_leaf(address: int, mask: int) -> None:
    expected = (
        "ldr x8, [x0, #0xe0]",
        f"orr x8, x8, #0x{mask:x}",
        "str x8, [x0, #0xe0]",
        "ret",
    )
    actual = tuple(instruction(address + offset)
                   for offset in (0, 4, 8, 12))
    if actual != expected:
        raise AssertionError(
            f"unexpected flag leaf 0x{address:x}: {actual!r} != {expected!r}")


def main() -> None:
    special = 0x008AD4
    expected_special = (
        "ldr x8, [x0, #0xe0]",
        "mov x9, #0x80000000000",
        "movk x9, #0x200, lsl #48",
        "orr x8, x8, x9",
        "str x8, [x0, #0xe0]",
        "ret",
    )
    actual_special = tuple(instruction(special + offset)
                           for offset in (0, 4, 8, 12, 16, 20))
    if actual_special != expected_special:
        raise AssertionError(
            f"unexpected special flag leaf: {actual_special!r}")

    for address, mask in FLAG_LEAVES.items():
        if address != special:
            verify_simple_leaf(address, mask)
    print("twenty exact ARM64 context+0xe0 flag-mask leaves: PASS")

    for address in NO_OP_LEAVES:
        if instruction(address) != "ret":
            raise AssertionError(f"0x{address:x} is not a pure RET leaf")
    print("three standalone ARM64 RET-only FDE leaves: PASS")

    require(CPP,
            r"constexpr std::array<recovereddetectorcontextflagleaf, 20>\s*"
            r"krecovereddetectorcontextflagleaves",
            "C++ flag-leaf table")
    for address, mask in FLAG_LEAVES.items():
        require(CPP,
                rf"\{{0x0*{address:x},\s*0x0*{mask:x}ull\}}",
                f"C++ leaf 0x{address:x}")
        require(GENERATOR,
                rf"0x0*{address:x}:\s*\(.*\"recovered\"",
                f"inventory mapping 0x{address:x}")
        require(COVERAGE,
                rf"`0x{address:x}\.\.[^`]+`.*\*\*recovered\*\*",
                f"coverage row 0x{address:x}")
    require(CPP,
            r"constexpr std::array<std::uint64_t, 3>\s*"
            r"krecovereddetectornoopleaves",
            "C++ no-op table")
    for address in NO_OP_LEAVES:
        require(GENERATOR,
                rf"0x0*{address:x}:\s*\(.*\"recovered\"",
                f"inventory no-op mapping 0x{address:x}")
        require(COVERAGE,
                rf"`0x{address:x}\.\.[^`]+`.*\*\*recovered\*\*",
                f"coverage no-op row 0x{address:x}")
    require(CPP,
            r"bool recovereddetectorcontextflagleavesregression\(\)",
            "C++ regression")
    require(CPP,
            r"if \(!recovereddetectorcontextflagleavesregression\(\)\)",
            "top-level regression guard")
    print("C++ address/mask mapping, no-op model and coverage guards: PASS")


if __name__ == "__main__":
    main()
