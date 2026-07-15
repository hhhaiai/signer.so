#!/usr/bin/env python3
"""Static evidence checker for ARM64 0xd9cc and 0xddc4 recovery."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARM = (ROOT / ".omx/static-audit-20260713/disasm-ddc4-e674.txt").read_text()
DIGEST = (ROOT / ".omx/static-audit-20260713/disasm-d9cc-ddc4.txt").read_text()
X64 = (ROOT / ".omx/static-audit-20260713/disasm-x86_64-11f34-12519.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(text: str, needles: list[str]) -> None:
    for needle in needles:
        assert needle in text, needle


require(ARM, [
    "de14: f9408801",       # context+0x110
    "bl\t0x124c90",
    "bl\t0x127194",
    "bl\t0xd9cc",
    "mov\tw1, #0x2a",
    "bl\t0x125074",
    "mov\tx9, #0x40000000000",
    "movk\tx9, #0x100, lsl #48",
])
require(DIGEST, [
    "ldr\tx8, [x1]",
    "bl\t0x11f238",
    "bl\t0x11f264",
    "bl\t0x11f414",
    "mov\tw9, #0x14",
    "and\tw0, w23, #0x1",
])
require(X64, [
    "callq\t0x11cb9c",
    "callq\t0x11e1d8",
    "callq\t0x11c20",
    "pushq\t$0x2a",
    "callq\t0x12519",
    "orq\t%rax, 0xe0(%rcx)",
    "callq\t0x11cf06",
])
require(CPP, [
    "std::array<std::uint8_t, 20> sha1(",
    "bool recoveredPublicSourceCandidateMatches(",
    "candidateBytes + 0x10",
    "if (candidate.data == 0) return false;",
    "void runRecoveredPublicSourceDigestCheck(",
    "parser->candidate38",
    "parser->candidate28",
    "parser->candidate18",
    "if (anyCandidate && !matched)",
    "applyProtectedCorrection2a(context);",
    "applyProtectedContextMask0100040000000000(context);",
    "operations.stage125074(parserAddress);",
])

print("PUBLIC_SOURCE_DIGEST_CHECK_AUDIT_PASS")
