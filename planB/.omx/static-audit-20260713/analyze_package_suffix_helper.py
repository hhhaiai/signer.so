#!/usr/bin/env python3
"""Static checker for ARM64 last-dot suffix helper 0xd6cb8."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ASM = (ROOT / ".omx/static-audit-20260713/disasm-d6cb8-d78b8.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()

for needle in [
    "ldrb\tw5, [x3], #0x1",
    "cmp\tw20, #0x2e",
    "add\tx2, x0, x4",
    "cmp\tx2, x0",
    "ccmp\tx2, #0x0",
    "adr\tx8, 0x3068",
    "csinc\tx0, x8, x2, eq",
]:
    assert needle in ASM, needle

for needle in [
    "const char* recoveredSuffixAfterLastDot(",
    "if (*cursor == '.') lastDot = cursor;",
    "if (lastDot == nullptr || lastDot == input) return kEmpty;",
    "return lastDot + 1;",
    "std::uint8_t recoveredAsciiLower(std::uint8_t byte)",
    "byte >= static_cast<std::uint8_t>('A')",
    "byte <= static_cast<std::uint8_t>('Z')",
    "byte | 0x20U",
    "bool recoveredAsciiCaseInsensitiveEquals(",
    "bool recoveredPathHasApkSuffix(const char* path)",
    'recoveredSuffixAfterLastDot(path), "apk"',
]:
    assert needle in CPP, needle

X86 = (ROOT / ".omx/static-audit-20260713/disasm-x86_64-19bdf-22b54.txt").read_text()
for needle in [
    "callq\t0xc34db",
    "# 0x13bb10",
    "orl\t$0x20, %ecx",
    "orl\t$0x20, %esi",
    "cmovbl\t%edx, %ecx",
    "cmovbl\t%eax, %esi",
    "cmpl\t%esi, %ecx",
]:
    assert needle in X86, needle

print("PACKAGE_SUFFIX_HELPER_AUDIT_PASS")
