#!/usr/bin/env python3
"""Static evidence checker for recovered producer 0x18540..0x1dbd8."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARM64 = (ROOT / ".omx/static-audit-20260713/disasm-18540-1dbd8.txt").read_text()
X86 = (ROOT / ".omx/static-audit-20260713/disasm-x86_64-19bdf-22b54.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
DOC = (ROOT / ".omx/static-audit-20260713/arm64-public-source-list-producer-progress.md").read_text()

for needle in [
    "bl\t0xd6cb8",
    "bl\t0x139e30 <access@plt>",
    "bl\t0x139e90 <fopen@plt>",
    "bl\t0x139e70 <fgets@plt>",
    "bl\t0x139e80 <sscanf@plt>",
    "bl\t0x139e50 <calloc@plt>",
    "bl\t0x139e40 <strdup@plt>",
]:
    assert needle in ARM64, needle

for needle in [
    "# 0x13bad0",
    "# 0x13bae0",
    "# 0x13baf0",
    "# 0x13bb10",
    "callq\t0x132860 <access@plt>",
    "callq\t0x1328c0 <fopen@plt>",
    "callq\t0x1328a0 <fgets@plt>",
    "callq\t0x1328b0 <sscanf@plt>",
    "callq\t0x132880 <calloc@plt>",
    "callq\t0x132870 <strdup@plt>",
    "movl\t$0x8, (%rax)",
    "movl\t$0x2, (%rax)",
    "callq\t0x132890 <fclose@plt>",
    "addq\t$-0x800, %rax",
    "movb\t-0x1(%rax,%r14), %al",
    "cmpb\t-0x1(%rcx,%r14), %al",
    "movq\t%rdx, (%rax)",
    "movq\t%rax, 0x8(%r9)",
]:
    assert needle in X86, needle

for needle in [
    "const char* recoveredSuffixAfterLastDot(",
    "std::uint8_t recoveredAsciiLower(std::uint8_t byte)",
    "bool recoveredAsciiCaseInsensitiveEquals(",
    "bool recoveredPathHasApkSuffix(const char* path)",
    "bool recoveredPathContainsPackageName(",
    "if (*packageName == '\\0') return true;",
    "bool recoveredPublicSourcePathCandidateMatches(",
    "recoveredPathHasApkSuffix(path)",
    "recoveredPathContainsPackageName(path, packageName)",
    "void runRecoveredPublicSourceListProducer(",
    'static constexpr char kMapsPath[] = "/proc/self/maps";',
    "if (::access(kMapsPath, R_OK) != 0)",
    "*status = 8;",
    "std::fopen(kMapsPath, kReadMode)",
    "std::fgets(line.data(), static_cast<int>(line.size()), file)",
    "std::sscanf(line.data(), kMapsFormat, path.data()) != 1",
    "std::calloc(1, sizeof(RecoveredOwnedStringNode))",
    "*tailSlot = static_cast<std::uint64_t>(",
    "reinterpret_cast<std::uintptr_t>(&node->next)",
    "char* const copy = ::strdup(path.data());",
    "node->value = static_cast<std::uint64_t>(",
    "std::fclose(file);",
]:
    assert needle in CPP, needle

assert "stage18540" not in CPP

source_order = [
    "std::calloc(1, sizeof(RecoveredOwnedStringNode))",
    "*tailSlot = static_cast<std::uint64_t>(",
    "reinterpret_cast<std::uintptr_t>(&node->next)",
    "char* const copy = ::strdup(path.data());",
    "node->value = static_cast<std::uint64_t>(",
    "if (copy == nullptr)",
    "std::fclose(file);",
]
positions = [CPP.index(needle) for needle in source_order]
assert positions == sorted(positions), source_order

for needle in [
    'access("/proc/self/maps", R_OK)',
    "*status = 8 at 0x1e0c9",
    "*status = 2 at 0x1e3cc..0x1e3d3",
    "Malformed lines (`sscanf != 1`) are skipped",
]:
    assert needle in DOC, needle

print("PUBLIC_SOURCE_LIST_PRODUCER_AUDIT_PASS")
