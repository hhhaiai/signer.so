#!/usr/bin/env python3
"""Cross-ABI static proof for ZIP EOCD matcher/scanner 0x125210/0x125770."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


def find_objdump() -> str:
    candidates = [
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def run_objdump(objdump: str, args: list[str], binary: Path) -> str:
    result = subprocess.run(
        [objdump, *args, str(binary)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.lower()


def disassemble(objdump: str, binary: Path, start: int, stop: int) -> str:
    return run_objdump(objdump, [
        "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}"
    ], binary)


def data_bytes(
        objdump: str, binary: Path, address: int, count: int) -> bytes:
    dump = run_objdump(objdump, [
        "-s",
        f"--start-address=0x{address:x}",
        f"--stop-address=0x{address + count:x}",
    ], binary)
    match = re.search(
        rf"^\s*{address:x}\s+([0-9a-f]{{{count * 2}}})",
        dump,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing data at 0x{address:x}")
    return bytes.fromhex(match.group(1))


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def require_token_order(text: str, tokens: list[str], label: str) -> None:
    positions = [text.find(token) for token in tokens]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"invalid {label} order: {tokens}")


def scan_offsets(match_at: int | None, seek_fails_at: int | None = None) -> tuple[int, list[int]]:
    offset = -22
    visited: list[int] = []
    while (offset & 0xFFFFFFFF) > 0xFFFEFFEB:
        visited.append(offset)
        if seek_fails_at == offset or match_at == offset:
            break
        offset -= 1
    return offset, visited


def main() -> None:
    objdump = find_objdump()
    arm_matcher = disassemble(objdump, ARM64_SO, 0x125210, 0x125770)
    arm_scanner = disassemble(objdump, ARM64_SO, 0x125770, 0x1259B8)
    x86_matcher = disassemble(objdump, X86_64_SO, 0x11D040, 0x11D3B2)
    x86_scanner = disassemble(objdump, X86_64_SO, 0x11D3B2, 0x11D585)

    arm_encoded = data_bytes(objdump, ARM64_SO, 0x145F88, 4)
    x86_encoded = data_bytes(objdump, X86_64_SO, 0x13EA28, 4)
    arm_marker = bytes(value ^ 0x5B for value in arm_encoded)
    x86_marker = bytes(value ^ 0x28 for value in x86_encoded)
    expected_marker = bytes.fromhex("504b0506")
    if arm_marker != expected_marker or x86_marker != expected_marker:
        raise AssertionError(
            f"EOCD marker mismatch arm={arm_marker.hex()} x86={x86_marker.hex()}"
        )

    for pattern, label in (
        (r"stur\s+wzr,\s*\[x29,\s*#-12\]", "ARM64 zeroed four-byte buffer"),
        (r"sub\s+x1,\s*x29,\s*#0xc", "ARM64 buffer argument"),
        (r"mov\s+w2,\s*#0x4", "ARM64 fread item size four"),
        (r"mov\s+w3,\s*#0x1", "ARM64 fread item count one"),
        (r"bl\s+(?:0x)?11f89c", "ARM64 checked fread"),
        (r"adr\s+x24,\s*(?:0x)?145f88", "ARM64 marker pointer"),
        (r"mov\s+w27,\s*#0x4", "ARM64 compare count four"),
        (r"ldrb\s+w9,\s*\[x23\]", "ARM64 marker byte load"),
        (r"ldrb\s+w10,\s*\[x21\]", "ARM64 buffer byte load"),
        (r"cmp\s+w9,\s*w10", "ARM64 ordered byte equality"),
        (r"sub\s+x27,\s*x19,\s*#0x1", "ARM64 compare decrement"),
        (r"add\s+x24,\s*x23,\s*#0x1", "ARM64 marker advance"),
        (r"add\s+x25,\s*x21,\s*#0x1", "ARM64 buffer advance"),
        (r"eor\s+w12,\s*w10,\s*w13", "ARM64 XOR marker decode"),
        (r"and\s+w0,\s*w26,\s*#0x1", "ARM64 boolean return"),
    ):
        require(arm_matcher, pattern, label)

    for pattern, label in (
        (r"lea\s+0x2c\(%rsp\),%rax", "x86_64 local buffer address"),
        (r"andl\s+\$0x0,\(%rax\)", "x86_64 zeroed four-byte buffer"),
        (r"lea\s+0x21820\(%rip\),%rdi.*13ea28", "x86_64 marker pointer"),
        (r"lea\s+0x2c\(%rsp\),%rsi", "x86_64 fread buffer"),
        (r"push\s+\$0x4", "x86_64 fread item size four"),
        (r"push\s+\$0x1", "x86_64 fread item count one"),
        (r"call\s+(?:0x)?1188b3", "x86_64 checked fread"),
        (r"lea\s+-0x1\(%r13\),%rax", "x86_64 compare decrement"),
        (r"lea\s+0x1\(%rbx\),%rax", "x86_64 marker advance"),
        (r"lea\s+0x1\(%r14\),%rax", "x86_64 buffer advance"),
        (r"mov\s+\(%rbx\),%al", "x86_64 marker byte load"),
        (r"cmp\s+\(%r14\),%al", "x86_64 ordered byte equality"),
        (r"xorl\s+\$0x28282828,.*13ea28", "x86_64 XOR marker decode"),
        (r"and\s+\$0x1,%bpl", "x86_64 boolean return"),
    ):
        require(x86_matcher, pattern, label)

    for pattern, label in (
        (r"mov\s+x8,\s*#0xffffffffffffffea", "ARM64 initial offset -22"),
        (r"mov\s+w8,\s*#0xffeb", "ARM64 lower-bound low half"),
        (r"movk\s+w8,\s*#0xfffe,\s*lsl\s*#16", "ARM64 lower bound 0xfffeffeb"),
        (r"cmp\s+w21,\s*w8", "ARM64 unsigned lower-bound comparison"),
        (r"mov\s+x2,\s*x20", "ARM64 current seek offset"),
        (r"mov\s+w3,\s*#0x2", "ARM64 SEEK_END"),
        (r"bl\s+(?:0x)?11f990", "ARM64 checked fseek"),
        (r"bl\s+(?:0x)?125210", "ARM64 EOCD matcher"),
        (r"sub\s+x22,\s*x20,\s*#0x1", "ARM64 offset decrement"),
    ):
        require(arm_scanner, pattern, label)

    for pattern, label in (
        (r"push\s+\$0xffffffffffffffea", "x86_64 initial offset -22"),
        (r"cmp\s+\$0xfffeffec,%r14d", "x86_64 equivalent inclusive scan bound"),
        (r"push\s+\$0x2", "x86_64 SEEK_END"),
        (r"call\s+(?:0x)?118937", "x86_64 checked fseek"),
        (r"call\s+(?:0x)?11d040", "x86_64 EOCD matcher"),
        (r"lea\s+-0x1\(%rax\),%r15", "x86_64 offset decrement"),
    ):
        require(x86_scanner, pattern, label)

    exhausted, visited = scan_offsets(None)
    if exhausted != -65557 or len(visited) != 65535:
        raise AssertionError((exhausted, len(visited)))
    if visited[0] != -22 or visited[-1] != -65556:
        raise AssertionError((visited[0], visited[-1]))
    found, visited = scan_offsets(-25)
    if found != -25 or visited != [-22, -23, -24, -25]:
        raise AssertionError((found, visited))
    failed, visited = scan_offsets(None, -22)
    if failed != -22 or visited != [-22]:
        raise AssertionError((failed, visited))

    for symbol in (
        "RecoveredZipEocdSignatureOperations125210",
        "runRecoveredZipEocdSignatureMatcher125210",
        "recoveredZipEocdSignatureMatcher125210Regression",
        "RecoveredZipEocdScanOperations125770",
        "runRecoveredZipEocdBackwardScan125770",
        "recoveredZipEocdBackwardScan125770Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    matcher_start = CPP.index(
        "bool runRecoveredZipEocdSignatureMatcher125210(\n"
        "        std::uint32_t* status,\n"
        "        std::FILE* stream,\n"
        "        const RecoveredZipEocdSignatureOperations125210& operations)"
    )
    matcher_end = CPP.index("\n}\n", matcher_start) + 3
    matcher_cpp = CPP[matcher_start:matcher_end]
    require_token_order(
        matcher_cpp,
        [
            "std::array<std::uint8_t, 4> bytes{}",
            "operations.read(",
            "0x50, 0x4b, 0x05, 0x06",
            "return bytes == expected",
        ],
        "C++ EOCD matcher",
    )

    scanner_start = CPP.index(
        "std::int64_t runRecoveredZipEocdBackwardScan125770(\n"
        "        std::uint32_t* status,\n"
        "        std::FILE* stream,\n"
        "        const RecoveredZipEocdScanOperations125770& operations)"
    )
    scanner_end = CPP.index("\n}\n", scanner_start) + 3
    scanner_cpp = CPP[scanner_start:scanner_end]
    require_token_order(
        scanner_cpp,
        [
            "std::int64_t offset = -22",
            "minimumOffset = 0xfffeffebU",
            "operations.seek(",
            "operations.matchesSignature(status, stream)",
            "--offset",
            "return offset",
        ],
        "C++ EOCD scanner",
    )

    require(
        GENERATOR,
        r"0x125210:.*ZIP EOCD signature matcher.*recovered",
        "0x125210 coverage entry",
    )
    require(
        GENERATOR,
        r"0x125770:.*ZIP EOCD backward offset scanner.*recovered",
        "0x125770 coverage entry",
    )

    print("ARM64/x86_64 EOCD marker 50 4b 05 06: PASS")
    print("0x125210/0x11d040 checked four-byte matcher: PASS")
    print("0x125770/0x11d3b2 offsets -22..-65556: PASS")
    print("exhaustion sentinel -65557 and stop conditions: PASS")


if __name__ == "__main__":
    main()
