#!/usr/bin/env python3
"""Static cross-ABI proof for APK Signing Block entry dispatcher 0x127194."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (ROOT / ".omx/static-audit-20260713/generate_arm64_function_inventory.py").read_text()


def find_objdump() -> str:
    for candidate in (
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def disassemble(objdump: str, binary: Path, start: int, end: int) -> str:
    return subprocess.run(
        [
            objdump,
            "-d",
            f"--start-address=0x{start:x}",
            f"--stop-address=0x{end:x}",
            str(binary),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.lower()


def body(disassembly: str, start: int, end: int) -> str:
    lines = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise AssertionError(f"missing/out-of-order {label}: {token}")
        cursor = position + len(token)


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0x127194, 0x127A78)
    x86 = disassemble(objdump, X86_64_SO, 0x11E1D8, 0x11E802)

    arm_initial = body(arm, 0x127194, 0x127330)
    require_order(arm_initial, [
        "bl\t1259b8",
        "add\tx9, x19, #0x28",
        "add\tx10, x19, #0x38",
        "ldr\tw8, [x20]",
        "add\tx9, x19, #0x18",
        "cmp\tw8, #0x0",
        "csel\tx8, x11, x9, eq",
    ], "ARM64 locator/status gate and owner field addresses")

    arm_size_read = body(arm, 0x12789C, 0x127930)
    require_order(arm_size_read, [
        "sub\tx0, x29, #0x18",
        "mov\tw1, #0x8",
        "mov\tw2, #0x1",
        "bl\t13a050",
        "cmp\tx0, #0x0",
    ], "ARM64 raw uint64 entry-size read")
    arm_id_read = body(arm, 0x1276AC, 0x127750)
    require_order(arm_id_read, [
        "sub\tx0, x29, #0xc",
        "mov\tw1, #0x4",
        "mov\tw2, #0x1",
        "bl\t13a050",
        "cmp\tx0, #0x0",
    ], "ARM64 raw uint32 entry-ID read")

    for pattern, label in (
        (r"mov\s+w8,\s*#0x871a.*movk\s+w8,\s*#0x7109",
         "ARM64 APK Signature Scheme v2 ID"),
        (r"mov\s+w8,\s*#0x68c0.*movk\s+w8,\s*#0xf053",
         "ARM64 APK Signature Scheme v3 ID"),
        (r"mov\s+w8,\s*#0xad61.*movk\s+w8,\s*#0x1b93",
         "ARM64 APK Signature Scheme v3.1 ID"),
    ):
        require(arm, pattern, label)

    arm_v2 = body(arm, 0x1275C0, 0x1275DC)
    require_order(arm_v2, [
        "ldur\tw8, [x29, #-24]",
        "ldr\tx1, [sp, #16]",
        "sub\tw2, w8, #0x4",
        "bl\t122fe8",
    ], "ARM64 v2 owner+0x18 low32(size)-4 route")
    arm_v3 = body(arm, 0x1279A4, 0x1279BC)
    require_order(arm_v3, [
        "ldur\tw8, [x29, #-24]",
        "ldr\tx1, [sp, #8]",
        "sub\tw2, w8, #0x4",
        "bl\t124a24",
    ], "ARM64 v3 owner+0x28 route")
    arm_v31 = body(arm, 0x127680, 0x12768C)
    require_order(arm_v31, [
        "ldur\tw8, [x29, #-24]",
        "ldr\tx1, [sp, #24]",
    ], "ARM64 v3.1 owner+0x38 route")
    require(arm, r"1279ac:.*sub\s+w2,\s*w8,\s*#0x4", "ARM64 v3.1 low32 size")
    require(arm, r"1279b8:.*bl\s+(?:0x)?124a24", "ARM64 v3.1 shared parser")

    arm_tell = body(arm, 0x127750, 0x1277DC)
    require_order(arm_tell, [
        "sub\tx2, x29, #0x20",
        "bl\t11fa74",
        "tst\tw0, #0x1",
    ], "ARM64 unknown-entry checked ftell")
    arm_bound = body(arm, 0x127870, 0x12789C)
    require_order(arm_bound, [
        "ldur\tx10, [x29, #-32]",
        "ldp\tx8, x9, [x9, #8]",
        "add\tx8, x9, x8",
        "cmp\tx10, x8",
    ], "ARM64 modulo footerOffset+size unsigned bound")
    arm_skip = body(arm, 0x1275DC, 0x127680)
    require_order(arm_skip, [
        "ldur\tx8, [x29, #-24]",
        "mov\tw2, #0x1",
        "sub\tx1, x8, #0x4",
        "bl\t13a060",
        "cmp\tw0, #0x0",
    ], "ARM64 full64(size)-4 raw skip")
    require(arm, r"mov\s+w10,\s*#0x7.*str\s+w10,\s*\[x8\]",
            "ARM64 raw fseek status 7")

    for pattern, label in (
        (r"call\s+(?:0x)?11d585", "x86_64 locator call"),
        (r"lea\s+0x40\(%rsp\),%rdi.*push\s+\$0x8.*call\s+(?:0x)?132a80",
         "x86_64 raw uint64 size read"),
        (r"lea\s+0x4c\(%rsp\),%rdi.*push\s+\$0x4.*call\s+(?:0x)?132a80",
         "x86_64 raw uint32 ID read"),
        (r"cmpl\s+\$0x7109871a,0x4\(%rsp\)", "x86_64 v2 ID"),
        (r"cmpl\s+\$0xf05368c0,0x4\(%rsp\)", "x86_64 v3 ID"),
        (r"cmpl\s+\$0x1b93ad61,0x4\(%rsp\)", "x86_64 v3.1 ID"),
        (r"mov\s+0x40\(%rsp\),%edx.*add\s+\$0xfffffffc,%edx.*call\s+(?:0x)?11b441",
         "x86_64 v2 low32 size route"),
        (r"mov\s+0x40\(%rsp\),%edx.*add\s+\$0xfffffffc,%edx.*call\s+(?:0x)?11c97c",
         "x86_64 v3/v3.1 low32 size route"),
        (r"lea\s+0x38\(%rsp\),%rdx.*call\s+(?:0x)?1189b2",
         "x86_64 checked ftell"),
        (r"mov\s+0x10\(%rcx\),%rax.*add\s+0x8\(%rcx\),%rax.*cmp\s+%rax,0x38\(%rsp\).*jb",
         "x86_64 modulo unsigned bound"),
        (r"mov\s+0x40\(%rsp\),%rsi.*add\s+\$0xfffffffffffffffc,%rsi.*call\s+(?:0x)?132a90",
         "x86_64 full64 unknown skip"),
        (r"movl\s+\$0x7,\(%rax\)", "x86_64 fseek status 7"),
    ):
        require(x86, pattern, label)

    for symbol in (
        "RecoveredApkSigningBlockEntryOperations127194",
        "runRecoveredApkSigningBlockEntries127194",
        "recoveredApkSigningBlockEntries127194Regression",
        "kRecoveredApkSignatureSchemeV2Id127194",
        "kRecoveredApkSignatureSchemeV3Id127194",
        "kRecoveredApkSignatureSchemeV31Id127194",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    cpp_start = CPP.index(
        "void runRecoveredApkSigningBlockEntries127194(\n"
        "        std::uint32_t* status,\n"
        "        RecoveredParserOwner125074* owner,\n"
        "        const RecoveredApkSigningBlockEntryOperations127194& operations)"
    )
    cpp_end = CPP.index("\n}\n", cpp_start) + 3
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "operations.locateSigningBlock(status, owner)",
        "if (*status != 0) return",
        "std::uint64_t entrySize",
        "operations.read(&entrySize",
        "std::uint32_t entryId",
        "operations.read(&entryId",
        "static_cast<std::uint32_t>(entrySize) - 4U",
        "case kRecoveredApkSignatureSchemeV2Id127194",
        "&owner->first",
        "case kRecoveredApkSignatureSchemeV3Id127194",
        "&owner->second",
        "case kRecoveredApkSignatureSchemeV31Id127194",
        "&owner->third",
        "operations.tell(",
        "footerOffsetBits + owner->signingBlockSize",
        ">= nativeBound",
        "entrySize - 4U",
        "operations.seek(",
        "*status = 7",
        "if (*status != 0) return",
    ], "C++ entry-loop operation order")
    require(
        GENERATOR,
        r"0x127194:.*APK Signing Block v2/v3/v3\.1 entry dispatcher.*recovered",
        "0x127194 coverage entry",
    )

    print("ARM64/x86_64 raw uint64-size + uint32-ID loop: PASS")
    print("v2 7109871a -> +0x18, v3 f05368c0 -> +0x28: PASS")
    print("v3.1 1b93ad61 -> +0x38 and low32(size)-4 routing: PASS")
    print("unknown checked-ftell bound, full64(size)-4 skip and status 7: PASS")
    print("C++ EOF/status behavior, parser routes and regression hook: PASS")


if __name__ == "__main__":
    main()
