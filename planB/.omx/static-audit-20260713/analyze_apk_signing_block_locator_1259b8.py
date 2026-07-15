#!/usr/bin/env python3
"""Static cross-ABI proof for libsigner APK Signing Block locator 0x1259b8."""

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


def run_objdump(objdump: str, arguments: list[str], binary: Path) -> str:
    return subprocess.run(
        [objdump, *arguments, str(binary)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.lower()


def disassemble(objdump: str, binary: Path, start: int, end: int) -> str:
    return run_objdump(objdump, [
        "-d",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{end:x}",
    ], binary)


def data_bytes(
        objdump: str, binary: Path, address: int, count: int) -> bytes:
    dump = run_objdump(objdump, [
        "-s",
        f"--start-address=0x{address:x}",
        f"--stop-address=0x{address + count:x}",
    ], binary)
    for line in dump.splitlines():
        fields = line.split()
        if not fields or fields[0] != f"{address:x}":
            continue
        encoded = "".join(
            field for field in fields[1:]
            if re.fullmatch(r"[0-9a-f]{8}", field)
        )
        if len(encoded) >= count * 2:
            return bytes.fromhex(encoded[:count * 2])
    raise AssertionError(f"missing data at 0x{address:x}")


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


def decode_arm_constants(disassembly: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in disassembly.splitlines():
        mov = re.search(r"\bmov\s+(x\d+|x30), #0x([0-9a-f]+)", line)
        if mov is not None:
            values[mov.group(1)] = int(mov.group(2), 16)
            continue
        movk = re.search(
            r"\bmovk\s+(x\d+|x30), #0x([0-9a-f]+), lsl #([0-9]+)",
            line,
        )
        if movk is not None:
            register = movk.group(1)
            shift = int(movk.group(3))
            mask = 0xFFFF << shift
            values[register] = (
                values.get(register, 0) & ~mask
            ) | (int(movk.group(2), 16) << shift)
    return values


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0x1259B8, 0x127194)
    x86 = disassemble(objdump, X86_64_SO, 0x11D585, 0x11E1D8)

    expected_cd = bytes.fromhex("504b0102")
    expected_magic = b"APK Sig Block 42"
    arm_cd = bytes(value ^ 0xA7 for value in
                   data_bytes(objdump, ARM64_SO, 0x145F90, 4))
    x86_cd = bytes(value ^ 0xB6 for value in
                   data_bytes(objdump, X86_64_SO, 0x13EA2C, 4))
    arm_magic = bytes(value ^ 0x3C for value in
                      data_bytes(objdump, ARM64_SO, 0x145FA0, 16))
    x86_magic = bytes(value ^ 0x16 for value in
                      data_bytes(objdump, X86_64_SO, 0x13EA30, 16))
    if arm_cd != expected_cd or x86_cd != expected_cd:
        raise AssertionError((arm_cd, x86_cd))
    if arm_magic != expected_magic or x86_magic != expected_magic:
        raise AssertionError((arm_magic, x86_magic))

    arm_initial = body(arm, 0x1259B8, 0x125AE0)
    require_order(arm_initial, [
        "ldr\tx1, [x8], #8",
        "bl\t125770",
        "ldr\tw8, [x20]",
        "cmp\tw8, #0x0",
        "csel\tx19, x9, x0, eq",
    ], "ARM64 EOCD scan and status gate")
    initial_constants = decode_arm_constants(arm_initial)
    if initial_constants.get("x9") != 0x32B90645F5DCCFA7:
        raise AssertionError("ARM64 scan-success state")
    if initial_constants.get("x0") != 0xCA1919240CE534DC:
        raise AssertionError("ARM64 status-exit state")

    arm_seek12 = body(arm, 0x1266D4, 0x1267BC)
    require_order(arm_seek12, [
        "mov\tw2, #0xc",
        "mov\tw3, #0x1",
        "bl\t11f990",
    ], "ARM64 EOCD +12 SEEK_CUR")
    seek12_constants = decode_arm_constants(arm_seek12)
    if seek12_constants.get("x12") != 0xDA52AD6428210BE5:
        raise AssertionError("ARM64 +12 success state")
    if seek12_constants.get("x11") != 0xBA28CF6092893F26:
        raise AssertionError("ARM64 +12 failure state")

    arm_cd_offset_read = body(arm, 0x126388, 0x126478)
    for pattern, label in (
        (r"sub\s+x1,\s*x29,\s*#0x20", "ARM64 uint32 central offset destination"),
        (r"mov\s+w2,\s*#0x4", "ARM64 central offset size four"),
        (r"bl\s+(?:0x)?11f89c", "ARM64 central offset fread"),
    ):
        require(arm_cd_offset_read, pattern, label)
    cd_offset_constants = decode_arm_constants(arm_cd_offset_read)
    if cd_offset_constants.get("x11") != 0xCDCAE89F08F350C1:
        raise AssertionError("ARM64 central offset read-success state")

    arm_cd_seek = body(arm, 0x1262A0, 0x126388)
    require_order(arm_cd_seek, [
        "mov\tw3, wzr",
        "ldur\tw2, [x29, #-32]",
        "bl\t11f990",
    ], "ARM64 absolute central-directory seek")

    arm_cd_read = body(arm, 0x126570, 0x12665C)
    require_order(arm_cd_read, [
        "sub\tx1, x29, #0x1c",
        "mov\tw2, #0x4",
        "bl\t11f89c",
    ], "ARM64 central-directory signature read")
    require(arm, r"adr\s+x17,\s*(?:0x)?145f90", "ARM64 PK marker pointer")
    require(arm, r"mov\s+w13,\s*#0xa7", "ARM64 PK XOR key")
    require(arm, r"mov\s+w8,\s*#0x3", "ARM64 PK mismatch status 3")

    arm_seek_minus20 = body(arm, 0x127050, 0x12712C)
    require_order(arm_seek_minus20, [
        "mov\tx2, #0xffffffffffffffec",
        "mov\tw3, #0x1",
        "bl\t11f990",
    ], "ARM64 -20 SEEK_CUR")
    arm_magic_read = body(arm, 0x1267BC, 0x1268A8)
    require_order(arm_magic_read, [
        "sub\tx1, x29, #0x18",
        "mov\tw2, #0x10",
        "bl\t11f89c",
    ], "ARM64 magic read")
    require(arm, r"ldr\s+q0,\s*\[x11,\s*#4000\]", "ARM64 magic vector load")
    require(arm, r"movi\s+v1\.16b,\s*#0x3c", "ARM64 magic XOR key")
    require(arm, r"mov\s+w8,\s*#0x5", "ARM64 magic mismatch status 5")

    arm_seek_minus24 = body(arm, 0x126D08, 0x126E00)
    require_order(arm_seek_minus24, [
        "mov\tx2, #0xffffffffffffffe8",
        "mov\tw3, #0x1",
        "bl\t11f990",
    ], "ARM64 -24 SEEK_CUR")
    arm_tell = body(arm, 0x1261BC, 0x1262A0)
    require_order(arm_tell, [
        "ldr\tx2, [sp, #8]",
        "bl\t11fa74",
    ], "ARM64 owner+0x08 footer-offset ftell")
    arm_footer_read = body(arm, 0x126938, 0x126A24)
    require_order(arm_footer_read, [
        "mov\tw2, #0x8",
        "ldr\tx1, [sp, #16]",
        "bl\t11f89c",
    ], "ARM64 owner+0x10 footer-size read")
    arm_block_seek = body(arm, 0x126480, 0x126570)
    require_order(arm_block_seek, [
        "ldr\tx8, [x9, #16]",
        "mov\tw9, #0x8",
        "sub\tx2, x9, x8",
        "bl\t11f990",
    ], "ARM64 modulo-64-bit 8-size seek")
    arm_header_read = body(arm, 0x126A60, 0x126B4C)
    require_order(arm_header_read, [
        "sub\tx1, x29, #0x28",
        "mov\tw2, #0x8",
        "bl\t11f89c",
    ], "ARM64 duplicate header-size read")
    require(arm, r"ldr\s+x11,\s*\[x8\]", "ARM64 footer-size compare load")
    require(arm, r"cmp\s+x11,\s*x12", "ARM64 header/footer size equality")
    require(arm, r"mov\s+w8,\s*#0x6", "ARM64 size mismatch status 6")

    for pattern, label in (
        (r"call\s+(?:0x)?11d3b2", "x86_64 EOCD scanner"),
        (r"push\s+\$0xc.*call\s+(?:0x)?118937", "x86_64 +12 seek"),
        (r"lea\s+0x68\(%rsp\),%rsi.*push\s+\$0x4.*call\s+(?:0x)?1188b3",
         "x86_64 central offset read"),
        (r"mov\s+0x68\(%rsp\),%edx.*xor\s+%ecx,%ecx.*call\s+(?:0x)?118937",
         "x86_64 absolute central seek"),
        (r"lea\s+0x6c\(%rsp\),%rsi.*push\s+\$0x4.*call\s+(?:0x)?1188b3",
         "x86_64 central signature read"),
        (r"xorl\s+\$0xb6b6b6b6,.*13ea2c", "x86_64 PK decode"),
        (r"push\s+\$0xffffffffffffffec.*call\s+(?:0x)?118937",
         "x86_64 -20 seek"),
        (r"lea\s+0x70\(%rsp\),%rsi.*push\s+\$0x10.*call\s+(?:0x)?1188b3",
         "x86_64 magic read"),
        (r"xorps.*13ea30", "x86_64 magic decode"),
        (r"push\s+\$0xffffffffffffffe8.*call\s+(?:0x)?118937",
         "x86_64 -24 seek"),
        (r"mov\s+0x50\(%rsp\),%rdx.*call\s+(?:0x)?1189b2",
         "x86_64 owner+0x08 ftell"),
        (r"mov\s+0x18\(%rsp\),%rsi.*push\s+\$0x8.*call\s+(?:0x)?1188b3",
         "x86_64 owner+0x10 footer read"),
        (r"push\s+\$0x8.*sub\s+0x10\(%rax\),%rdx.*call\s+(?:0x)?118937",
         "x86_64 8-size seek"),
        (r"lea\s+0x60\(%rsp\),%rsi.*push\s+\$0x8.*call\s+(?:0x)?1188b3",
         "x86_64 header-size read"),
        (r"push\s+\$0x3", "x86_64 status 3"),
        (r"push\s+\$0x5", "x86_64 status 5"),
        (r"push\s+\$0x6", "x86_64 status 6"),
    ):
        require(x86, pattern, label)

    for symbol in (
        "RecoveredApkSigningBlockLocatorOperations1259b8",
        "runRecoveredApkSigningBlockLocator1259b8",
        "recoveredApkSigningBlockLocator1259b8Regression",
        "signingBlockFooterOffset",
        "signingBlockSize",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    cpp_start = CPP.index(
        "void runRecoveredApkSigningBlockLocator1259b8(\n"
        "        std::uint32_t* status,\n"
        "        RecoveredParserOwner125074* owner,\n"
        "        const RecoveredApkSigningBlockLocatorOperations1259b8& operations)"
    )
    cpp_end = CPP.index("\n}\n", cpp_start) + 3
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "operations.scanEocd(status, owner->stream)",
        "if (*status != 0) return",
        "12, SEEK_CUR",
        "centralDirectoryOffset",
        "SEEK_SET",
        "kRecoveredZipCentralDirectorySignature1259b8",
        "*status = 3",
        "-20, SEEK_CUR",
        "kRecoveredApkSigningBlockMagic1259b8",
        "*status = 5",
        "-24, SEEK_CUR",
        "&owner->signingBlockFooterOffset",
        "&owner->signingBlockSize",
        "std::uint64_t{8} - owner->signingBlockSize",
        "relativeOffset, SEEK_CUR",
        "headerSize",
        "*status = 6",
    ], "C++ locator operation order")
    require(
        GENERATOR,
        r"0x1259B8:.*APK Signing Block locator.*recovered",
        "0x1259b8 coverage entry",
    )

    print("ARM64/x86_64 PK 01 02 and APK Sig Block 42 decode: PASS")
    print("EOCD+12, absolute central-directory seek and signature status 3: PASS")
    print("-20 magic read/status 5 and -24 footer offset/size publication: PASS")
    print("modulo-64-bit 8-size seek, duplicate header read and status 6: PASS")
    print("C++ operation order, owner +0x08/+0x10 layout and regression hook: PASS")


if __name__ == "__main__":
    main()
