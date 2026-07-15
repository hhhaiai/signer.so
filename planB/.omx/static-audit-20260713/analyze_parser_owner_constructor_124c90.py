#!/usr/bin/env python3
"""Prove the public-source parser-owner constructor at ARM64 0x124c90."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
X86_DISASM = (HERE / "x86_64-full-objdump.txt").read_text(
    errors="replace"
)
ARM_BINARY = (
    ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
).read_bytes()
X86_BINARY = (
    ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
).read_bytes()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


def body(disassembly: str, start: int, end: int) -> str:
    lines: list[str] = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_order(text: str, addresses: list[str], label: str) -> None:
    positions = [text.find(f"{address}:") for address in addresses]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"invalid {label} order: {addresses}")


def require_token_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise AssertionError(f"invalid {label} order: {tokens}")
        cursor = position + len(token)


def decode_arm_constants(disassembly: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in disassembly.splitlines():
        mov = re.search(r"\bmov\s+(x\d+), #0x([0-9a-f]+)", line)
        if mov is not None:
            values[mov.group(1)] = int(mov.group(2), 16)
            continue
        movk = re.search(
            r"\bmovk\s+(x\d+), #0x([0-9a-f]+), lsl #([0-9]+)", line
        )
        if movk is not None:
            register = movk.group(1)
            shift = int(movk.group(3))
            mask = 0xFFFF << shift
            values[register] = (
                values.get(register, 0) & ~mask
            ) | (int(movk.group(2), 16) << shift)
    return values


def read_data(
    binary: bytes,
    address: int,
    size: int,
    section_address: int,
    section_offset: int,
) -> bytes:
    offset = section_offset + address - section_address
    return binary[offset:offset + size]


arm = body(ARM_DISASM, 0x124C90, 0x125074)
x86 = body(X86_DISASM, 0x11CB9C, 0x11CF06)

for pattern, label in (
    (r"124cbc:.*mov\s+w1, #0x4", "ARM64 R_OK argument"),
    (r"124cc0:.*bl\s+0x139e30 <access@plt>", "ARM64 access"),
    (r"124d40:.*csel\s+x28, x19, x27, eq", "ARM64 access result state"),
    (r"124ee[c-f]:.*adr\s+x1, 0x145f84", "ARM64 fopen mode address"),
    (r"124ef8:.*bl\s+0x139e90 <fopen@plt>", "ARM64 fopen"),
    (r"124f24:.*csel\s+x9, x22, x8, eq", "ARM64 fopen result state"),
    (r"124f50:.*", "ARM64 allocation failure block"),
    (r"124f58:.*mov\s+w10, #0x1", "ARM64 allocation status 1"),
    (r"124f74:.*", "ARM64 access/open failure block"),
    (r"124f7c:.*mov\s+w10, #0x2", "ARM64 access/open status 2"),
    (r"124fe4:.*mov\s+w0, #0x1", "ARM64 calloc count"),
    (r"124fe8:.*mov\s+w1, #0x48", "ARM64 calloc owner size"),
    (r"124fec:.*bl\s+0x139e50 <calloc@plt>", "ARM64 calloc"),
    (r"125004:.*csel\s+x9, x23, x21, eq", "ARM64 allocation result state"),
    (r"124ea0:.*str\s+x8, \[x25\], #0x38", "ARM64 stream store"),
    (r"124ea4:.*bl\s+0x122fdc", "ARM64 first owner initializer"),
    (r"124eac:.*bl\s+0x124a18", "ARM64 second owner initializer"),
    (r"124eb4:.*bl\s+0x124a18", "ARM64 third owner initializer"),
    (r"125050:.*mov\s+x0, x25", "ARM64 owner return"),
):
    require(arm, pattern, label)

require_order(
    arm,
    ["124cb4", "124cbc", "124cc0"],
    "ARM64 access block",
)
require_order(
    arm,
    ["124e94", "124ea0", "124ea4", "124ea8", "124eac", "124eb0", "124eb4"],
    "ARM64 initialization block",
)
require_order(
    arm,
    ["124ee4", "124eec", "124ef8"],
    "ARM64 fopen block",
)
require_order(
    arm,
    ["124fe4", "124fe8", "124fec"],
    "ARM64 calloc block",
)
if "fclose@plt" in arm:
    raise AssertionError("ARM64 constructor unexpectedly closes the stream")

for pattern, label in (
    (r"11cbd0:.*pushq\s+\$0x4", "x86_64 R_OK argument"),
    (r"11cbdb:.*callq\s+0x132860 <access@plt>", "x86_64 access"),
    (r"11cbf9:.*cmoveq\s+%rsi, %r12", "x86_64 access result state"),
    (r"11cd8a:.*# 0x13ea23", "x86_64 fopen mode address"),
    (r"11cd91:.*callq\s+0x1328c0 <fopen@plt>", "x86_64 fopen"),
    (r"11ce23:.*movl\s+\$0x1, \(%rax\)", "x86_64 allocation status 1"),
    (r"11ce30:.*movl\s+\$0x2, \(%rax\)", "x86_64 access/open status 2"),
    (r"11ce70:.*pushq\s+\$0x1", "x86_64 calloc count"),
    (r"11ce73:.*pushq\s+\$0x48", "x86_64 calloc owner size"),
    (r"11ce76:.*callq\s+0x132880 <calloc@plt>", "x86_64 calloc"),
    (r"11cec4:.*testq\s+%rax, %rax", "x86_64 allocation test"),
    (r"11cd03:.*movq\s+%rax, \(%r15\)", "x86_64 stream store"),
    (r"11cd06:.*leaq\s+0x18\(%r15\), %rdi", "x86_64 first owner offset"),
    (r"11cd0a:.*callq\s+0x11b433", "x86_64 first owner initializer"),
    (r"11cd0f:.*leaq\s+0x28\(%r15\), %rdi", "x86_64 second owner offset"),
    (r"11cd13:.*callq\s+0x11c96e", "x86_64 second owner initializer"),
    (r"11cd18:.*leaq\s+0x38\(%r15\), %rdi", "x86_64 third owner offset"),
    (r"11cd1c:.*callq\s+0x11c96e", "x86_64 third owner initializer"),
    (r"11cef2:.*movq\s+0x8\(%rsp\), %rax", "x86_64 owner return"),
):
    require(x86, pattern, label)

require_order(
    x86,
    ["11cbd0", "11cbd8", "11cbdb"],
    "x86_64 access block",
)
require_order(
    x86,
    ["11ccfe", "11cd03", "11cd06", "11cd0a", "11cd0f", "11cd13",
     "11cd18", "11cd1c"],
    "x86_64 initialization block",
)
require_order(
    x86,
    ["11cd85", "11cd8a", "11cd91"],
    "x86_64 fopen block",
)
require_order(
    x86,
    ["11ce70", "11ce73", "11ce76"],
    "x86_64 calloc block",
)
if "fclose@plt" in x86:
    raise AssertionError("x86_64 constructor unexpectedly closes the stream")

arm_constants = decode_arm_constants(body(ARM_DISASM, 0x124CC4, 0x124D58))
expected_arm_constants = {
    "x27": 0xA842E90BAE3495BB,  # access failure
    "x19": 0xFA920924ADA02EB9,  # access success
    "x12": 0x11219E0278DB95DD,  # initial dispatch
    "x20": 0xAD49ED3F14BB6C25,  # mode already decoded
    "x26": 0xC92BCD3FC878051B,  # mode guard acquired
    "x23": 0xD11BC7CB30FDBE0A,  # allocation failure
    "x21": 0xEE1E1596A9561665,  # allocation success
    "x22": 0x01B72BF9ACF894C8,  # fopen failure
}
if any(arm_constants.get(register) != value
       for register, value in expected_arm_constants.items()):
    raise AssertionError(f"ARM64 state constants mismatch: {arm_constants}")

for value in expected_arm_constants.values():
    require(
        x86,
        rf"imm = 0x{value:X}",
        f"x86_64 mirrored state 0x{value:016x}",
    )

arm_mode = read_data(
    ARM_BINARY, 0x145F84, 3, section_address=0x142E10,
    section_offset=0x13AE10,
)
x86_mode = read_data(
    X86_BINARY, 0x13EA23, 3, section_address=0x13B7E0,
    section_offset=0x1337E0,
)
if bytes(byte ^ 0xFE for byte in arm_mode) != b"rb\0":
    raise AssertionError(f"ARM64 mode decode mismatch: {arm_mode.hex()}")
if bytes(byte ^ 0x5D for byte in x86_mode) != b"rb\0":
    raise AssertionError(f"x86_64 mode decode mismatch: {x86_mode.hex()}")

for symbol in (
    "RecoveredParserOwnerCreateOperations124c90",
    "runRecoveredParserOwnerCreate124c90",
    "recoveredParserOwnerCreate124c90Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

create_start = CPP.index(
    "RecoveredParserOwner125074* runRecoveredParserOwnerCreate124c90(\n"
    "        std::uint32_t* status,\n"
    "        const char* path,\n"
    "        const RecoveredParserOwnerCreateOperations124c90& operations)"
)
create_end = CPP.index("\n}\n", create_start) + 3
create_body = CPP[create_start:create_end]
require_token_order(
    create_body,
    [
        "operations.checkAccess(path, R_OK)",
        "*status = 2",
        "operations.openStream(path, \"rb\")",
        "*status = 2",
        "operations.allocateOwner(1, sizeof(RecoveredParserOwner125074))",
        "*status = 1",
        "owner->stream = stream",
        "operations.initializeFirst(&owner->first)",
        "operations.initializeLarge(&owner->second)",
        "operations.initializeLarge(&owner->third)",
        "return owner",
    ],
    "C++ constructor operations",
)
if "close" in create_body.lower():
    raise AssertionError("C++ constructor must preserve allocation-failure leak")

for pattern, label in (
    (r"offsetof\(RecoveredParserOwner125074, stream\) == 0x00", "C++ stream offset"),
    (r"offsetof\(RecoveredParserOwner125074, first\) == 0x18", "C++ first offset"),
    (r"offsetof\(RecoveredParserOwner125074, second\) == 0x28", "C++ second offset"),
    (r"offsetof\(RecoveredParserOwner125074, third\) == 0x38", "C++ third offset"),
    (r"sizeof\(RecoveredParserOwner125074\) == 0x48", "C++ owner size"),
    (r"recoveredParserOwnerCreate124c90Regression\(\)", "C++ regression"),
):
    require(CPP, pattern, label)

require(
    GENERATOR,
    r"0x124C90:.*parser-owner constructor.*recovered",
    "0x124c90 coverage entry",
)

print("ARM64 0x124c90..0x125074 parser-owner constructor: PASS")
print("x86_64 0x11cb9c..0x11cf06 constructor parity: PASS")
print("R_OK, decoded rb mode, status 2/1 branches: PASS")
print("FILE* +0x00 and +0x18/+0x28/+0x38 initialization: PASS")
print("allocation-failure stream leak preserved and documented: PASS")
