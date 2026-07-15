#!/usr/bin/env python3
"""Prove the composite parser-owner destructor at ARM64 0x125074."""

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
    positions = [text.find(token) for token in tokens]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"invalid {label} order: {tokens}")


def decode_arm_constants(prologue: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in prologue.splitlines():
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


def decode_x86_constants(prologue: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in prologue.splitlines():
        match = re.search(
            r"movabsq.*%(r[a-z0-9]+).*# imm = 0x([0-9a-f]+)",
            line,
            re.IGNORECASE,
        )
        if match is not None:
            values[match.group(1)] = int(match.group(2), 16)
    return values


START = 0xBD90B4B110236D42
LOAD_STREAM = 0xB32DD9062098C8BA
NULL_OWNER = 0x0C2EF5AD806EEE04
STREAM_PRESENT = 0xFC5400BB3FC18FA8
STREAM_ABSENT = 0x2F061C6B0CBAC6F7
DESTROY = 0xDCEADCCBE705FD3C
RETURN = 0x969C524878CFE7A5


def destructor_events(owner_present: bool, stream_present: bool) -> list[str]:
    state = START
    events: list[str] = []
    while state != RETURN:
        if state == START:
            state = LOAD_STREAM if owner_present else NULL_OWNER
        elif state == NULL_OWNER:
            state = RETURN
        elif state == LOAD_STREAM:
            state = STREAM_PRESENT if stream_present else STREAM_ABSENT
        elif state == STREAM_PRESENT:
            events.extend(("fclose", "clear-stream"))
            state = DESTROY
        elif state == STREAM_ABSENT:
            state = DESTROY
        elif state == DESTROY:
            events.extend((
                "destroy-0x18",
                "destroy-0x28",
                "destroy-0x38",
                "free",
            ))
            state = RETURN
        else:
            raise AssertionError(f"unknown state 0x{state:016x}")
    return events


arm = body(ARM_DISASM, 0x125074, 0x125210)
arm_first_alias = body(ARM_DISASM, 0x122FE4, 0x122FE8)
arm_large_alias = body(ARM_DISASM, 0x124A20, 0x124A24)
x86 = body(X86_DISASM, 0x11CF06, 0x11D040)
x86_first_alias = body(X86_DISASM, 0x11B43C, 0x11B441)
x86_large_alias = body(X86_DISASM, 0x11C977, 0x11C97C)

for pattern, label in (
    (r"125094:.*add\s+x8, x0, #0x18", "ARM64 first owner +0x18"),
    (r"125098:.*add\s+x9, x0, #0x28", "ARM64 second owner +0x28"),
    (r"1250b0:.*add\s+x8, x0, #0x38", "ARM64 third owner +0x38"),
    (r"1250f8:.*cmp\s+x0, #0x0", "ARM64 null-owner test"),
    (r"125170:.*ldr\s+x23, \[x19\]", "ARM64 stream load"),
    (r"125174:.*cmp\s+x23, #0x0", "ARM64 null-stream test"),
    (r"12518c:.*bl\s+0x122fe4", "ARM64 first owner destroy"),
    (r"125194:.*bl\s+0x124a20", "ARM64 second owner destroy"),
    (r"12519c:.*bl\s+0x124a20", "ARM64 third owner destroy"),
    (r"1251a4:.*bl\s+0x139de0", "ARM64 outer free"),
    (r"1251c0:.*bl\s+0x139e60", "ARM64 fclose"),
    (r"1251c8:.*str\s+xzr, \[x19\]", "ARM64 stream clear"),
):
    require(arm, pattern, label)

require_order(
    arm,
    ["125188", "12518c", "125190", "125194", "125198", "12519c", "1251a0", "1251a4"],
    "ARM64 embedded destruction",
)
require(arm_first_alias, r"122fe4:.*b\s+0x122bb8", "ARM64 first alias")
require(arm_large_alias, r"124a20:.*b\s+0x124608", "ARM64 large alias")

for pattern, label in (
    (r"11cf28:.*leaq\s+0x18\(%rdi\), %rax", "x86_64 first owner +0x18"),
    (r"11cf31:.*leaq\s+0x28\(%rdi\), %rax", "x86_64 second owner +0x28"),
    (r"11cf3a:.*leaq\s+0x38\(%rdi\), %rax", "x86_64 third owner +0x38"),
    (r"11cf48:.*testq\s+%rdi, %rdi", "x86_64 null-owner test"),
    (r"11cfba:.*movq\s+\(%rax\), %rax", "x86_64 stream load"),
    (r"11cfc2:.*testq\s+%rax, %rax", "x86_64 null-stream test"),
    (r"11cfda:.*callq\s+0x11b43c", "x86_64 first owner destroy"),
    (r"11cfe4:.*callq\s+0x11c977", "x86_64 second owner destroy"),
    (r"11cfee:.*callq\s+0x11c977", "x86_64 third owner destroy"),
    (r"11cff8:.*callq\s+0x132810 <free@plt>", "x86_64 outer free"),
    (r"11d011:.*callq\s+0x132890 <fclose@plt>", "x86_64 fclose"),
    (r"11d025:.*andq\s+\$0x0, \(%rax\)", "x86_64 stream clear"),
):
    require(x86, pattern, label)

require_order(
    x86,
    ["11cfd5", "11cfda", "11cfdf", "11cfe4", "11cfe9", "11cfee", "11cff3", "11cff8"],
    "x86_64 embedded destruction",
)
require(x86_first_alias, r"11b43c:.*jmp\s+0x11b0d8", "x86_64 first alias")
require(x86_large_alias, r"11c977:.*jmp\s+0x11c5fe", "x86_64 large alias")

arm_constants = decode_arm_constants(body(ARM_DISASM, 0x12509C, 0x125134))
x86_constants = decode_x86_constants(body(X86_DISASM, 0x11CF14, 0x11CF89))
expected_arm = {
    "x20": START,
    "x26": LOAD_STREAM,
    "x27": NULL_OWNER,
    "x21": STREAM_PRESENT,
    "x22": STREAM_ABSENT,
    "x24": DESTROY,
    "x25": RETURN,
}
expected_x86 = {
    "r13": START,
    "r12": LOAD_STREAM,
    "rcx": NULL_OWNER,
    "r15": STREAM_PRESENT,
    "rbx": STREAM_ABSENT,
    "rbp": DESTROY,
    "r14": RETURN,
}
if any(arm_constants.get(register) != value
       for register, value in expected_arm.items()):
    raise AssertionError(f"ARM64 state constants mismatch: {arm_constants}")
if any(x86_constants.get(register) != value
       for register, value in expected_x86.items()):
    raise AssertionError(f"x86_64 state constants mismatch: {x86_constants}")

assert destructor_events(False, False) == []
assert destructor_events(False, True) == []
assert destructor_events(True, False) == [
    "destroy-0x18", "destroy-0x28", "destroy-0x38", "free"
]
assert destructor_events(True, True) == [
    "fclose", "clear-stream", "destroy-0x18", "destroy-0x28",
    "destroy-0x38", "free"
]

for symbol in (
    "RecoveredParserOwner125074",
    "RecoveredParserOwnerDestroyOperations125074",
    "runRecoveredParserOwnerDestroy125074",
    "recoveredParserOwnerDestroy125074Regression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

default_operations_start = CPP.index(
    "recoveredParserOwnerDestroyOperations125074()"
)
default_operations_end = CPP.index("\n}\n", default_operations_start) + 3
default_operations = CPP[default_operations_start:default_operations_end]
require_token_order(
    default_operations,
    [
        "recoveredParserOwnerCloseStream125074",
        "runRecoveredContainerListDestroy122fe4",
        "runRecoveredLargeContainerListDestroy124a20",
        "recoveredParserOwnerRelease125074",
    ],
    "C++ canonical operations",
)

destroy_start = CPP.index(
    "void runRecoveredParserOwnerDestroy125074(\n"
    "        RecoveredParserOwner125074* owner,\n"
    "        const RecoveredParserOwnerDestroyOperations125074& operations)"
)
destroy_end = CPP.index("\n}\n", destroy_start) + 3
destroy_body = CPP[destroy_start:destroy_end]
require_token_order(
    destroy_body,
    [
        "operations.closeStream(owner->stream)",
        "owner->stream = nullptr",
        "operations.destroyFirst(&owner->first)",
        "operations.destroyLarge(&owner->second)",
        "operations.destroyLarge(&owner->third)",
        "operations.releaseOwner(owner)",
    ],
    "C++ destructor operations",
)

for pattern, label in (
    (r"offsetof\(RecoveredParserOwner125074, stream\) == 0x00", "C++ stream offset"),
    (r"offsetof\(RecoveredParserOwner125074, first\) == 0x18", "C++ first offset"),
    (r"offsetof\(RecoveredParserOwner125074, second\) == 0x28", "C++ second offset"),
    (r"offsetof\(RecoveredParserOwner125074, third\) == 0x38", "C++ third offset"),
    (r"sizeof\(RecoveredParserOwner125074\) == 0x48", "C++ owner size"),
    (r"operations\.closeStream\(owner->stream\)", "C++ close operation"),
    (r"owner->stream = nullptr", "C++ stream clear"),
    (r"operations\.destroyFirst\(&owner->first\)", "C++ first destruction"),
    (r"operations\.destroyLarge\(&owner->second\)", "C++ second destruction"),
    (r"operations\.destroyLarge\(&owner->third\)", "C++ third destruction"),
    (r"operations\.releaseOwner\(owner\)", "C++ outer release"),
):
    require(CPP, pattern, label)

require(
    GENERATOR,
    r"0x125074:.*composite parser-owner destructor.*recovered",
    "0x125074 coverage entry",
)

print("ARM64 0x125074..0x125210 parser-owner evidence: PASS")
print("x86_64 0x11cf06..0x11d040 parser-owner evidence: PASS")
print("null owner no-op: PASS")
print("stream close/clear before +0x18/+0x28/+0x38/free: PASS")
