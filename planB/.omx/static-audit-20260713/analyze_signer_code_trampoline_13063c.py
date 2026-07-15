#!/usr/bin/env python3
"""Interpret ARM64 0x13063c and verify the recovered trampoline scanner."""

from __future__ import annotations

import re
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TEXT = (HERE / "disasm-13063c-1309cc.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
MASK64 = (1 << 64) - 1


instructions: dict[int, tuple[str, str]] = {}
for line in TEXT.splitlines():
    match = re.match(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
        r"(.*?)(?:\s+//.*)?$",
        line,
    )
    if match:
        instructions[int(match.group(1), 16)] = (
            match.group(2), match.group(3).strip()
        )


def split_operands(source: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(source):
        if character == "[":
            depth += 1
        elif character == "]":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(source[start:index].strip())
            start = index + 1
    if source[start:].strip():
        result.append(source[start:].strip())
    return result


class VM:
    def __init__(self, tables: list[list[tuple[bytes, int]]]):
        self.registers = [0] * 31
        self.sp = 0x800000
        self.pc = 0x13063C
        self.memory: dict[int, int] = {}
        self.n = self.z = self.c = self.v = False
        self.steps = 0
        self.memcpy_lengths: list[int] = []
        self.tpidr = 0x900000
        self.store(self.tpidr + 0x28, 0x1122334455667788, 8)

        tables_base = 0x200000
        bounds_base = 0x210000
        self.store(0x13EC08, tables_base, 8)
        self.store(0x13EC10, bounds_base, 8)
        for table_index, entries in enumerate(tables):
            entries_base = 0x300000 + table_index * 0x1000
            self.store(tables_base + table_index * 8, entries_base, 8)
            upper_bound = max((bound for _, bound in entries), default=0)
            self.store(bounds_base + table_index * 8, upper_bound, 8)
            for entry_index, (code, bound) in enumerate(entries):
                code_address = 0x400000 + table_index * 0x1000 + entry_index * 0x100
                self.store(entries_base + entry_index * 8, code_address, 8)
                for offset, byte in enumerate(code):
                    self.memory[code_address + offset] = byte
                if bound >= 0:
                    self.store(bounds_base + table_index * 8,
                               code_address + bound, 8)
            self.store(entries_base + len(entries) * 8, 0, 8)
        self.store(tables_base + len(tables) * 8, 0, 8)

    def register(self, name: str) -> int:
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        match = re.fullmatch(r"([xw])(\d+)", name)
        assert match, name
        value = self.registers[int(match.group(2))]
        return value if match.group(1) == "x" else value & 0xFFFFFFFF

    def set_register(self, name: str, value: int) -> None:
        if name in ("xzr", "wzr"):
            return
        if name == "sp":
            self.sp = value & MASK64
            return
        match = re.fullmatch(r"([xw])(\d+)", name)
        assert match, name
        self.registers[int(match.group(2))] = (
            value & MASK64 if match.group(1) == "x" else value & 0xFFFFFFFF
        )

    def value(self, operand: str) -> int:
        if operand.startswith("#"):
            return int(operand[1:], 0)
        if operand.startswith("0x"):
            return int(operand.split()[0], 0)
        return self.register(operand)

    def address(self, operand: str) -> tuple[int, str]:
        match = re.fullmatch(r"\[(.*)\](!)?", operand)
        assert match, operand
        parts = [part.strip() for part in match.group(1).split(",")]
        base = parts[0]
        offset = 0
        if len(parts) > 1:
            offset = self.value(parts[1])
            if len(parts) > 2 and parts[2].startswith("lsl "):
                offset <<= int(parts[2].split("#")[1], 0)
        address = (self.register(base) + offset) & MASK64
        if match.group(2):
            self.set_register(base, address)
        return address, base

    def load(self, address: int, size: int) -> int:
        return sum(self.memory.get(address + index, 0) << (index * 8)
                   for index in range(size))

    def store(self, address: int, value: int, size: int) -> None:
        for index in range(size):
            self.memory[address + index] = (value >> (index * 8)) & 0xFF

    def compare(self, left: int, right: int, bits: int) -> None:
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        left &= mask
        right &= mask
        result = (left - right) & mask
        self.n = bool(result & sign)
        self.z = result == 0
        self.c = left >= right
        self.v = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def condition(self, name: str) -> bool:
        return {
            "eq": self.z,
            "ne": not self.z,
            "hi": self.c and not self.z,
            "lo": not self.c,
        }[name]

    def shifted_value(self, parts: list[str], index: int) -> int:
        value = self.value(parts[index])
        if len(parts) > index + 1 and parts[index + 1].startswith("lsl "):
            value <<= int(parts[index + 1].split("#")[1], 0)
        return value

    def run(self) -> tuple[bool, list[int]]:
        while self.steps < 200000:
            self.steps += 1
            operation, arguments = instructions[self.pc]
            parts = split_operands(arguments)
            next_pc = self.pc + 4

            if operation == "ret":
                return bool(self.register("w0") & 1), self.memcpy_lengths
            if operation == "b":
                self.pc = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                continue
            if operation.startswith("b."):
                if self.condition(operation[2:]):
                    self.pc = int(
                        re.search(r"0x([0-9a-f]+)", arguments).group(1), 16
                    )
                    continue
            elif operation == "bl":
                target = int(
                    re.search(r"0x([0-9a-f]+)", arguments).group(1), 16
                )
                if target != 0x13A0E0:
                    raise AssertionError(f"unexpected call {target:#x}")
                destination = self.register("x0")
                source = self.register("x1")
                length = self.register("x2")
                assert length <= self.register("x3") == 8
                self.memcpy_lengths.append(length)
                for offset in range(length):
                    self.memory[destination + offset] = self.memory.get(
                        source + offset, 0
                    )
                self.set_register("x0", destination)
            elif operation == "mrs":
                assert parts[1] == "TPIDR_EL0"
                self.set_register(parts[0], self.tpidr)
            elif operation == "adrp":
                self.set_register(parts[0], self.value(parts[1]))
            elif operation == "mov":
                self.set_register(parts[0], self.value(parts[1]))
            elif operation == "movk":
                shift = int(parts[2].split("#")[1]) if len(parts) > 2 else 0
                mask = 0xFFFF << shift
                value = (self.register(parts[0]) & ~mask) \
                    | (self.value(parts[1]) << shift)
                self.set_register(parts[0], value)
            elif operation in ("add", "sub"):
                right = self.shifted_value(parts, 2)
                value = self.value(parts[1]) + right \
                    if operation == "add" else self.value(parts[1]) - right
                self.set_register(parts[0], value)
            elif operation == "and":
                self.set_register(parts[0],
                                  self.value(parts[1]) & self.value(parts[2]))
            elif operation == "cmp":
                self.compare(self.value(parts[0]), self.value(parts[1]),
                             32 if parts[0].startswith("w") else 64)
            elif operation == "csel":
                self.set_register(
                    parts[0],
                    self.value(parts[1]) if self.condition(parts[3])
                    else self.value(parts[2]),
                )
            elif operation == "cset":
                self.set_register(parts[0], int(self.condition(parts[1])))
            elif operation in ("str", "stur", "ldr", "ldur"):
                address, _ = self.address(parts[1])
                size = 4 if parts[0].startswith("w") else 8
                if operation in ("str", "stur"):
                    self.store(address, self.register(parts[0]), size)
                else:
                    self.set_register(parts[0], self.load(address, size))
            elif operation in ("stp", "ldp"):
                address, base = self.address(parts[2])
                size = 4 if parts[0].startswith("w") else 8
                for index, name in enumerate(parts[:2]):
                    if operation == "stp":
                        self.store(address + index * size,
                                   self.register(name), size)
                    else:
                        self.set_register(name,
                                          self.load(address + index * size, size))
                if len(parts) > 3:
                    self.set_register(base,
                                      self.register(base) + self.value(parts[3]))
            else:
                raise AssertionError((hex(self.pc), operation, arguments))
            self.pc = next_pc
        raise AssertionError("instruction limit")


ordinary = bytes.fromhex("fd7bbfa9fd030091")
literal_branch = bytes.fromhex("5000005820021fd6")
literal_branch_link = bytes.fromhex("5000005820023fd6")

assert VM([]).run() == (False, [])
assert VM([[]]).run() == (False, [])
assert VM([[(ordinary, 8), (literal_branch_link, 8)]]).run() == (
    False, [8, 8]
)
assert VM([[(literal_branch, 7)]]).run() == (False, [7])
assert VM([[(literal_branch, 0)]]).run() == (False, [])
assert VM([[(ordinary, 8)], [(literal_branch, 8)]]).run() == (
    True, [8, 8]
)

for needle in (
    "kRecoveredSignerTrampolineMask13063c =\n        0xfffffc1fff000000ULL",
    "kRecoveredSignerTrampolineValue13063c =\n        0xd61f000058000000ULL",
    "recoveredSignerCodeEntryIsTrampoline13063c(",
    "runRecoveredSignerCodeTrampolineDetector13063c(",
    "recoveredSignerCodeTrampolineDetector13063cRegression()",
):
    assert needle in CPP, needle

(HERE / "arm64-signer-code-trampoline-13063c.md").write_text(
    """# ARM64 signer-code trampoline detector `0x13063c..0x1309cc`

The flattened FDE walks a null-terminated outer array of function-entry
tables. Each inner table is null-terminated and has a parallel upper address
bound. Entries at or beyond the bound are skipped. For every entry below its
bound, the native function zeroes an eight-byte local, copies
`min(upperBound - entry, 8)` bytes, and checks:

```text
(firstEightBytes & 0xfffffc1fff000000) == 0xd61f000058000000
```

In little-endian byte order this requires byte 3 to be `0x58` (ARM64 LDR
literal class) and the fixed opcode bits of bytes 4..7 to be an indirect
`BR Xn`; the register fields and LDR literal/register fields are ignored.
The first match returns true. Exhausting every table, null tables, entries at
the bound, truncated seven-byte entries, and `BLR` instead of `BR` return
false.

The static interpreter executes the original ARM64 instructions for empty,
miss, truncated, at-bound, and later-table-hit matrices and verifies the
native `__memcpy_chk(..., 8)` lengths.
"""
)

print("arm64 signer-code trampoline detector 0x13063c evidence: PASS")
