#!/usr/bin/env python3
"""Interpret ARM64 0xd78b8 proc-maps scanner with libc/getline stubs."""

from __future__ import annotations

import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-d78b8-db410.txt").read_text(errors="replace")
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1


def operands(text: str) -> list[str]:
    result: list[str] = []
    start = depth = 0
    for index, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    if text[start:].strip():
        result.append(text[start:].strip())
    return result


INSTRUCTIONS: dict[int, tuple[str, str]] = {}
for line in TEXT.splitlines():
    match = re.match(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
        r"(.*?)(?:\s+//.*)?$", line)
    if match:
        INSTRUCTIONS[int(match.group(1), 16)] = (
            match.group(2), match.group(3).strip())


image = SO.read_bytes()
program_offset = struct.unpack_from("<Q", image, 32)[0]
entry_size = struct.unpack_from("<H", image, 54)[0]
entry_count = struct.unpack_from("<H", image, 56)[0]
segments: list[tuple[int, int, int]] = []
for index in range(entry_count):
    fields = struct.unpack_from(
        "<IIQQQQQQ", image, program_offset + index * entry_size)
    if fields[0] == 1:
        segments.append((fields[2], fields[3], fields[5]))


def image_memory() -> dict[int, int]:
    result: dict[int, int] = {}
    for offset, address, size in segments:
        for index, byte in enumerate(image[offset:offset + size]):
            result[address + index] = byte
    return result


class VM:
    def __init__(self, lines: list[bytes] | None = None,
                 access_result: int = 0,
                 fopen_succeeds: bool = True,
                 initial_status: int = 0,
                 predecoded: bool = False,
                 memory_override: dict[int, int] | None = None):
        self.registers = [0] * 31
        self.vectors = [0] * 32
        self.sp = 0x900000
        self.memory = (image_memory() if memory_override is None
                       else dict(memory_override))
        self.N = self.Z = self.C = self.V = False
        self.pc = 0xD78B8
        self.steps = 0
        self.lines = list(lines or [])
        self.line_index = 0
        self.access_result = access_result
        self.fopen_succeeds = fopen_succeeds
        self.calls: list[tuple[str, object]] = []
        self.frees: list[int] = []
        self.next_allocation = 0x2000000

        self.thread = 0x1000000
        self.stack_guard = 0x1122334455667788
        self.status = 0x1001000
        self.path = 0x1002000
        self.file = 0x1003000
        self.store(self.thread + 0x28, self.stack_guard, 8)
        self.store(self.status, initial_status, 4)
        self.write_bytes(self.path, b"/proc/self/maps\0")
        self.registers[0] = self.status
        self.registers[1] = self.path
        if predecoded:
            self.memory[0x1458C0] ^= 0x85
            self.memory[0x1458C1] ^= 0x85
            self.memory[0x146B30] = 0
            self.memory[0x146B55] = 1
            for index in range(12):
                self.memory[0x1458C8 + index] ^= 0x45
            self.memory[0x146B34] = 0
            self.memory[0x146B56] = 1

    def register(self, name: str) -> int:
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        vector = re.fullmatch(r"([dqv])(\d+)(?:\.(?:2d|8b|16b))?", name)
        if vector:
            value = self.vectors[int(vector.group(2))]
            return value & (MASK64 if vector.group(1) == "d" else MASK128)
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
        vector = re.fullmatch(r"([dqv])(\d+)(?:\.(?:2d|8b|16b))?", name)
        if vector:
            index = int(vector.group(2))
            if vector.group(1) == "d":
                self.vectors[index] = (self.vectors[index] & ~MASK64) \
                        | (value & MASK64)
            else:
                self.vectors[index] = value & MASK128
            return
        match = re.fullmatch(r"([xw])(\d+)", name)
        assert match, name
        self.registers[int(match.group(2))] = (
            value & MASK64 if match.group(1) == "x"
            else value & 0xFFFFFFFF)

    def value(self, operand: str) -> int:
        return (int(operand.lstrip("#"), 0) if operand.startswith("#")
                else self.register(operand))

    def address(self, operand: str) -> tuple[int, str]:
        match = re.fullmatch(r"\[(.*)\](!)?", operand)
        assert match, operand
        parts = [part.strip() for part in match.group(1).split(",")]
        base = parts[0]
        offset = self.value(parts[1]) if len(parts) > 1 else 0
        if len(parts) > 2:
            assert parts[2].startswith("lsl #"), parts
            offset <<= int(parts[2].split("#")[1], 0)
        address = (self.register(base) + offset) & MASK64
        if match.group(2):
            self.set_register(base, address)
        return address, base

    def load(self, address: int, size: int) -> int:
        return sum(self.memory.get(address + index, 0) << (8 * index)
                   for index in range(size))

    def store(self, address: int, value: int, size: int) -> None:
        for index in range(size):
            self.memory[address + index] = (value >> (8 * index)) & 0xFF

    def write_bytes(self, address: int, value: bytes) -> None:
        for index, byte in enumerate(value):
            self.memory[address + index] = byte

    def c_string(self, address: int) -> str:
        data = bytearray()
        while self.memory.get(address + len(data), 0):
            data.append(self.memory[address + len(data)])
        return data.decode("ascii", errors="replace")

    def sub_flags(self, left: int, right: int, bits: int) -> None:
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        left &= mask
        right &= mask
        result = (left - right) & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def add_flags(self, left: int, right: int, bits: int) -> None:
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        left &= mask
        right &= mask
        full = left + right
        result = full & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = full > mask
        self.V = bool((~(left ^ right) & (left ^ result) & sign) != 0)

    def condition(self, name: str) -> bool:
        return {
            "eq": self.Z,
            "ne": not self.Z,
            "lt": self.N != self.V,
            "lo": not self.C,
            "hi": self.C and not self.Z,
        }[name]

    def _getline(self) -> None:
        output_pointer = self.register("x0")
        capacity_pointer = self.register("x1")
        if self.line_index >= len(self.lines):
            self.set_register("x0", MASK64)
            self.calls.append(("getline", -1))
            return
        data = self.lines[self.line_index]
        self.line_index += 1
        buffer = self.load(output_pointer, 8)
        capacity = self.load(capacity_pointer, 8)
        if buffer == 0 or capacity < len(data) + 1:
            buffer = self.next_allocation
            self.next_allocation += max(0x1000, len(data) + 1)
            capacity = len(data) + 1
            self.store(output_pointer, buffer, 8)
            self.store(capacity_pointer, capacity, 8)
        self.write_bytes(buffer, data + b"\0")
        self.set_register("x0", len(data))
        self.calls.append(("getline", data))

    def _call(self, target: int) -> None:
        if target == 0x139E30:
            self.calls.append(("access", {
                "path": self.c_string(self.register("x0")),
                "mode": self.register("w1"),
            }))
            self.set_register("w0", self.access_result)
        elif target == 0x139E90:
            self.calls.append(("fopen", {
                "path": self.c_string(self.register("x0")),
                "mode": self.c_string(self.register("x1")),
            }))
            self.set_register("x0", self.file if self.fopen_succeeds else 0)
        elif target == 0xD6ED8:
            self._getline()
        elif target == 0x139E60:
            self.calls.append(("fclose", self.register("x0")))
            self.set_register("w0", 0)
        elif target == 0x139DE0:
            pointer = self.register("x0")
            self.frees.append(pointer)
            self.calls.append(("free", pointer))
        elif target == 0x139800:
            address = self.register("x2")
            expected = self.register("w0") & 0xFF
            desired = self.register("w1") & 0xFF
            old = self.load(address, 1)
            if old == expected:
                self.store(address, desired, 1)
            self.set_register("w0", old)
        elif target == 0x139DF0:
            raise AssertionError("stack check failure")
        else:
            raise AssertionError((hex(self.pc), hex(target)))

    def run(self) -> dict[str, object]:
        while self.steps < 1_000_000:
            self.steps += 1
            operation, argument_text = INSTRUCTIONS[self.pc]
            args = operands(argument_text)
            next_pc = self.pc + 4
            if operation == "ret":
                return {
                    "result": self.register("w0"),
                    "status": self.load(self.status, 4),
                    "calls": self.calls,
                    "frees": self.frees,
                    "mode": self.c_string(0x1458C0),
                    "marker": self.c_string(0x1458C8),
                    "steps": self.steps,
                }
            if operation == "b":
                self.pc = int(re.search(
                    r"0x([0-9a-f]+)", argument_text).group(1), 16)
                continue
            if operation.startswith("b."):
                if self.condition(operation[2:]):
                    self.pc = int(re.search(
                        r"0x([0-9a-f]+)", argument_text).group(1), 16)
                    continue
            elif operation == "bl":
                target = int(re.search(
                    r"0x([0-9a-f]+)", argument_text).group(1), 16)
                self._call(target)
            elif operation == "nop":
                pass
            elif operation == "mrs":
                self.set_register(args[0], self.thread)
            elif operation == "movi":
                byte = self.value(args[1]) & 0xFF
                size = 16 if ".2d" in args[0] or ".16b" in args[0] else 8
                self.set_register(args[0],
                    int.from_bytes(bytes([byte]) * size, "little"))
            elif operation == "mov":
                self.set_register(args[0], self.value(args[1]))
            elif operation == "movk":
                shift = int(args[2].split("#")[1]) if len(args) > 2 else 0
                mask = 0xFFFF << shift
                self.set_register(args[0],
                    (self.register(args[0]) & ~mask)
                    | (self.value(args[1]) << shift))
            elif operation in ("add", "sub"):
                result = (self.value(args[1]) + self.value(args[2])
                          if operation == "add"
                          else self.value(args[1]) - self.value(args[2]))
                self.set_register(args[0], result)
            elif operation == "eor":
                self.set_register(args[0],
                    self.value(args[1]) ^ self.value(args[2]))
            elif operation == "orr":
                self.set_register(args[0],
                    self.value(args[1]) | self.value(args[2]))
            elif operation == "and":
                self.set_register(args[0],
                    self.value(args[1]) & self.value(args[2]))
            elif operation in ("lsl", "lsr"):
                value = self.value(args[1])
                shift = self.value(args[2]) & (
                    31 if args[0].startswith("w") else 63)
                self.set_register(args[0], value << shift
                    if operation == "lsl" else value >> shift)
            elif operation == "sxtb":
                value = self.value(args[1]) & 0xFF
                self.set_register(args[0],
                    value if value < 0x80 else value - 0x100)
            elif operation == "cmp":
                self.sub_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "cmn":
                self.add_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                value = self.value(args[0]) & self.value(args[1])
                bits = 32 if args[0].startswith("w") else 64
                self.N = bool(value & (1 << (bits - 1)))
                self.Z = value == 0
                self.C = self.V = False
            elif operation == "csel":
                self.set_register(args[0], self.value(args[1])
                    if self.condition(args[3]) else self.value(args[2]))
            elif operation == "cset":
                self.set_register(args[0], int(self.condition(args[1])))
            elif operation in ("adr", "adrp"):
                self.set_register(args[0], int(re.search(
                    r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation in (
                    "str", "stur", "strb", "sturb", "stlrb",
                    "ldr", "ldur", "ldrb", "ldurb"):
                address, base = self.address(args[1])
                size = (1 if operation in (
                            "strb", "sturb", "stlrb", "ldrb", "ldurb")
                        else 16 if args[0].startswith("q")
                        else 8 if args[0].startswith(("x", "d")) else 4)
                if operation in ("str", "stur", "strb", "sturb", "stlrb"):
                    self.store(address, self.register(args[0]), size)
                else:
                    self.set_register(args[0], self.load(address, size))
                if len(args) > 2:
                    self.set_register(base,
                        self.register(base) + self.value(args[2]))
            elif operation in ("stp", "ldp"):
                address, base = self.address(args[2])
                size = (16 if args[0].startswith("q")
                        else 8 if args[0].startswith(("x", "d")) else 4)
                for index, name in enumerate(args[:2]):
                    if operation == "stp":
                        self.store(address + index * size,
                                   self.register(name), size)
                    else:
                        self.set_register(name,
                            self.load(address + index * size, size))
                if len(args) > 3:
                    self.set_register(base,
                        self.register(base) + self.value(args[3]))
            else:
                raise RuntimeError((hex(self.pc), operation, argument_text))
            self.pc = next_pc
        raise RuntimeError(("step limit", hex(self.pc), self.calls[-8:],
                            self.line_index, hex(self.register("x17"))))


def execute(**kwargs: object) -> dict[str, object]:
    return VM(**kwargs).run()


cases = {
    "empty": execute(predecoded=True),
    "coldMarker": execute(lines=[b"frida-agent\n"]),
    "ordinary": execute(lines=[
        b"70000000-70001000 r-xp 0000 00:00 0 /data/app/base.apk\n"],
        predecoded=True),
    "marker": execute(lines=[
        b"70000000-70001000 r-xp 0000 00:00 0 /data/local/tmp/frida-agent-64.so\n"],
        predecoded=True),
    "caseMismatch": execute(lines=[b"/data/local/tmp/Frida-agent.so\n"],
                            predecoded=True),
    "prefix": execute(lines=[b"frida-agent\n"], predecoded=True),
    "accessFailure": execute(access_result=-1, predecoded=True),
    "fopenFailure": execute(fopen_succeeds=False, predecoded=True),
    "preexistingStatus": execute(initial_status=77, predecoded=True),
}

for name, result in cases.items():
    assert result["mode"] == "r"
    assert result["marker"] == "frida-agent"

assert cases["marker"]["result"] == 1
assert cases["prefix"]["result"] == 1
assert cases["coldMarker"]["result"] == 1
for name in ("empty", "ordinary", "caseMismatch", "accessFailure",
             "fopenFailure", "preexistingStatus"):
    assert cases[name]["result"] == 0, (name, cases[name])
assert cases["accessFailure"]["status"] == 8
assert [call[0] for call in cases["accessFailure"]["calls"]] == ["access"]
assert cases["fopenFailure"]["status"] == 8
assert [call[0] for call in cases["fopenFailure"]["calls"]] == [
    "access", "fopen"]
assert cases["preexistingStatus"]["status"] == 77
assert [call[0] for call in cases["marker"]["calls"]] == [
    "access", "fopen", "getline", "free", "fclose"]
assert cases["empty"]["frees"] == []
assert len(cases["ordinary"]["frees"]) == 1

CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
for needle in (
        "struct RecoveredProcMapsFridaScannerOperationsD78b8",
        "runRecoveredProcMapsFridaScannerD78b8(",
        'operations.access(path, 4)',
        'operations.open(path, "r")',
        'std::strstr(line, "frida-agent")',
        "recoveredProcMapsFridaScannerD78b8Regression()"):
    assert needle in CPP, needle

(AUDIT / "arm64-proc-maps-frida-scanner-d78b8.md").write_text("""# ARM64 proc-maps Frida scanner `0xd78b8..0xdb410`

## Status

Recovered by complete flattened-FDE interpretation with stubbed file/libc
operations. The interpreter does not load or execute `libsigner.so`.

## Exact behavior

1. Preserve the incoming status unless an open precondition fails.
2. Call `access(path, R_OK=4)`; failure writes status `8` and returns false.
3. Call `fopen(path, "r")`; null writes status `8` and returns false.
4. Repeatedly call the local getline-compatible helper `0xd6ed8`.
5. Search each NUL-terminated line for the case-sensitive substring
   `frida-agent`; a match returns true and stops before another read.
6. Free a non-null owned line buffer, then call `fclose`; EOF and close failure
   do not change status.

The one-time decoded literals are exactly `r` (XOR `0x85`) and
`frida-agent` (XOR `0x45`). The direct C++ execution form is
`runRecoveredProcMapsFridaScannerD78b8()`, with callback regression coverage
in `recoveredProcMapsFridaScannerD78b8Regression()`.
""")

print("arm64 proc maps scanner 0xd78b8 full evidence: PASS")
