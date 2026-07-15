#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-6dbbc-6f758.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
MASK = (1 << 64) - 1


def operands(text):
    result, start, depth = [], 0, 0
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


INSTRUCTIONS = {}
for line in TEXT.splitlines():
    match = re.match(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
        r"(.*?)(?:\s+//.*)?$", line)
    if match:
        INSTRUCTIONS[int(match.group(1), 16)] = (
            match.group(2), match.group(3).strip())


class VM:
    def __init__(self, value):
        self.registers = [0] * 31
        self.sp = 0x800000
        self.memory = {}
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x6DBBC
        self.steps = 0
        scratch = 0x100000
        pointer = 0
        if value is not None:
            pointer = 0x200000
            for index, byte in enumerate(value.encode("ascii") + b"\0"):
                self.memory[pointer + index] = byte
        self.registers[0] = scratch
        self.store(scratch + 0x58, pointer, 8)
        for index, byte in enumerate(b"leapdroid\0"):
            self.memory[0x144710 + index] = byte
        # Model the already-published one-time decoder state.  The CAS target
        # is at 0x1461fc and the decoded-state byte read by the body is +1.
        self.memory[0x1461FC] = 0
        self.memory[0x1461FD] = 1

    def register(self, name):
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        match = re.fullmatch(r"([xw])(\d+)", name)
        assert match, name
        value = self.registers[int(match.group(2))]
        return value if match.group(1) == "x" else value & 0xFFFFFFFF

    def set_register(self, name, value):
        if name in ("xzr", "wzr"):
            return
        if name == "sp":
            self.sp = value & MASK
            return
        match = re.fullmatch(r"([xw])(\d+)", name)
        assert match, name
        self.registers[int(match.group(2))] = (
            value & MASK if match.group(1) == "x" else value & 0xFFFFFFFF)

    def value(self, operand):
        return (int(operand.lstrip("#"), 0) if operand.startswith("#")
                else self.register(operand))

    def address(self, operand):
        match = re.fullmatch(r"\[(.*)\](!)?", operand)
        assert match, operand
        parts = [part.strip() for part in match.group(1).split(",")]
        base, offset = parts[0], 0
        if len(parts) > 1:
            offset = self.value(parts[1])
            if len(parts) > 2 and parts[2].startswith("lsl "):
                offset <<= int(parts[2].split("#")[1], 0)
        address = (self.register(base) + offset) & MASK
        if match.group(2):
            self.set_register(base, address)
        return address, base

    def load(self, address, size):
        return sum(self.memory.get(address + index, 0) << (8 * index)
                   for index in range(size))

    def store(self, address, value, size):
        for index in range(size):
            self.memory[address + index] = (value >> (8 * index)) & 0xFF

    def sub_flags(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        result = (left - right) & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def add_flags(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        full, result = left + right, (left + right) & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = full > mask
        self.V = bool((~(left ^ right) & (left ^ result) & sign) != 0)

    def condition(self, name):
        return {
            "eq": self.Z,
            "ne": not self.Z,
            "lt": self.N != self.V,
            "ge": self.N == self.V,
            "lo": not self.C,
            "hs": self.C,
            "hi": self.C and not self.Z,
            "ls": not self.C or self.Z,
        }[name]

    def run(self):
        while self.steps < 2_000_000:
            self.steps += 1
            operation, argument_text = INSTRUCTIONS[self.pc]
            args = operands(argument_text)
            next_pc = self.pc + 4
            if operation == "ret":
                return self.register("w0") & 1
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
                assert target == 0x139800
                self.set_register("w0", 0)
            elif operation in ("nop", "movi"):
                pass
            elif operation == "mov":
                self.set_register(args[0], self.value(args[1]))
            elif operation == "movk":
                shift = int(args[2].split("#")[1]) if len(args) > 2 else 0
                mask = 0xFFFF << shift
                self.set_register(args[0],
                    (self.register(args[0]) & ~mask)
                    | (self.value(args[1]) << shift))
            elif operation in ("add", "sub"):
                self.set_register(args[0],
                    self.value(args[1]) + self.value(args[2])
                    if operation == "add"
                    else self.value(args[1]) - self.value(args[2]))
            elif operation in ("orr", "eor", "and"):
                # Vector XOR only belongs to the skipped decoder publication
                # path when the decoded-state byte is already set.
                if args[0].startswith("v"):
                    pass
                else:
                    left, right = self.value(args[1]), self.value(args[2])
                    self.set_register(args[0], {
                        "orr": left | right,
                        "eor": left ^ right,
                        "and": left & right,
                    }[operation])
            elif operation == "cmp":
                self.sub_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "cmn":
                self.add_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                result = self.value(args[0]) & self.value(args[1])
                bits = 32 if args[0].startswith("w") else 64
                self.N = bool(result & (1 << (bits - 1)))
                self.Z = result == 0
                self.C = self.V = 0
            elif operation == "ccmp":
                if self.condition(args[3]):
                    self.sub_flags(self.value(args[0]), self.value(args[1]),
                        32 if args[0].startswith("w") else 64)
                else:
                    nzcv = self.value(args[2])
                    self.N, self.Z = (nzcv >> 3) & 1, (nzcv >> 2) & 1
                    self.C, self.V = (nzcv >> 1) & 1, nzcv & 1
            elif operation == "csel":
                self.set_register(args[0], self.value(args[1])
                    if self.condition(args[3]) else self.value(args[2]))
            elif operation == "cset":
                self.set_register(args[0], 1 if self.condition(args[1]) else 0)
            elif operation in ("adr", "adrp"):
                self.set_register(args[0], int(re.search(
                    r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation in (
                    "str", "stur", "strb", "stlrb",
                    "ldr", "ldur", "ldrb"):
                address, base = self.address(args[1])
                floating = args[0].startswith(("d", "s", "v"))
                size = (1 if operation in ("strb", "stlrb", "ldrb")
                        else 4 if args[0].startswith(("w", "s")) else 8)
                if operation in ("str", "stur", "strb", "stlrb"):
                    self.store(address,
                        0 if floating else self.register(args[0]), size)
                elif not floating:
                    self.set_register(args[0], self.load(address, size))
                if len(args) > 2:
                    self.set_register(base,
                        self.register(base) + self.value(args[2]))
            elif operation in ("stp", "ldp"):
                address, base = self.address(args[2])
                size = 4 if args[0].startswith("w") else 8
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
        raise RuntimeError("step limit")


for value, expected in (
        (None, 0), ("", 0), ("leapdroid", 1), ("LEAPDROID", 1),
        ("prefix-leapdroid", 1), ("leapdroid-tail", 1),
        ("xleapdroidx", 1), ("leapdroi", 0), ("physical", 0),
        ("LEAP-DROID", 0)):
    assert VM(value).run() == expected, (value, expected)


image = SO.read_bytes()
program_offset = struct.unpack_from("<Q", image, 32)[0]
entry_size = struct.unpack_from("<H", image, 54)[0]
entry_count = struct.unpack_from("<H", image, 56)[0]


def virtual_bytes(address, size):
    for index in range(entry_count):
        fields = struct.unpack_from(
            "<IIQQQQQQ", image, program_offset + index * entry_size)
        if (fields[0] == 1 and fields[3] <= address
                and address + size <= fields[3] + fields[5]):
            start = fields[2] + address - fields[3]
            return image[start:start + size]
    raise AssertionError(hex(address))


assert bytes(value ^ 0xB7 for value in virtual_bytes(
    0x144710, 10)) == b"leapdroid\0"
for needle in (
        "6dbe4: f9402c03     \tldr\tx3, [x0, #0x58]",
        "6ea5c: 106ae5a8     \tadr\tx8, 0x144710",
        "6f74c: 12000100     \tand\tw0, w8, #0x1"):
    assert needle in TEXT, needle
for needle in (
        'kRecoveredPostDetectorLeapdroidMarker6dbbc[] = "leapdroid"',
        "bool runRecoveredLeapdroidPredicate6dbbc(",
        "+ 0x58",
        "recoveredAsciiCaseInsensitiveContains40ffc(",
        "recoveredPostDetectorPredicate6dbbcRegression()"):
    assert needle in CPP, needle

print("arm64 post-detector predicate 0x6dbbc evidence: PASS")
