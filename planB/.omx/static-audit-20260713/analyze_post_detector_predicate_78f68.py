#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-78f68-7ba5c.txt").read_text(errors="replace")
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
    def __init__(self, fixed20=None, fixed30=None):
        self.registers = [0] * 31
        self.sp = 0x800000
        self.memory = {}
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x78F68
        self.steps = 0
        scratch = 0x100000
        self.registers[0] = scratch
        next_string = 0x200000
        for offset, value in ((0x20, fixed20), (0x30, fixed30)):
            pointer = 0
            if value is not None:
                pointer = next_string
                next_string += 0x100
                for byte_index, byte in enumerate(
                        value.encode("ascii") + b"\0"):
                    self.memory[pointer + byte_index] = byte
            self.store(scratch + offset, pointer, 8)
        markers = {
            0x1447C4: b"HWEVA\0",
            0x1447D0: b"eva-al00\0",
            0x1447E0: b"zerofltezc\0",
            0x1447F0: b":6.0.1/RB3N5C\0",
        }
        for address, marker in markers.items():
            for index, byte in enumerate(marker):
                self.memory[address + index] = byte
        for lock in (0x146220, 0x146224, 0x146228, 0x14622C):
            self.memory[lock] = 0
        for initialized in (0x14663D, 0x14663E, 0x14663F, 0x146640):
            self.memory[initialized] = 1

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
            "lo": not self.C,
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
                right = self.value(args[2])
                if len(args) > 3 and args[3].startswith("lsl "):
                    right <<= int(args[3].split("#")[1], 0)
                self.set_register(args[0],
                    self.value(args[1]) + right
                    if operation == "add" else self.value(args[1]) - right)
            elif operation in ("orr", "eor", "and"):
                # Vector XOR belongs only to the skipped decoder publication
                # path when the decoded-state byte is already set.
                if not args[0].startswith("v"):
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
                floating = args[0].startswith(("d", "s", "v", "q"))
                size = 4 if args[0].startswith("w") else 8
                for index, name in enumerate(args[:2]):
                    if operation == "stp":
                        self.store(address + index * size,
                            0 if floating else self.register(name), size)
                    elif not floating:
                        self.set_register(name,
                            self.load(address + index * size, size))
                if len(args) > 3:
                    self.set_register(base,
                        self.register(base) + self.value(args[3]))
            else:
                raise RuntimeError((hex(self.pc), operation, argument_text))
            self.pc = next_pc
        raise RuntimeError("step limit")


for fixed20, fixed30, expected in (
        (None, None, 0),
        ("", "", 0),
        ("physical", "physical", 0),
        ("HWEVA", None, 0),
        (None, ":6.0.1/RB3N5C", 0),
        ("HWEVA", ":6.0.1/RB3N5C", 1),
        ("eva-al00", ":6.0.1/RB3N5C", 1),
        ("zerofltezc", ":6.0.1/RB3N5C", 1),
        ("prefix-HWEVA-tail", "prefix-:6.0.1/rb3n5c-tail", 1),
        ("prefix-EVA-AL00-tail", ":6.0.1/RB3N5C", 1),
        ("prefix-ZEROFLTEZC-tail", ":6.0.1/RB3N5C", 1),
        ("HWEV", ":6.0.1/RB3N5C", 0),
        ("eva-al0", ":6.0.1/RB3N5C", 0),
        ("zerofltez", ":6.0.1/RB3N5C", 0),
        ("HWEVA", ":6.0.1/RB3N5", 0),
        (":6.0.1/RB3N5C", "HWEVA", 0)):
    assert VM(fixed20, fixed30).run() == expected, (
        fixed20, fixed30, expected)


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


for address, key, marker in (
        (0x1447C4, 0x38, b"HWEVA\0"),
        (0x1447D0, 0xFC, b"eva-al00\0"),
        (0x1447E0, 0x46, b"zerofltezc\0"),
        (0x1447F0, 0x66, b":6.0.1/RB3N5C\0")):
    assert bytes(value ^ key for value in virtual_bytes(
        address, len(marker))) == marker
for needle in (
        "7ad38: f940111e     \tldr\tx30, [x8, #0x20]",
        "7afec: f9401909     \tldr\tx9, [x8, #0x30]",
        "7ba30: 120002c0     \tand\tw0, w22, #0x1"):
    assert needle in TEXT, needle
for needle in (
        "kRecoveredPostDetectorDeviceMarkers78f68",
        '"HWEVA", "eva-al00", "zerofltezc"',
        'kRecoveredPostDetectorBuildFragment78f68[] =',
        '        ":6.0.1/RB3N5C"',
        "bool runRecoveredDeviceBuildPairPredicate78f68(",
        "scratch->fixedString20",
        "scratch->fixedString30",
        "recoveredPostDetectorPredicate78f68Regression()"):
    assert needle in CPP, needle

print("arm64 post-detector predicate 0x78f68 evidence: PASS")
