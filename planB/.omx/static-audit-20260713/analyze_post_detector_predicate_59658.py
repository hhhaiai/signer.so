#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-59658-5a8e0.txt").read_text(errors="replace")
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
    def __init__(self, pairs):
        self.registers = [0] * 31
        self.sp = 0x800000
        self.memory = {}
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x59658
        self.steps = 0
        scratch = 0x100000
        self.registers[0] = scratch
        self.store(scratch + 0x870, len(pairs), 8)
        next_string = 0x200000
        for slot_index, pair in enumerate(pairs):
            for word_index, value in enumerate(pair):
                pointer = 0
                if value is not None:
                    pointer = next_string
                    next_string += 0x100
                    for byte_index, byte in enumerate(
                            value.encode("ascii") + b"\0"):
                        self.memory[pointer + byte_index] = byte
                self.store(scratch + 0x70 + slot_index * 0x10
                           + word_index * 8, pointer, 8)
        for index, byte in enumerate(b"microvirt\0"):
            self.memory[0x143368 + index] = byte
        # Model the already-published one-time decoder state.  The CAS lock
        # and decoded-state byte are separate globals in this function.
        self.memory[0x1464B4] = 0
        self.memory[0x1466DD] = 1

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


for pairs, expected in (
        ([], 0),
        ([(None, None)], 0),
        ([("", "")], 0),
        ([("microvirt", None)], 0),
        ([(None, "microvirt")], 0),
        ([("microvirt", "physical")], 0),
        ([("physical", "microvirt")], 0),
        ([("microvirt", "microvirt")], 1),
        ([("MICROVIRT", "microvirt")], 1),
        ([("prefix-microvirt", "microvirt-tail")], 1),
        ([("xmicrovirtx", "vendor-MICROVIRT")], 1),
        ([("microvir", "microvirt")], 0),
        ([("microvirt", "microvir")], 0),
        ([("physical", "physical"),
          ("microvirt-service", "vendor-microvirt")], 1),
        ([("microvirt", "physical"),
          ("physical", "microvirt")], 0),
        ([(None, None), ("microvirt", "microvirt")], 1)):
    assert VM(pairs).run() == expected, (pairs, expected)


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


assert bytes(value ^ 0x1D for value in virtual_bytes(
    0x143368, 10)) == b"microvirt\0"
for needle in (
        "5a0cc: f9443908     \tldr\tx8, [x8, #0x870]",
        "5a328: 8b091108     \tadd\tx8, x8, x9, lsl #4",
        "5a338: f940390c     \tldr\tx12, [x8, #0x70]",
        "5a844: f9403d0c     \tldr\tx12, [x8, #0x78]",
        "5a8d4: 12000100     \tand\tw0, w8, #0x1"):
    assert needle in TEXT, needle
for needle in (
        'kRecoveredPostDetectorMicrovirtMarker59658[] = "microvirt"',
        "bool runRecoveredMicrovirtPairPredicate59658(",
        "scratch->strings[index].value",
        "scratch->strings[index].secondaryValue08",
        "recoveredPostDetectorPredicate59658Regression()"):
    assert needle in CPP, needle

print("arm64 post-detector predicate 0x59658 evidence: PASS")
