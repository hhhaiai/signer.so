#!/usr/bin/env python3
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-4b020-4d9ac.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
MASK = (1 << 64) - 1


def split_operands(text):
    result = []
    start = 0
    depth = 0
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


def load_image():
    image = SO.read_bytes()
    memory = {}
    program_offset = struct.unpack_from("<Q", image, 32)[0]
    entry_size = struct.unpack_from("<H", image, 54)[0]
    entry_count = struct.unpack_from("<H", image, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        fields = struct.unpack_from("<IIQQQQQQ", image, offset)
        if fields[0] != 1:
            continue
        file_offset, virtual_address, file_size = fields[2], fields[3], fields[5]
        for byte_index, value in enumerate(
                image[file_offset:file_offset + file_size]):
            memory[virtual_address + byte_index] = value
    return memory


class VM:
    def __init__(self, field10, field20, score=0.25, count=1):
        self.registers = [0] * 31
        self.float_registers = {8: 0.0}
        self.sp = 0x800000
        self.memory = load_image()
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x4B020
        self.steps = 0
        self.trace = []

        self.scratch = 0x1000000
        self.score = 0x1001000
        self.corrections = 0x1002000
        self.count = 0x1003000
        self.registers[0] = self.scratch
        self.registers[1] = self.score
        self.registers[2] = self.corrections
        self.registers[3] = self.count
        self.store(self.score, struct.unpack("<I", struct.pack("<f", score))[0], 4)
        self.store(self.count, count, 8)
        self.store(self.corrections, 0xAAAA, 2)

        next_string = 0x1010000
        for offset, value in ((0x10, field10), (0x20, field20)):
            pointer = 0
            if value is not None:
                pointer = next_string
                data = value.encode("ascii") + b"\0"
                for byte_index, byte in enumerate(data):
                    self.memory[pointer + byte_index] = byte
                next_string += 0x100
            self.store(self.scratch + offset, pointer, 8)

        for address, plaintext in (
                (0x1443F0, b"apple\0"),
                (0x1443F8, b"iphone\0")):
            for byte_index, byte in enumerate(plaintext):
                self.memory[address + byte_index] = byte
        self.memory[0x1466B0] = 1
        self.memory[0x1466B1] = 1

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

    @staticmethod
    def immediate(value):
        return int(value.strip().lstrip("#"), 0)

    def value(self, operand):
        operand = operand.strip()
        return (self.immediate(operand) if operand.startswith("#")
                else self.register(operand))

    def condition(self, name):
        conditions = {
            "eq": self.Z == 1,
            "ne": self.Z == 0,
            "lt": self.N != self.V,
            "ge": self.N == self.V,
            "lo": self.C == 0,
            "hs": self.C == 1,
            "hi": self.C == 1 and self.Z == 0,
            "ls": self.C == 0 or self.Z == 1,
            "le": self.Z == 1 or self.N != self.V,
            "gt": self.Z == 0 and self.N == self.V,
        }
        return conditions[name]

    def sub_flags(self, left, right, bits):
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        left &= mask
        right &= mask
        result = (left - right) & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def add_flags(self, left, right, bits):
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

    def address(self, operand):
        match = re.fullmatch(r"\[(.*)\](!)?", operand)
        assert match, operand
        parts = [part.strip() for part in match.group(1).split(",")]
        base = parts[0]
        offset = 0
        if len(parts) > 1:
            if parts[1].startswith("#"):
                offset = self.immediate(parts[1])
            else:
                offset = self.register(parts[1])
                if len(parts) > 2 and parts[2].startswith("lsl "):
                    offset <<= self.immediate(parts[2].split()[1])
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

    @staticmethod
    def integer_size(register):
        if register.startswith("w"):
            return 4
        if register.startswith(("d", "s")):
            return 8 if register.startswith("d") else 4
        return 8

    def run(self):
        while self.steps < 2_000_000:
            self.steps += 1
            operation, arguments = INSTRUCTIONS[self.pc]
            operands = split_operands(arguments)
            next_pc = self.pc + 4

            if self.pc in (
                    0x4D14C, 0x4D4EC, 0x4D544, 0x4D6AC,
                    0x4CAAC, 0x4CB2C):
                self.trace.append(self.pc)

            if operation == "ret":
                break
            if operation == "b":
                self.pc = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                continue
            if operation.startswith("b."):
                if self.condition(operation[2:]):
                    self.pc = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                    continue
            elif operation == "bl":
                target = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                assert target == 0x139800, (hex(self.pc), hex(target))
                # This is the one-time decoder guard.  The probe preloads the
                # decoded bytes, so model the already-initialized return.
                self.set_register("w0", 0)
            elif operation == "nop":
                pass
            elif operation == "mov":
                self.set_register(operands[0], self.value(operands[1]))
            elif operation == "movk":
                shift = (int(operands[2].split("#")[1])
                         if len(operands) > 2 else 0)
                current = self.register(operands[0])
                value = self.immediate(operands[1])
                mask = 0xFFFF << shift
                self.set_register(
                    operands[0], (current & ~mask) | (value << shift))
            elif operation in ("add", "sub"):
                left = self.value(operands[1])
                right = self.value(operands[2])
                self.set_register(
                    operands[0], left + right if operation == "add"
                    else left - right)
            elif operation in ("orr", "eor"):
                left = self.value(operands[1])
                right = self.value(operands[2])
                self.set_register(
                    operands[0], left | right if operation == "orr"
                    else left ^ right)
            elif operation == "cmp":
                self.sub_flags(
                    self.value(operands[0]), self.value(operands[1]),
                    32 if operands[0].startswith("w") else 64)
            elif operation == "cmn":
                self.add_flags(
                    self.value(operands[0]), self.value(operands[1]),
                    32 if operands[0].startswith("w") else 64)
            elif operation == "ccmp":
                if self.condition(operands[3]):
                    self.sub_flags(
                        self.value(operands[0]), self.value(operands[1]),
                        32 if operands[0].startswith("w") else 64)
                else:
                    nzcv = self.immediate(operands[2])
                    self.N = (nzcv >> 3) & 1
                    self.Z = (nzcv >> 2) & 1
                    self.C = (nzcv >> 1) & 1
                    self.V = nzcv & 1
            elif operation == "csel":
                self.set_register(
                    operands[0], self.value(operands[1])
                    if self.condition(operands[3]) else self.value(operands[2]))
            elif operation in ("adr", "adrp"):
                target = int(re.search(r"0x([0-9a-f]+)", operands[1]).group(1), 16)
                self.set_register(operands[0], target)
            elif operation == "fmov":
                self.float_registers[int(operands[0][1:])] = float(
                    operands[1].lstrip("#"))
            elif operation in ("fsub", "fadd"):
                destination = int(operands[0][1:])
                left = self.float_registers[int(operands[1][1:])]
                right = self.float_registers[int(operands[2][1:])]
                self.float_registers[destination] = (
                    left - right if operation == "fsub" else left + right)
            elif operation in ("str", "stur", "strb", "strh", "stlrb"):
                address, base = self.address(operands[1])
                if operands[0].startswith("s"):
                    value = struct.unpack(
                        "<I", struct.pack("<f", self.float_registers[
                            int(operands[0][1:])]))[0]
                    size = 4
                elif operands[0].startswith("d"):
                    value = 0
                    size = 8
                else:
                    value = self.register(operands[0])
                    size = (1 if operation in ("strb", "stlrb") else
                            2 if operation == "strh" else
                            self.integer_size(operands[0]))
                self.store(address, value, size)
                if len(operands) > 2:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[2]))
            elif operation in ("ldr", "ldur", "ldrb"):
                address, base = self.address(operands[1])
                if operands[0].startswith("s"):
                    self.float_registers[int(operands[0][1:])] = struct.unpack(
                        "<f", struct.pack("<I", self.load(address, 4)))[0]
                elif operands[0].startswith("d"):
                    self.float_registers[int(operands[0][1:])] = 0.0
                else:
                    size = 1 if operation == "ldrb" else self.integer_size(operands[0])
                    self.set_register(operands[0], self.load(address, size))
                if len(operands) > 2:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[2]))
            elif operation in ("stp", "ldp"):
                size = self.integer_size(operands[0])
                address, base = self.address(operands[2])
                if operation == "stp":
                    first = (0 if operands[0].startswith(("s", "d"))
                             else self.register(operands[0]))
                    second = (0 if operands[1].startswith(("s", "d"))
                              else self.register(operands[1]))
                    self.store(address, first, size)
                    self.store(address + size, second, size)
                else:
                    self.set_register(operands[0], self.load(address, size))
                    self.set_register(operands[1], self.load(address + size, size))
                if len(operands) > 3:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[3]))
            else:
                raise RuntimeError((hex(self.pc), operation, arguments))
            self.pc = next_pc
        else:
            raise RuntimeError("step limit")

        score_bits = self.load(self.score, 4)
        return {
            "score": struct.unpack("<f", struct.pack("<I", score_bits))[0],
            "count": self.load(self.count, 8),
            "correction0": self.load(self.corrections, 2),
            "correction1": self.load(self.corrections + 2, 2),
            "steps": self.steps,
            "trace": [hex(address) for address in self.trace],
        }


for needle in (
    "4b044: f100005f     \tcmp\tx2, #0x0",
    "4b050: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "4b06c: f9000be3     \tstr\tx3, [sp, #0x10]",
    "4b094: f90003e1     \tstr\tx1, [sp]",
    "4b0c8: f90007e2     \tstr\tx2, [sp, #0x8]",
    "4b0cc: f90017e0     \tstr\tx0, [sp, #0x28]",
    "4d544: f940090e     \tldr\tx14, [x8, #0x10]",
    "4d6ac: f940110e     \tldr\tx14, [x8, #0x20]",
    "4c82c: 107bde3e     \tadr\tx30, 0x1443f0",
    "4c8bc: 107bd9fe     \tadr\tx30, 0x1443f8",
    "4c930: b94037ec     \tldr\tw12, [sp, #0x34]",
    "4c938: 51016d88     \tsub\tw8, w12, #0x5b",
    "4c93c: 321b0189     \torr\tw9, w12, #0x20",
    "4c95c: 6b0a013f     \tcmp\tw9, w10",
    "4cab0: 52800394     \tmov\tw20, #0x1c",
    "4caf8: f9000303     \tstr\tx3, [x24]",
    "4cb08: bd0003c0     \tstr\ts0, [x30]",
    "4cb2c: 782f7a74     \tstrh\tw20, [x19, x15, lsl #1]",
):
    assert needle in TEXT, needle

image = SO.read_bytes()


def virtual_bytes(address, size):
    program_offset = struct.unpack_from("<Q", image, 32)[0]
    entry_size = struct.unpack_from("<H", image, 54)[0]
    entry_count = struct.unpack_from("<H", image, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        fields = struct.unpack_from("<IIQQQQQQ", image, offset)
        if fields[0] != 1:
            continue
        file_offset, virtual_address, file_size = fields[2], fields[3], fields[5]
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return image[start:start + size]
    raise AssertionError(hex(address))


assert bytes(value ^ 0x83 for value in virtual_bytes(0x1443F0, 6)) == b"apple\0"
assert bytes(value ^ 0xC6 for value in virtual_bytes(0x1443F8, 7)) == b"iphone\0"


def result(field10, field20):
    return VM(field10, field20).run()


def matched(output):
    return (output["score"] == 1.0 and output["count"] == 2
            and output["correction0"] == 0xAAAA
            and output["correction1"] == 0x1C
            and "0x4caac" in output["trace"]
            and output["trace"][-1] == "0x4cb2c")


null_output = result(None, None)
assert null_output["score"] == 0.25 and null_output["count"] == 1
assert null_output["correction1"] == 0
assert null_output["trace"] == ["0x4d544", "0x4d6ac"]

physical_output = result("physical", "real-hardware")
assert physical_output["score"] == 0.25 and physical_output["count"] == 1
assert physical_output["correction1"] == 0

field10_apple = result("prefix-APPLE-suffix", "physical")
assert matched(field10_apple)
assert "0x4d544" in field10_apple["trace"]
assert "0x4d6ac" not in field10_apple["trace"]

assert matched(result("prefix-iPhOnE-tail", None))
assert matched(result(None, "prefix-apple-tail"))
assert matched(result(None, "prefix-IPHONE-tail"))

short_output = result("app", "iphon")
assert short_output["score"] == 0.25 and short_output["count"] == 1
assert short_output["correction1"] == 0

for needle in (
    "kRecoveredDetectorAppleIphoneMarkers4b020",
    '"apple", "iphone"',
    "runRecoveredAppleIphoneDetector4b020(",
    "scratch->fixedString10",
    "scratch->fixedString20",
    "recoveredAsciiCaseInsensitiveContains40ffc(value, marker)",
    "corrections[index] = 0x1c;",
    "recoveredAppleIphoneDetector4b020Regression()",
    '"prefix-APPLE-suffix"',
    '"prefix-iPhOnE-tail"',
):
    assert needle in CPP, needle

function_start = CPP.index("void runRecoveredAppleIphoneDetector4b020(")
count_store = CPP.index("*correctionCount = index + 1;", function_start)
score_store = CPP.index(
    "*score = (1.0F - currentScore) + currentScore;", count_store)
correction_store = CPP.index("corrections[index] = 0x1c;", score_store)
assert count_store < score_store < correction_store

print("arm64 apple/iphone detector 0x4b020 evidence: PASS")
