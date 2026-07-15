#!/usr/bin/env python3
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
MAIN_TEXT = (AUDIT / "disasm-352d4-36bfc.txt").read_text(errors="replace")
HELPER_TEXT = (AUDIT / "disasm-36bfc-37340.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
MASK = (1 << 64) - 1
MARKERS = (
    "android",
    "android-x86",
    "android sdk built for x86",
    "android sdk built for x86_64",
    "generic_x86",
    "generic_x86_64",
)


def parse(text):
    instructions = {}
    for line in text.splitlines():
        match = re.match(
            r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
            r"(.*?)(?:\s+//.*)?$", line)
        if match:
            instructions[int(match.group(1), 16)] = (
                match.group(2), match.group(3).strip())
    return instructions


INSTRUCTIONS = parse(MAIN_TEXT)
INSTRUCTIONS.update(parse(HELPER_TEXT))


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
    return image, memory


IMAGE, BASE_MEMORY = load_image()


def load_segments():
    program_offset = struct.unpack_from("<Q", IMAGE, 32)[0]
    entry_size = struct.unpack_from("<H", IMAGE, 54)[0]
    entry_count = struct.unpack_from("<H", IMAGE, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        fields = struct.unpack_from("<IIQQQQQQ", IMAGE, offset)
        if fields[0] == 1:
            yield fields[2], fields[3], fields[5]


def virtual_bytes(address, size):
    for file_offset, virtual_address, file_size in load_segments():
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return IMAGE[start:start + size]
    raise AssertionError(hex(address))


for address, length, key, plaintext in (
        (0x144030, 8, 0xFB, b"android\0"),
        (0x144038, 12, 0xB6, b"android-x86\0"),
        (0x144050, 26, 0x42, b"android sdk built for x86\0"),
        (0x144070, 29, 0x99, b"android sdk built for x86_64\0"),
        (0x144090, 12, 0x04, b"generic_x86\0"),
        (0x1440A0, 15, 0x99, b"generic_x86_64\0")):
    assert bytes(value ^ key for value in virtual_bytes(address, length)) == plaintext


class VM:
    def __init__(
            self, start, fields=(None, None, None), helper_value=None,
            helper_pair=0, helper_length=None):
        self.registers = [0] * 31
        self.vectors = {index: bytearray(16) for index in range(32)}
        self.sp = 0x800000
        self.memory = dict(BASE_MEMORY)
        self.N = self.Z = self.C = self.V = 0
        self.pc = start
        self.steps = 0
        self.top_return = 0
        self.calls = []

        marker_addresses = (
            0x144030, 0x144038, 0x144050,
            0x144070, 0x144090, 0x1440A0)
        for address, marker in zip(marker_addresses, MARKERS):
            self.write_bytes(address, marker.encode("ascii") + b"\0")
        for index, address in enumerate(marker_addresses):
            self.store(0x146758 + index * 8, address, 8)
        for address in range(0x146670, 0x146676):
            self.memory[address] = 1

        next_string = 0x1010000
        if start == 0x352D4:
            scratch = 0x1000000
            self.registers[0] = scratch
            for offset, value in zip((0x10, 0x18, 0x20), fields):
                pointer = 0
                if value is not None:
                    pointer = next_string
                    self.write_bytes(pointer, value.encode("ascii") + b"\0")
                    next_string += 0x100
                self.store(scratch + offset, pointer, 8)
        else:
            value = helper_value if helper_value is not None else ""
            self.registers[0] = next_string
            self.registers[1] = (
                len(value) if helper_length is None else helper_length)
            self.registers[2] = 0x146758 + helper_pair * 0x10
            self.write_bytes(next_string, value.encode("ascii") + b"\0")

    def write_bytes(self, address, data):
        for index, value in enumerate(data):
            self.memory[address + index] = value

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
        return {
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
        }[name]

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
    def size(name):
        if name.startswith("q"):
            return 16
        if name.startswith("d"):
            return 8
        if name.startswith("w"):
            return 4
        return 8

    def run(self):
        while self.steps < 2_000_000:
            self.steps += 1
            operation, arguments = INSTRUCTIONS[self.pc]
            operands = split_operands(arguments)
            next_pc = self.pc + 4

            if operation == "ret":
                target = self.register("x30")
                if target == self.top_return:
                    return self.register("w0") & 1
                self.pc = target
                continue
            if operation == "b":
                self.pc = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                continue
            if operation.startswith("b."):
                if self.condition(operation[2:]):
                    self.pc = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                    continue
            elif operation == "bl":
                target = int(re.search(r"0x([0-9a-f]+)", arguments).group(1), 16)
                self.calls.append((self.pc, target))
                if target == 0x139800:
                    self.set_register("w0", 0)
                else:
                    assert target == 0x36BFC, (hex(self.pc), hex(target))
                    self.set_register("x30", next_pc)
                    self.pc = target
                    continue
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
            elif operation in ("orr", "eor", "and"):
                if operands[0].startswith("v"):
                    destination = int(operands[0].split(".")[0][1:])
                    left = int(operands[1].split(".")[0][1:])
                    right = int(operands[2].split(".")[0][1:])
                    self.vectors[destination] = bytearray(
                        a ^ b for a, b in zip(
                            self.vectors[left], self.vectors[right]))
                else:
                    left = self.value(operands[1])
                    right = self.value(operands[2])
                    self.set_register(operands[0], {
                        "orr": left | right,
                        "eor": left ^ right,
                        "and": left & right,
                    }[operation])
            elif operation == "cmp":
                self.sub_flags(
                    self.value(operands[0]), self.value(operands[1]),
                    32 if operands[0].startswith("w") else 64)
            elif operation == "cmn":
                self.add_flags(
                    self.value(operands[0]), self.value(operands[1]),
                    32 if operands[0].startswith("w") else 64)
            elif operation == "tst":
                result = self.value(operands[0]) & self.value(operands[1])
                bits = 32 if operands[0].startswith("w") else 64
                self.N = bool(result & (1 << (bits - 1)))
                self.Z = result == 0
                self.C = self.V = 0
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
            elif operation == "cset":
                self.set_register(
                    operands[0], 1 if self.condition(operands[1]) else 0)
            elif operation in ("adr", "adrp"):
                target = int(re.search(r"0x([0-9a-f]+)", operands[1]).group(1), 16)
                self.set_register(operands[0], target)
            elif operation == "movi":
                register = int(operands[0].split(".")[0][1:])
                value = self.immediate(operands[1]) & 0xFF
                self.vectors[register] = bytearray([value] * 16)
            elif operation in ("str", "stur", "strb", "stlrb"):
                address, base = self.address(operands[1])
                name = operands[0]
                if name.startswith(("q", "d")):
                    register = int(name[1:])
                    size = self.size(name)
                    self.write_bytes(address, self.vectors[register][:size])
                else:
                    size = 1 if operation in ("strb", "stlrb") else self.size(name)
                    self.store(address, self.register(name), size)
                if len(operands) > 2:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[2]))
            elif operation in ("ldr", "ldur", "ldrb"):
                address, base = self.address(operands[1])
                name = operands[0]
                if name.startswith(("q", "d")):
                    register = int(name[1:])
                    size = self.size(name)
                    self.vectors[register][:size] = bytes(
                        self.memory.get(address + index, 0)
                        for index in range(size))
                else:
                    size = 1 if operation == "ldrb" else self.size(name)
                    self.set_register(name, self.load(address, size))
                if len(operands) > 2:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[2]))
            elif operation in ("stp", "ldp"):
                size = self.size(operands[0])
                address, base = self.address(operands[2])
                names = operands[:2]
                for index, name in enumerate(names):
                    current = address + index * size
                    if operation == "stp":
                        if name.startswith(("q", "d")):
                            register = int(name[1:])
                            self.write_bytes(
                                current, self.vectors[register][:size])
                        else:
                            self.store(current, self.register(name), size)
                    elif name.startswith(("q", "d")):
                        register = int(name[1:])
                        self.vectors[register][:size] = bytes(
                            self.memory.get(current + byte_index, 0)
                            for byte_index in range(size))
                    else:
                        self.set_register(name, self.load(current, size))
                if len(operands) > 3:
                    self.set_register(
                        base, self.register(base) + self.immediate(operands[3]))
            else:
                raise RuntimeError((hex(self.pc), operation, arguments))
            self.pc = next_pc
        raise RuntimeError("step limit")


def helper(value, pair=0, length=None):
    return VM(
        0x36BFC, helper_value=value, helper_pair=pair,
        helper_length=length).run()


for pair, value, expected in (
        (0, "", 0),
        (0, "physical", 0),
        (0, "android", 1),
        (0, "ANDROID-X86", 1),
        (0, "prefix-ANDROID-X86-tail", 0),
        (1, "android sdk built for x86", 1),
        (1, "ANDROID SDK BUILT FOR X86_64", 1),
        (1, "prefix-android sdk built for x86-tail", 0),
        (2, "generic_x86", 1),
        (2, "GENERIC_X86_64", 1),
        (2, "prefix-generic_x86_64-tail", 0)):
    result = helper(value, pair)
    assert result == expected, (pair, value, result, expected)

assert helper("androidx", 0, 7) == 1
assert helper("android", 0, 8) == 0


def predicate(field10, field18, field20):
    vm = VM(0x352D4, fields=(field10, field18, field20))
    return vm.run(), vm.calls


CASES = (
    ((None, None, None), 0),
    (("physical", None, None), 0),
    (("android-x86", None, None), 1),
    ((None, "ANDROID SDK BUILT FOR X86_64", None), 1),
    ((None, None, "GENERIC_X86_64"), 1),
    (("prefix-android-x86", None, None), 0),
    (("physical", "android-x86", "physical"), 0),
)
for case, expected in CASES:
    result, calls = predicate(*case)
    assert result == expected, (case, result, expected, calls)

all_misses_result, all_misses_calls = predicate(
    "physical", "physical", "physical")
assert all_misses_result == 0
assert [site for site, target in all_misses_calls if target == 0x36BFC] == [
    0x3613C, 0x35D78, 0x35EEC]

first_hit_result, first_hit_calls = predicate(
    "ANDROID-X86", "android sdk built for x86", "generic_x86")
assert first_hit_result == 1
assert [site for site, target in first_hit_calls if target == 0x36BFC] == [
    0x3613C]

for needle in (
    "365ec: f9400914     \tldr\tx20, [x8, #0x10]",
    "36688: f9400d15     \tldr\tx21, [x8, #0x18]",
    "36254: f9401116     \tldr\tx22, [x8, #0x20]",
    "36130: 90000882     \tadrp\tx2, 0x146000",
    "36134: 911d6042     \tadd\tx2, x2, #0x758",
    "35d70: 911da042     \tadd\tx2, x2, #0x768",
    "35ee4: 911de042     \tadd\tx2, x2, #0x778",
    "3613c: 940002b0     \tbl\t0x36bfc",
    "35d78: 940003a1     \tbl\t0x36bfc",
    "35eec: 94000344     \tbl\t0x36bfc",
):
    assert needle in MAIN_TEXT, needle

for needle in (
    "36c18: f100005f     \tcmp\tx2, #0x0",
    "36c24: fa401824     \tccmp\tx1, #0x0, #0x4, ne",
    "37244: f8607a00     \tldr\tx0, [x16, x0, lsl #3]",
    "37150: 51016d50     \tsub\tw16, w10, #0x5b",
    "37154: 321b0140     \torr\tw0, w10, #0x20",
    "37174: 6b10001f     \tcmp\tw0, w16",
    "372ec: f1000a1f     \tcmp\tx16, #0x2",
):
    assert needle in HELPER_TEXT, needle

for needle in (
    "kRecoveredBuildIdentityMarkerPairs352d4",
    '{{"android", "android-x86"}}',
    '{{"android sdk built for x86", "android sdk built for x86_64"}}',
    '{{"generic_x86", "generic_x86_64"}}',
    "runRecoveredTwoMarkerEquality36bfc(",
    "runRecoveredBuildIdentityPredicate352d4(",
    "scratch->fixedString10",
    "scratch->fixedString18",
    "scratch->fixedString20",
    "recoveredDetectorPredicate352d4Regression()",
):
    assert needle in CPP, needle

print("arm64 detector predicate 0x352d4 and helper 0x36bfc evidence: PASS")
