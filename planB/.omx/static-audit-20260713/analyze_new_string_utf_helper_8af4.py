#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-8af4-a334.txt").read_text(errors="replace")
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


image = SO.read_bytes()
program_offset = struct.unpack_from("<Q", image, 32)[0]
entry_size = struct.unpack_from("<H", image, 54)[0]
entry_count = struct.unpack_from("<H", image, 56)[0]
segments = []
for index in range(entry_count):
    fields = struct.unpack_from(
        "<IIQQQQQQ", image, program_offset + index * entry_size)
    if fields[0] == 1:
        segments.append((fields[2], fields[3], fields[5]))


def image_memory():
    result = {}
    for offset, address, size in segments:
        for index, byte in enumerate(image[offset:offset + size]):
            result[address + index] = byte
    return result


class VM:
    def __init__(self, input_value, initial_status=0,
                 new_string_result=0x500000, exception_pending=False,
                 predecoded=False):
        self.registers = [0] * 31
        self.vectors = [0] * 32
        self.sp = 0x800000
        self.memory = image_memory()
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x8AF4
        self.steps = 0
        self.new_string_result = new_string_result
        self.exception_pending = exception_pending
        self.new_string_input = None
        self.exception_checks = 0

        status = 0x1000000
        environment = 0x1001000
        vtable = 0x1002000
        output = 0x1003000
        input_pointer = 0
        if input_value is not None:
            input_pointer = 0x1004000
            for index, byte in enumerate(input_value.encode("ascii") + b"\0"):
                self.memory[input_pointer + index] = byte
        self.store(status, initial_status, 4)
        self.store(environment, vtable, 8)
        self.store(vtable + 0x538, 0xF00D0001, 8)
        self.store(output, 0xDEADBEEF, 8)
        self.registers[0] = status
        self.registers[1] = environment
        self.registers[2] = input_pointer
        self.registers[3] = output
        self.status = status
        self.output = output

        if predecoded:
            decoded = {
                0x142E90: b"secret_id\0",
                0x142EA0: b"1400000\0",
                0x142EA8: b"headers_id\0",
                0x142EB4: b"9\0",
                0x142EB8: b"native_version\0",
                0x142EC8: b"3.67.0\0",
            }
            for address, value in decoded.items():
                for index, byte in enumerate(value):
                    self.memory[address + index] = byte
            for flag in range(0x146179, 0x14617F):
                self.memory[flag] = 1

    def register(self, name):
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        vector = re.fullmatch(r"[dv](\d+)(?:\.8b)?", name)
        if vector:
            return self.vectors[int(vector.group(1))]
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
        vector = re.fullmatch(r"[dv](\d+)(?:\.8b)?", name)
        if vector:
            self.vectors[int(vector.group(1))] = value & MASK
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

    def c_string(self, address):
        if address == 0:
            return None
        result = bytearray()
        while self.memory.get(address + len(result), 0) != 0:
            result.append(self.memory[address + len(result)])
        return result.decode("ascii")

    def sub_flags(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        result = (left - right) & mask
        self.N = bool(result & sign)
        self.Z = result == 0
        self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def condition(self, name):
        return {"eq": self.Z, "ne": not self.Z}[name]

    def run(self):
        while self.steps < 2_000_000:
            self.steps += 1
            operation, argument_text = INSTRUCTIONS[self.pc]
            args = operands(argument_text)
            next_pc = self.pc + 4
            if operation == "ret":
                return {
                    "return": self.register("w0") & 1,
                    "status": self.load(self.status, 4),
                    "output": self.load(self.output, 8),
                    "new_string_input": self.new_string_input,
                    "exception_checks": self.exception_checks,
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
                if target == 0x92A20:
                    self.exception_checks += 1
                    self.set_register("w0", 1 if self.exception_pending else 0)
                elif target == 0x139800:
                    address = self.register("x2")
                    expected = self.register("w0") & 0xFF
                    desired = self.register("w1") & 0xFF
                    old = self.load(address, 1)
                    if old == expected:
                        self.store(address, desired, 1)
                    self.set_register("w0", old)
                else:
                    raise AssertionError((hex(self.pc), hex(target)))
            elif operation == "blr":
                assert self.register(args[0]) == 0xF00D0001
                self.new_string_input = self.c_string(self.register("x1"))
                self.set_register("x0", self.new_string_result)
            elif operation == "movi":
                byte = self.value(args[1]) & 0xFF
                self.set_register(args[0], int.from_bytes(bytes([byte]) * 8,
                                                          "little"))
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
                    if operation == "add" else self.value(args[1]) - self.value(args[2]))
            elif operation in ("and", "eor"):
                left, right = self.value(args[1]), self.value(args[2])
                self.set_register(args[0],
                    left & right if operation == "and" else left ^ right)
            elif operation == "cmp":
                self.sub_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                value = self.value(args[0]) & self.value(args[1])
                self.N = bool(value & (1 << 31))
                self.Z = value == 0
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
            elif operation == "adrp":
                self.set_register(args[0], int(re.search(
                    r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation in (
                    "str", "stur", "strb", "stlrb",
                    "ldr", "ldur", "ldrb"):
                address, base = self.address(args[1])
                size = (1 if operation in ("strb", "stlrb", "ldrb")
                        else 4 if args[0].startswith("w") else 8)
                if operation in ("str", "stur", "strb", "stlrb"):
                    self.store(address, self.register(args[0]), size)
                else:
                    self.set_register(args[0], self.load(address, size))
                if len(args) > 2:
                    self.set_register(base,
                        self.register(base) + self.value(args[2]))
            elif operation in ("stp", "ldp"):
                address, base = self.address(args[2])
                size = 8
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


CASES = (
    (None, None),
    ("", None),
    ("secret_id", "1400000"),
    ("headers_id", "9"),
    ("native_version", "3.67.0"),
    ("ad_impressions_count", None),
    ("secret_i", None),
    ("secret_idx", None),
    ("SECRET_ID", None),
)
for input_value, expected_string in CASES:
    result = VM(input_value).run()
    steady_result = VM(input_value, predecoded=True).run()
    for field in ("return", "status", "output", "new_string_input",
                  "exception_checks"):
        assert steady_result[field] == result[field], (
            input_value, field, result, steady_result)
    assert result["new_string_input"] == expected_string, (
        input_value, expected_string, result)
    if expected_string is None:
        assert result["return"] == 0
        assert result["output"] == 0xDEADBEEF
        assert result["exception_checks"] == 0
    else:
        assert result["return"] == 1
        assert result["output"] == 0x500000
        assert result["exception_checks"] == 1

for exception_pending, new_string_result, expected_return in (
        (False, 0x500000, 1),
        (False, 0, 1),
        (True, 0x500000, 0),
        (True, 0, 0)):
    result = VM("secret_id", new_string_result=new_string_result,
                exception_pending=exception_pending).run()
    assert result["return"] == expected_return, result
    assert result["output"] == new_string_result, result
    assert result["status"] == (34 if exception_pending else 0), result

for initial_status in (1, 2, 34, 0xFFFFFFFF):
    result = VM("secret_id", initial_status=initial_status).run()
    assert result["return"] == 1, result
    assert result["status"] == initial_status, result
    assert result["output"] == 0x500000, result
    assert result["exception_checks"] == 1, result


def virtual_bytes(address, size):
    for offset, virtual_address, segment_size in segments:
        if (virtual_address <= address
                and address + size <= virtual_address + segment_size):
            start = offset + address - virtual_address
            return image[start:start + size]
    raise AssertionError(hex(address))


for address, key, plaintext in (
        (0x142E90, 0xA6, b"secret_id\0"),
        (0x142EA0, 0x4D, b"1400000\0"),
        (0x142EA8, 0x26, b"headers_id\0"),
        (0x142EB4, 0xA4, b"9\0"),
        (0x142EB8, 0x7C, b"native_version\0"),
        (0x142EC8, 0xD9, b"3.67.0\0")):
    assert bytes(byte ^ key for byte in virtual_bytes(
        address, len(plaintext))) == plaintext

for needle in (
        "9468: aa1303e1     \tmov\tx1, x19",
        "947c: f9429d08     \tldr\tx8, [x8, #0x538]",
        "9488: f9000100     \tstr\tx0, [x8]",
        "9490: 94022564     \tbl\t0x92a20",
        "98c8: 52800453     \tmov\tw19, #0x22"):
    assert needle in TEXT, needle
for needle in (
        "runRecoveredJniExceptionConsumer92a20(",
        "recoveredReservedMapValue8af4(",
        'std::strcmp(key, "secret_id") == 0',
        'std::strcmp(key, "headers_id") == 0',
        'std::strcmp(key, "native_version") == 0',
        "runRecoveredReservedMapValue8af4(",
        "recoveredReservedMapValue8af4Regression()"):
    assert needle in CPP, needle

print("arm64 reserved Map value helper 0x8af4 evidence: PASS")
