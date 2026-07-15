#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-11ba78-11d40c.txt").read_text(errors="replace")
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
    def __init__(self, values=None, initial_status=0,
                 contains_status_key=None, get_status_key=None,
                 callback_status_key=None, special_exception_key=None,
                 malloc_failure_index=None, predecoded=False):
        self.registers = [0] * 31
        self.vectors = [0] * 32
        self.sp = 0x800000
        self.memory = image_memory()
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x11BA78
        self.steps = 0
        self.values = values or {}
        self.contains_status_key = contains_status_key
        self.get_status_key = get_status_key
        self.callback_status_key = callback_status_key
        self.special_exception_key = special_exception_key
        self.malloc_failure_index = malloc_failure_index
        self.allocations = []
        self.frees = []
        self.contains_calls = []
        self.get_calls = []
        self.callbacks = []
        self.deleted_refs = []
        self.next_allocation = 0x2000000

        self.status = 0x1000000
        self.environment = 0x1001000
        self.vtable = 0x1002000
        self.map_object = 0x1003000
        self.callback = 0xF00D0001
        self.opaque = 0x1004000
        self.delete_local_ref = 0xF00D0002
        self.thread = 0x1005000
        self.store(self.status, initial_status, 4)
        self.store(self.environment, self.vtable, 8)
        self.store(self.vtable + 0xB8, self.delete_local_ref, 8)
        self.store(self.thread + 0x28, 0x1122334455667788, 8)
        self.registers[0] = self.status
        self.registers[1] = self.environment
        self.registers[2] = self.map_object
        self.registers[3] = self.callback
        self.registers[4] = self.opaque
        if predecoded:
            for index in range(1363):
                self.memory[0x145A30 + index] ^= 0x52
            self.memory[0x146B61] = 1

    def register(self, name):
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        vector = re.fullmatch(r"[qv](\d+)(?:\.16b)?", name)
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
        vector = re.fullmatch(r"[qv](\d+)(?:\.16b)?", name)
        if vector:
            self.vectors[int(vector.group(1))] = value & ((1 << 128) - 1)
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
        return {
            "eq": self.Z,
            "ne": not self.Z,
            "lt": self.N != self.V,
        }[name]

    def special_value(self, key):
        return {
            "secret_id": ("1400000", 0x5100001),
            "headers_id": ("9", 0x5100002),
            "native_version": ("3.67.0", 0x5100003),
        }.get(key)

    def run(self):
        while self.steps < 20_000_000:
            self.steps += 1
            operation, argument_text = INSTRUCTIONS[self.pc]
            args = operands(argument_text)
            next_pc = self.pc + 4
            if operation == "ret":
                return {
                    "status": self.load(self.status, 4),
                    "allocations": self.allocations,
                    "frees": self.frees,
                    "contains_calls": self.contains_calls,
                    "get_calls": self.get_calls,
                    "callbacks": self.callbacks,
                    "deleted_refs": self.deleted_refs,
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
                if target == 0x139800:
                    address = self.register("x2")
                    expected = self.register("w0") & 0xFF
                    desired = self.register("w1") & 0xFF
                    old = self.load(address, 1)
                    if old == expected:
                        self.store(address, desired, 1)
                    self.set_register("w0", old)
                elif target == 0x8AF4:
                    key = self.c_string(self.register("x2"))
                    special = self.special_value(key)
                    if special is None:
                        self.set_register("w0", 0)
                    else:
                        self.store(self.register("x3"), special[1], 8)
                        if key == self.special_exception_key:
                            self.store(self.register("x0"), 34, 4)
                            self.set_register("w0", 0)
                        else:
                            self.set_register("w0", 1)
                elif target == 0xACD90:
                    key = self.c_string(self.register("x3"))
                    self.contains_calls.append(key)
                    if key == self.contains_status_key:
                        self.store(self.register("x0"), 18, 4)
                    self.store(self.register("x4"),
                               1 if key in self.values else 0, 1)
                elif target == 0xADBF4:
                    key = self.c_string(self.register("x3"))
                    self.get_calls.append(key)
                    if key == self.get_status_key:
                        self.store(self.register("x0"), 28, 4)
                    self.store(self.register("x4"),
                               self.values.get(key, 0), 8)
                elif target == 0x139E20:
                    allocation_index = len(self.allocations)
                    if allocation_index == self.malloc_failure_index:
                        pointer = 0
                    else:
                        pointer = self.next_allocation
                        self.next_allocation += 0x1000
                    self.allocations.append((self.register("x0"), pointer))
                    self.set_register("x0", pointer)
                elif target == 0x139DE0:
                    self.frees.append(self.register("x0"))
                elif target == 0x139DF0:
                    raise AssertionError("stack check failure")
                else:
                    raise AssertionError((hex(self.pc), hex(target)))
            elif operation == "blr":
                target = self.register(args[0])
                if target == self.callback:
                    key = self.c_string(self.register("x2"))
                    reference = self.register("x3")
                    self.callbacks.append((key, reference,
                                           self.register("x4")))
                    if key == self.callback_status_key:
                        self.store(self.register("x0"), 6, 4)
                elif target == self.delete_local_ref:
                    self.deleted_refs.append(self.register("x1"))
                else:
                    raise AssertionError((hex(self.pc), hex(target)))
            elif operation in ("nop",):
                pass
            elif operation == "mrs":
                self.set_register(args[0], self.thread)
            elif operation == "movi":
                byte = self.value(args[1]) & 0xFF
                self.set_register(args[0], int.from_bytes(bytes([byte]) * 16,
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
            elif operation == "eor":
                self.set_register(args[0],
                    self.value(args[1]) ^ self.value(args[2]))
            elif operation == "cmp":
                self.sub_flags(self.value(args[0]), self.value(args[1]),
                    32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                value = self.value(args[0]) & self.value(args[1])
                bits = 32 if args[0].startswith("w") else 64
                self.N = bool(value & (1 << (bits - 1)))
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
            elif operation in ("adr", "adrp"):
                self.set_register(args[0], int(re.search(
                    r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation in ("sxtb",):
                value = self.value(args[1]) & 0xFF
                self.set_register(args[0],
                    value if value < 0x80 else value - 0x100)
            elif operation in (
                    "str", "stur", "strb", "sturb", "stlrb",
                    "ldr", "ldur", "ldrb", "ldurb"):
                address, base = self.address(args[1])
                size = (1 if operation in (
                            "strb", "sturb", "stlrb", "ldrb", "ldurb")
                        else 16 if args[0].startswith("q")
                        else 4 if args[0].startswith("w") else 8)
                if operation in ("str", "stur", "strb", "sturb", "stlrb"):
                    self.store(address, self.register(args[0]), size)
                else:
                    self.set_register(args[0], self.load(address, size))
                if len(args) > 2:
                    self.set_register(base,
                        self.register(base) + self.value(args[2]))
            elif operation in ("stp", "ldp"):
                address, base = self.address(args[2])
                vector = args[0].startswith("q")
                size = 16 if vector else (4 if args[0].startswith("w") else 8)
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


empty = VM().run()
assert empty["status"] == 0
assert len(empty["allocations"]) == 1
assert empty["allocations"][0][0] == 1363
assert len(empty["frees"]) == 1
assert len(empty["contains_calls"]) == 97
assert empty["get_calls"] == []
assert empty["callbacks"] == [
    ("secret_id", 0x5100001, 0x1004000),
    ("headers_id", 0x5100002, 0x1004000),
    ("native_version", 0x5100003, 0x1004000),
]
assert empty["deleted_refs"] == [0x5100001, 0x5100002, 0x5100003]

selected = VM(values={"android_id": 0x6000001,
                      "payload": 0,
                      "updated_at": 0x6000002}, predecoded=True).run()
assert selected["get_calls"] == ["android_id", "payload", "updated_at"]
assert selected["callbacks"] == [
    ("android_id", 0x6000001, 0x1004000),
    ("payload", 0, 0x1004000),
    ("secret_id", 0x5100001, 0x1004000),
    ("updated_at", 0x6000002, 0x1004000),
    ("headers_id", 0x5100002, 0x1004000),
    ("native_version", 0x5100003, 0x1004000),
]
assert selected["deleted_refs"] == [
    0x6000001, 0x5100001, 0x6000002, 0x5100002, 0x5100003]

malloc_failure = VM(malloc_failure_index=0, predecoded=True).run()
assert malloc_failure["status"] == 2
assert len(malloc_failure["allocations"]) == 1
assert len(malloc_failure["frees"]) == 1
assert malloc_failure["frees"][-1] == 0
assert malloc_failure["callbacks"] == []

contains_failure = VM(contains_status_key="android_id", predecoded=True).run()
assert contains_failure["status"] == 18
assert contains_failure["contains_calls"][-1] == "android_id"
assert contains_failure["get_calls"] == []
assert contains_failure["callbacks"] == []
assert len(contains_failure["frees"]) == 1

get_failure = VM(values={"android_id": 0x6000001},
                 get_status_key="android_id", predecoded=True).run()
assert get_failure["status"] == 28
assert get_failure["get_calls"] == ["android_id"]
assert get_failure["callbacks"] == []
assert get_failure["deleted_refs"] == []

callback_failure = VM(values={"android_id": 0x6000001},
                      callback_status_key="android_id", predecoded=True).run()
assert callback_failure["status"] == 6
assert callback_failure["callbacks"] == [
    ("android_id", 0x6000001, 0x1004000)]
assert callback_failure["deleted_refs"] == [0x6000001]

special_failure = VM(special_exception_key="secret_id", predecoded=True).run()
assert special_failure["status"] == 34
assert special_failure["callbacks"] == []
assert special_failure["deleted_refs"] == []

initial_failure = VM(initial_status=9, predecoded=True).run()
assert initial_failure["status"] == 9
assert len(initial_failure["allocations"]) == 1
assert len(initial_failure["frees"]) == 1
assert initial_failure["contains_calls"] == []
assert initial_failure["callbacks"] == []

for needle in (
        "struct RecoveredMapSelectedValueWalkerOperations11ba78",
        "recoveredMapKeyTableSize11ba78() == 1363",
        "runRecoveredMapSelectedValueWalker11ba78(",
        "operations.containsKey(status, jniEnvironment, mapObject,",
        "operations.get(status, jniEnvironment, mapObject,",
        "operations.callback(status, jniEnvironment, key,",
        "operations.deleteLocalRef(jniEnvironment, selectedValue)",
        "recoveredMapSelectedValueWalker11ba78Regression()"):
    assert needle in CPP, needle

print("arm64 JNI Map selected-value walker 0x11ba78 full evidence: PASS")
