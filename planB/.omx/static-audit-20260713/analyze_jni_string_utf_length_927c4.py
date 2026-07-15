#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
TEXT = (AUDIT / "disasm-927c4-92b24.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
MASK = (1 << 64) - 1


def operands(text):
    result, start, depth = [], 0, 0
    for index, char in enumerate(text):
        if char == "[": depth += 1
        elif char == "]": depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip()); start = index + 1
    if text[start:].strip(): result.append(text[start:].strip())
    return result


instructions = {}
for line in TEXT.splitlines():
    match = re.match(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
        r"(.*?)(?:\s+//.*)?$", line)
    if match:
        address = int(match.group(1), 16)
        if 0x927C4 <= address < 0x92A20:
            instructions[address] = (match.group(2), match.group(3).strip())


class VM:
    def __init__(self, initial_status, java_string,
                 jni_length=17, exception_pending=False):
        self.r = [0] * 31
        self.sp = 0x800000
        self.mem = {}
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x927C4
        self.steps = 0
        self.jni_length = jni_length
        self.exception_pending = exception_pending
        self.length_calls = 0
        self.exception_checks = 0
        self.status = 0x1000000
        self.environment = 0x1001000
        self.vtable = 0x1002000
        self.output = 0x1003000
        self.store(self.status, initial_status, 4)
        self.store(self.environment, self.vtable, 8)
        self.store(self.vtable + 0x540, 0xF00D0001, 8)
        self.store(self.output, 0xDEADBEEF, 8)
        self.r[0] = self.status
        self.r[1] = self.environment
        self.r[2] = java_string
        self.r[3] = self.output

    def reg(self, name):
        if name in ("xzr", "wzr"): return 0
        if name == "sp": return self.sp
        match = re.fullmatch(r"([xw])(\d+)", name); assert match, name
        value = self.r[int(match.group(2))]
        return value if match.group(1) == "x" else value & 0xFFFFFFFF

    def set(self, name, value):
        if name in ("xzr", "wzr"): return
        if name == "sp": self.sp = value & MASK; return
        match = re.fullmatch(r"([xw])(\d+)", name); assert match, name
        self.r[int(match.group(2))] = (
            value & MASK if match.group(1) == "x" else value & 0xFFFFFFFF)

    def val(self, operand):
        return int(operand.lstrip("#"), 0) if operand.startswith("#") else self.reg(operand)

    def address(self, operand):
        match = re.fullmatch(r"\[(.*)\](!)?", operand); assert match, operand
        parts = [part.strip() for part in match.group(1).split(",")]
        base = parts[0]
        address = self.reg(base) + (self.val(parts[1]) if len(parts) > 1 else 0)
        if match.group(2): self.set(base, address)
        return address & MASK, base

    def load(self, address, size):
        return sum(self.mem.get(address + index, 0) << (8 * index)
                   for index in range(size))

    def store(self, address, value, size):
        for index in range(size): self.mem[address + index] = (value >> (8 * index)) & 0xFF

    def flags(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        result = (left - right) & mask
        self.N = bool(result & sign); self.Z = result == 0
        self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def cond(self, name): return {"eq": self.Z, "ne": not self.Z}[name]

    def run(self):
        while self.steps < 100000:
            self.steps += 1
            operation, text = instructions[self.pc]
            args = operands(text); next_pc = self.pc + 4
            if operation == "ret":
                return (self.load(self.status, 4), self.load(self.output, 8),
                        self.length_calls, self.exception_checks)
            if operation == "b":
                self.pc = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16); continue
            if operation.startswith("b."):
                if self.cond(operation[2:]):
                    self.pc = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16); continue
            elif operation == "bl":
                target = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16)
                assert target == 0x92A20
                self.exception_checks += 1
                self.set("w0", 1 if self.exception_pending else 0)
            elif operation == "blr":
                assert self.reg(args[0]) == 0xF00D0001
                self.length_calls += 1
                self.set("w0", self.jni_length)
            elif operation == "mov": self.set(args[0], self.val(args[1]))
            elif operation == "movk":
                shift = int(args[2].split("#")[1]) if len(args) > 2 else 0
                mask = 0xFFFF << shift
                self.set(args[0], (self.reg(args[0]) & ~mask) | (self.val(args[1]) << shift))
            elif operation in ("add", "sub"):
                self.set(args[0], self.val(args[1]) + self.val(args[2])
                         if operation == "add" else self.val(args[1]) - self.val(args[2]))
            elif operation == "cmp":
                self.flags(self.val(args[0]), self.val(args[1]),
                           32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                value = self.val(args[0]) & self.val(args[1]); self.Z = value == 0
                self.N = self.C = self.V = 0
            elif operation == "csel":
                self.set(args[0], self.val(args[1]) if self.cond(args[3]) else self.val(args[2]))
            elif operation == "sxtw":
                value = self.val(args[1]) & 0xFFFFFFFF
                self.set(args[0], value if value < 0x80000000 else value - 0x100000000)
            elif operation in ("str", "ldr"):
                address, base = self.address(args[1])
                size = 4 if args[0].startswith("w") else 8
                if operation == "str": self.store(address, self.reg(args[0]), size)
                else: self.set(args[0], self.load(address, size))
                if len(args) > 2: self.set(base, self.reg(base) + self.val(args[2]))
            elif operation in ("stp", "ldp"):
                address, base = self.address(args[2]); size = 8
                for index, name in enumerate(args[:2]):
                    if operation == "stp": self.store(address + index * size, self.reg(name), size)
                    else: self.set(name, self.load(address + index * size, size))
                if len(args) > 3: self.set(base, self.reg(base) + self.val(args[3]))
            else: raise AssertionError((hex(self.pc), operation, text))
            self.pc = next_pc
        raise AssertionError("step limit")


assert VM(0, 0).run() == (3, 0, 0, 0)
assert VM(9, 0).run() == (3, 0, 0, 0)
assert VM(9, 0x400000).run() == (9, 0, 1, 1)
assert VM(0, 0x400000, 17, False).run() == (0, 17, 1, 1)
assert VM(0, 0x400000, -1, False).run() == (0, MASK, 1, 1)
assert VM(0, 0x400000, 17, True).run() == (28, 0, 1, 1)

for needle in (
        "runRecoveredJniStringUtfLength927c4(",
        "*outputLength = 0;",
        "*status = 3;",
        "*status = 28;"):
    assert needle in CPP, needle

print("arm64 JNI GetStringUTFLength helper 0x927c4 evidence: PASS")
