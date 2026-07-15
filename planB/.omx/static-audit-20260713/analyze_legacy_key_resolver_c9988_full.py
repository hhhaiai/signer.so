#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-c9988-ca648.txt").read_text(errors="replace")
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
        instructions[int(match.group(1), 16)] = (
            match.group(2), match.group(3).strip())

image = SO.read_bytes()
phoff = struct.unpack_from("<Q", image, 32)[0]
phentsize = struct.unpack_from("<H", image, 54)[0]
phnum = struct.unpack_from("<H", image, 56)[0]
segments = []
for index in range(phnum):
    fields = struct.unpack_from("<IIQQQQQQ", image, phoff + index * phentsize)
    if fields[0] == 1: segments.append((fields[2], fields[3], fields[5]))


def image_memory():
    result = {}
    for offset, address, size in segments:
        for index, byte in enumerate(image[offset:offset + size]):
            result[address + index] = byte
    return result


class VM:
    def __init__(self, initial_status=0, fail_stage=None, null_stage=None,
                 rsa_boolean=True):
        self.r = [0] * 31
        self.v = [0] * 32
        self.sp = 0x800000
        self.mem = image_memory()
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0xC9988
        self.steps = 0
        self.fail_stage = fail_stage
        self.null_stage = null_stage
        self.rsa_boolean = rsa_boolean
        self.calls = []
        self.deleted = []

        self.environment = 0x1000000
        self.vtable = 0x1001000
        self.status = 0x1002000
        self.context = 0x1003000
        self.output = 0x1004000
        self.delete_local_ref = 0xF00D0001
        self.store(self.environment, self.vtable, 8)
        self.store(self.vtable + 0xB8, self.delete_local_ref, 8)
        self.store(self.status, initial_status, 4)
        self.store(self.output, 0xDEADBEEF, 8)
        self.thread = 0x1005000
        self.store(self.thread + 0x28, 0x1122334455667788, 8)
        self.r[0] = self.environment
        self.r[1] = self.status
        self.r[2] = self.context
        self.r[3] = self.output

    def reg(self, name):
        if name in ("xzr", "wzr"): return 0
        if name == "sp": return self.sp
        vector = re.fullmatch(r"[dv](\d+)(?:\.8b)?", name)
        if vector: return self.v[int(vector.group(1))]
        match = re.fullmatch(r"([xw])(\d+)", name); assert match, name
        value = self.r[int(match.group(2))]
        return value if match.group(1) == "x" else value & 0xFFFFFFFF

    def set(self, name, value):
        if name in ("xzr", "wzr"): return
        if name == "sp": self.sp = value & MASK; return
        vector = re.fullmatch(r"[dv](\d+)(?:\.8b)?", name)
        if vector: self.v[int(vector.group(1))] = value & MASK; return
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
        left, right = left & mask, right & mask; result = (left - right) & mask
        self.N = bool(result & sign); self.Z = result == 0; self.C = left >= right
        self.V = bool(((left ^ right) & (left ^ result) & sign) != 0)

    def cond(self, name):
        return {"eq": self.Z, "ne": not self.Z}[name]

    def helper(self, stage, status_pointer, output_pointer, reference,
               return_value=0):
        self.calls.append(stage)
        self.store(output_pointer, 0 if stage == self.null_stage else reference, 8)
        if stage == self.fail_stage:
            self.store(status_pointer, 70 + len(self.calls), 4)
        self.set("w0", return_value)

    def run(self):
        while self.steps < 2_000_000:
            self.steps += 1
            operation, text = instructions[self.pc]
            args = operands(text); next_pc = self.pc + 4
            if operation == "ret":
                return {
                    "return": self.reg("w0") & 1,
                    "status": self.load(self.status, 4),
                    "output": self.load(self.output, 8),
                    "calls": self.calls,
                    "deleted": self.deleted,
                    "steps": self.steps,
                }
            if operation == "b":
                self.pc = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16); continue
            if operation.startswith("b."):
                if self.cond(operation[2:]):
                    self.pc = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16); continue
            elif operation == "bl":
                target = int(re.search(r"0x([0-9a-f]+)", text).group(1), 16)
                if target == 0x139800:
                    address = self.reg("x2"); expected = self.reg("w0") & 0xFF
                    desired = self.reg("w1") & 0xFF; old = self.load(address, 1)
                    if old == expected: self.store(address, desired, 1)
                    self.set("w0", old)
                elif target == 0xB479C:
                    self.helper("preferences", self.reg("x0"), self.reg("x5"), 0x5101)
                elif target == 0xC0D84:
                    self.helper("getString", self.reg("x0"), self.reg("x5"), 0x5102)
                elif target == 0x93014:
                    self.helper("base64", self.reg("x0"), self.reg("x3"), 0x5103)
                elif target == 0xCAC40:
                    self.helper("rsa", self.reg("x1"), self.reg("x3"), 0x5104,
                                1 if self.rsa_boolean else 0)
                elif target == 0xBD6A8:
                    self.helper("secretKey", self.reg("x0"), self.reg("x4"), 0x5105)
                elif target == 0x139DF0:
                    raise AssertionError("stack check failure")
                else: raise AssertionError((hex(self.pc), hex(target)))
            elif operation == "blr":
                assert self.reg(args[0]) == self.delete_local_ref
                self.deleted.append(self.reg("x1"))
            elif operation in ("nop",): pass
            elif operation == "mrs": self.set(args[0], self.thread)
            elif operation == "movi":
                byte = self.val(args[1]) & 0xFF
                self.set(args[0], int.from_bytes(bytes([byte]) * 8, "little"))
            elif operation == "mov": self.set(args[0], self.val(args[1]))
            elif operation == "movk":
                shift = int(args[2].split("#")[1]) if len(args) > 2 else 0
                mask = 0xFFFF << shift
                self.set(args[0], (self.reg(args[0]) & ~mask) | (self.val(args[1]) << shift))
            elif operation in ("add", "sub"):
                self.set(args[0], self.val(args[1]) + self.val(args[2])
                         if operation == "add" else self.val(args[1]) - self.val(args[2]))
            elif operation in ("eor", "and"):
                self.set(args[0], self.val(args[1]) ^ self.val(args[2])
                         if operation == "eor" else self.val(args[1]) & self.val(args[2]))
            elif operation == "cmp":
                self.flags(self.val(args[0]), self.val(args[1]),
                           32 if args[0].startswith("w") else 64)
            elif operation == "tst":
                value = self.val(args[0]) & self.val(args[1]); self.Z = value == 0
                self.N = self.C = self.V = 0
            elif operation == "ccmp":
                if self.cond(args[3]):
                    self.flags(self.val(args[0]), self.val(args[1]),
                               32 if args[0].startswith("w") else 64)
                else:
                    nzcv = self.val(args[2]); self.N = (nzcv >> 3) & 1
                    self.Z = (nzcv >> 2) & 1; self.C = (nzcv >> 1) & 1; self.V = nzcv & 1
            elif operation == "csel":
                self.set(args[0], self.val(args[1]) if self.cond(args[3]) else self.val(args[2]))
            elif operation in ("adr", "adrp"):
                self.set(args[0], int(re.search(r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation in ("str", "stur", "strb", "stlrb", "ldr", "ldur", "ldrb"):
                address, base = self.address(args[1])
                size = 1 if operation in ("strb", "stlrb", "ldrb") else (4 if args[0].startswith("w") else 8)
                if operation in ("str", "stur", "strb", "stlrb"):
                    self.store(address, self.reg(args[0]), size)
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


success = VM().run()
assert success == {
    "return": 1, "status": 0, "output": 0x5105,
    "calls": ["preferences", "getString", "base64", "rsa", "secretKey"],
    "deleted": [0x5104, 0x5103, 0x5101, 0x5102],
    "steps": success["steps"],
}

failure_expectations = {
    "preferences": (71, ["preferences"], [0x5101]),
    "getString": (72, ["preferences", "getString"], [0x5101, 0x5102]),
    "base64": (26, ["preferences", "getString", "base64"],
               [0x5103, 0x5101, 0x5102]),
    "rsa": (74, ["preferences", "getString", "base64", "rsa", "secretKey"],
            [0x5104, 0x5103, 0x5101, 0x5102]),
    "secretKey": (75,
                  ["preferences", "getString", "base64", "rsa", "secretKey"],
                  [0x5104, 0x5103, 0x5101, 0x5102]),
}
for stage, (status, calls, deleted) in failure_expectations.items():
    result = VM(fail_stage=stage).run()
    assert result["return"] == 0 and result["status"] == status
    assert result["output"] == 0xDEADBEEF
    assert result["calls"] == calls and result["deleted"] == deleted

null_expectations = {
    "preferences": [0x5104, 0x5103, 0x5102],
    "getString": [0x5104, 0x5103, 0x5101],
    "base64": [0x5104, 0x5101, 0x5102],
    "rsa": [0x5103, 0x5101, 0x5102],
    "secretKey": [0x5104, 0x5103, 0x5101, 0x5102],
}
for stage, deleted in null_expectations.items():
    result = VM(null_stage=stage).run()
    assert result["return"] == 1 and result["status"] == 0
    assert result["output"] == (0 if stage == "secretKey" else 0x5105)
    assert result["deleted"] == deleted

rsa_false = VM(rsa_boolean=False).run()
assert rsa_false["return"] == 0 and rsa_false["status"] == 0
assert rsa_false["output"] == 0xDEADBEEF
assert rsa_false["calls"] == ["preferences", "getString", "base64", "rsa"]
assert rsa_false["deleted"] == [0x5104, 0x5103, 0x5101, 0x5102]

prestatus = VM(initial_status=9).run()
assert prestatus["return"] == 0 and prestatus["status"] == 9
assert prestatus["calls"] == ["preferences"]
assert prestatus["deleted"] == [0x5101]
assert prestatus["output"] == 0xDEADBEEF

for needle in (
        "struct RecoveredLegacyWrappedKeyOperationsC9988",
        "runRecoveredLegacyWrappedKeyResolverC9988(",
        '"adjust_keys", 0, &preferences',
        '"encrypted_key", 0, &encryptedString',
        "if (*status != 0) *status = 26;",
        'rawKeyBytes, "AES", &key',
        "if (success) *outputKey = key;"):
    assert needle in CPP, needle

print("arm64 legacy wrapped-key resolver 0xc9988 full evidence: PASS")
