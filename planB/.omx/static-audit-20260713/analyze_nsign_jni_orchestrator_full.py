#!/usr/bin/env python3
"""Interpret ARM64 nSign without loading the target shared object."""

from __future__ import annotations

import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
TEXT = (AUDIT / "disasm-cc604-cd934.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
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
    def __init__(self, environment_value: str | None = "sandbox",
                 map_copy_status: int = 0,
                 first_clock_status: int = 0,
                 second_clock_status: int = 0,
                 signing_result: int = 0x7001000,
                 predecoded: bool = False):
        self.registers = [0] * 31
        self.vectors = [0] * 32
        self.sp = 0x800000
        self.memory = image_memory()
        self.N = self.Z = self.C = self.V = False
        self.pc = 0xCC604
        self.steps = 0
        self.environment_value = environment_value
        self.map_copy_status = map_copy_status
        self.clock_statuses = [first_clock_status, second_clock_status]
        self.signing_result = signing_result
        self.calls: list[tuple[str, object]] = []
        self.timestamps: list[tuple[str, int]] = []
        self.first_merge = None
        self.final_merge = None
        self.environment_auxiliary_flag = None
        self.saved_descriptor = None

        self.thread = 0x1000000
        self.stack_guard = 0x1122334455667788
        self.jni_environment = 0x1001000
        self.java_context = 0x1002000
        self.map_object = 0x1003000
        self.supplied_hmac = 0x1004000
        self.native_environment_string = 0x1100000
        self.store(self.thread + 0x28, self.stack_guard, 8)
        self.write_c_string(self.native_environment_string,
                            environment_value or "")
        self.registers[0] = self.jni_environment
        self.registers[1] = 0x1005000
        self.registers[2] = self.java_context
        self.registers[3] = self.map_object
        self.registers[4] = self.supplied_hmac
        self.registers[5] = 35
        if predecoded:
            self._predecode_global(0x1457C0, 12, 0x28, 0x146AE5)
            self._predecode_global(0x1457D0, 8, 0x1A, 0x146AE6)
            self._predecode_global(0x1457E0, 33, 0xB7, 0x146AE7)
            self._predecode_global(0x145810, 33, 0xEE, 0x146AE8)

    def _predecode_global(self, address: int, size: int, key: int,
                          gate: int) -> None:
        for index in range(size):
            self.memory[address + index] ^= key
        self.memory[gate] = 1

    def register(self, name: str) -> int:
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        vector = re.fullmatch(r"([dqv])(\d+)(?:\.(?:8b|16b))?", name)
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
        vector = re.fullmatch(r"([dqv])(\d+)(?:\.(?:8b|16b))?", name)
        if vector:
            index = int(vector.group(2))
            mask = MASK64 if vector.group(1) == "d" else MASK128
            if vector.group(1) == "d":
                self.vectors[index] = (self.vectors[index] & ~MASK64) \
                        | (value & mask)
            else:
                self.vectors[index] = value & mask
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

    def write_c_string(self, address: int, value: str) -> None:
        data = value.encode("ascii") + b"\0"
        for index, byte in enumerate(data):
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

    def condition(self, name: str) -> bool:
        return {"eq": self.Z, "ne": not self.Z}[name]

    def _call(self, target: int) -> None:
        if target == 0x139800:
            address = self.register("x2")
            expected = self.register("w0") & 0xFF
            desired = self.register("w1") & 0xFF
            old = self.load(address, 1)
            if old == expected:
                self.store(address, desired, 1)
            self.set_register("w0", old)
            self.calls.append(("cas", address))
        elif target == 0xD4908:
            self.calls.append(("periodicTimer", None))
        elif target == 0xAEBF8:
            status_pointer = self.register("x0")
            output_pointer = self.register("x4")
            self.store(status_pointer, self.map_copy_status, 4)
            self.store(output_pointer,
                       0 if self.map_copy_status != 0
                               or self.environment_value is None
                       else self.native_environment_string, 8)
            self.calls.append(("environmentMapCopy", {
                "key": self.c_string(self.register("x3")),
                "status": self.map_copy_status,
                "value": self.environment_value,
            }))
        elif target == 0xCC47C:
            clock_index = 2 - len(self.clock_statuses)
            status = self.clock_statuses.pop(0)
            if status != 0:
                self.store(self.register("x0"), status, 4)
            self.set_register("d0", 0x4000000000000000 + clock_index)
            self.calls.append(("clockRealtime",
                               self.load(self.register("x0"), 4)))
        elif target == 0x12EC1C:
            text = self.c_string(self.register("x0"))
            value = self.register("d0")
            self.timestamps.append((text, value))
            self.calls.append(("timestampLog", text))
        elif target == 0xCBE98:
            descriptor = self.register("x0")
            self.saved_descriptor = {
                "environment": self.load(descriptor + 0x00, 8),
                "contextWrapper": self.load(descriptor + 0x08, 8),
                "mapWrapper": self.load(descriptor + 0x10, 8),
                "hmacWrapper": self.load(descriptor + 0x18, 8),
                "apiWrapper": self.load(descriptor + 0x20, 8),
            }
            self.saved_descriptor.update({
                "context": self.load(
                    self.saved_descriptor["contextWrapper"], 8),
                "map": self.load(self.saved_descriptor["mapWrapper"], 8),
                "hmac": self.load(self.saved_descriptor["hmacWrapper"], 8),
                "api": self.load(self.saved_descriptor["apiWrapper"], 4),
            })
            self.set_register("x0", self.signing_result)
            self.calls.append(("signingContext", descriptor))
        elif target == 0x139DF0:
            raise AssertionError("stack check failure")
        else:
            raise AssertionError((hex(self.pc), hex(target)))

    def run(self) -> dict[str, object]:
        while self.steps < 2_000_000:
            self.steps += 1
            operation, argument_text = INSTRUCTIONS[self.pc]
            args = operands(argument_text)
            next_pc = self.pc + 4
            if self.pc == 0xCD538:
                self.first_merge = self.register("w8") | self.register("w28")
            if self.pc == 0xCD7B4:
                self.final_merge = self.register("w8") | self.register("w9")
            if self.pc == 0xCD5B4:
                self.environment_auxiliary_flag = self.register("w28")
            if operation == "ret":
                return {
                    "result": self.register("x0"),
                    "calls": self.calls,
                    "timestamps": self.timestamps,
                    "firstMerge": self.first_merge,
                    "finalMerge": self.final_merge,
                    "environmentAuxiliaryFlag":
                        self.environment_auxiliary_flag,
                    "descriptor": self.saved_descriptor,
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
                size = 8 if ".8b" in args[0] else 16
                self.set_register(args[0], int.from_bytes(bytes([byte]) * size,
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
            elif operation == "cmp":
                self.sub_flags(self.value(args[0]), self.value(args[1]),
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
            elif operation == "csinc":
                self.set_register(args[0], self.value(args[1])
                    if self.condition(args[3]) else self.value(args[2]) + 1)
            elif operation in ("adr", "adrp"):
                self.set_register(args[0], int(re.search(
                    r"0x([0-9a-f]+)", args[1]).group(1), 16))
            elif operation == "fmov":
                self.set_register(args[0], self.register(args[1]))
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
        raise RuntimeError("step limit")


def execute(**kwargs: object) -> dict[str, object]:
    return VM(**kwargs).run()


cases = {
    "sandbox": execute(environment_value="sandbox"),
    "sandboxSteady": execute(environment_value="sandbox", predecoded=True),
    "sandboxX": execute(environment_value="sandboxX", predecoded=True),
    "production": execute(environment_value="production", predecoded=True),
    "empty": execute(environment_value="", predecoded=True),
    "null": execute(environment_value=None, predecoded=True),
    "mapFailure": execute(environment_value="sandbox", map_copy_status=28,
                          predecoded=True),
    "firstClockFailure": execute(environment_value="sandbox",
                                 first_clock_status=14, predecoded=True),
    "secondClockFailure": execute(environment_value="sandbox",
                                  second_clock_status=14, predecoded=True),
    "bothClockFailures": execute(environment_value="sandbox",
                                 first_clock_status=14,
                                 second_clock_status=14, predecoded=True),
    "caseMismatch": execute(environment_value="Sandbox", predecoded=True),
    "nullSigningResult": execute(environment_value="sandbox",
                                 signing_result=0, predecoded=True),
}

for name, result in cases.items():
    assert result["result"] == (0 if name == "nullSigningResult" else 0x7001000)
    call_names = [call[0] for call in result["calls"]]
    assert call_names.count("periodicTimer") == 1
    assert call_names.count("environmentMapCopy") == 1
    assert call_names.count("clockRealtime") == 2
    assert call_names.count("signingContext") == 1
    assert call_names.count("timestampLog") in (0, 1, 2)

assert cases["sandbox"]["firstMerge"] == 0
assert cases["sandbox"]["finalMerge"] == 0
for name in ("sandboxX", "production", "empty", "null", "mapFailure",
             "secondClockFailure", "bothClockFailures", "caseMismatch"):
    assert cases[name]["finalMerge"] & 1, (name, cases[name])
assert cases["firstClockFailure"]["finalMerge"] == 0

assert cases["sandboxX"]["firstMerge"] == 1
assert cases["production"]["firstMerge"] == 1
assert cases["empty"]["firstMerge"] == 1
assert cases["null"]["firstMerge"] == 1
assert cases["mapFailure"]["firstMerge"] == 1
assert cases["firstClockFailure"]["firstMerge"] == 1
assert cases["secondClockFailure"]["firstMerge"] == 0

for name in ("sandbox", "sandboxSteady", "firstClockFailure", "secondClockFailure",
             "bothClockFailures", "nullSigningResult"):
    assert cases[name]["environmentAuxiliaryFlag"] == 0
for name in ("sandboxX", "production", "empty", "null", "mapFailure",
             "caseMismatch"):
    assert cases[name]["environmentAuxiliaryFlag"] == 1

assert len(cases["sandbox"]["timestamps"]) == 2
assert cases["sandboxSteady"]["timestamps"] == cases["sandbox"]["timestamps"]
assert len(cases["firstClockFailure"]["timestamps"]) == 1
assert cases["firstClockFailure"]["timestamps"][0][0].endswith("end  ")
assert len(cases["secondClockFailure"]["timestamps"]) == 1
assert cases["secondClockFailure"]["timestamps"][0][0].endswith("begin")
for name in ("sandboxX", "production", "empty", "null", "mapFailure",
             "caseMismatch", "bothClockFailures"):
    assert cases[name]["timestamps"] == []

descriptor = cases["sandbox"]["descriptor"]
assert descriptor is not None
assert descriptor["environment"] == 0x1001000
assert descriptor["context"] == 0x1002000
assert descriptor["map"] == 0x1003000
assert descriptor["hmac"] == 0x1004000
assert descriptor["api"] == 35

for needle in (
        "struct RecoveredNsignDescriptorCC604",
        "struct RecoveredNsignOperationsCC604",
        "struct RecoveredNsignTraceCC604",
        "runRecoveredNsignOrchestratorCC604(",
        '"environment", &environmentOwnedString',
        '"sandbox") != 0',
        '"Signing all the parameters begin"',
        '"Signing all the parameters end  "',
        "recoveredNsignOrchestratorCC604Regression()"):
    assert needle in CPP, needle

print("arm64 nSign JNI orchestrator 0xcc604 full evidence: PASS")
