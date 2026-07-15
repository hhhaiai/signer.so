#!/usr/bin/env python3
import re
import runpy
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
HELPER_TEXT = (AUDIT / "disasm-58498-59658.txt").read_text(errors="replace")
WRAPPER_TEXT = (AUDIT / "disasm-6c590-6dbbc.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


base = runpy.run_path(str(AUDIT / "analyze_post_detector_predicate_6dbbc.py"))


def parse(text):
    result = {}
    for line in text.splitlines():
        match = re.match(
            r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
            r"(.*?)(?:\s+//.*)?$", line)
        if match:
            result[int(match.group(1), 16)] = (
                match.group(2), match.group(3).strip())
    return result


# The inherited interpreter resolves this name from its defining globals.
base["VM"].run.__globals__["INSTRUCTIONS"] = parse(HELPER_TEXT)


class HelperVM(base["VM"]):
    def __init__(self, slots, expected_pairs, pair_count,
            null_scratch=False, null_table=False):
        self.registers = [0] * 31
        self.sp = 0x800000
        self.memory = {}
        self.N = self.Z = self.C = self.V = 0
        self.pc = 0x58498
        self.steps = 0
        scratch = 0 if null_scratch else 0x100000
        table = 0 if null_table else 0x300000
        self.registers[0] = scratch
        self.registers[1] = table
        self.registers[2] = pair_count
        next_string = 0x400000

        def put_string(value):
            nonlocal next_string
            if value is None:
                return 0
            pointer = next_string
            next_string += 0x100
            for index, byte in enumerate(value.encode("ascii") + b"\0"):
                self.memory[pointer + index] = byte
            return pointer

        for index, (primary, secondary) in enumerate(slots):
            self.store(scratch + 0x70 + index * 0x10,
                put_string(primary), 8)
            self.store(scratch + 0x78 + index * 0x10,
                put_string(secondary), 8)
        self.store(scratch + 0x870, len(slots), 8)
        for index, value in enumerate(expected_pairs):
            self.store(table + index * 8, put_string(value), 8)


pair = ["Genymotion Accelerometer", "Genymobile"]
cases = (
    ([], pair, 1, 0),
    ([(None, None)], pair, 1, 0),
    ([("", "")], ["", ""], 1, 1),
    ([(pair[0], pair[1])], pair, 1, 1),
    ([(pair[0].upper(), pair[1].upper())], pair, 1, 1),
    ([("prefix-" + pair[0], pair[1])], pair, 1, 0),
    ([(pair[0] + "-tail", pair[1])], pair, 1, 0),
    ([(pair[0], "prefix-" + pair[1])], pair, 1, 0),
    ([(pair[0], pair[1] + "-tail")], pair, 1, 0),
    ([(pair[0], "Other")], pair, 1, 0),
    ([("Other", pair[1])], pair, 1, 0),
    ([(pair[0], pair[1]), ("Other", "Vendor")],
        pair + ["Other", "Vendor"], 1, 0),
    ([(pair[0], pair[1]), ("Other", "Vendor")],
        pair + ["Other", "Vendor"], 2, 1),
)
for slots, expected, count, result in cases:
    assert HelperVM(slots, expected, count).run() == result, (
        slots, expected, count, result)

assert HelperVM([], [], 0).run() == 1
assert HelperVM([], [], 0, null_scratch=True).run() == 0
assert HelperVM([], [], 0, null_table=True).run() == 0


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


assert bytes(value ^ 0xA1 for value in virtual_bytes(
    0x1446E0, 25)) == b"Genymotion Accelerometer\0"
assert bytes(value ^ 0x69 for value in virtual_bytes(
    0x144700, 11)) == b"Genymobile\0"

for needle in (
        "584b4: f100003f     \tcmp\tx1, #0x0",
        "584c0: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
        "59444: f9443908     \tldr\tx8, [x8, #0x870]",
        "594a4: 8b0a1108     \tadd\tx8, x8, x10, lsl #4",
        "594a8: f9403d08     \tldr\tx8, [x8, #0x78]",
        "5964c: 12000100     \tand\tw0, w8, #0x1"):
    assert needle in HELPER_TEXT, needle
for needle in (
        "6cf70: 106bbb80     \tadr\tx0, 0x1446e0",
        "6cf84: f81f0180     \tstur\tx0, [x12, #-0x10]",
        "6cf8c: 106bbba0     \tadr\tx0, 0x144700",
        "6cfa4: f81f8180     \tstur\tx0, [x12, #-0x8]",
        "6d594: f85903a0     \tldur\tx0, [x29, #-0x70]",
        "6d598: 52800022     \tmov\tw2, #0x1",
        "6d59c: f85583a1     \tldur\tx1, [x29, #-0xa8]",
        "6d5a0: 97ffabbe     \tbl\t0x58498",
        "6db8c: 12000100     \tand\tw0, w8, #0x1"):
    assert needle in WRAPPER_TEXT, needle

for needle in (
        "kRecoveredPostDetectorGenymotionSensorPair6c590",
        '"Genymotion Accelerometer", "Genymobile"',
        "bool runRecoveredDetectorStringPairArrayEquality58498(",
        "scratch->stringCount != pairCount",
        "scratch->strings[index].secondaryValue08",
        "bool runRecoveredGenymotionSensorPredicate6c590(",
        "recoveredPostDetectorPredicate6c590Regression()"):
    assert needle in CPP, needle

print("arm64 helper 0x58498 and post-detector predicate 0x6c590 evidence: PASS")
