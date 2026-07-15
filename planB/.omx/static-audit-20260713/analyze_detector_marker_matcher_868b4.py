#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-868b4-87158.txt").read_text(errors="replace")
X64 = (AUDIT / "disasm-x86_64-87ac8-881ea.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


def ordered(text: str, needles: tuple[str, ...]) -> None:
    cursor = 0
    for needle in needles:
        cursor = text.index(needle, cursor) + len(needle)


for needle in (
    "868d0: f100005f     \tcmp\tx2, #0x0",
    "868d8: fa401824     \tccmp\tx1, #0x0, #0x4, ne",
    "868f0: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "86e98: f94439e9     \tldr\tx9, [x15, #0x870]",
    "86f8c: 8b0911ef     \tadd\tx15, x15, x9, lsl #4",
    "86f90: f94039f1     \tldr\tx17, [x15, #0x70]",
    "86eb4: f86979e3     \tldr\tx3, [x15, x9, lsl #3]",
    "86f00: 3940010f     \tldrb\tw15, [x8]",
    "86f0c: 3940000a     \tldrb\tw10, [x0]",
    "86fa4: b9406fef     \tldr\tw15, [sp, #0x6c]",
    "86fb0: 6b0a01ff     \tcmp\tw15, w10",
    "870a0: f94013e8     \tldr\tx8, [sp, #0x20]",
    "870b8: 91000510     \tadd\tx16, x8, #0x1",
    "870c4: 91000506     \tadd\tx6, x8, #0x1",
    "86f5c: 2a0b03e4     \tmov\tw4, w11",
    "86f64: eb0901ff     \tcmp\tx15, x9",
    "86f68: 1a9f27e9     \tcset\tw9, lo",
    "87148: b9402fe8     \tldr\tw8, [sp, #0x2c]",
    "8714c: 12000100     \tand\tw0, w8, #0x1",
):
    assert needle in ARM, needle

ordered(
    ARM,
    (
        "86e14: 51016d44",  # candidate byte - '['
        "86e28: 321b00d0",  # candidate | 0x20
        "86e2c: 310069ff",  # unsigned A-Z range test
        "86e30: 321b014f",  # marker | 0x20
        "86e38: 3100689f",  # marker A-Z range test
        "86e54: 6b0f021f",  # folded compare
    ),
)
ordered(
    ARM,
    (
        "87014: 51016d64",
        "87028: 321b00d0",
        "8702c: 310069ff",
        "87030: 321b016f",
        "87038: 3100689f",
        "87044: 6b0f021f",
    ),
)

for needle in (
    "87aeb: 48 85 d2",  # marker count
    "87b0e: 48 85 f6",  # marker pointer array
    "87b1a: 48 85 ff",  # scratch pointer
    "88048: 48 8b 92 70 08 00 00",  # scratch+0x870 count
    "87fad: 48 c1 e2 04",  # slot index * 16
    "87fb6: 48 8b 54 16 70",  # slot pointer at scratch+0x70
    "87fef: 48 8b 14 f2",  # marker pointer array[index]
    "87f6a: 41 0f b6 16",  # candidate byte
    "87f75: 8a 17",  # marker byte
    "8814f: 48 3b 54 24 c8",  # stopped before scratch count
    "88154: 0f 92 c2",  # result = current scratch index < count
):
    assert needle in X64, needle

assert "\tcall" not in X64
assert "\tbl\t" not in ARM

for needle in (
    "struct RecoveredDetectorScratch868b4",
    "offsetof(RecoveredDetectorScratch868b4, strings) == 0x70",
    "offsetof(RecoveredDetectorScratch868b4, stringCount) == 0x870",
    "foldRecoveredAsciiDetectorByte868b4",
    "recoveredAsciiCaseInsensitiveEqual868b4",
    "runRecoveredDetectorMarkerMatcher868b4(",
    "if (markerCount == 0 || markers == nullptr || scratch == nullptr)",
    "stringIndex < scratch->stringCount",
    "markerIndex < markerCount",
    "if (value == nullptr) continue;",
    "recoveredDetectorMarkerMatcher868b4Regression()",
    '"physical-device-extra"',
    '"PHYSICAL-DEVICE"',
):
    assert needle in CPP, needle

print("arm64/x86_64 detector marker matcher 0x868b4 evidence: PASS")
