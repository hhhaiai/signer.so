#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-42eb0-430f4.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


for needle in (
    "42f24: f100003f     \tcmp\tx1, #0x0",
    "42f68: f81f83a3     \tstur\tx3, [x29, #-0x8]",
    "42f6c: a9008be1     \tstp\tx1, x2, [sp, #0x8]",
    "42f70: f90003e0     \tstr\tx0, [sp]",
    "4302c: a94023e0     \tldp\tx0, x8, [sp]",
    "43030: f8787901     \tldr\tx1, [x8, x24, lsl #3]",
    "43038: b8787902     \tldr\tw2, [x8, x24, lsl #2]",
    "4303c: 97ff81bd     \tbl\t0x23730",
    "43064: 7200001f     \ttst\tw0, #0x1",
    "43074: 91000708     \tadd\tx8, x24, #0x1",
    "430a4: f85f83a9     \tldur\tx9, [x29, #-0x8]",
    "430b0: eb09033f     \tcmp\tx25, x9",
    "430c4: 2a1f03eb     \tmov\tw11, wzr",
    "430d0: 120002e0     \tand\tw0, w23, #0x1",
):
    assert needle in ARM, needle

for needle in (
    "runRecoveredAnyDescriptorMatcher42eb0(",
    "if (descriptors == nullptr) return false;",
    "index < count",
    "descriptors[index]",
    "descriptorKinds[index]",
    "recoveredAnyDescriptorMatcher42eb0Regression()",
    "matchedCalls.size() == 3",
    "state.calls.size() == 4",
):
    assert needle in CPP, needle

print("arm64 descriptor any-match wrapper 0x42eb0 evidence: PASS")
