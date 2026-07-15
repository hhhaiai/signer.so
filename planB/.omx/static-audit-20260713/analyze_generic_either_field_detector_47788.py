#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
ARM = (AUDIT / "disasm-47788-47f84.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


for needle in (
    "477ac: f100005f     \tcmp\tx2, #0x0",
    "477d4: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "47f4c: f9400908     \tldr\tx8, [x8, #0x10]",
    "47b3c: f94013e0     \tldr\tx0, [sp, #0x20]",
    "47b40: 94037fce     \tbl\t0x127a78",
    "47b44: 7200001f     \ttst\tw0, #0x1",
    "47dd8: f9401108     \tldr\tx8, [x8, #0x20]",
    "47e40: f9400fe0     \tldr\tx0, [sp, #0x18]",
    "47e44: 94037f0d     \tbl\t0x127a78",
    "47e6c: 7200001f     \ttst\tw0, #0x1",
    "47ce0: 1e203901     \tfsub\ts1, s8, s0",
    "47ce8: 1e212800     \tfadd\ts0, s0, s1",
    "47cf4: 528002cb     \tmov\tw11, #0x16",
    "47cf8: 7828794b     \tstrh\tw11, [x10, x8, lsl #1]",
):
    assert needle in ARM, needle

image = SO.read_bytes()
encoded = image[0x143718 - 0x8000:0x143720 - 0x8000]
assert bytes(value ^ 0xDF for value in encoded) == b"generic\0"

for needle in (
    "runRecoveredGenericEitherFieldDetector47788(",
    "scratch->fixedString10",
    "scratch->fixedString20",
    "runRecoveredSubstringPredicate127a78(",
    "corrections[index] = 0x16;",
    "recoveredGenericEitherFieldDetector47788Regression()",
    'scratch.fixedString10 = "Generic";',
    'scratch.fixedString20 = "generic-tail";',
):
    assert needle in CPP, needle

print("arm64 generic either-field detector 0x47788 evidence: PASS")
