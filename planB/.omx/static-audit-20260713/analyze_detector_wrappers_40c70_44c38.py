#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
A = (AUDIT / "disasm-40c70-40fec.txt").read_text(errors="replace")
B = (AUDIT / "disasm-44c38-44da0.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


for needle in (
    "40d14: f100001f     \tcmp\tx0, #0x0",
    "40e6c: f9401908     \tldr\tx8, [x8, #0x30]",
    "40e7c: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "40e90: f0000801     \tadrp\tx1, 0x143000",
    "40e94: 911c6021     \tadd\tx1, x1, #0x718",
    "40ea0: 94039af6     \tbl\t0x127a78",
    "40f14: 9403e23b     \tbl\t0x139800",
    "40f68: fd438d00     \tldr\td0, [x8, #0x718]",
    "40f70: 2e281c00     \teor\tv0.8b, v0.8b, v8.8b",
    "40f94: bd400180     \tldr\ts0, [x12]",
    "40f9c: f9400168     \tldr\tx8, [x11]",
    "40fa0: 1e203921     \tfsub\ts1, s9, s0",
    "40fa8: 1f0a0020     \tfmadd\ts0, s1, s10, s0",
    "40fac: f900016a     \tstr\tx10, [x11]",
    "40fb4: 5280016b     \tmov\tw11, #0xb",
    "40fb8: 7828794b     \tstrh\tw11, [x10, x8, lsl #1]",
    "40fbc: bd000180     \tstr\ts0, [x12]",
):
    assert needle in A, needle

for needle in (
    "44c58: f100005f     \tcmp\tx2, #0x0",
    "44c64: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "44d2c: aa1603e0     \tmov\tx0, x22",
    "44d30: 97ffc169     \tbl\t0x352d4",
    "44d34: 7200001f     \ttst\tw0, #0x1",
    "44d40: bd4002a0     \tldr\ts0, [x21]",
    "44d48: f9400269     \tldr\tx9, [x19]",
    "44d54: 1e203901     \tfsub\ts1, s8, s0",
    "44d5c: 9100052a     \tadd\tx10, x9, #0x1",
    "44d60: 1e212800     \tfadd\ts0, s0, s1",
    "44d64: f900026a     \tstr\tx10, [x19]",
    "44d68: 5280026a     \tmov\tw10, #0x13",
    "44d6c: 78297a8a     \tstrh\tw10, [x20, x9, lsl #1]",
    "44d70: bd0002a0     \tstr\ts0, [x21]",
):
    assert needle in B, needle

image = SO.read_bytes()
# The writable data segment containing vaddr 0x143718 has a 0x8000 file
# offset delta.  Its eight encoded bytes are XORed with 0xdf by 0x40c70.
encoded = image[0x143718 - 0x8000:0x143720 - 0x8000]
assert bytes(value ^ 0xDF for value in encoded) == b"generic\0"
assert struct.unpack("<f", image[0x2F64:0x2F68])[0] == struct.unpack(
    "<f", bytes.fromhex("9a99993e")
)[0]

for needle in (
    'kRecoveredDetectorGenericMarker[] = "generic"',
    "runRecoveredGenericSubstringDetector40c70(",
    "scratch->fixedString30",
    "corrections[index] = 0x0b;",
    "(1.0F - currentScore) * 0.3F + currentScore",
    "runRecoveredDetectorWrapper44c38(",
    "RecoveredDetectorPredicate352d4 predicate",
    "corrections[index] = 0x13;",
    "(1.0F - currentScore) + currentScore",
    "recoveredDetectorStage40c70Regression()",
    "recoveredDetectorWrapper44c38Regression()",
):
    assert needle in CPP, needle

print("arm64 detector wrappers 0x40c70/0x44c38 evidence: PASS")
