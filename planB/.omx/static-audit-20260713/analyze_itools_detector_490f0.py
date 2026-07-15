#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
ARM = (AUDIT / "disasm-490f0-4afd4.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


def load_segments(image: bytes):
    program_offset = struct.unpack_from("<Q", image, 32)[0]
    entry_size = struct.unpack_from("<H", image, 54)[0]
    entry_count = struct.unpack_from("<H", image, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        fields = struct.unpack_from("<IIQQQQQQ", image, offset)
        if fields[0] == 1:
            yield fields[2], fields[3], fields[5]


def virtual_bytes(image: bytes, address: int, size: int) -> bytes:
    for file_offset, virtual_address, file_size in load_segments(image):
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return image[start:start + size]
    raise AssertionError(f"unmapped virtual address: {address:#x}")


for needle in (
    "49114: f100005f     \tcmp\tx2, #0x0",
    "49124: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "49188: f9001fe0     \tstr\tx0, [sp, #0x38]",
    "4a1d0: f940050d     \tldr\tx13, [x8, #0x8]",
    "4a874: f9400d0d     \tldr\tx13, [x8, #0x18]",
    "4ac1c: f940110d     \tldr\tx13, [x8, #0x20]",
    "4a260: 107d0c40     \tadr\tx0, 0x1443e8",
    "4a264: 528006cd     \tmov\tw13, #0x36",
    "4a2f8: 910fb908     \tadd\tx8, x8, #0x3ee",
    "4a438: 910fb908     \tadd\tx8, x8, #0x3ee",
    "4abbc: 910fb908     \tadd\tx8, x8, #0x3ee",
    "4a448: eb08009f     \tcmp\tx4, x8",
    "4abd8: eb08013f     \tcmp\tx9, x8",
    "4a560: 51016e88     \tsub\tw8, w20, #0x5b",
    "4a564: 321b0289     \torr\tw9, w20, #0x20",
    "4a588: 6b08013f     \tcmp\tw9, w8",
    "4a718: 51016ee8     \tsub\tw8, w23, #0x5b",
    "4a728: 321b0348     \torr\tw8, w26, #0x20",
    "4a740: 6b08013f     \tcmp\tw9, w8",
    "4aa04: 3100691f     \tcmn\tw8, #0x1a",
    "4aa20: 6b08013f     \tcmp\tw9, w8",
    "4ab64: 3100691f     \tcmn\tw8, #0x1a",
    "4ab80: 6b08013f     \tcmp\tw9, w8",
    "4ac74: 3100691f     \tcmn\tw8, #0x1a",
    "4ac90: 6b08013f     \tcmp\tw9, w8",
    "4ad90: 3100691f     \tcmn\tw8, #0x1a",
    "4adac: 6b08013f     \tcmp\tw9, w8",
    "4a9cc: 91000468     \tadd\tx8, x3, #0x1",
    "4a9e8: 91000488     \tadd\tx8, x4, #0x1",
    "4af40: 9100056a     \tadd\tx10, x11, #0x1",
    "4af48: 91000528     \tadd\tx8, x9, #0x1",
    "4af6c: 91000669     \tadd\tx9, x19, #0x1",
    "4af70: 91000728     \tadd\tx8, x25, #0x1",
    "4aae0: 52800300     \tmov\tw0, #0x18",
    "4ab24: f90000e2     \tstr\tx2, [x7]",
    "4ab38: 783078e0     \tstrh\tw0, [x7, x16, lsl #1]",
    "4ab40: bd0003c0     \tstr\ts0, [x30]",
):
    assert needle in ARM, needle

image = SO.read_bytes()
encoded = virtual_bytes(image, 0x1443E8, len(b"itools\0"))
assert bytes(value ^ 0x36 for value in encoded) == b"itools\0"

for needle in (
    "kRecoveredDetectorItoolsMarker490f0",
    '"itools"',
    "runRecoveredItoolsDetector490f0(",
    "scratch->fixedString08",
    "scratch->fixedString18",
    "scratch->fixedString20",
    "recoveredAsciiCaseInsensitiveEqual868b4(",
    "corrections[index] = 0x18;",
    "recoveredItoolsDetector490f0Regression()",
    '"prefix-itools"',
    '"itools-suffix"',
    '"ITOOLS"',
    '"iToOlS"',
):
    assert needle in CPP, needle

function_start = CPP.index("void runRecoveredItoolsDetector490f0(")
count_store = CPP.index("*correctionCount = index + 1;", function_start)
correction_store = CPP.index("corrections[index] = 0x18;", count_store)
score_store = CPP.index("*score = (1.0F - currentScore) + currentScore;", correction_store)
assert count_store < correction_store < score_store

print("arm64 itools detector 0x490f0 evidence: PASS")
