#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
STAGE = (AUDIT / "disasm-456b8-47778.txt").read_text(errors="replace")
PREDICATE = (AUDIT / "disasm-23730-24444.txt").read_text(errors="replace")
PREFIX = (AUDIT / "disasm-12ad00-12b474.txt").read_text(errors="replace")
CONTAINS = (AUDIT / "disasm-12ba10-12c12c.txt").read_text(errors="replace")
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
    "45708: f100001f     \tcmp\tx0, #0x0",
    "45764: f90013e0     \tstr\tx0, [sp, #0x20]",
    "46f2c: f94013e8     \tldr\tx8, [sp, #0x20]",
    "46f3c: f9400108     \tldr\tx8, [x8]",
    "46f50: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "46c2c: 910223e1     \tadd\tx1, sp, #0x88",
    "46c30: 910143e2     \tadd\tx2, sp, #0x50",
    "46c34: 52800163     \tmov\tw3, #0xb",
    "46c54: a9057fff     \tstp\txzr, xzr, [sp, #0x50]",
    "46c58: fd003bee     \tstr\td14, [sp, #0x70]",
    "46c70: 3d801be0     \tstr\tq0, [sp, #0x60]",
    "46cc4: b9007be8     \tstr\tw8, [sp, #0x78]",
    "46cc8: 97fff07a     \tbl\t0x42eb0",
    "46c04: bd000100     \tstr\ts0, [x8]",
    "46c10: f900016a     \tstr\tx10, [x11]",
    "46c18: 528002ab     \tmov\tw11, #0x15",
    "46c1c: 7828794b     \tstrh\tw11, [x10, x8, lsl #1]",
):
    assert needle in STAGE, needle

for needle in (
    "2377c: 7100005f     \tcmp\tw2, #0x0",
    "23794: 7100045f     \tcmp\tw2, #0x1",
    "24104: 94041e43     \tbl\t0x12ba10",
    "24384: 94041a5f     \tbl\t0x12ad00",
    "24424: 12000000     \tand\tw0, w0, #0x1",
):
    assert needle in PREDICATE, needle

for needle in (
    "12ad1c: f100003f     \tcmp\tx1, #0x0",
    "12ad28: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "12b1b4: 384016cd     \tldrb\tw13, [x22], #0x1",
    "12b208: b9403fec     \tldr\tw12, [sp, #0x3c]",
    "12b210: 321b014e     \torr\tw14, w10, #0x20",
    "12b230: 1a8d318d     \tcsel\tw13, w12, w13, lo",
    "12b1d4: f94007ec     \tldr\tx12, [sp, #0x8]",
    "12b200: 9100058e     \tadd\tx14, x12, #0x1",
    "12b468: 12000100     \tand\tw0, w8, #0x1",
):
    assert needle in PREFIX, needle

for needle in (
    "12ba2c: f100003f     \tcmp\tx1, #0x0",
    "12ba38: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "12bf60: 3840172a     \tldrb\tw10, [x25], #0x1",
    "12bfb4: 38401e8a     \tldrb\tw10, [x20, #0x1]!",
    "12c02c: 321b004f     \torr\tw15, w2, #0x20",
    "12c034: 321b018a     \torr\tw10, w12, #0x20",
    "12c044: 91000531     \tadd\tx17, x9, #0x1",
    "12c120: 12000100     \tand\tw0, w8, #0x1",
):
    assert needle in CONTAINS, needle

image = SO.read_bytes()
assert image[0x2F80:0x2F90] == struct.pack("<IIII", 0, 3, 0, 0)
encoded_markers = (
    (0x144300, 0xDC, b"sdk_x86_64\0"),
    (0x1436C4, 0xB2, b"sdk\0"),
    (0x144298, 0x90, b"google_sdk\0"),
    (0x144310, 0x2D, b"sdk_x86\0"),
    (0x144318, 0x69, b"vbox86p\0"),
    (0x144320, 0xEC, b"sdk_google\0"),
    (0x144330, 0x9F, b"sdk_google_phone_x86_64\0"),
    (0x144350, 0x45, b"sdk_google_phone_arm64\0"),
    (0x144370, 0xF5, b"sdk_gphone64_arm64\0"),
    (0x143734, 0xED, b"vbox\0"),
    (0x1436D8, 0xC3, b"sdk_gphone_\0"),
)
for address, key, plaintext in encoded_markers:
    encoded = virtual_bytes(image, address, len(plaintext))
    assert bytes(value ^ key for value in encoded) == plaintext

for needle in (
    "kRecoveredDetectorFingerprintMarkers456b8",
    '"sdk_x86_64", "sdk", "google_sdk", "sdk_x86", "vbox86p"',
    '"sdk_google", "sdk_google_phone_x86_64", "sdk_google_phone_arm64"',
    '"sdk_gphone64_arm64", "vbox", "sdk_gphone_"',
    "kRecoveredDetectorFingerprintKinds456b8",
    "0, 0, 0, 0, 0, 3, 0, 0, 3, 3, 1",
    "recoveredAsciiCaseInsensitiveStartsWith12ad00(",
    "recoveredAsciiCaseInsensitiveContains12ba10(",
    "runRecoveredDescriptorPredicate23730(",
    "runRecoveredFingerprintDescriptorDetector456b8(",
    "scratch->fixedString00",
    "runRecoveredAnyDescriptorMatcher42eb0(",
    "*score = (1.0F - currentScore) + currentScore;",
    "*correctionCount = index + 1;",
    "corrections[index] = 0x15;",
    "recoveredFingerprintDescriptorDetector456b8Regression()",
    '"SDK_GPHONE_X86"',
    '"product-SDK_GPHONE_"',
    '"prefix-SDK_GOOGLE-suffix"',
):
    assert needle in CPP, needle

score_store = CPP.index("*score = (1.0F - currentScore) + currentScore;", CPP.index(
    "runRecoveredFingerprintDescriptorDetector456b8("))
count_store = CPP.index("*correctionCount = index + 1;", score_store)
correction_store = CPP.index("corrections[index] = 0x15;", count_store)
assert score_store < count_store < correction_store

print("arm64 fingerprint descriptor detector 0x456b8 evidence: PASS")
