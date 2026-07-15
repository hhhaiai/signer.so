#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
A = (AUDIT / "disasm-40ffc-418d8.txt").read_text(errors="replace")
B = (AUDIT / "disasm-418e8-421cc.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


def assert_ordered(text: str, *needles: str) -> None:
    position = -1
    for needle in needles:
        position = text.index(needle, position + 1)


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
    "41024: f100001f     \tcmp\tx0, #0x0",
    "41758: f9400d08     \tldr\tx8, [x8, #0x18]",
    "4176c: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "41608: b9402feb     \tldr\tw11, [sp, #0x2c]",
    "4160c: 51016cea     \tsub\tw10, w7, #0x5b",
    "41618: 3100691f     \tcmn\tw8, #0x1a",
    "416fc: 9100054a     \tadd\tx10, x10, #0x1",
    "4177c: aa1303e9     \tmov\tx9, x19",
    "41780: 91000768     \tadd\tx8, x27, #0x1",
    "41794: 38401d2e     \tldrb\tw14, [x9, #0x1]!",
    "41810: 78297a74     \tstrh\tw20, [x19, x9, lsl #1]",
    "417f4: 528001b4     \tmov\tw20, #0xd",
    "41808: 1e203921     \tfsub\ts1, s9, s0",
    "41814: 1e212800     \tfadd\ts0, s0, s1",
):
    assert needle in A, needle

for needle in (
    "41970: f100001f     \tcmp\tx0, #0x0",
    "4211c: f9400d08     \tldr\tx8, [x8, #0x18]",
    "4213c: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "41ec0: b9402feb     \tldr\tw11, [sp, #0x2c]",
    "41ec4: 51016cea     \tsub\tw10, w7, #0x5b",
    "41ed0: 3100691f     \tcmn\tw8, #0x1a",
    "41f98: 9100055a     \tadd\tx26, x10, #0x1",
    "4214c: aa1303e9     \tmov\tx9, x19",
    "42150: 91000768     \tadd\tx8, x27, #0x1",
    "42164: 38401d2f     \tldrb\tw15, [x9, #0x1]!",
    "41de8: 528001ce     \tmov\tw14, #0xe",
    "41df4: 7829788e     \tstrh\tw14, [x4, x9, lsl #1]",
    "41dd0: 1e203901     \tfsub\ts1, s8, s0",
    "41de0: 1e212800     \tfadd\ts0, s0, s1",
):
    assert needle in B, needle

image = SO.read_bytes()
google_encoded = virtual_bytes(image, 0x144298, 11)
emulator_encoded = virtual_bytes(image, 0x143618, 9)
assert bytes(value ^ 0x90 for value in google_encoded) == b"google_sdk\0"
assert bytes(value ^ 0x68 for value in emulator_encoded) == b"emulator\0"

assert_ordered(
    A,
    "41810: 78297a74",
    "41818: f90001ee",
    "41834: bd000200",
)
assert_ordered(
    B,
    "41de4: f90001ee",
    "41df4: 7829788e",
    "41dfc: bd000200",
)
google_cpp = CPP[CPP.index("void runRecoveredGoogleSdkSubstringDetector40ffc("):
                 CPP.index("void runRecoveredEmulatorSubstringDetector418e8(")]
emulator_cpp = CPP[CPP.index("void runRecoveredEmulatorSubstringDetector418e8("):
                   CPP.index("void runRecoveredGoldfishSubstringDetector43104(")]
assert_ordered(
    google_cpp,
    "corrections[index] = 0x0d;",
    "*correctionCount = index + 1;",
    "*score = (1.0F - currentScore) + currentScore;",
)
assert_ordered(
    emulator_cpp,
    "*correctionCount = index + 1;",
    "corrections[index] = 0x0e;",
    "*score = (1.0F - currentScore) + currentScore;",
)

for needle in (
    "recoveredAsciiCaseInsensitiveContains40ffc(",
    "for (const char* start = haystack; *start != '\\0'; ++start)",
    "foldRecoveredAsciiDetectorByte868b4(*left)",
    'kRecoveredDetectorGoogleSdkMarker[] = "google_sdk"',
    'kRecoveredDetectorEmulatorMarker[] = "emulator"',
    "runRecoveredGoogleSdkSubstringDetector40ffc(",
    "runRecoveredEmulatorSubstringDetector418e8(",
    "scratch->fixedString18",
    "corrections[index] = 0x0d;",
    "corrections[index] = 0x0e;",
    "*score = (1.0F - currentScore) + currentScore;",
    "recoveredDetectorStages40ffc418e8Regression()",
    '"head-GOOGLE_SDK-tail"',
    '"ggoogle_sdk"',
    '"prefix-EmUlAtOr-suffix"',
):
    assert needle in CPP, needle

print("arm64 detectors 0x40ffc/0x418e8 evidence: PASS")
