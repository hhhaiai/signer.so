#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / 'adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so'
A = (AUDIT / 'disasm-456b8-47778.txt').read_text(errors='replace')
B = (AUDIT / 'disasm-47f94-490e0.txt').read_text(errors='replace')
CPP = (ROOT / 'native-reimplementation/recovered_primitives.cpp').read_text(
    errors='replace')


def assert_ordered(text, *needles):
    position = -1
    for needle in needles:
        position = text.index(needle, position + 1)


def load_segments(image):
    program_offset = struct.unpack_from('<Q', image, 32)[0]
    entry_size = struct.unpack_from('<H', image, 54)[0]
    entry_count = struct.unpack_from('<H', image, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        fields = struct.unpack_from('<IIQQQQQQ', image, offset)
        if fields[0] == 1:
            yield fields[2], fields[3], fields[5]


def virtual_bytes(image, address, size):
    for file_offset, virtual_address, file_size in load_segments(image):
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return image[start:start + size]
    raise AssertionError(f'unmapped virtual address: {address:#x}')


image = SO.read_bytes()
marker_specs = (
    (0x144300, 0xDC, 11, b'sdk_x86_64\0'),
    (0x1436C4, 0xB2, 4, b'sdk\0'),
    (0x144298, 0x90, 11, b'google_sdk\0'),
    (0x144310, 0x2D, 8, b'sdk_x86\0'),
    (0x144318, 0x69, 8, b'vbox86p\0'),
    (0x144320, 0xEC, 11, b'sdk_google\0'),
    (0x144330, 0x9F, 24, b'sdk_google_phone_x86_64\0'),
    (0x144350, 0x45, 23, b'sdk_google_phone_arm64\0'),
    (0x144370, 0xF5, 19, b'sdk_gphone64_arm64\0'),
    (0x143734, 0xED, 5, b'vbox\0'),
    (0x1436D8, 0xC3, 12, b'sdk_gphone_\0'),
    (0x144390, 0xE2, 21, b'sdk_google_phone_arm\0'),
    (0x1443B0, 0xBC, 19, b'google/sdk_gphone_\0'),
    (0x1443D0, 0xF2, 21, b'google/sdk_gphone64_\0'),
)
for address, key, size, expected in marker_specs:
    decoded = bytes(value ^ key for value in virtual_bytes(image, address, size))
    assert decoded == expected, (hex(address), decoded)

# 0x456b8 reads the candidate from scratch+0, not stack+0x28.  It forwards
# eleven pointers and eleven kind tags to 0x42eb0 and emits correction 0x15.
for needle in (
    '46f2c: f94013e8     \tldr\tx8, [sp, #0x20]',
    '46f3c: f9400108     \tldr\tx8, [x8]',
    '46f44: f9001fe8     \tstr\tx8, [sp, #0x38]',
    '46c2c: 910223e1     \tadd\tx1, sp, #0x88',
    '46c30: 910143e2     \tadd\tx2, sp, #0x50',
    '46c34: 52800163     \tmov\tw3, #0xb',
    '46c50: f9401fe0     \tldr\tx0, [sp, #0x38]',
    '46cc8: 97fff07a     \tbl\t0x42eb0',
    '46c18: 528002ab     \tmov\tw11, #0x15',
    '46c1c: 7828794b     \tstrh\tw11, [x10, x8, lsl #1]',
):
    assert needle in A, needle

# 0x47f94 reads scratch+0x30, first scans the inline arm marker, then calls
# kind one with the two google/sdk prefixes.  A match emits correction 0x17.
for needle in (
    '48cb8: f9401908     \tldr\tx8, [x8, #0x30]',
    '489e8: 107dcd55     \tadr\tx21, 0x144390',
    '488dc: 107dd6a1     \tadr\tx1, 0x1443b0',
    '488e0: 52800022     \tmov\tw2, #0x1',
    '488ec: 97ff6b91     \tbl\t0x23730',
    '48f88: 107da241     \tadr\tx1, 0x1443d0',
    '48f8c: 52800022     \tmov\tw2, #0x1',
    '48f98: f9401900     \tldr\tx0, [x8, #0x30]',
    '48f9c: 97ff69e5     \tbl\t0x23730',
    '48b78: 528002f3     \tmov\tw19, #0x17',
    '48bb8: 782979d3     \tstrh\tw19, [x14, x9, lsl #1]',
):
    assert needle in B, needle

for needle in (
    'kRecoveredDetectorFingerprintKinds456b8 = {{\n    0, 0, 0, 0, 0, 3, 0, 0, 3, 3, 1',
    'const char* value = scratch->fixedString00;',
    'runRecoveredFingerprintDescriptorDetector456b8(',
    'corrections[index] = 0x15;',
    'kRecoveredDetectorGooglePhoneArmMarker47f94[] =\n        "sdk_google_phone_arm"',
    'recoveredAsciiCaseInsensitiveStartsWith12ad00(\n                    value, kRecoveredDetectorGoogleGphonePrefix47f94)',
    'recoveredAsciiCaseInsensitiveStartsWith12ad00(\n                    value, kRecoveredDetectorGoogleGphone64Prefix47f94)',
    'runRecoveredGooglePhoneDetector47f94(',
    'corrections[index] = 0x17;',
):
    assert needle in CPP, needle

google_phone = CPP[
    CPP.index('void runRecoveredGooglePhoneDetector47f94('):
    CPP.index('using RecoveredDetectorPredicate352d4')
]
assert_ordered(
    google_phone,
    'recoveredAsciiCaseInsensitiveContains40ffc(',
    'recoveredAsciiCaseInsensitiveStartsWith12ad00(',
    'kRecoveredDetectorGoogleGphonePrefix47f94',
    'kRecoveredDetectorGoogleGphone64Prefix47f94',
    '*correctionCount = index + 1;',
    'corrections[index] = 0x17;',
    '*score = (1.0F - currentScore) + currentScore;',
)

print('arm64 detectors 0x456b8/0x47f94 evidence: PASS')
