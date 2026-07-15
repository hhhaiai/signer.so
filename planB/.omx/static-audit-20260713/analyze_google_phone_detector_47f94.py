#!/usr/bin/env python3
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
ARM = (AUDIT / "disasm-47f94-490e0.txt").read_text(errors="replace")
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
    "47fbc: f100001f     \tcmp\tx0, #0x0",
    "48ca0: f94013e8     \tldr\tx8, [sp, #0x20]",
    "48cb8: f9401908     \tldr\tx8, [x8, #0x30]",
    "48cd0: f100011f     \tcmp\tx8, #0x0",
    "48cd8: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "48bdc: 107dbdae     \tadr\tx14, 0x144390",
    "48be0: 52801c4d     \tmov\tw13, #0xe2",
    "48b0c: 51016d88     \tsub\tw8, w12, #0x5b",
    "48b10: 321b0189     \torr\tw9, w12, #0x20",
    "48b28: 321b0168     \torr\tw8, w11, #0x20",
    "48b30: 6b08013f     \tcmp\tw9, w8",
    "4908c: aa1803fb     \tmov\tx27, x24",
    "49090: 91000675     \tadd\tx21, x19, #0x1",
    "490a0: 38401f77     \tldrb\tw23, [x27, #0x1]!",
    "48cec: 910e8d08     \tadd\tx8, x8, #0x3a3",
    "48cf0: eb08027f     \tcmp\tx19, x8",
    "488dc: 107dd6a1     \tadr\tx1, 0x1443b0",
    "488e0: 52800022     \tmov\tw2, #0x1",
    "488ec: 97ff6b91     \tbl\t0x23730",
    "4891c: 7200001f     \ttst\tw0, #0x1",
    "48f88: 107da241     \tadr\tx1, 0x1443d0",
    "48f8c: 52800022     \tmov\tw2, #0x1",
    "48f98: f9401900     \tldr\tx0, [x8, #0x30]",
    "48f9c: 97ff69e5     \tbl\t0x23730",
    "48fd4: 7200001f     \ttst\tw0, #0x1",
    "48b78: 528002f3     \tmov\tw19, #0x17",
    "48ba4: f90001ee     \tstr\tx14, [x15]",
    "48bb8: 782979d3     \tstrh\tw19, [x14, x9, lsl #1]",
    "48bbc: bd000200     \tstr\ts0, [x16]",
):
    assert needle in ARM, needle


instructions = []
for line in ARM.splitlines():
    match = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+(.+)", line)
    if match:
        instructions.append((
            int(match.group(1), 16),
            match.group(2).split("//", 1)[0].strip(),
        ))

constants = {}
pending_state = None
state_targets = {}
aliases = {}
for address, operation in instructions:
    move = re.fullmatch(r"mov\s+(x\d+),\s+#0x([0-9a-f]+)", operation)
    if move:
        constants[move.group(1)] = int(move.group(2), 16)
        continue
    move_keep = re.fullmatch(
        r"movk\s+(x\d+),\s+#0x([0-9a-f]+),\s+lsl\s+#(\d+)",
        operation,
    )
    if move_keep:
        register = move_keep.group(1)
        value = int(move_keep.group(2), 16)
        shift = int(move_keep.group(3))
        old = constants.get(register)
        if old is not None:
            constants[register] = (old & ~(0xFFFF << shift)) | (value << shift)
        continue
    if not 0x480E4 <= address < 0x486EC:
        continue
    compare = re.fullmatch(r"cmp\s+x9,\s+(x\d+)", operation)
    if compare:
        pending_state = constants.get(compare.group(1))
        continue
    branch = re.fullmatch(r"b\.eq\s+0x([0-9a-f]+).*", operation)
    if branch and pending_state is not None:
        target = int(branch.group(1), 16)
        state_targets[pending_state] = target
        if target == 0x480E4:
            aliases[pending_state] = constants["x12"]
        pending_state = None
    elif operation.startswith(("cmp ", "subs ", "tst ", "ccmp ")):
        pending_state = None


def resolve(state: int):
    seen = set()
    while state in aliases and state not in seen:
        seen.add(state)
        state = aliases[state]
    return state, state_targets.get(state)


assert state_targets[0x1E6ADE7030712334] == 0x48CA0
assert resolve(0x4CC9ACFCB2599EE7) == (0x12EF9BC115EEBC4F, 0x48C60)
assert resolve(0x5D51B1641094B405) == (0xDC463C5E96FC7CBA, 0x48B68)
assert resolve(0x165ED03C1F77C33A) == (0x12EF9BC115EEBC4F, 0x48C60)
assert resolve(0xF525F2257E94843D) == (0xDC463C5E96FC7CBA, 0x48B68)
assert resolve(0x3CBE2EF19BCF30E8) == (0x98000E35A0A7DBC2, 0x48718)
assert resolve(0x44BF8D32CF45F215) == (0xDC463C5E96FC7CBA, 0x48B68)
assert resolve(0x93E3B888EF6D67D5) == (0xB635699A2FEB6557, None)

image = SO.read_bytes()
encoded_markers = (
    (0x144390, 0xE2, b"sdk_google_phone_arm\0"),
    (0x1443B0, 0xBC, b"google/sdk_gphone_\0"),
    (0x1443D0, 0xF2, b"google/sdk_gphone64_\0"),
)
for address, key, plaintext in encoded_markers:
    encoded = virtual_bytes(image, address, len(plaintext))
    assert bytes(value ^ key for value in encoded) == plaintext

for needle in (
    "kRecoveredDetectorGooglePhoneArmMarker47f94",
    '"sdk_google_phone_arm"',
    "kRecoveredDetectorGoogleGphonePrefix47f94",
    '"google/sdk_gphone_"',
    "kRecoveredDetectorGoogleGphone64Prefix47f94",
    '"google/sdk_gphone64_"',
    "runRecoveredGooglePhoneDetector47f94(",
    "scratch->fixedString30",
    "recoveredAsciiCaseInsensitiveContains40ffc(",
    "recoveredAsciiCaseInsensitiveStartsWith12ad00(",
    "corrections[index] = 0x17;",
    "recoveredGooglePhoneDetector47f94Regression()",
    '"prefix-SDK_GOOGLE_PHONE_ARM64-suffix"',
    '"GOOGLE/SDK_GPHONE_X86/build"',
    '"GOOGLE/SDK_GPHONE64_ARM64/build"',
    '"product-google/sdk_gphone_-tail"',
):
    assert needle in CPP, needle

function_start = CPP.index("void runRecoveredGooglePhoneDetector47f94(")
count_store = CPP.index("*correctionCount = index + 1;", function_start)
correction_store = CPP.index("corrections[index] = 0x17;", count_store)
score_store = CPP.index("*score = (1.0F - currentScore) + currentScore;", correction_store)
assert count_store < correction_store < score_store

print("arm64 google-phone detector 0x47f94 evidence: PASS")
