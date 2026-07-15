#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
STAGE = (AUDIT / "disasm-421dc-42eb0.txt").read_text(errors="replace")
PREDICATE = (AUDIT / "disasm-23730-24444.txt").read_text(errors="replace")
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
    "42308: f100001f     \tcmp\tx0, #0x0",
    "42be4: f9400d08     \tldr\tx8, [x8, #0x18]",
    "42bf4: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
    "42734: 910143e1     \tadd\tx1, sp, #0x50",
    "42738: 910103e2     \tadd\tx2, sp, #0x40",
    "4273c: 52800083     \tmov\tw3, #0x4",
    "42758: a9047fff     \tstp\txzr, xzr, [sp, #0x40]",
    "4275c: a90523e9     \tstp\tx9, x8, [sp, #0x50]",
    "42770: a90623e9     \tstp\tx9, x8, [sp, #0x60]",
    "42774: 940001cf     \tbl\t0x42eb0",
    "42820: 7200001f     \ttst\tw0, #0x1",
    "42b84: 1e203981     \tfsub\ts1, s12, s0",
    "42b88: 1e212800     \tfadd\ts0, s0, s1",
    "42b8c: bd000100     \tstr\ts0, [x8]",
    "42ba0: 528001eb     \tmov\tw11, #0xf",
    "42ba4: 7828794b     \tstrh\tw11, [x10, x8, lsl #1]",
):
    assert needle in STAGE, needle

for needle in (
    "2377c: 7100005f     \tcmp\tw2, #0x0",
    "24424: 12000000     \tand\tw0, w0, #0x1",
):
    assert needle in PREDICATE, needle

image = SO.read_bytes()
encoded_markers = (
    (0x144050, 26, 0x42, b"android sdk built for x86\0"),
    (0x1442B0, 28, 0x09, b"android sdk built for arm64\0"),
    (0x1442D0, 28, 0x39, b"android sdk built for armv7\0"),
    (0x144070, 29, 0x99, b"android sdk built for x86_64\0"),
)
for address, size, key, plaintext in encoded_markers:
    encoded = virtual_bytes(image, address, size)
    assert bytes(value ^ key for value in encoded) == plaintext

for needle in (
    "kRecoveredDetectorBuildMarkers421dc",
    '"android sdk built for x86"',
    '"android sdk built for arm64"',
    '"android sdk built for armv7"',
    '"android sdk built for x86_64"',
    "runRecoveredDescriptorPredicate23730Kind0(",
    "recoveredAsciiCaseInsensitiveEqual868b4(value, marker)",
    "runRecoveredBuildFingerprintDetector421dc(",
    "std::array<std::uint32_t, kRecoveredDetectorBuildMarkers421dc.size()>",
    "runRecoveredAnyDescriptorMatcher42eb0(",
    "corrections[index] = 0x0f;",
    "recoveredBuildFingerprintDetector421dcRegression()",
    '"Android SDK built for x86"',
    '"prefix-android sdk built for armv7-suffix"',
):
    assert needle in CPP, needle

print("arm64 build detector 0x421dc evidence: PASS")
