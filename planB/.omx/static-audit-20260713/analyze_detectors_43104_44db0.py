#!/usr/bin/env python3
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
FILES = {
    "43104": (AUDIT / "disasm-43104-43998.txt").read_text(errors="replace"),
    "439a8": (AUDIT / "disasm-439a8-442dc.txt").read_text(errors="replace"),
    "442ec": (AUDIT / "disasm-442ec-44c28.txt").read_text(errors="replace"),
    "44db0": (AUDIT / "disasm-44db0-456a8.txt").read_text(errors="replace"),
}
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
        fields = struct.unpack_from(
            "<IIQQQQQQ", image, program_offset + index * entry_size
        )
        if fields[0] == 1:
            yield fields[2], fields[3], fields[5]


def virtual_bytes(image: bytes, address: int, size: int) -> bytes:
    for file_offset, virtual_address, file_size in load_segments(image):
        if virtual_address <= address and address + size <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return image[start:start + size]
    raise AssertionError(f"unmapped virtual address: {address:#x}")


checks = {
    "43104": (
        "43564: f940211c     \tldr\tx28, [x8, #0x40]",
        "43570: fa401844     \tccmp\tx2, #0x0, #0x4, ne",
        "436b0: b9401feb     \tldr\tw11, [sp, #0x1c]",
        "436e8: 9100054a     \tadd\tx10, x10, #0x1",
        "43724: 52800214     \tmov\tw20, #0x10",
        "4374c: 78297854     \tstrh\tw20, [x2, x9, lsl #1]",
    ),
    "439a8": (
        "44108: f9402108     \tldr\tx8, [x8, #0x40]",
        "4411c: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
        "440dc: 910006d5     \tadd\tx21, x22, #0x1",
        "4405c: 52800234     \tmov\tw20, #0x11",
        "440a0: 782979d4     \tstrh\tw20, [x14, x9, lsl #1]",
    ),
    "442ec": (
        "447a4: f9401108     \tldr\tx8, [x8, #0x20]",
        "447b4: fa401904     \tccmp\tx8, #0x0, #0x4, ne",
        "44874: b85f83ab     \tldur\tw11, [x29, #-0x8]",
        "44a6c: 9100054a     \tadd\tx10, x10, #0x1",
        "44ab8: 52800257     \tmov\tw23, #0x12",
        "44af0: 782978b7     \tstrh\tw23, [x5, x9, lsl #1]",
    ),
    "44db0": (
        "455e8: f940211a     \tldr\tx26, [x8, #0x40]",
        "455f4: fa401844     \tccmp\tx2, #0x0, #0x4, ne",
        "4556c: 91000668     \tadd\tx8, x19, #0x1",
        "45618: 52800293     \tmov\tw19, #0x14",
        "45640: 78297853     \tstrh\tw19, [x2, x9, lsl #1]",
    ),
}
for name, needles in checks.items():
    for needle in needles:
        assert needle in FILES[name], needle

for name, addresses in {
    "43104": ("4374c: 78297854", "43754: f90001ee", "43770: bd000200"),
    "439a8": ("44090: f90001ee", "440a0: 782979d4", "440a8: bd000200"),
    "442ec": ("44af0: 782978b7", "44b00: f90001ee", "44b1c: bd000200"),
    "44db0": ("45640: 78297853", "45648: f90001ee", "45664: bd000200"),
}.items():
    assert_ordered(FILES[name], *addresses)

image = SO.read_bytes()
for address, size, key, plaintext in (
    (0x1434E8, 9, 0x30, b"goldfish\0"),
    (0x143634, 7, 0x31, b"vbox86\0"),
    (0x1442F0, 12, 0x28, b"android_x86\0"),
):
    encoded = virtual_bytes(image, address, size)
    assert bytes(value ^ key for value in encoded) == plaintext

for needle in (
    "const char* fixedString40;",
    "offsetof(RecoveredDetectorScratch868b4, fixedString40) == 0x40",
    'kRecoveredDetectorGoldfishMarker[] = "goldfish"',
    'kRecoveredDetectorVbox86Marker[] = "vbox86"',
    'kRecoveredDetectorAndroidX86Marker[] = "android_x86"',
    "runRecoveredGoldfishSubstringDetector43104(",
    "runRecoveredVbox86SubstringDetector439a8(",
    "runRecoveredVbox86SubstringDetector442ec(",
    "runRecoveredAndroidX86SubstringDetector44db0(",
    "corrections[index] = 0x10;",
    "corrections[index] = 0x11;",
    "corrections[index] = 0x12;",
    "corrections[index] = 0x14;",
    "recoveredDetectorStages43104To44db0Regression()",
):
    assert needle in CPP, needle

function_bounds = (
    ("void runRecoveredGoldfishSubstringDetector43104(",
     "void runRecoveredVbox86SubstringDetector439a8(", "0x10", "correction-first"),
    ("void runRecoveredVbox86SubstringDetector439a8(",
     "void runRecoveredVbox86SubstringDetector442ec(", "0x11", "count-first"),
    ("void runRecoveredVbox86SubstringDetector442ec(",
     "void runRecoveredAndroidX86SubstringDetector44db0(", "0x12", "correction-first"),
    ("void runRecoveredAndroidX86SubstringDetector44db0(",
     "using RecoveredDetectorPredicate352d4", "0x14", "correction-first"),
)
for start, end, code, order in function_bounds:
    function = CPP[CPP.index(start):CPP.index(end)]
    operations = (
        (f"corrections[index] = {code};", "*correctionCount = index + 1;")
        if order == "correction-first"
        else ("*correctionCount = index + 1;", f"corrections[index] = {code};")
    )
    assert_ordered(
        function,
        *operations,
        "*score = (1.0F - currentScore) + currentScore;",
    )

print("arm64 detectors 0x43104/0x439a8/0x442ec/0x44db0 evidence: PASS")
