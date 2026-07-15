#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-fce0-12a30.txt").read_text(errors="replace")
PCS = set((AUDIT / "fce0-executed-pcs.txt").read_text().split())
DIFF = (AUDIT / "fce0-global-byte-diff.txt").read_text().splitlines()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)

calls = []
for line in ARM.splitlines():
    match = re.search(r"^\s*([0-9a-f]+):.*\tbl\t0x([0-9a-f]+)", line)
    if match:
        calls.append(("0x" + match.group(1), "0x" + match.group(2)))

cas_calls = [pc for pc, target in calls if target == "0x139800"]
assert len(cas_calls) == 24
assert all(pc in PCS for pc in cas_calls)
assert "0x11600" not in PCS  # decoy correction-array path on the frozen success run
for pc in ("0x1213c", "0x121b4", "0x11b6c", "0x122bc", "0x129d4"):
    assert pc in PCS, pc

memory = {}
for line in DIFF:
    match = re.search(
        r"fce0-diff data\+0x([0-9a-f]+) [0-9a-f]{2}->([0-9a-f]{2})",
        line,
    )
    if match:
        memory[int(match.group(1), 16)] = int(match.group(2), 16)


def strings(start: int, end: int) -> list[str]:
    data = bytes(memory.get(index, 0) for index in range(start, end))
    result = []
    cursor = 0
    while cursor < len(data):
        terminator = data.find(b"\0", cursor)
        if terminator < 0:
            break
        value = data[cursor:terminator]
        if value and all(32 <= byte < 127 for byte in value):
            result.append(value.decode("ascii"))
        cursor = terminator + 1
    return result


tools = strings(0x0F08, 0x104A)
builds = strings(0x2030, 0x20AF) + strings(0x2298, 0x2400)
assert len(tools) == 24
assert len(builds) == 23
assert tools[0] == "Emulator" and tools[-1] == "redfinger"
assert builds[0] == "android" and builds[-1] == "iphone"
for value in tools + builds:
    assert f'"{value}"' in CPP, value

assert "applyRecoveredCorrectionArray(" in CPP
for needle in (
    "1213c: 94049f35     \tbl\t0x139e10",
    "121b4: 9401a62a     \tbl\t0x7ba5c",
    "121e8: b9000100     \tstr\tw0, [x8]",
    "11b6c: 9401a811     \tbl\t0x7bbb0",
    "11334: 5280032a     \tmov\tw10, #0x19",
    "122bc: 9401d17e     \tbl\t0x868b4",
    "12450: 5280018a     \tmov\tw10, #0xc",
    "1142c: 1e2821a0     \tfcmp\ts13, s8",
    "11600: 94048faf     \tbl\t0x1354bc",
    "11620: b2400108     \torr\tx8, x8, #0x1",
    "129d4: 9400019c     \tbl\t0x13044",
    "129f0: 1a9f17e0     \tcset\tw0, eq",
):
    assert needle in ARM, needle

for needle in (
    "void runRecoveredDetectorFanout7ba5cDirect(",
    "bool runRecoveredEnvironmentStageFce0(",
    "corrections[correctionCount++] = 0x19;",
    "corrections[correctionCount++] = 0x0c;",
    "if (score >= kCommitThreshold)",
    "applyRecoveredCorrectionArray(",
    "applyProtectedContextBit0(context);",
    "applyProtectedContextMask02001000Stage(context);",
    "recoveredEnvironmentStageFce0Regression()",
):
    assert needle in CPP, needle

direct = CPP[
    CPP.index("void runRecoveredDetectorFanout7ba5cDirect("):
    CPP.index("// libsigner.so+0x139800")]
position = -1
for address in (
        "40c70", "40ffc", "418e8", "421dc", "43104", "439a8",
        "442ec", "44c38", "44db0", "456b8", "47788", "47f94",
        "490f0", "4b020"):
    position = direct.index(address, position + 1)

print("arm64 environment stage 0xfce0 complete evidence: PASS")
