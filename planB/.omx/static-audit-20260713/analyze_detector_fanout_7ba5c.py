#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-7ba5c-7bb98.txt").read_text(errors="replace")
X64 = (AUDIT / "disasm-x86_64-7c1f8-7c32f.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


def targets(text: str, opcode: str) -> list[int]:
    return [
        int(match.group(1), 16)
        for match in re.finditer(rf"\t{opcode}\t0x([0-9a-f]+)", text)
    ]


arm_targets = targets(ARM, "bl")
x64_targets = targets(X64, "callq")
assert arm_targets == [
    0x40C70, 0x40FFC, 0x418E8, 0x421DC, 0x43104, 0x439A8, 0x442EC,
    0x44C38, 0x44DB0, 0x456B8, 0x47788, 0x47F94, 0x490F0, 0x4B020,
]
assert len(x64_targets) == 17
assert "7bb88: 2a1f03e0" in ARM
assert "7c321: 31 c0" in X64
for target in arm_targets:
    assert f"0x{target:x}" in CPP
assert "runRecoveredDetectorFanout7ba5c(" in CPP
assert "state.calls == 14" in CPP
print("arm64 detector fanout 0x7ba5c direct orchestration evidence: PASS")
