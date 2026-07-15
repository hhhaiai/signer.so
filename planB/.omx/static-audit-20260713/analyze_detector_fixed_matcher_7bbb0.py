#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-7bbb0-868b4.txt").read_text(errors="replace")
FCE0_X64 = (AUDIT / "disasm-x86_64-13920-15996.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


for needle in (
    "7bbcc: f100005f     \tcmp\tx2, #0x0",
    "7bbd4: fa401824     \tccmp\tx1, #0x0, #0x4, ne",
    "7bbec: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "7bc54: f900b7e2     \tstr\tx2, [sp, #0x168]",
    "7bc58: a91503e1     \tstp\tx1, x0, [sp, #0x150]",
    "8335c: f9400108     \tldr\tx8, [x8]",
    "85fec: f9400508     \tldr\tx8, [x8, #0x8]",
    "821d8: f9400908     \tldr\tx8, [x8, #0x10]",
    "82100: f9400d08     \tldr\tx8, [x8, #0x18]",
    "8311c: f9401108     \tldr\tx8, [x8, #0x20]",
    "8510c: f9401908     \tldr\tx8, [x8, #0x30]",
    "84b88: f9401d08     \tldr\tx8, [x8, #0x38]",
    "842e8: f9402908     \tldr\tx8, [x8, #0x50]",
    "83584: 52800029     \tmov\tw9, #0x1",
    "8358c: b90167e9     \tstr\tw9, [sp, #0x164]",
    "84d04: b90167ff     \tstr\twzr, [sp, #0x164]",
    "8688c: b94167e8     \tldr\tw8, [sp, #0x164]",
    "86890: 12000100     \tand\tw0, w8, #0x1",
):
    assert needle in ARM, needle

assert len(re.findall(r"\tldr\tx8, \[x8, x10, lsl #3\]", ARM)) == 8
assert len(re.findall(r"\tldrb\tw[0-9]+, \[x[0-9]+\]", ARM)) == 16
assert len(re.findall(r"\tcmp\tw[0-9]+, #0x0", ARM)) == 16
assert len(re.findall(r"\tadd\tx[0-9]+, x[0-9]+, #0x1", ARM)) == 24
assert len(re.findall(r"\tsub\tw8, w10, #0x5b", ARM)) == 16
assert len(re.findall(r"\torr\tw8, w10, #0x20", ARM)) == 16
assert len(re.findall(r"\tcmn\tw8, #0x1a", ARM)) == 16
assert not re.search(r"\tbl\t0x", ARM)
assert not re.search(r"\t(?:str|strb|strh|stp)\t[^\n]*, \[x[0-9]+", ARM)

# x86_64's FCE0 initializer calls its fanout and the dynamic-slot matcher, but
# has no additional call corresponding to ARM64's fixed-field 0x7bbb0 prepass.
assert "callq\t0x7c1f8" in FCE0_X64
assert "callq\t0x87ac8" in FCE0_X64

for needle in (
    "fixedString00",
    "fixedString08",
    "fixedString10",
    "fixedString18",
    "fixedString20",
    "fixedString30",
    "fixedString38",
    "fixedString50",
    "runRecoveredDetectorFixedMarkerMatcher7bbb0(",
    "const std::array<const char*, 8> values",
    "markerIndex < markerCount",
    "recoveredAsciiCaseInsensitiveEqual868b4(",
    "recoveredDetectorFixedMarkerMatcher7bbb0Regression()",
):
    assert needle in CPP, needle

print("arm64 detector fixed marker matcher 0x7bbb0 evidence: PASS")
