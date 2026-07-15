#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-127a78-128038.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


for needle in (
    "127a94: f100003f     \tcmp\tx1, #0x0",
    "127aa4: fa401804     \tccmp\tx0, #0x0, #0x4, ne",
    "127e04: 91000599     \tadd\tx25, x12, #0x1",
    "127e14: 91000597     \tadd\tx23, x12, #0x1",
    "127e24: 394003b8     \tldrb\tw24, [x29]",
    "127e3c: 3940002c     \tldrb\tw12, [x1]",
    "127e78: 384014ac     \tldrb\tw12, [x5], #0x1",
    "127e8c: 7100019f     \tcmp\tw12, #0x0",
    "127ed8: b9402fec     \tldr\tw12, [sp, #0x2c]",
    "127ee4: 6b0c013f     \tcmp\tw9, w12",
    "127f54: 5280002c     \tmov\tw12, #0x1",
    "127de4: b9003fff     \tstr\twzr, [sp, #0x3c]",
    "127fa0: cb0a00bc     \tsub\tx28, x5, x10",
    "127fa8: cb00018c     \tsub\tx12, x12, x0",
    "127fac: eb1c019f     \tcmp\tx12, x28",
    "127fe8: 3840150c     \tldrb\tw12, [x8], #0x1",
    "128028: b9403fe8     \tldr\tw8, [sp, #0x3c]",
    "12802c: 12000100     \tand\tw0, w8, #0x1",
):
    assert needle in ARM, needle

assert not re.search(r"\tbl\t0x", ARM)
assert "#0x5b" not in ARM

for needle in (
    "runRecoveredSubstringPredicate127a78(",
    "if (haystack == nullptr || needle == nullptr) return false;",
    "if (*needle == '\\0') return true;",
    "for (const char* start = haystack; *start != '\\0'; ++start)",
    "while (*right != '\\0' && *left == *right)",
    "recoveredSubstringPredicate127a78Regression()",
    '"Generic", "generic"',
    '"aaaaab", "aaab"',
):
    assert needle in CPP, needle

print("arm64 substring predicate 0x127a78 evidence: PASS")
