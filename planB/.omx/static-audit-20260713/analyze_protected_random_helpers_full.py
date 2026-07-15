#!/usr/bin/env python3
"""Static proof for ARM64 Park-Miller and 16-byte permutation helpers."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
ASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
MASK64 = (1 << 64) - 1


def require(pattern: str, label: str) -> None:
    if re.search(pattern, ASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


# 0x12f298 is a pure tail alias. 0x12f29c uses the Park-Miller constants
# 127773, 16807, 2836 and 0x7fffffff, with a distinct zero-state substitute.
require(r"12f298:.*b\s+0x12f29c", "Park-Miller tail alias")
require(r"12f29c:.*ldr\s+x10, \[x0\]", "64-bit state load")
require(r"12f2a0:.*mov\s+w9, #0xd924", "zero-state low immediate")
require(r"12f2a4:.*movk\s+w9, #0x75b, lsl #16", "123459876 substitute")
require(r"12f2c8:.*udiv\s+x10, x9, x10", "127773 quotient")
require(r"12f2d0:.*mov\s+w11, #0x41a7", "16807 multiplier")
require(r"12f2d4:.*mul\s+x10, x10, x12", "negative 2836 term")
require(r"12f2dc:.*mov\s+w10, #0x7fffffff", "Park-Miller modulus")
require(r"12f2ec:.*and\s+w0, w9, #0x7fffffff", "31-bit result")
require(r"12f2f0:.*str\s+x9, \[x8\]", "unmasked state store")

# 0x12f2f8 conditionally publishes the zero-extended 32-bit seed as one
# 64-bit store. 0x134f40 builds a permutation incrementally from zero bytes.
require(r"12f32c:.*cmp\s+x0, #0x0", "null seed-state gate")
require(r"12f344:.*mov\s+w11, w1", "32-bit seed capture")
require(r"12f38c:.*str\s+x11, \[x0\]", "zero-extended seed store")
require(r"134fb4:.*stp\s+xzr, xzr, \[x0\]", "16-byte zero initialization")
require(r"134ff4:.*mov\s+x0, x19", "random-state argument")
require(r"134ff8:.*bl\s+0x12f298", "one random sample per iteration")
require(r"134ffc:.*udiv\s+w8, w0, w26", "sample divided by i plus one")
require(r"135010:.*msub\s+w10, w8, w26, w0", "sample modulo i plus one")
require(r"135018:.*ldrb\s+w11, \[x20, w10, uxtw\]", "selected-byte load")
require(r"13501c:.*strb\s+w11, \[x20, x25\]", "selected byte moved to i")
require(r"135020:.*strb\s+w25, \[x20, w10, uxtw\]", "i stored at selection")
require(r"135028:.*cmp\s+x8, #0x10", "sixteen-iteration bound")


def park_miller_next(state: int) -> tuple[int, int]:
    value = state or 123459876
    quotient = value // 127773
    remainder = (value + quotient * ((-127773) & MASK64)) & MASK64
    value = (remainder * 16807
             + quotient * ((-2836) & MASK64)) & MASK64
    if value >> 63:
        value = (value + 0x7fffffff) & MASK64
    return value, value & 0x7fffffff


def permutation(seed: int) -> tuple[int, list[int]]:
    state = seed
    output = [0] * 16
    for index in range(16):
        state, sample = park_miller_next(state)
        selected = sample % (index + 1)
        output[index] = output[selected]
        output[selected] = index
    return state, output


state, first = park_miller_next(1)
assert state == first == 16807
state, second = park_miller_next(state)
assert state == second == 282475249
state, zero_first = park_miller_next(0)
assert state == zero_first == 520932930
state, values = permutation(1)
assert state == 0x43CD3747
assert values == [4, 1, 6, 2, 0, 11, 13, 15, 8, 9, 7, 12, 14, 10, 3, 5]

for symbol in (
        "recoveredParkMillerSeed12f2f8",
        "recoveredParkMillerNext12f29c",
        "recoveredParkMillerNext12f298",
        "recoveredPermutationShuffle134f40",
        "recoveredProtectedRandomHelpersRegression"):
    if symbol not in CPP:
        raise AssertionError(f"missing C++ evidence: {symbol}")

print("arm64 protected random helpers 0x12f298..0x12f3ac/0x134f40: PASS")
