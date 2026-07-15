#!/usr/bin/env python3
"""Static-only audit for alternate final-algorithm selectors in libsigner."""

from __future__ import annotations

import collections
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[2]
DISASSEMBLY = ROOT / ".omx" / "libsigner-arm64-objdump.txt"
ENGINE_START = 0xF1EC8
ENGINE_END = 0x11BA78
STATUS_EXIT = 0xF214C

BINARIES = {
    "arm64-v8a": ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so",
    "armeabi-v7a": ROOT / "adjust-android-signature-3.67.0/jni/armeabi-v7a/libsigner.so",
    "x86": ROOT / "adjust-android-signature-3.67.0/jni/x86/libsigner.so",
    "x86_64": ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so",
}

ALTERNATE_SUITE_PATTERNS = {
    "ChaCha20 sigma": b"expand 32-byte k",
    "ChaCha20 tau": b"expand 16-byte k",
    "ChaCha20": b"ChaCha20",
    "Poly1305": b"Poly1305",
    "AES/GCM": b"AES/GCM",
    "GCM/NoPadding": b"GCM/NoPadding",
}


def parse_engine_instructions() -> list[tuple[int, str, str]]:
    instructions: list[tuple[int, str, str]] = []
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([^\s]+)\s*(.*)")
    for line in DISASSEMBLY.read_text(errors="replace").splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if ENGINE_START <= address < ENGINE_END:
            instructions.append((address, match.group(2), match.group(3).strip()))
    return instructions


def branch_summary(
        instructions: list[tuple[int, str, str]]) -> tuple[
            list[tuple[int, str, str, int | None]], int]:
    branches: list[tuple[int, str, str, int | None]] = []
    load_guarded_status_exits = 0
    for index, (address, opcode, operands) in enumerate(instructions):
        if not (opcode.startswith("b.")
                or opcode in {"cbz", "cbnz", "tbz", "tbnz"}):
            continue
        target_match = re.search(r"0x([0-9a-f]+)", operands)
        target = int(target_match.group(1), 16) if target_match else None
        branches.append((address, opcode, operands, target))
        if opcode == "cbnz" and target == STATUS_EXIT and index > 0:
            previous = instructions[index - 1]
            if previous[1] == "ldr" and previous[2] == "w8, [x19]":
                load_guarded_status_exits += 1
    return branches, load_guarded_status_exits


def call_summary(
        instructions: list[tuple[int, str, str]]) -> tuple[
            collections.Counter[int], int]:
    direct: collections.Counter[int] = collections.Counter()
    indirect = 0
    for _, opcode, operands in instructions:
        if opcode == "blr":
            indirect += 1
        if opcode != "bl":
            continue
        target_match = re.search(r"0x([0-9a-f]+)", operands)
        if target_match:
            direct[int(target_match.group(1), 16)] += 1
    return direct, indirect


def binary_pattern_hits() -> dict[str, dict[str, list[int]]]:
    result: dict[str, dict[str, list[int]]] = {}
    for abi, path in BINARIES.items():
        data = path.read_bytes()
        abi_hits: dict[str, list[int]] = {}
        for name, pattern in ALTERNATE_SUITE_PATTERNS.items():
            offsets: list[int] = []
            cursor = 0
            while True:
                offset = data.find(pattern, cursor)
                if offset < 0:
                    break
                offsets.append(offset)
                cursor = offset + 1
            abi_hits[name] = offsets
        result[abi] = abi_hits
    return result


def main() -> None:
    instructions = parse_engine_instructions()
    branches, load_guarded = branch_summary(instructions)
    direct_calls, indirect_calls = call_summary(instructions)
    target_counts = collections.Counter(target for *_, target in branches)
    patterns = binary_pattern_hits()

    print(f"instructions={len(instructions)}")
    print(f"conditional_branches={len(branches)}")
    print(f"status_exit_branches={target_counts[STATUS_EXIT]}")
    print(f"immediate_ldr_w8_x19_status_guards={load_guarded}")
    print(f"direct_call_sites={sum(direct_calls.values())}")
    print(f"unique_direct_targets={len(direct_calls)}")
    print(f"indirect_blr_calls={indirect_calls}")
    print("top_branch_targets=")
    for target, count in target_counts.most_common(10):
        rendered = "none" if target is None else hex(target)
        print(f"  {rendered}:{count}")
    print("alternate_suite_ascii_hits=")
    for abi, abi_hits in patterns.items():
        rendered = {
            name: [hex(offset) for offset in offsets]
            for name, offsets in abi_hits.items() if offsets
        }
        print(f"  {abi}:{rendered}")


if __name__ == "__main__":
    main()
