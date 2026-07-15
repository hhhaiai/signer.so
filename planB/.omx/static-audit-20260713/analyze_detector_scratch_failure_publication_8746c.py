#!/usr/bin/env python3
"""Prove the flattened 0x8746c helper-failure publication paths.

This verifier intentionally focuses on native evidence.  It establishes which
helper failures preserve the helper status and which paths normalize it before
the producer returns.  The source-level C++ parity change is kept separate so
the current red/green state cannot be hidden by the static proof itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
X86_TEXT = (AUDIT / "disasm-x86-88475-93f86.txt").read_text(
    errors="replace").lower()
ARM_TEXT = (AUDIT / "disasm-8746c-8f56c.txt").read_text(
    errors="replace").lower()
CPP_TEXT = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")
COVERAGE_TEXT = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text(
    errors="replace")
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str


def parse_instructions(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    pattern = re.compile(
        r"^\s*([0-9a-f]+):\s+"
        r"(?:(?:[0-9a-f]{2})\s+)+\s*"
        r"([a-z][a-z0-9.]*)\s*(.*)$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        instructions.append(Instruction(
            int(match.group(1), 16),
            match.group(2),
            match.group(3).strip()))
    return instructions


X86 = parse_instructions(X86_TEXT)
X86_BY_ADDRESS = {instruction.address: instruction for instruction in X86}


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_instruction(address: int, mnemonic: str, operands: str) -> None:
    instruction = X86_BY_ADDRESS.get(address)
    if instruction is None:
        raise AssertionError(f"missing x86 instruction 0x{address:x}")
    if instruction.mnemonic != mnemonic or re.fullmatch(
            operands, instruction.operands) is None:
        raise AssertionError(
            f"unexpected x86 0x{address:x}: "
            f"{instruction.mnemonic} {instruction.operands}")


def build_state_dispatch() -> tuple[
        dict[int, int], dict[int, tuple[int, int, int]]]:
    """Map each flattened literal to its conditional jump target."""
    dispatch: dict[int, int] = {}
    metadata: dict[int, tuple[int, int, int]] = {}
    register_pattern = re.compile(
        r"(r(?:ax|bx|cx|dx|si|di|8|9|10|11|12|13|14|15)),"
        r"0x([0-9a-f]+)$")
    for index, instruction in enumerate(X86):
        match = register_pattern.fullmatch(instruction.operands)
        if instruction.mnemonic != "movabs" or match is None:
            continue
        constant_register = match.group(1)
        literal = int(match.group(2), 16)
        for compare_index in range(index + 1, min(index + 6, len(X86))):
            compare = X86[compare_index]
            if compare.mnemonic != "cmp" or re.search(
                    rf"(?<![a-z0-9]){constant_register}(?![a-z0-9])",
                    compare.operands) is None:
                continue
            for jump_index in range(
                    compare_index + 1, min(compare_index + 4, len(X86))):
                jump = X86[jump_index]
                if jump.mnemonic not in {"je", "jz"}:
                    continue
                target_match = re.match(r"([0-9a-f]+)", jump.operands)
                if target_match is None:
                    continue
                if literal in dispatch:
                    raise AssertionError(
                        f"duplicate flattened state literal 0x{literal:x}")
                dispatch[literal] = int(target_match.group(1), 16)
                metadata[literal] = (index, compare_index, jump_index)
                break
            break
    return dispatch, metadata


DISPATCH, DISPATCH_METADATA = build_state_dispatch()
DISPATCHER = 0x884D2


def alias_successor(literal: int) -> tuple[int, int]:
    """Recover the rdx literal selected before an alias jump to dispatcher."""
    state_index, _, _ = DISPATCH_METADATA[literal]
    for index in range(state_index - 1, max(-1, state_index - 80), -1):
        instruction = X86[index]
        match = re.fullmatch(r"rdx,0x([0-9a-f]+)", instruction.operands)
        if instruction.mnemonic == "movabs" and match is not None:
            return int(match.group(1), 16), instruction.address
    raise AssertionError(f"no alias successor for state 0x{literal:x}")


def flattened_path(initial: int) -> tuple[list[int], int, list[int]]:
    states: list[int] = []
    alias_sites: list[int] = []
    current = initial
    for _ in range(32):
        if current in states:
            raise AssertionError(f"state loop at 0x{current:x}")
        states.append(current)
        target = DISPATCH.get(current)
        if target is None:
            raise AssertionError(f"unmapped state 0x{current:x}")
        if target != DISPATCHER:
            return states, target, alias_sites
        current, alias_site = alias_successor(current)
        alias_sites.append(alias_site)
    raise AssertionError(f"flattened path from 0x{initial:x} did not terminate")


HELPERS = {
    "service": (0x9089F, 0xAC4D5,
                0x511B92F006C5852C, 0x56A2DDEEC5C96164),
    "sensor-list": (0x91510, 0xB278E,
                    0xC3DBAC45FC607D45, 0x0094E94F0AF6A39E),
    "size": (0x91BC8, 0xA469C,
             0x73607F7509817246, 0x3199538427A241A3),
    "get": (0x93CA9, 0xA4CD9,
            0xB802CAEAE0E4A0D2, 0xAA768935B940BFB7),
    "name": (0x91CB6, 0xB1A13,
             0xFCFF3EA2C56C77D9, 0xFAF27D0F8D2F3090),
    "name-utf": (0x8F131, 0x96AE0,
                 0xE6EF1FEFFAF9A40D, 0xD390D4B079CD3C97),
    "vendor": (0x91EEA, 0xB20C2,
               0xB2CC4B2081A7185E, 0x4C5051BA5AD0AABC),
    "vendor-utf": (0x910E3, 0x96AE0,
                   0x4100C8504F2EB2A9, 0x18246E893E2E4458),
    "append": (0x92F15, 0x93F86,
               0x0D1E6B2750A48083, 0x1973E4091D2A593B),
    "resources": (0x8F5CA, 0xAFB26,
                  0x6D6D9FA913227D9D, 0x681EDE27B32B19E6),
    "display": (0x90B18, 0xB0994,
                0x74574FF53DCB9D86, 0xE36EE3627A8F39C8),
    "width": (0x8E91C, 0xAA362,
              0x020E1B70F0D6F1B0, 0xD465D68FFBAD0166),
    "height": (0x9374D, 0xAA362,
               0x4F84173953A2CE45, 0x79D49194777ED6B3),
}


EXPECTED_FAILURE_PATHS = {
    "service": ([0x511B92F006C5852C], 0x913A3),
    "sensor-list": ([
        0xC3DBAC45FC607D45, 0xDD444637593236A1], 0x8E258),
    "size": ([
        0x73607F7509817246, 0xDD444637593236A1], 0x8E258),
    "get": ([
        0xB802CAEAE0E4A0D2, 0x4248ED4D74A94315,
        0xBFB923327604D41B], 0x90F13),
    "name": ([
        0xFCFF3EA2C56C77D9, 0xD461C435C0DC6AE9,
        0x4248ED4D74A94315, 0xBFB923327604D41B], 0x90F13),
    "name-utf": ([
        0xE6EF1FEFFAF9A40D, 0x370EE1EC39F3C372,
        0xD461C435C0DC6AE9, 0x4248ED4D74A94315,
        0xBFB923327604D41B], 0x90F13),
    "vendor": ([
        0xB2CC4B2081A7185E, 0x477719065BBB9E1D,
        0x370EE1EC39F3C372, 0xD461C435C0DC6AE9,
        0x4248ED4D74A94315, 0xBFB923327604D41B], 0x90F13),
    "vendor-utf": ([
        0x4100C8504F2EB2A9, 0x73DB4FB59530BEB2,
        0x477719065BBB9E1D, 0x370EE1EC39F3C372,
        0xD461C435C0DC6AE9, 0x4248ED4D74A94315,
        0xBFB923327604D41B], 0x90F13),
    "append": ([
        0x0D1E6B2750A48083, 0x73DB4FB59530BEB2,
        0x477719065BBB9E1D, 0x370EE1EC39F3C372,
        0xD461C435C0DC6AE9, 0x4248ED4D74A94315,
        0xBFB923327604D41B], 0x90F13),
    "resources": ([
        0x6D6D9FA913227D9D, 0x5BEC243530511574], 0x913B5),
    "display": ([
        0x74574FF53DCB9D86, 0x5BEC243530511574], 0x913B5),
    "width": ([0x020E1B70F0D6F1B0], 0x8D1E3),
    "height": ([0x4F84173953A2CE45], 0x8D1E3),
}


def verify_helper_pairs() -> None:
    for name, (call_address, target, failure, success) in HELPERS.items():
        call = X86_BY_ADDRESS.get(call_address)
        if call is None or call.mnemonic != "call" or re.match(
                rf"0*{target:x}\b", call.operands) is None:
            raise AssertionError(f"unexpected {name} helper call")
        call_index = X86.index(call)
        nearby = X86[call_index + 1:call_index + 12]
        literals = {
            int(match.group(1), 16)
            for instruction in nearby
            for match in [re.search(r"0x([0-9a-f]+)$", instruction.operands)]
            if instruction.mnemonic == "movabs" and match is not None
        }
        if failure not in literals or success not in literals:
            raise AssertionError(
                f"missing {name} failure/success state pair")


def main() -> None:
    if len(DISPATCH) != 231:
        raise AssertionError(
            f"expected 231 x86 flattened states, found {len(DISPATCH)}")
    verify_helper_pairs()
    print("thirteen x86 helper calls and failure/success state pairs: PASS")

    for name, (expected_states, expected_terminal) in (
            EXPECTED_FAILURE_PATHS.items()):
        actual_states, actual_terminal, _ = flattened_path(
            HELPERS[name][2])
        if actual_states != expected_states or actual_terminal != expected_terminal:
            raise AssertionError(
                f"unexpected {name} failure path: "
                f"{[hex(state) for state in actual_states]} -> "
                f"0x{actual_terminal:x}")
    print("all thirteen flattened failure aliases and cleanup entries: PASS")

    require_instruction(0x913A3, "mov", r"rax,qword ptr \[rbp-0x140\]")
    require_instruction(0x913AA, "mov", r"dword ptr \[rax\],0x24")
    require_instruction(0x8D1E3, "mov", r"rax,qword ptr \[rbp-0x148\]")
    require_instruction(0x8D1EA, "mov", r"dword ptr \[rax\],0x1d")
    require_instruction(0x8D29A, "movabs", r"rdx,0x5bec243530511574")
    print("service status 0x24 and width/height status 0x1d normalization: PASS")

    require_instruction(0x8F781, "mov", r"rax,qword ptr \[rbp-0x140\]")
    require_instruction(0x8F788, "mov", r"eax,dword ptr \[rax\]")
    require_instruction(0x8F78A, "mov", r"dword ptr \[rbp-0x1b8\],eax")
    require_instruction(0x890FC, "mov", r"eax,dword ptr \[rbp-0x1b8\]")
    require_instruction(0x89102, "mov", r"dword ptr \[rbp-0x34\],eax")
    require_instruction(0x8FEC4, "mov", r"rax,qword ptr \[rbp-0x148\]")
    require_instruction(0x8FECB, "mov", r"eax,dword ptr \[rax\]")
    require_instruction(0x8FECD, "mov", r"dword ptr \[rbp-0x34\],eax")
    require_instruction(0x8851F, "mov", r"r14d,dword ptr \[rbp-0x34\]")
    require_instruction(0x88577, "mov", r"dword ptr \[rbp-0x3c\],r14d")
    require_instruction(0x93F6F, "mov", r"eax,dword ptr \[rbp-0x3c\]")
    print("sensor/display status cells reach the x86_64 return value: PASS")

    require(X86_TEXT,
            r"92f15:.*call\s+93f86.*"
            r"92f23:.*test\s+eax,eax.*"
            r"92f25:.*0xd1e6b2750a48083.*"
            r"92f2f:.*0x1973e4091d2a593b.*"
            r"92fd7:.*inc\s+r10d",
            "post-appender status selection and unconditional index increment")
    print("post-appender index increment occurs after both status outcomes: PASS")

    require(ARM_TEXT,
            r"8af24:.*bl\s+b5828.*8af58:.*ldr\s+w14, \[x8\]",
            "ARM64 service helper status load")
    require(ARM_TEXT,
            r"8ac40:.*mov\s+w0, #0x24.*8ac4c:.*b\s+8bd38",
            "ARM64 service status normalization")
    require(ARM_TEXT,
            r"8d564:.*bl\s+b21b4.*8d598:.*ldr\s+w14, \[x8\]",
            "ARM64 width helper status load")
    require(ARM_TEXT,
            r"8c320:.*bl\s+b21b4.*8c354:.*ldr\s+w14, \[x8\]",
            "ARM64 height helper status load")
    require(ARM_TEXT,
            r"8dbc4:.*mov\s+w0, #0x1d.*8dbdc:.*str\s+w0, \[x7\]",
            "ARM64 width/height status normalization")
    require(ARM_TEXT, r"8f534:.*mov\s+w0, w20", "ARM64 final status return")
    print("ARM64 fixed statuses and final w20 return corroborate x86_64: PASS")

    require(CPP_TEXT,
            r"getSystemService\(.*?if \(status != 0\) \{\s*"
            r"status = 0x24;\s*\}.*?getSensorList\(",
            "C++ service status normalization")
    require(CPP_TEXT,
            r'getIntField\(.*?"widthPixels".*?'
            r"if \(status != 0\) status = 0x1d;.*?"
            r'getIntField\(.*?"heightPixels".*?'
            r"if \(status != 0\) status = 0x1d;",
            "C++ width/height status normalization")
    require(CPP_TEXT,
            r"expectedStatus =\s*"
            r"std::strcmp\(failure\.failEvent, \"service\"\) == 0\s*"
            r"\? 0x24 : 0x5a;",
            "C++ exact service failure regression")
    require(CPP_TEXT,
            r"std::strcmp\(failure, \"widthPixels\"\) == 0 \? 0x1d : 0x5b;",
            "C++ exact width failure regression")
    require(CPP_TEXT,
            r'state\.failEvent = "heightPixels";.*?'
            r"state\.failStatus = 0x5c;.*?status == 0x1d",
            "C++ exact height failure regression")
    print("C++ exact native-status model and regressions: PASS")

    require(ARM_FULL,
            r"f3ac:.*add\s+x2, sp, #0x38.*"
            r"f3bc:.*bl\s+0x8746c.*"
            r"fc94:.*add\s+x0, sp, #0x38.*"
            r"fc98:.*bl\s+0x8fb44",
            "ARM64 producer scratch forwarded to final destructor")
    require(X86_FULL,
            r"13185:.*leaq\s+0x38\(%rsp\), %rdx.*"
            r"1318a:.*callq\s+0x88475.*"
            r"138e6:.*leaq\s+0x38\(%rsp\), %rdi.*"
            r"138eb:.*callq\s+0x94496",
            "x86_64 producer scratch forwarded to final destructor")
    require(CPP_TEXT,
            r"bool recoveredDetectorScratchProducerNativeDestructorEnvelope8746cRegression\(\).*?"
            r"for \(std::size_t failure = 0;.*?"
            r"const std::array<const char\*, 9> sensorFailures.*?"
            r'"resources", "display", "widthPixels", "heightPixels".*?'
            r"if \(!recoveredDetectorScratchProducerNativeDestructorEnvelope8746cRegression\(\)\)",
            "C++ all-class partial scratch destructor envelope regression")
    print("sole caller and all producer exit classes use the native destructor envelope: PASS")

    require(COVERAGE_TEXT,
            r"`0x8746c\.\.0x8f56c`.*\*\*recovered\*\*",
            "recovered producer coverage")
    print("0x8746c function-level coverage is recovered: PASS")


if __name__ == "__main__":
    main()
