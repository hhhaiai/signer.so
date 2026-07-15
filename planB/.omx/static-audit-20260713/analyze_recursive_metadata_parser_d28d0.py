#!/usr/bin/env python3
"""Static cross-ABI proof for recursive metadata parser ARM64 0xd28d0."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_EH = (AUDIT / "arm64-eh-frame.txt").read_text(errors="replace").lower()
X86_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(errors="replace").lower()
ARM_FULL = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_FULL = (AUDIT / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (AUDIT / "generate_arm64_function_inventory.py").read_text()


EXPECTED_STATES = {
    0x2368E3FCA25D5C59,
    0x2DCA464A07D83050,
    0x36FAC22A3D940C73,
    0x3EF56BC71D77E94A,
    0x4CB87CC1CAB6BDFB,
    0x5066A5E79BD560AB,
    0x7D1F3048C6876040,
    0x85FDB8AE3AC98E29,
    0x94790566F824151E,
    0x9968646D3B15F4FF,
    0xA17EE611C756BA29,
    0xA7031C90E4AA2AD0,
    0xAE36807CB23B5AE7,
    0xB3AFC6D8E6630B2A,
    0xB66D937EB8A70D82,
    0xCDCAE89F08F350C1,
    0xD50033840A88FC68,
    0xD6539B2CD582E226,
    0xD864508F018A32B1,
    0xDB1EFF74705AE0FC,
    0xE6931745503D7A23,
    0xEB1127B4C10106DF,
    0xF15128ECBAD31992,
    0xFA351281BE88595D,
}


def find_objdump() -> str:
    for candidate in (
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def disassemble(
        objdump: str, binary: Path, start: int, end: int,
        intel: bool = False) -> str:
    command = [
        objdump,
        "-d",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{end:x}",
    ]
    if intel:
        command.extend(["-M", "intel"])
    command.append(str(binary))
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.lower()


def body(disassembly: str, start: int, end: int) -> str:
    lines = []
    for line in disassembly.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_order(text: str, tokens: list[str], label: str) -> None:
    cursor = 0
    for token in tokens:
        position = text.find(token, cursor)
        if position < 0:
            raise AssertionError(f"missing/out-of-order {label}: {token}")
        cursor = position + len(token)


def fde_ranges(text: str) -> set[tuple[int, int]]:
    return {
        (int(start, 16), int(end, 16))
        for start, end in re.findall(r"pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", text)
    }


def direct_callers(text: str, target: int) -> list[int]:
    pattern = re.compile(
        rf"^\s*([0-9a-f]+):.*\b(?:bl|callq?|call)\s+(?:0x)?{target:x}\b",
        re.MULTILINE,
    )
    return [int(match.group(1), 16) for match in pattern.finditer(text)]


def arm64_constants(disassembly: str) -> set[int]:
    registers: dict[str, int] = {}
    values: set[int] = set()
    for line in disassembly.splitlines():
        instruction = line.split("//", 1)[0]
        match = re.search(r"\bmov\s+(x\d+),\s*#0x([0-9a-f]+)\b", instruction)
        if match is not None:
            registers[match.group(1)] = int(match.group(2), 16)
            values.add(registers[match.group(1)])
            continue
        match = re.search(
            r"\bmovk\s+(x\d+),\s*#0x([0-9a-f]+),\s*lsl\s*#(\d+)\b",
            instruction,
        )
        if match is None or match.group(1) not in registers:
            continue
        register, immediate, shift = (
            match.group(1), int(match.group(2), 16), int(match.group(3))
        )
        mask = 0xFFFF << shift
        registers[register] = (
            registers[register] & ~mask) | (immediate << shift)
        values.add(registers[register] & ((1 << 64) - 1))
    return values


def x86_constants(disassembly: str) -> set[int]:
    return {
        int(value, 16)
        for value in re.findall(
            r"\bmovabs\s+r\w+,0x([0-9a-f]{16})\b", disassembly)
    }


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0xD28D0, 0xD313C)
    x86 = disassemble(objdump, X86_64_SO, 0xC0340, 0xC0912, intel=True)
    (AUDIT / "disasm-d28d0-d313c.txt").write_text(arm)
    (AUDIT / "disasm-x86-c0340-c0912.txt").write_text(x86)

    assert (0xD28D0, 0xD313C) in fde_ranges(ARM_EH)
    assert (0xC0340, 0xC0912) in fde_ranges(X86_EH)
    assert direct_callers(ARM_FULL, 0xD28D0) == [0xD2F58, 0xD41A4]
    assert direct_callers(X86_FULL, 0xC0340) == [0xC07B3, 0xC166F]
    assert direct_callers(ARM_FULL, 0xD2018)[-2:] == [0xD2944, 0xD2E18]
    assert direct_callers(X86_FULL, 0xBFB83)[-2:] == [0xC03BC, 0xC06E6]
    assert direct_callers(ARM_FULL, 0xD22D4)[-2:] == [0xD2C9C, 0xD4230]
    assert direct_callers(X86_FULL, 0xBFE08)[-2:] == [0xC05F3, 0xC1717]

    missing_arm_states = EXPECTED_STATES - arm64_constants(arm)
    x86_states = x86_constants(x86)
    if missing_arm_states or x86_states != EXPECTED_STATES:
        raise AssertionError(
            f"opaque-state mismatch: arm={sorted(map(hex, missing_arm_states))} "
            f"x86_missing={sorted(map(hex, EXPECTED_STATES - x86_states))} "
            f"x86_extra={sorted(map(hex, x86_states - EXPECTED_STATES))}"
        )

    require_order(body(arm, 0xD28F0, 0xD2948), [
        "ldr\tx8, [x2]",
        "add\tx9, x8, #0x1c",
        "ldr\tw11, [x8, #8]",
        "ldp\tw10, w20, [x8]",
        "ldp\tw21, w8, [x8, #20]",
        "str\tx9, [x2]",
        "ldr\tx9, [x1, #8]",
        "add\tx9, x9, x10",
        "str\tx9, [x2]",
        "bl\td2018",
    ], "ARM64 descriptor loads, 0x1c advance and own-pair redirect")
    arm_entry = body(arm, 0xD28F0, 0xD2948)
    if "[x8, #12]" in arm_entry or "[x8, #16]" in arm_entry:
        raise AssertionError("ARM64 unexpectedly reads reserved descriptor words")

    require_order(body(x86, 0xC036F, 0xC03C1), [
        "mov    rax,qword ptr [rdx]",
        "mov    edi,dword ptr [rax]",
        "mov    r8d,dword ptr [rax+0x4]",
        "mov    r8d,dword ptr [rax+0x8]",
        "mov    ebx,dword ptr [rax+0x14]",
        "mov    r8d,dword ptr [rax+0x18]",
        "add    rax,0x1c",
        "mov    qword ptr [rdx],rax",
        "add    rdi,qword ptr [rsi+0x8]",
        "mov    qword ptr [rdx],rdi",
        "call   bfb83",
    ], "x86 descriptor loads, 0x1c advance and own-pair redirect")
    x86_entry = body(x86, 0xC036F, 0xC03C1)
    if "[rax+0xc]" in x86_entry or "[rax+0x10]" in x86_entry:
        raise AssertionError("x86 unexpectedly reads reserved descriptor words")

    require_order(body(arm, 0xD2FFC, 0xD3044), [
        "ldr\tx0, [sp, #32]",
        "mov\tw1, #0x30",
        "bl\t139e50",
        "cmp\tx0, #0x0",
        "str\tx0, [x8, #24]",
    ], "ARM64 recursive-array calloc and immediate +0x18 publication")
    require_order(body(x86, 0xC081A, 0xC0883), [
        "mov    rdi,qword ptr [rsp+0x18]",
        "push   0x30",
        "call   132880",
        "mov    qword ptr [rcx+0x18],rax",
        "test   rax,rax",
    ], "x86 recursive-array calloc and immediate +0x18 publication")

    require_order(body(arm, 0xD2F14, 0xD2FF8), [
        "ldr\tx9, [sp, #16]",
        "add\tx8, x8, x9",
        "add\tx8, x8, x10, lsl #2",
        "ldr\tw9, [x8], #4",
        "str\tx8, [x2]",
        "add\tx8, x8, x9",
        "str\tx8, [x2]",
        "ldr\tx8, [x8, #24]",
        "madd\tx3, x10, x9, x8",
        "bl\td28d0",
        "cmp\tw8, #0x0",
    ], "ARM64 first offset table, recursive child and status gate")
    require_order(body(x86, 0xC0771, 0xC0816), [
        "add    rax,qword ptr [rsp+0x68]",
        "lea    rax,[rax+rdi*4]",
        "mov    ecx,dword ptr [rax-0x4]",
        "mov    qword ptr [rdx],rax",
        "add    rcx,qword ptr [rsi+0x8]",
        "mov    qword ptr [rdx],rcx",
        "imul   rcx,rdi,0x30",
        "add    rcx,qword ptr [rax+0x18]",
        "call   c0340",
        "cmp    dword ptr [r14],0x0",
    ], "x86 first offset table, recursive child and status gate")

    require_order(body(arm, 0xD2ECC, 0xD2EF8), [
        "ldr\tw8, [x10, #16]",
        "add\tx9, x9, #0x1",
        "add\tw8, w8, #0x1",
        "str\tw8, [x10, #16]",
    ], "ARM64 first count publication after child success")
    require_order(body(x86, 0xC074D, 0xC0766), [
        "inc    dword ptr [rax+0x10]",
        "inc    rax",
        "mov    qword ptr [rsp+0x40],rax",
    ], "x86 first count publication after child success")

    require_order(body(arm, 0xD2D34, 0xD2DD0), [
        "ldr\tx0, [sp, #24]",
        "mov\tw1, #0x30",
        "bl\t139e50",
        "cmp\tx0, #0x0",
        "str\tx0, [x8, #40]",
    ], "ARM64 leaf-array calloc and immediate +0x28 publication")
    require_order(body(x86, 0xC0637, 0xC069F), [
        "mov    rdi,qword ptr [rsp+0x28]",
        "push   0x30",
        "call   132880",
        "mov    qword ptr [rcx+0x28],rax",
        "test   rax,rax",
    ], "x86 leaf-array calloc and immediate +0x28 publication")

    require_order(body(arm, 0xD2DD4, 0xD2EC8), [
        "ldr\tx9, [sp, #8]",
        "add\tx8, x8, x9",
        "add\tx8, x8, x10, lsl #2",
        "ldr\tw9, [x8], #4",
        "str\tx8, [x2]",
        "add\tx8, x8, x9",
        "str\tx8, [x2]",
        "ldr\tx8, [x8, #40]",
        "madd\tx3, x10, x9, x8",
        "bl\td2018",
        "cmp\tw8, #0x0",
    ], "ARM64 second offset table and pair-only child materialization")
    require_order(body(x86, 0xC06A4, 0xC0748), [
        "add    rax,qword ptr [rsp+0x60]",
        "lea    rax,[rax+rdi*4]",
        "mov    ecx,dword ptr [rax-0x4]",
        "mov    qword ptr [rdx],rax",
        "add    rcx,qword ptr [rsi+0x8]",
        "mov    qword ptr [rdx],rcx",
        "imul   rcx,rdi,0x30",
        "add    rcx,qword ptr [rax+0x28]",
        "call   bfb83",
        "cmp    dword ptr [r14],0x0",
    ], "x86 second offset table and pair-only child materialization")

    require_order(body(arm, 0xD30EC, 0xD3118), [
        "ldr\tw8, [x10, #32]",
        "add\tx9, x9, #0x1",
        "add\tw8, w8, #0x1",
        "str\tw8, [x10, #32]",
    ], "ARM64 second count publication after pair success")
    require_order(body(x86, 0xC08DF, 0xC08FF), [
        "inc    dword ptr [rax+0x20]",
        "inc    rax",
        "mov    qword ptr [rsp+0x50],rax",
    ], "x86 second count publication after pair success")

    require_order(body(arm, 0xD2C70, 0xD2CA0), [
        "mov\tw10, #0x2",
        "str\tw10, [x8]",
        "ldur\tx0, [x29, #-16]",
        "bl\td22d4",
    ], "ARM64 allocation status 2 and shared rollback")
    require_order("\n".join((
        body(x86, 0xC05D4, 0xC0633),
    )), [
        "mov    dword ptr [rax],0x2",
        "mov    rdi,qword ptr [rsp+0x8]",
        "call   bfe08",
    ], "x86 allocation status 2 and shared rollback")

    for symbol in (
        "RecoveredRecursiveMetadataDescriptorD28d0",
        "RecoveredRecursiveMetadataParserOperationsD28d0",
        "runRecoveredRecursiveMetadataParserD28d0",
        "recoveredRecursiveMetadataParserD28d0Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    for field, offset in (
        ("ownedStringPairOffset", "0x00"),
        ("firstChildCount", "0x04"),
        ("firstChildOffsetTable", "0x08"),
        ("reserved0c", "0x0c"),
        ("reserved10", "0x10"),
        ("secondChildCount", "0x14"),
        ("secondChildOffsetTable", "0x18"),
    ):
        require(
            CPP,
            rf"offsetof\(RecoveredRecursiveMetadataDescriptorD28d0,\s*{field}\) == {offset}",
            f"C++ descriptor field {field}@{offset}",
        )
    require(
        CPP,
        r"sizeof\(RecoveredRecursiveMetadataDescriptorD28d0\) == 0x1c",
        "C++ descriptor size",
    )

    cpp_start = CPP.index(
        "void runRecoveredRecursiveMetadataParserD28d0(\n"
        "        std::uint32_t* status,\n"
        "        const RecoveredSliceSourceD1a38* source,\n"
        "        const std::uint8_t** cursor,\n"
        "        RecoveredRecursiveMetadataNodeD22d4* output,\n"
        "        const RecoveredRecursiveMetadataParserOperationsD28d0& operations)"
    )
    cpp_end = CPP.index(
        "\nvoid* recoveredRecursiveMetadataPairAllocateD28d0", cpp_start)
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "descriptor + 0x00",
        "descriptor + 0x04",
        "descriptor + 0x08",
        "descriptor + 0x14",
        "descriptor + 0x18",
        "descriptor + sizeof(RecoveredRecursiveMetadataDescriptorD28d0)",
        "source->data + ownedStringPairOffset",
        "operations.materializePair(status, source, cursor, output)",
        "if (*status != 0)",
        "operations.destroyContent(output)",
        "operations.allocate(firstChildCount",
        "output->firstChildren == nullptr",
        "*status = 2",
        "firstChildOffsetTable + index * sizeof(std::uint32_t)",
        "*cursor = tableEntry + sizeof(relativeOffset)",
        "*cursor = source->data + relativeOffset",
        "runRecoveredRecursiveMetadataParserD28d0(",
        "++output->firstChildCount",
        "operations.allocate(secondChildCount",
        "output->secondChildren == nullptr",
        "secondChildOffsetTable + index * sizeof(std::uint32_t)",
        "operations.materializePair(",
        "++output->secondChildCount",
    ], "C++ descriptor, recursive-array, leaf-array and rollback order")
    require(
        GENERATOR,
        r"0x0D28D0:.*recursive metadata-node parser.*recovered",
        "0xd28d0 coverage entry",
    )
    require(
        CPP,
        r"if \(!recoveredRecursiveMetadataParserD28d0Regression\(\)\)",
        "top-level recursive parser regression guard",
    )

    (AUDIT / "arm64-recursive-metadata-parser-d28d0.md").write_text(
        """# Recursive metadata-node parser `0xd28d0`

Cross-ABI mapping:

```text
ARM64:  0xd28d0..0xd313c
x86_64: 0xc0340..0xc0912
```

The two implementations contain the same 24 opaque state constants.  The
four arguments are `uint32_t* status`, the shared source whose data pointer is
at `+0x08`, `const uint8_t** cursor`, and a zero-initialized 0x30-byte metadata
node.  The 0x1c-byte wire descriptor is:

```text
+0x00 uint32 owned-string-pair relative offset
+0x04 uint32 recursive child count
+0x08 uint32 recursive-child offset-table relative offset
+0x0c uint32 reserved, not loaded
+0x10 uint32 reserved, not loaded
+0x14 uint32 string-pair-only child count
+0x18 uint32 string-pair-child offset-table relative offset
```

The parser first publishes `descriptor+0x1c`, redirects the shared cursor to
`source->data + field00`, and calls 0xd2018 for the node's two owned strings.
With zero status it conditionally allocates `calloc(field04, 0x30)`, publishes
the result at node+0x18, resolves each uint32 child offset through the table at
field08 and recursively calls 0xd28d0.  Node+0x10 is incremented only after a
child succeeds.

After the recursive array completes, the parser conditionally allocates
`calloc(field14, 0x30)`, publishes it at node+0x28, resolves offsets through the
table at field18, and calls only 0xd2018 for each element.  These second-array
elements are therefore zeroed leaf nodes containing the owned string pair;
node+0x20 is incremented only after pair materialization succeeds.

Any nonzero status after a materializer/recursive call enters the common
0xd22d4 rollback.  Either calloc failure stores null in the corresponding
published pointer, writes status 2, and uses the same rollback.  A preexisting
nonzero status still permits the initial 0xd2018 stage and then rolls back.
The current child is cleaned by its nested parser or 0xd2018 before the parent
rolls back only the previously published counts.

No native bounds checks exist for the 0x1c-byte descriptor, source-relative
offsets, offset tables, string descriptors, counts, total allocation size, or
recursion depth.  `calloc(uint32_count, 0x30)` delegates multiplication-overflow
handling to libc.  The two reserved wire words and node reserved words are not
used by this parser.

C++ implementation and non-executed regression entry:

```text
RecoveredRecursiveMetadataDescriptorD28d0
RecoveredRecursiveMetadataParserOperationsD28d0
runRecoveredRecursiveMetadataParserD28d0
recoveredRecursiveMetadataParserD28d0Regression
```
"""
    )

    print("ARM64/x86_64 FDEs, callers and 24 opaque states: PASS")
    print("0x1c descriptor and source-relative cursor redirects: PASS")
    print("recursive +0x18 and pair-only +0x28 array construction: PASS")
    print("post-success count publication and d22d4 rollback: PASS")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
