#!/usr/bin/env python3
"""Static cross-ABI proof for metadata area-name resolver ARM64 0xd313c."""

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
    0x2773B06D406C84A3,
    0x31B7741C90860793,
    0x4100A9C31FA50DBE,
    0x5FCF00712233B0D5,
    0x63530103C9BE6D9D,
    0x6F022DC4EC7C4472,
    0x70AC8F846CA50310,
    0x73A9E0897A6E742C,
    0x9AC0F19331C99AA5,
    0x9E396FFFED04929E,
    0xB08D59DA510448CD,
    0xB9A430D3F426FB88,
    0xE2C041301598B1FA,
    0xEE971C7EC250FDC3,
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
        command, check=True, text=True, stdout=subprocess.PIPE
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
    arm = disassemble(objdump, ARM64_SO, 0xD313C, 0xD352C)
    x86 = disassemble(objdump, X86_64_SO, 0xC0912, 0xC0CDD, intel=True)
    (AUDIT / "disasm-d313c-d352c.txt").write_text(arm)
    (AUDIT / "disasm-x86-c0912-c0cdd.txt").write_text(x86)

    assert (0xD313C, 0xD352C) in fde_ranges(ARM_EH)
    assert (0xC0912, 0xC0CDD) in fde_ranges(X86_EH)
    assert direct_callers(ARM_FULL, 0xD313C) == [0xD427C]
    assert direct_callers(X86_FULL, 0xC0912) == [0xC1751]

    missing_arm_states = EXPECTED_STATES - arm64_constants(arm)
    x86_states = x86_constants(x86)
    if missing_arm_states or x86_states != EXPECTED_STATES:
        raise AssertionError(
            f"opaque-state mismatch: arm={sorted(map(hex, missing_arm_states))} "
            f"x86_missing={sorted(map(hex, EXPECTED_STATES - x86_states))} "
            f"x86_extra={sorted(map(hex, x86_states - EXPECTED_STATES))}"
        )

    assert len(re.findall(r"\bbl\s+(?:0x)?139ed0\s+<strchr@plt>", arm)) == 1
    assert len(re.findall(r"\bbl\s+(?:0x)?139ee0\s+<strcmp@plt>", arm)) == 1
    assert len(re.findall(r"\bbl\s+(?:0x)?139ef0\s+<strncmp@plt>", arm)) == 1
    assert len(re.findall(r"\bcall\s+(?:0x)?132900\s+<strchr@plt>", x86)) == 1
    assert len(re.findall(r"\bcall\s+(?:0x)?132910\s+<strcmp@plt>", x86)) == 1
    assert len(re.findall(r"\bcall\s+(?:0x)?132920\s+<strncmp@plt>", x86)) == 1

    require_order(body(arm, 0xD331C, 0xD3354), [
        "ldur\tx24, [x29, #-48]",
        "mov\tw1, #0x2e",
        "mov\tx0, x24",
        "bl\t139ed0",
        "cmp\tx0, #0x0",
        "stur\tx0, [x29, #-32]",
    ], "ARM64 separator search")
    require_order(body(x86, 0xC0A87, 0xC0AEC), [
        "mov    r15,qword ptr [rsp+0x20]",
        "mov    rdi,r15",
        "push   0x2e",
        "call   132900",
        "mov    qword ptr [rsp+0x38],rax",
        "test   rax,rax",
    ], "x86 separator search")

    require_order(body(arm, 0xD34A8, 0xD34DC), [
        "ldr\tw9, [x22, #16]",
        "add\tx9, x22, #0x18",
        "sub\tx9, x9, x24",
    ], "ARM64 recursive child count/array and segment length")
    require_order(body(x86, 0xC0C6A, 0xC0C9E), [
        "mov    eax,dword ptr [rcx+0x10]",
        "lea    rax,[rcx+0x18]",
        "sub    rax,r15",
    ], "x86 recursive child count/array and segment length")

    require_order(body(arm, 0xD3438, 0xD34A8), [
        "madd\tx8, x20, x9, x8",
        "ldr\tx0, [x8]",
        "bl\t139ef0",
        "add\tx8, x20, #0x1",
        "cmp\tw0, #0x0",
    ], "ARM64 first-child prefix scan")
    require_order(body(x86, 0xC0BF3, 0xC0C66), [
        "imul   rcx,rbp,0x30",
        "mov    rdi,qword ptr [rax+rcx*1]",
        "mov    rdx,qword ptr [rsp+0x50]",
        "call   132920",
        "lea    rcx,[rbp+0x1]",
        "test   eax,eax",
    ], "x86 first-child prefix scan")

    require_order(body(arm, 0xD3388, 0xD33B4), [
        "ldur\tx8, [x29, #-32]",
        "add\tx8, x8, #0x1",
        "stur\tx9, [x29, #-56]",
        "stur\tx8, [x29, #-48]",
    ], "ARM64 prefix-match descent and next segment")
    require_order(body(x86, 0xC0B19, 0xC0B3B), [
        "mov    rax,qword ptr [rsp+0x38]",
        "inc    rax",
        "mov    qword ptr [rsp+0x20],rax",
        "mov    rcx,qword ptr [rsp+0x68]",
        "mov    qword ptr [rsp+0x18],rcx",
    ], "x86 prefix-match descent and next segment")

    require_order(body(arm, 0xD33DC, 0xD3404), [
        "ldr\tw9, [x22, #32]",
        "add\tx8, x22, #0x28",
    ], "ARM64 final leaf count/array")
    require_order(body(x86, 0xC0B7D, 0xC0BA5), [
        "mov    eax,dword ptr [rcx+0x20]",
        "lea    rax,[rcx+0x28]",
    ], "x86 final leaf count/array")

    require_order(body(arm, 0xD3404, 0xD3438), [
        "mul\tx8, x9, x8",
        "ldr\tx0, [x9, x8]",
        "bl\t139ee0",
        "cmp\tw0, #0x0",
    ], "ARM64 final exact leaf scan")
    require_order(body(x86, 0xC0BA5, 0xC0BF3), [
        "imul   rax,qword ptr [rsp+0x10],0x30",
        "mov    rdi,qword ptr [rcx+rax*1]",
        "call   132910",
        "test   eax,eax",
    ], "x86 final exact leaf scan")

    require_order(body(arm, 0xD3354, 0xD3370), [
        "mov\tw9, #0x30",
        "umaddl\tx8, w8, w9, x10",
        "ldr\tx8, [x8, #8]",
        "stur\tx8, [x29, #-24]",
    ], "ARM64 matched leaf second-string return")
    require_order(body(x86, 0xC0AF0, 0xC0B19), [
        "imul   rax,rax,0x30",
        "mov    rax,qword ptr [rcx+rax*1+0x8]",
        "mov    qword ptr [rsp+0x8],rax",
    ], "x86 matched leaf second-string return")

    for symbol in (
        "runRecoveredMetadataAreaNameResolverD313c",
        "recoveredMetadataAreaNameResolverD313cRegression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    cpp_start = CPP.index(
        "const char* runRecoveredMetadataAreaNameResolverD313c("
    )
    cpp_end = CPP.index(
        "\nbool recoveredMetadataAreaNameResolverD313cRegression()", cpp_start
    )
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "std::strchr(segment, '.')",
        "index < node->secondChildCount",
        "node->secondChildren[index]",
        "std::strcmp(child.firstOwnedString, segment) == 0",
        "return child.secondOwnedString",
        "separator - segment",
        "index < node->firstChildCount",
        "node->firstChildren[index]",
        "std::strncmp(",
        "child.firstOwnedString, segment, segmentLength",
        "next = &child",
        "if (next == nullptr) return nullptr",
        "node = next",
        "segment = separator + 1",
    ], "C++ dot-separated descent and final exact lookup")
    require(
        GENERATOR,
        r"0x0D313C:.*dot-separated metadata area-name resolver.*recovered",
        "0xd313c coverage entry",
    )
    require(
        CPP,
        r"if \(!recoveredMetadataAreaNameResolverD313cRegression\(\)\)",
        "top-level metadata resolver regression guard",
    )

    (AUDIT / "arm64-metadata-area-resolver-d313c.md").write_text(
        """# Dot-separated metadata area-name resolver `0xd313c`

Cross-ABI mapping:

```text
ARM64:  0xd313c..0xd352c
x86_64: 0xc0912..0xc0cdd
```

The two implementations contain the same 14 opaque state constants and each
calls `strchr`, `strncmp`, and `strcmp` exactly once in the flattened body.
Arguments are a 0x30-byte recursive metadata root and a property name.  The
returned pointer is an owned-string pointer stored in the tree; the resolver
does not allocate or transfer ownership.

For every non-final dot-separated segment, the helper scans node+0x18 using
the uint32 count at +0x10.  Children are contiguous 0x30-byte nodes.  It calls
`strncmp(child.firstOwnedString, segment, separator-segment)` and descends into
the first matching child, then continues at `separator+1`.  There is no
terminator/equal-length check on the child string, so a shorter query segment
can match the prefix of a longer child name.  An empty segment passes length
zero to `strncmp` and therefore selects the first child when the array is
nonempty.

When no dot remains, the helper scans node+0x28 using the count at +0x20 and
requires full `strcmp(child.firstOwnedString, finalSegment)==0`.  It returns
that leaf's second owned string or null when no match exists.  Native code does
not validate the root, property name, counts, child pointers, or child strings.

C++ implementation and non-executed regression entry:

```text
runRecoveredMetadataAreaNameResolverD313c
recoveredMetadataAreaNameResolverD313cRegression
```
"""
    )

    print("ARM64/x86_64 FDEs, caller and 14 opaque states: PASS")
    print("dot-separated +0x18 prefix descent: PASS")
    print("final +0x28 exact lookup and second-string return: PASS")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
