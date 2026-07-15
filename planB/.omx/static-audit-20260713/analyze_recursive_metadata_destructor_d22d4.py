#!/usr/bin/env python3
"""Static cross-ABI proof for recursive metadata destructor ARM64 0xd22d4."""

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
    0x186CFF5EFA29590F,
    0x2C66D6F3629F2FF4,
    0x32B90645F5DCCFA7,
    0x490A210D7990FB70,
    0x5B06F9FE7B095AD3,
    0x65BC251E357F7F8D,
    0x68EE11A3AE6FEAD8,
    0x840AB20DFA262E0E,
    0x861B7DE483DF32B5,
    0x95DE285D491E8CA0,
    0xA43F4EF974D4BE7B,
    0xA56DC3D2165A87C5,
    0xABDC39130FBA380D,
    0xBA28CF6092893F26,
    0xBCBEDA64F00F9416,
    0xBD7976E72DEB1331,
    0xC1C996C1C2A19BB3,
    0xCA1919240CE534DC,
    0xDA52AD6428210BE5,
    0xEA949B19FB787422,
    0xEDFB6C3C819F485E,
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
        for value in re.findall(r"\bmovabs\s+r\w+,0x([0-9a-f]{16})\b", disassembly)
    }


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0xD22D4, 0xD28D0)
    x86 = disassemble(objdump, X86_64_SO, 0xBFE08, 0xC0340, intel=True)
    arm_wrapper = disassemble(objdump, ARM64_SO, 0xD4220, 0xD4244)
    x86_wrapper = disassemble(
        objdump, X86_64_SO, 0xC1713, 0xC1725, intel=True)
    (AUDIT / "disasm-d22d4-d28d0.txt").write_text(arm)
    (AUDIT / "disasm-x86-bfe08-c0340.txt").write_text(x86)
    (AUDIT / "disasm-d4220-d4244.txt").write_text(arm_wrapper)
    (AUDIT / "disasm-x86-c1713-c1725.txt").write_text(x86_wrapper)

    assert (0xD22D4, 0xD28D0) in fde_ranges(ARM_EH)
    assert (0xBFE08, 0xC0340) in fde_ranges(X86_EH)
    assert (0xD4220, 0xD4244) in fde_ranges(ARM_EH)
    assert (0xC1713, 0xC1725) in fde_ranges(X86_EH)
    assert direct_callers(ARM_FULL, 0xD22D4) == [
        0xD259C, 0xD27BC, 0xD2C9C, 0xD4230]
    assert direct_callers(X86_FULL, 0xBFE08) == [
        0xBFFF4, 0xC022D, 0xC05F3, 0xC1717]

    missing_arm_states = EXPECTED_STATES - arm64_constants(arm)
    missing_x86_states = EXPECTED_STATES - x86_constants(x86)
    if missing_arm_states or missing_x86_states:
        raise AssertionError(
            f"opaque-state mismatch: arm={sorted(map(hex, missing_arm_states))} "
            f"x86={sorted(map(hex, missing_x86_states))}"
        )

    assert len(re.findall(r"\bbl\s+(?:0x)?d22d4\b", arm)) == 2
    assert len(re.findall(r"\bbl\s+(?:0x)?139de0\s+<free@plt>", arm)) == 4
    assert len(re.findall(r"\bcall\s+(?:0x)?bfe08\b", x86)) == 2
    assert len(re.findall(r"\bcall\s+(?:0x)?132810\s+<free@plt>", x86)) == 4

    require_order(body(arm, 0xD2858, 0xD2888), [
        "ldr\tw8, [x19, #16]",
        "ldr\tx9, [x19, #24]",
        "cmp\tx10, x8",
        "stur\tx9, [x29, #-8]",
    ], "ARM64 first child count/pointer/index gate")
    require_order(body(arm, 0xD2588, 0xD25FC), [
        "mov\tw8, #0x30",
        "madd\tx0, x27, x8, x9",
        "bl\td22d4",
        "add\tx8, x27, #0x1",
    ], "ARM64 first child recursion and ascending increment")
    require_order(body(x86, 0xC02BD, 0xC02EE), [
        "mov    eax,dword ptr [rcx+0x10]",
        "cmp    rdi,rax",
        "mov    rax,qword ptr [rcx+0x18]",
    ], "x86_64 first child count/pointer/index gate")
    require_order(body(x86, 0xBFFD8, 0xC005B), [
        "imul   rdi,rbp,0x30",
        "add    rdi,qword ptr [rsp+0x18]",
        "call   bfe08",
        "lea    rax,[rbp+0x1]",
    ], "x86_64 first child recursion and ascending increment")

    require_order(body(arm, 0xD25FC, 0xD2668), [
        "ldur\tx0, [x29, #-8]",
        "bl\t139de0",
        "str\txzr, [x19, #24]",
        "str\twzr, [x19, #16]",
    ], "ARM64 first child array free/pointer/count clear")
    require_order(body(x86, 0xC005B, 0xC00C6), [
        "mov    rdi,qword ptr [rsp+0x18]",
        "call   132810",
        "and    qword ptr [rax+0x18],0x0",
        "and    dword ptr [rax+0x10],0x0",
    ], "x86_64 first child array free/pointer/count clear")

    require_order(body(arm, 0xD2668, 0xD2698), [
        "ldr\tw8, [x19, #32]",
        "ldr\tx9, [x19, #40]",
        "cmp\tx10, x8",
        "stur\tx9, [x29, #-16]",
    ], "ARM64 second child count/pointer/index gate")
    require_order(body(arm, 0xD27A8, 0xD281C), [
        "mov\tw8, #0x30",
        "madd\tx0, x20, x8, x9",
        "bl\td22d4",
        "add\tx8, x20, #0x1",
    ], "ARM64 second child recursion and ascending increment")
    require_order(body(x86, 0xC00C6, 0xC00F5), [
        "mov    eax,dword ptr [rcx+0x20]",
        "cmp    rbx,rax",
        "mov    rax,qword ptr [rcx+0x28]",
    ], "x86_64 second child count/pointer/index gate")
    require_order(body(x86, 0xC021F, 0xC0279), [
        "imul   rdi,rbx,0x30",
        "add    rdi,qword ptr [rsp+0x10]",
        "call   bfe08",
        "inc    rbx",
    ], "x86_64 second child recursion and ascending increment")

    require_order("\n".join((
        body(arm, 0xD2758, 0xD27A8),
        body(arm, 0xD2888, 0xD28A0),
    )), [
        "ldur\tx0, [x29, #-16]",
        "bl\t139de0",
        "str\txzr, [x19, #40]",
        "str\twzr, [x19, #32]",
    ], "ARM64 second child array free/pointer/count clear")
    require_order("\n".join((
        body(x86, 0xC01C7, 0xC021F),
        body(x86, 0xC02EE, 0xC031F),
    )), [
        "mov    rdi,qword ptr [rsp+0x10]",
        "call   132810",
        "and    qword ptr [rax+0x28],0x0",
        "and    dword ptr [rax+0x20],0x0",
    ], "x86_64 second child array free/pointer/count clear")

    require_order("\n".join((
        body(arm, 0xD26B8, 0xD2758),
    )), [
        "ldr\tx0, [sp, #16]",
        "bl\t139de0",
        "str\txzr, [x19]",
        "ldr\tx0, [sp, #24]",
        "bl\t139de0",
        "str\txzr, [x19, #8]",
    ], "ARM64 first then second owned-string release/clear")
    require_order("\n".join((
        body(x86, 0xC0118, 0xC01C7),
    )), [
        "mov    rdi,qword ptr [rsp+0x40]",
        "call   132810",
        "and    qword ptr [rax],0x0",
        "mov    rdi,qword ptr [rsp+0x38]",
        "call   132810",
        "and    qword ptr [rax+0x8],0x0",
    ], "x86_64 first then second owned-string release/clear")

    require_order(arm_wrapper, [
        "mov\tx19, x0",
        "bl\td22d4",
        "mov\tx0, x19",
        "b\t139de0",
    ], "ARM64 owner wrapper content-then-outer free")
    require_order(x86_wrapper, [
        "mov    rbx,rdi",
        "call   bfe08",
        "mov    rdi,rbx",
        "jmp    132810",
    ], "x86_64 owner wrapper content-then-outer free")

    for symbol in (
        "RecoveredRecursiveMetadataNodeD22d4",
        "runRecoveredRecursiveMetadataNodeContentDestroyD22d4",
        "runRecoveredRecursiveMetadataNodeDestroyD4220",
        "recoveredRecursiveMetadataNodeDestroyD22d4D4220Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    for field, offset in (
        ("firstOwnedString", "0x00"),
        ("secondOwnedString", "0x08"),
        ("firstChildCount", "0x10"),
        ("firstChildren", "0x18"),
        ("secondChildCount", "0x20"),
        ("secondChildren", "0x28"),
    ):
        require(
            CPP,
            rf"offsetof\(RecoveredRecursiveMetadataNodeD22d4,\s*{field}\) == {offset}",
            f"C++ metadata field {field}@{offset}",
        )
    require(
        CPP,
        r"sizeof\(RecoveredRecursiveMetadataNodeD22d4\) == 0x30",
        "C++ metadata node size",
    )

    cpp_start = CPP.index(
        "void runRecoveredRecursiveMetadataNodeContentDestroyD22d4(\n"
        "        RecoveredRecursiveMetadataNodeD22d4* node,\n"
        "        RecoveredRecursiveMetadataReleaseD22d4 release)"
    )
    cpp_end = CPP.index("\n}\n", cpp_start) + 3
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "if (node == nullptr) return",
        "index < node->firstChildCount",
        "&node->firstChildren[index]",
        "release(node->firstChildren)",
        "node->firstChildren = nullptr",
        "node->firstChildCount = 0",
        "index < node->secondChildCount",
        "&node->secondChildren[index]",
        "release(node->secondChildren)",
        "node->secondChildren = nullptr",
        "node->secondChildCount = 0",
        "release(node->firstOwnedString)",
        "node->firstOwnedString = nullptr",
        "release(node->secondOwnedString)",
        "node->secondOwnedString = nullptr",
    ], "C++ recursive content destruction order")
    require(
        CPP,
        r"runRecoveredRecursiveMetadataNodeContentDestroyD22d4\(node, release\);\s*release\(node\);",
        "C++ owner wrapper order",
    )
    require(
        GENERATOR,
        r"0x0D22D4:.*recursive 0x30-byte metadata-node content destructor.*recovered",
        "0xd22d4 coverage entry",
    )
    require(
        GENERATOR,
        r"0x00D4220:.*recursive metadata-node owner destructor.*recovered",
        "0xd4220 coverage entry",
    )
    require(
        CPP,
        r"if \(!recoveredRecursiveMetadataNodeDestroyD22d4D4220Regression\(\)\)",
        "top-level recursive metadata regression guard",
    )

    (AUDIT / "arm64-recursive-metadata-destructor-d22d4.md").write_text(
        """# Recursive metadata-node destructors `0xd22d4` and `0xd4220`

Cross-ABI mapping:

```text
ARM64 content: 0xd22d4..0xd28d0
x86_64:       0xbfe08..0xc0340
ARM64 owner:  0xd4220..0xd4244
x86_64:       0xc1713..0xc1725
```

`0xd22d4` is a content destructor for a 0x30-byte recursive node:

```text
+0x00 char* firstOwnedString
+0x08 char* secondOwnedString
+0x10 uint32 firstChildCount
+0x14 reserved
+0x18 Node* firstChildren
+0x20 uint32 secondChildCount
+0x24 reserved
+0x28 Node* secondChildren
```

The two ABIs contain the same 21 opaque state constants.  Destruction order is
strictly: first children in ascending order, first array free/pointer/count
clear, second children in ascending order, second array free/pointer/count
clear, first string free/clear, second string free/clear.  Recursive children
are contiguous 0x30-byte elements and are not individually freed; their parent
array allocation is freed once after every child content is destroyed.

`0xd4220` preserves the outer pointer, calls the content destructor, and then
tail-calls `free` on that same pointer.  A null pointer still reaches
`free(nullptr)`.  Neither helper validates counts, child-array bounds, cycles,
or recursion depth; reserved fields +0x14/+0x24 are unchanged.

C++ implementation and non-executed regression entry:

```text
RecoveredRecursiveMetadataNodeD22d4
runRecoveredRecursiveMetadataNodeContentDestroyD22d4
runRecoveredRecursiveMetadataNodeDestroyD4220
recoveredRecursiveMetadataNodeDestroyD22d4D4220Regression
```
"""
    )

    print("ARM64/x86_64 FDEs, four callers and 21 opaque states: PASS")
    print("0x30-byte recursive node layout and two child arrays: PASS")
    print("depth-first array/string release and clear order: PASS")
    print("0xd4220 content-then-outer free wrapper: PASS")
    print("C++ implementation, regression guard and coverage entries: PASS")


if __name__ == "__main__":
    main()
