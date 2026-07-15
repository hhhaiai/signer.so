#!/usr/bin/env python3
"""Static cross-ABI proof for getline-compatible helper ARM64 0xd6ed8."""

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
    0x391EB0D45A9E2403,
    0x3A78A5AFB9BCE064,
    0x4598677E71F3CE98,
    0x490A210D7990FB70,
    0x55D8C062ED524882,
    0x5B06F9FE7B095AD3,
    0x68EE11A3AE6FEAD8,
    0x7220E1FD2725A2BE,
    0x840AB20DFA262E0E,
    0x861B7DE483DF32B5,
    0x95DE285D491E8CA0,
    0x969C524878CFE7A5,
    0x9C36B45DF01978DD,
    0xA43F4EF974D4BE7B,
    0xA56DC3D2165A87C5,
    0xABDC39130FBA380D,
    0xBCBEDA64F00F9416,
    0xBD7976E72DEB1331,
    0xBE234F34EA49BAA2,
    0xC1C996C1C2A19BB3,
    0xCA1919240CE534DC,
    0xE330CE445400BEDB,
    0xEA949B19FB787422,
    0xEDFB6C3C819F485E,
    0xEE06826E7E72ECBE,
    0xFED4D108D6A73F4F,
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
    callers = []
    pattern = re.compile(
        rf"^\s*([0-9a-f]+):.*\b(?:bl|callq?|call)\s+(?:0x)?{target:x}\b",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        callers.append(int(match.group(1), 16))
    return callers


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


def native_clear_indices(pointer_modulo_four: int, capacity: int) -> set[int]:
    if capacity == 0:
        return set()
    indices = {0, capacity - 1}
    if capacity >= 3:
        indices.update((1, 2, capacity - 3, capacity - 2))
    if capacity >= 7:
        indices.update((3, capacity - 4))
    if capacity >= 9:
        alignment = (-pointer_modulo_four) & 3
        count = (capacity - alignment) & ~3
        indices.update(range(alignment, alignment + count))
    return indices


def rounded_capacity(required: int) -> int:
    return ((required & ~0x7F) + 0x80) & ((1 << 64) - 1)


def main() -> None:
    objdump = find_objdump()
    arm = disassemble(objdump, ARM64_SO, 0xD6ED8, 0xD7890)
    x86 = disassemble(objdump, X86_64_SO, 0xC36C3, 0xC3E4A, intel=True)
    (AUDIT / "disasm-d6ed8-d7890.txt").write_text(arm)
    (AUDIT / "disasm-x86-c36c3-c3e4a.txt").write_text(x86)

    assert (0xD6ED8, 0xD7890) in fde_ranges(ARM_EH)
    assert (0xC36C3, 0xC3E4A) in fde_ranges(X86_EH)
    assert direct_callers(ARM_FULL, 0xD6ED8) == [0xD9E1C, 0xE69EC]
    assert direct_callers(X86_FULL, 0xC36C3) == [0xC8ABB, 0xDDE9B]

    missing_arm_states = EXPECTED_STATES - arm64_constants(arm)
    missing_x86_states = EXPECTED_STATES - x86_constants(x86)
    if missing_arm_states or missing_x86_states:
        raise AssertionError(
            f"opaque-state mismatch: arm={sorted(map(hex, missing_arm_states))} "
            f"x86={sorted(map(hex, missing_x86_states))}"
        )

    for pattern, label in (
        (r"bl\s+(?:0x)?139e70\s+<fgets@plt>", "ARM64 fgets"),
        (r"bl\s+(?:0x)?139fa0\s+<__strlen_chk@plt>", "ARM64 strlen_chk"),
        (r"bl\s+(?:0x)?139e50\s+<calloc@plt>", "ARM64 calloc"),
        (r"bl\s+(?:0x)?139f90\s+<realloc@plt>", "ARM64 realloc"),
        (r"bl\s+(?:0x)?139ea0\s+<memcpy@plt>", "ARM64 memcpy"),
        (r"call\s+(?:0x)?1328a0\s+<fgets@plt>", "x86_64 fgets"),
        (r"call\s+(?:0x)?1329d0\s+<__strlen_chk@plt>", "x86_64 strlen_chk"),
        (r"call\s+(?:0x)?132880\s+<calloc@plt>", "x86_64 calloc"),
        (r"call\s+(?:0x)?1329c0\s+<realloc@plt>", "x86_64 realloc"),
        (r"call\s+(?:0x)?1328d0\s+<memcpy@plt>", "x86_64 memcpy"),
    ):
        require(arm if label.startswith("ARM64") else x86, pattern, label)

    require_order(body(arm, 0xD6F2C, 0xD6FE8), [
        "ldr\tx9, [x0]",
        "neg\tw8, w9",
        "and\tx8, x8, #0x3",
        "stp\tx9, x0, [sp, #96]",
        "add\tx8, x9, x8",
        "str\tx8, [sp, #8]",
    ], "ARM64 incoming line pointer and four-byte alignment")
    require_order(body(x86, 0xC372D, 0xC374E), [
        "mov    qword ptr [rsp+0x8],rdi",
        "mov    rax,qword ptr [rdi]",
        "neg    ecx",
        "and    ecx,0x3",
        "add    rcx,rax",
    ], "x86_64 incoming line pointer and four-byte alignment")

    arm_clear_edges = "\n".join((
        body(arm, 0xD7330, 0xD737C),
        body(arm, 0xD7528, 0xD755C),
        body(arm, 0xD755C, 0xD7598),
        body(arm, 0xD7748, 0xD7784),
    ))
    for pattern, label in (
        (r"strb\s+wzr,\s*\[x13,\s*#3\]", "ARM64 clear byte +3"),
        (r"sturb\s+wzr,\s*\[x11,\s*#-4\]", "ARM64 clear trailing byte -4"),
        (r"strb\s+wzr,\s*\[x13\]", "ARM64 clear byte zero"),
        (r"sturb\s+wzr,\s*\[x11,\s*#-1\]", "ARM64 clear final byte"),
        (r"sturh\s+wzr,\s*\[x13,\s*#1\]", "ARM64 clear leading halfword"),
        (r"sturh\s+wzr,\s*\[x11,\s*#-3\]", "ARM64 clear trailing halfword"),
        (r"strb\s+wzr,\s*\[x11\],\s*#1", "ARM64 aligned clear loop"),
    ):
        require(arm_clear_edges, pattern, label)

    for modulo in range(4):
        for capacity in range(1, 1025):
            assert native_clear_indices(modulo, capacity) == set(range(capacity))
    assert native_clear_indices(0, 0) == set()

    require_order(body(arm, 0xD76B0, 0xD7748), [
        "mov\tw9, #0x80",
        "mov\tw0, #0x80",
        "mov\tw1, #0x1",
        "str\tx9, [x8]",
        "bl\t139e50",
        "cmp\tx0, #0x0",
        "str\tx0, [x11]",
    ], "ARM64 capacity-before-calloc and pointer publication")
    require_order(body(x86, 0xC3CFD, 0xC3D57), [
        "mov    qword ptr [rax],0x80",
        "mov    edi,0x80",
        "call   132880",
        "test   rax,rax",
        "mov    qword ptr [rcx],rax",
    ], "x86_64 capacity-before-calloc and pointer publication")

    require_order(body(arm, 0xD7470, 0xD74FC), [
        "add\tx0, sp, #0x80",
        "mov\tw1, #0x80",
        "ldr\tx2, [sp, #24]",
        "bl\t139e70",
        "cmp\tx0, #0x0",
    ], "ARM64 128-byte fgets and EOF branch")
    require_order(body(x86, 0xC3B12, 0xC3B73), [
        "lea    rdi,[rsp+0x90]",
        "mov    esi,0x80",
        "call   1328a0",
        "test   rax,rax",
    ], "x86_64 128-byte fgets and EOF branch")

    arm_length = body(arm, 0xD75EC, 0xD76B0)
    require_order(arm_length, [
        "bl\t139fa0",
        "sub\tx9, x0, #0x1",
        "ldrb\tw10, [x10, x9]",
        "cmp\tw10, #0xa",
        "csel\tx9, x9, x0, eq",
        "add\tx28, x9, x28",
        "add\tx10, x28, #0x1",
        "cmp\tx8, x10",
    ], "ARM64 strlen/newline/required/capacity flow")
    x86_length = body(x86, 0xC3C5E, 0xC3CFD)
    require_order(x86_length, [
        "call   1329d0",
        "lea    rcx,[rax-0x1]",
        "cmp    byte ptr [rsp+rax*1+0x8f],0xa",
        "cmovne rcx,rax",
        "lea    rdx,[rcx+rbp*1]",
        "inc    rdx",
        "cmp    qword ptr [rax],rdx",
    ], "x86_64 strlen/newline/required/capacity flow")

    require_order(body(arm, 0xD737C, 0xD743C), [
        "and\tx8, x8, #0x7f",
        "sub\tx8, x28, x8",
        "add\tx1, x8, #0x81",
        "str\tx1, [x8]",
        "ldr\tx0, [x21]",
        "bl\t139f90",
        "str\tx22, [x21]",
        "cmp\tx22, #0x0",
    ], "ARM64 rounded capacity and direct realloc publication")
    require_order(body(x86, 0xC3A5D, 0xC3ADD), [
        "and    eax,0x7f",
        "sub    rsi,rax",
        "add    rsi,0x81",
        "mov    qword ptr [rax],rsi",
        "mov    rdi,qword ptr [r14]",
        "call   1329c0",
        "test   rax,rax",
        "mov    qword ptr [r14],rcx",
    ], "x86_64 rounded capacity and direct realloc publication")

    assert rounded_capacity(1) == 0x80
    assert rounded_capacity(127) == 0x80
    assert rounded_capacity(128) == 0x100
    assert rounded_capacity(129) == 0x100
    assert rounded_capacity(256) == 0x180
    assert rounded_capacity(0) == 0x80

    require_order(body(arm, 0xD7784, 0xD7830), [
        "add\tx0, x26, x8",
        "bl\t139ea0",
        "ldr\tx11, [x8]",
        "tst\tw8, #0x1",
        "strb\twzr, [x11, x28]",
    ], "ARM64 append, newline route and final NUL")
    require_order(body(x86, 0xC3D88, 0xC3DF2), [
        "lea    rdi,[rax+r13*1]",
        "call   1328d0",
        "mov    rax,qword ptr [rax]",
        "test   byte ptr [rsp+0x7],0x1",
        "mov    byte ptr [rax+rcx*1],0x0",
    ], "x86_64 append, newline route and final NUL")
    require(arm, r"d7314:.*mov\s+x8,\s*#0xffffffffffffffff", "ARM64 -1 return")
    require(x86, r"c3a18:.*push\s+0xffffffffffffffff", "x86_64 -1 return")

    for symbol in (
        "RecoveredGetLineOperationsD6ed8",
        "recoveredCheckedStringLengthD6ed8",
        "runRecoveredGetLineD6ed8",
        "recoveredGetLineD6ed8Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    cpp_start = CPP.index(
        "std::int64_t runRecoveredGetLineD6ed8(\n"
        "        char** ownedLine,\n"
        "        std::size_t* capacity,\n"
        "        std::FILE* stream,\n"
        "        const RecoveredGetLineOperationsD6ed8& operations)"
    )
    cpp_end = CPP.index("\n}\n", cpp_start) + 3
    implementation = CPP[cpp_start:cpp_end]
    require_order(implementation, [
        "if (*ownedLine == nullptr)",
        "*capacity = 0x80",
        "operations.allocateZeroed(0x80, 1)",
        "if (*ownedLine == nullptr) return -1",
        "else if (*capacity != 0)",
        "operations.clear(*ownedLine, 0, *capacity)",
        "std::uint64_t accumulated = kNoAccumulatedLine",
        "operations.readChunk(",
        "return accumulated == kNoAccumulatedLine",
        "recoveredCheckedStringLengthD6ed8(",
        "chunk[chunkLength - 1U] == '\\n'",
        "previous + copiedLength",
        "newLength + 1U",
        "static_cast<std::uint64_t>(*capacity) < required",
        "(required & ~std::uint64_t{0x7f}) + 0x80U",
        "*capacity = static_cast<std::size_t>(newCapacity)",
        "*ownedLine = static_cast<char*>(operations.reallocate(",
        "if (*ownedLine == nullptr) return -1",
        "operations.copy(*ownedLine + previous",
        "(*ownedLine)[newLength] = '\\0'",
        "if (hasNewline) return recoveredGetLineResultD6ed8(newLength)",
        "accumulated = newLength",
    ], "C++ getline-compatible operation order")
    require(
        GENERATOR,
        r"0x0D6ED8:.*getline-compatible.*recovered",
        "0xd6ed8 coverage entry",
    )
    require(
        CPP,
        r"if \(!recoveredGetLineD6ed8Regression\(\)\)",
        "top-level d6ed8 regression guard",
    )

    (AUDIT / "arm64-getline-helper-d6ed8.md").write_text(
        """# ARM64 getline-compatible helper `0xd6ed8..0xd7890`

Cross-ABI mapping:

```text
ARM64:  0xd6ed8..0xd7890
x86_64: 0xc36c3..0xc3e4a
```

Both FDEs contain the same 28 opaque state constants and the same five libc
operations: `fgets`, `__strlen_chk`, `calloc`, `realloc`, and `memcpy`.  Direct
call sites are ARM64 `0xd9e1c/0xe69ec` and x86_64 `0xc8abb/0xdde9b`.

Recovered behavior:

1. Inputs are `char **line`, `size_t *capacity`, and `FILE *stream`; pointer
   arguments are not guarded.
2. A null `*line` forces `*capacity=128`, performs `calloc(128,1)`, publishes
   the result, and returns `-1` on allocation failure.
3. A non-null buffer with nonzero capacity is cleared across exactly
   `[line,line+capacity)`.  The flattened byte/halfword/aligned loop is proven
   equivalent to that full clear for every pointer alignment modulo four.
4. Reads use `fgets(chunk,128,stream)`.  A final newline is removed; an empty
   line therefore returns zero and stores an empty string.
5. Chunks without newline are appended.  Initial EOF returns `-1`; EOF after
   accumulated chunks returns their total length.
6. Required capacity is `total+1`.  Growth uses
   `(required & ~127) + 128`, so an exact 128-byte multiple receives one extra
   128-byte block.
7. Capacity is published before `realloc`, and the returned pointer directly
   overwrites `*line`.  Failure therefore retains the new capacity, loses the
   caller-visible old pointer, leaks the old allocation, and returns `-1`.
8. The copied line is always NUL terminated.  The native newline probe reads
   `chunk[strlen(chunk)-1]`; conforming successful `fgets(...,128,...)` is
   nonempty, but the helper itself has no explicit zero-length guard.

C++ implementation and non-executed regression entry:

```text
RecoveredGetLineOperationsD6ed8
runRecoveredGetLineD6ed8
recoveredGetLineD6ed8Regression
```
"""
    )

    print("ARM64/x86_64 FDEs, callers and 28 opaque states: PASS")
    print("full incoming-buffer clear and 128-byte fgets loop: PASS")
    print("newline stripping, append/EOF and NUL publication: PASS")
    print("capacity rounding and direct realloc-failure state: PASS")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
