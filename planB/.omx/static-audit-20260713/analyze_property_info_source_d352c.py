#!/usr/bin/env python3
"""Static cross-ABI proof for property-info source creator ARM64 0xd352c."""

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
    0x13E17013990AC44B,
    0x253B8DC9B1F6A352,
    0x36024800DCC1A6DE,
    0x3BA140A9BE28BC50,
    0x466BA40D4916CEE5,
    0x503753E0AE4798BC,
    0x59E82660F83D7C2C,
    0x5D78403248B2B029,
    0x5E552FB6155AA6AC,
    0x5F30D8F6436F4E2B,
    0x654C132D1B9CFAC9,
    0x6F2D55AA13EEC79D,
    0x8689970CE5A5BD6D,
    0x96EEB6C1AF4D042A,
    0x96FB5A5AD1280E0C,
    0xA75A6F0F9AC87AAD,
    0xBCD164272BF8AF2D,
    0xC30A4A8E1721B162,
    0xC8E7A3831C04ECFD,
    0xCBEB4F827C5A03D5,
    0xD02C834FE59DD8D5,
    0xD8E551C8D36C3F01,
    0xDCA35FA4A4CC1776,
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


def find_readelf() -> str:
    for candidate in (
        os.environ.get("GNU_READELF"),
        "/opt/homebrew/opt/binutils/bin/readelf",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/readelf",
        shutil.which("greadelf"),
    ):
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU readelf not found; set GNU_READELF")


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


def read_vma(readelf: str, binary: Path, vma: int, size: int) -> bytes:
    blob = binary.read_bytes()
    program_headers = subprocess.check_output(
        [readelf, "-lW", str(binary)], text=True
    )
    for line in program_headers.splitlines():
        match = re.match(
            r"\s*load\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+"
            r"0x[0-9a-f]+\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)",
            line.lower(),
        )
        if match is None:
            continue
        file_offset, virtual_address, file_size, _ = (
            int(value, 16) for value in match.groups()
        )
        if virtual_address <= vma and vma + size <= virtual_address + file_size:
            offset = file_offset + vma - virtual_address
            return blob[offset:offset + size]
    raise AssertionError(f"VMA 0x{vma:x}+0x{size:x} not file-backed")


def main() -> None:
    objdump = find_objdump()
    readelf = find_readelf()
    arm = disassemble(objdump, ARM64_SO, 0xD352C, 0xD3D90)
    x86 = disassemble(objdump, X86_64_SO, 0xC0CDD, 0xC1318, intel=True)
    (AUDIT / "disasm-d352c-d3d90.txt").write_text(arm)
    (AUDIT / "disasm-x86-c0cdd-c1318.txt").write_text(x86)

    assert (0xD352C, 0xD3D90) in fde_ranges(ARM_EH)
    assert (0xC0CDD, 0xC1318) in fde_ranges(X86_EH)
    assert direct_callers(ARM_FULL, 0xD352C) == [0xD4024]
    assert direct_callers(X86_FULL, 0xC0CDD) == [0xC1537]
    assert direct_callers(ARM_FULL, 0xD3D90)[-2:] == [0xD3BD8, 0xD41F4]
    assert direct_callers(X86_FULL, 0xC1318)[-2:] == [0xC11E7, 0xC16F7]

    missing_arm_states = EXPECTED_STATES - arm64_constants(arm)
    x86_states = x86_constants(x86)
    if missing_arm_states or x86_states != EXPECTED_STATES:
        raise AssertionError(
            f"opaque-state mismatch: arm={sorted(map(hex, missing_arm_states))} "
            f"x86_missing={sorted(map(hex, EXPECTED_STATES - x86_states))} "
            f"x86_extra={sorted(map(hex, x86_states - EXPECTED_STATES))}"
        )

    arm_encoded = read_vma(readelf, ARM64_SO, 0x145850, 34)
    arm_path = bytes(value ^ 0xC1 for value in arm_encoded)
    x86_encoded = bytearray(read_vma(readelf, X86_64_SO, 0x13E2E0, 34))
    x86_mask = read_vma(readelf, X86_64_SO, 0x3510, 16)
    for block in (0, 16):
        for index, mask in enumerate(x86_mask):
            x86_encoded[block + index] ^= mask
    x86_encoded[32] ^= 0x9A
    x86_encoded[33] ^= 0x9A
    expected_path = b"/dev/__properties__/property_info\0"
    assert arm_path == expected_path
    assert bytes(x86_encoded) == expected_path

    require_order(body(arm, 0xD3560, 0xD35E0), [
        "mov\tw0, #0x1",
        "mov\tw1, #0x30",
        "bl\t139e50",
        "add\tx8, x0, #0x18",
        "cmp\tx0, #0x0",
    ], "ARM64 0x30-byte source allocation")
    require_order(body(x86, 0xC0D2C, 0xC0D64), [
        "push   0x1",
        "push   0x30",
        "call   132880",
        "lea    rcx,[rax+0x18]",
        "test   rax,rax",
    ], "x86 0x30-byte source allocation")

    require_order(body(arm, 0xD3864, 0xD388C), [
        "mov\tw8, #0x8",
        "mov\tw10, #0xffffffff",
        "str\tw10, [x8]",
    ], "ARM64 fd -1 initialization and status-8 state")
    require_order(body(x86, 0xC0F24, 0xC0F33), [
        "or     dword ptr [rax],0xffffffff",
        "push   0x8",
    ], "x86 fd -1 initialization and status-8 state")

    require_order(body(arm, 0xD3AA8, 0xD3B2C), [
        "mov\tx0, x21",
        "mov\tw1, #0x4",
        "bl\t139e30",
        "cmp\tw0, #0x0",
    ], "ARM64 R_OK access")
    require_order(body(x86, 0xC10DA, 0xC1147), [
        "lea    rdi,[rip+",
        "push   0x4",
        "call   132860",
        "test   eax,eax",
    ], "x86 R_OK access")

    require_order(body(arm, 0xD3B2C, 0xD3BC8), [
        "mov\tw0, #0x38",
        "mov\tw1, #0xffffff9c",
        "mov\tx2, x21",
        "mov\tw3, wzr",
        "mov\tw4, wzr",
        "bl\t139e00",
        "cmp\tw0, #0x0",
        "str\tw0, [x8]",
    ], "ARM64 openat syscall and fd publication")
    require_order(body(x86, 0xC114B, 0xC11D7), [
        "mov    edi,0x101",
        "push   0xffffffffffffff9c",
        "lea    rdx,[rip+",
        "xor    ecx,ecx",
        "xor    r8d,r8d",
        "call   132830",
        "mov    dword ptr [rax],ecx",
        "test   ecx,ecx",
    ], "x86 openat syscall and fd publication")

    require_order(body(arm, 0xD3A18, 0xD3AA0), [
        "add\tx1, sp, #0x50",
        "ldr\tx0, [sp, #48]",
        "bl\t139f10",
        "cmp\tw0, #0x0",
    ], "ARM64 fstat")
    require_order(body(x86, 0xC1069, 0xC10D3), [
        "mov    rdi,qword ptr [rsp+0x10]",
        "lea    rsi,[rsp+0x40]",
        "call   132940",
        "test   eax,eax",
    ], "x86 fstat")

    require_order(body(arm, 0xD39F4, 0xD3A18), [
        "ldr\tx8, [sp, #128]",
        "str\tx8, [sp, #32]",
        "cmp\tx8, #0x18",
    ], "ARM64 minimum 24-byte file gate")
    require_order(body(x86, 0xC103E, 0xC1069), [
        "mov    rax,qword ptr [rsp+0x70]",
        "mov    qword ptr [rsp+0x30],rax",
        "cmp    rax,0x18",
    ], "x86 minimum 24-byte file gate")

    require_order(body(arm, 0xD388C, 0xD393C), [
        "mov\tx0, xzr",
        "mov\tw2, #0x1",
        "mov\tw3, #0x2",
        "mov\tx5, xzr",
        "str\tx1, [x27, #16]",
        "bl\t139f00",
        "str\tx0, [x27, #8]",
        "ldr\tq0, [x0]",
        "ldr\tx8, [x0, #16]",
        "str\tq0, [x10]",
        "str\tx8, [x10, #16]",
    ], "ARM64 mmap publication then unchecked first-24-byte copy")
    require_order(body(x86, 0xC0F33, 0xC0FD9), [
        "mov    qword ptr [rbx+0x10],rsi",
        "xor    edi,edi",
        "push   0x1",
        "push   0x2",
        "xor    r9d,r9d",
        "call   132930",
        "mov    qword ptr [rbx+0x8],rax",
        "movups xmm0,xmmword ptr [rax]",
        "movups xmmword ptr [rcx],xmm0",
        "mov    rax,qword ptr [rax+0x10]",
        "mov    qword ptr [rcx+0x10],rax",
    ], "x86 mmap publication then unchecked first-24-byte copy")

    for value in (2, 8, 10, 12):
        require(CPP, rf"return fail\({value}\)", f"C++ status {value}")
    for symbol in (
        "RecoveredPropertyInfoHeaderD352c",
        "RecoveredPropertyInfoSourceCreateOperationsD352c",
        "runRecoveredPropertyInfoSourceCreateD352c",
        "recoveredPropertyInfoSourceCreateD352cRegression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")
    require(CPP, re.escape("/dev/__properties__/property_info"), "C++ path")
    require(
        CPP,
        r"operations\.map\(\s*nullptr, fileSize, 1, 2, opened, 0\);\s*std::memcpy\(&source->fileHeader, source->bytes",
        "C++ unchecked mmap publication/copy order",
    )
    require(
        GENERATOR,
        r"0x0D352C:.*property-info mapped source creator.*recovered",
        "0xd352c coverage entry",
    )
    require(
        CPP,
        r"if \(!recoveredPropertyInfoSourceCreateD352cRegression\(\)\)",
        "top-level property-info source regression guard",
    )

    (AUDIT / "arm64-property-info-source-d352c.md").write_text(
        """# Property-info mapped source creator `0xd352c`

Cross-ABI mapping:

```text
ARM64:  0xd352c..0xd3d90
x86_64: 0xc0cdd..0xc1318
```

Both implementations contain the same 23 opaque state constants and decode
the same fixed path:

```text
/dev/__properties__/property_info
```

The helper always runs even with a preexisting nonzero status.  It allocates a
zeroed 0x30-byte source, initializes fd at +0x00 to -1, checks `access(path,4)`,
opens with `openat(AT_FDCWD,path,O_RDONLY,0)`, runs fstat, and requires
`st_size >= 24`.  It stores the size at +0x10, maps the whole file with
`mmap(nullptr,size,PROT_READ,MAP_PRIVATE,fd,0)`, stores the pointer at +0x08,
and copies the first 24 mapped bytes to source+0x18.  These copied header bytes
place the string-table offset at source+0x24 and root-node offset at +0x2c.

Failure statuses are 2 for the source calloc, 8 for access/open, 10 for fstat,
and 12 for a file shorter than 24 bytes.  Each failure calls the d3d90 mapped
source destructor and returns null.  Success preserves incoming status.

There is no mmap-result gate: pointer publication is immediately followed by
16-byte and 8-byte loads from the returned address.  `MAP_FAILED` or null
therefore faults before the state machine can assign a status or invoke normal
rollback.  The first 24 bytes are copied without validating magic, version, or
embedded offsets; later parser stages trust those offsets as documented in the
d28d0 evidence.

C++ implementation and non-executed regression entry:

```text
RecoveredPropertyInfoHeaderD352c
RecoveredPropertyInfoSourceCreateOperationsD352c
runRecoveredPropertyInfoSourceCreateD352c
recoveredPropertyInfoSourceCreateD352cRegression
```
"""
    )

    print("ARM64/x86_64 FDEs, caller and 23 opaque states: PASS")
    print("decoded /dev/__properties__/property_info path: PASS")
    print("access/openat/fstat/size statuses 2/8/10/12: PASS")
    print("read-only private mmap and unchecked first-24-byte copy: PASS")
    print("C++ implementation, regression guard and coverage entry: PASS")


if __name__ == "__main__":
    main()
