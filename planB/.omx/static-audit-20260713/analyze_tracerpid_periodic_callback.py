#!/usr/bin/env python3
"""Recover the periodic TracerPid callback and its context consumer."""

from __future__ import annotations

import pathlib
import re
import struct


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM = (HERE / "disasm-d4e0c-d6888.txt").read_text()
X64 = (HERE / "disasm-x86_64-c2115-c3126.txt").read_text()
POST_ARM = ROOT.joinpath(".omx/static-audit-20260713/disasm-d6888-d6994.txt")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def disassembly(start: int, end: int) -> str:
    import subprocess
    return subprocess.check_output([
        "objdump", "-d", f"--start-address={start}",
        f"--stop-address={end}", str(ARM_SO)
    ], text=True)


POST = disassembly(0xD6888, 0xD6994)
POST_ARM.write_text(POST)


def require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def virtual_bytes(path: pathlib.Path, address: int, size: int) -> bytes:
    data = path.read_bytes()
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    for index in range(shnum):
        offset = shoff + index * shentsize
        section = struct.unpack_from("<IIQQQQIIQQ", data, offset)
        section_address, file_offset, section_size = (
                section[3], section[4], section[5])
        if section_address <= address < section_address + section_size:
            start = file_offset + address - section_address
            return data[start:start + size]
    raise AssertionError(f"unmapped virtual address {address:#x}")


arm_marker = virtual_bytes(ARM_SO, 0x145898, 11)
arm_path = virtual_bytes(ARM_SO, 0x1458B0, 16)
x64_marker = virtual_bytes(X64_SO, 0x13E328, 11)
x64_path = virtual_bytes(X64_SO, 0x13E340, 16)
assert bytes(value ^ 0xF6 for value in arm_marker) == b"TracerPid:\0"
assert bytes(value ^ 0x78 for value in arm_path) == b"/proc/%d/status\0"
assert bytes(value ^ 0x74 for value in x64_marker) == b"TracerPid:\0"
assert bytes(value ^ 0x24 for value in x64_path) == b"/proc/%d/status\0"

# ARM64 syscall and I/O surface.
require(r"d5c78:.*mov\s+w0, #0x38", ARM, "ARM64 openat syscall 56")
require(r"d5c7c:.*mov\s+w1, #-0x64", ARM, "AT_FDCWD -100")
require(r"d5c88:.*bl\s+0x139e00 <syscall@plt>", ARM, "openat syscall")
require(r"d5fa4:.*mov\s+w1, #0x4", ARM, "R_OK")
require(r"d5fa8:.*bl\s+0x139e30 <access@plt>", ARM, "access")
require(r"d60f4:.*mov\s+w2, #0x800", ARM, "read bound")
require(r"d60fc:.*bl\s+0x139f70 <read@plt>", ARM, "read")
require(r"d6108:.*bl\s+0x139f80 <close@plt>", ARM, "close")
require(r"d630c:.*mov\s+w0, #0xac", ARM, "ARM64 getpid syscall 172")
require(r"d6484:.*adr\s+x2, 0x1458b0", ARM, "formatted proc path")
require(r"d648c:.*bl\s+0xd6994", ARM, "vsnprintf wrapper")
require(r"d5c10:.*sub\s+w9, w8, #0x30", ARM, "decimal digit")
require(r"d6758:.*mov\s+w9, #0xa", ARM, "decimal multiply base")
require(r"d65f8:.*strb\s+w9, \[x23, #0xb21\]", ARM,
        "sticky tracer verdict")

# x86_64 cross-ABI confirmation.
require(r"c2adb:.*movl\s+\$0x101, %edi", X64, "x86_64 openat 257")
require(r"c2c03:.*callq\s+0x132860 <access@plt>", X64, "x86 access")
require(r"c2c81:.*movl\s+\$0x800, %edx", X64, "x86 read bound")
require(r"c2c95:.*callq\s+0x1329a0 <read@plt>", X64, "x86 read")
require(r"c2ca2:.*callq\s+0x1329b0 <close@plt>", X64, "x86 close")
require(r"c2da9:.*pushq\s+\$0x27", X64, "x86_64 getpid 39")
require(r"c2ef7:.*movb\s+\$0x1,.*# 0x13f0bd", X64,
        "x86 sticky tracer verdict")

# Consumer: correction 0x26 only on sticky verdict; bit 38 always.
require(r"d68fc:.*ldrb\s+w10, \[x22, #0xb21\]", POST,
        "sticky verdict load")
require(r"d6938:.*mov\s+w1, #0x26", POST, "correction 0x26")
require(r"d693c:.*bl\s+0x13548c", POST, "correction writer")
require(r"d6950:.*orr\s+x8, x8, #0x1", POST, "flag bit zero")
require(r"d6974:.*orr\s+x8, x8, #0x4000000000", POST,
        "unconditional flag bit 38")

for symbol in ("RecoveredTracerPidProbeInput",
               "RecoveredTracerPidProbeOutput",
               "modelRecoveredTracerPidProbe",
               "runRecoveredTracerPidPeriodicCallback",
               "applyRecoveredTracerPidPostStage"):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

(HERE / "arm64-tracerpid-periodic-callback.md").write_text("""# TracerPid periodic callback and consumer

## Ranges

- ARM64 callback: `0xd4e0c..0xd6888`
- x86_64 callback: `0xc2115..0xc3126`
- ARM64 consumer: `0xd6888..0xd6994`
- x86_64 consumer: `0xc3126..0xc31ce`

## Static strings

| ABI | address | transform | plaintext |
|---|---:|---:|---|
| ARM64 | `0x145898` | XOR `0xf6` | `TracerPid:` |
| ARM64 | `0x1458b0` | XOR `0x78` | `/proc/%d/status` |
| x86_64 | `0x13e328` | XOR `0x74` | `TracerPid:` |
| x86_64 | `0x13e340` | XOR `0x24` | `/proc/%d/status` |

The strings are decoded once under byte-sized atomic/CAS guards. These guards
are initialization locks, not alternate cipher selectors.

## Callback behavior

The callback keeps a process-global sticky verdict. When it is not already
set, it obtains the PID, formats `/proc/<pid>/status`, checks readability,
opens with `openat(AT_FDCWD, path, O_RDONLY, 0)`, reads at most `0x800` bytes,
and closes the descriptor even when `read` fails. It searches for
`TracerPid:` using ASCII case-insensitive byte comparison and parses the
suffix with the SO's whitespace/sign/decimal `atoi` behavior. A nonzero value
sets the sticky verdict to one; ordinary path/open/read/marker failures leave
the previous verdict unchanged.

ARM64 direct syscall numbers are `56` for `openat` and `172` for `getpid`;
x86_64 uses `257` and `39` respectively.

## Context consumer

`0xd6888` reads the sticky verdict after the environment dispatcher:

```text
if tracerDetected:
    write correction 0x26
    context.flags |= 1
context.flags |= 0x0000004000000000  // bit 38
```

Thus correction `0x26` is the native `/proc/<pid>/status` TracerPid verdict,
not a cryptographic algorithm-selection signal.

## C++

- `modelRecoveredTracerPidProbe()`
- `runRecoveredTracerPidPeriodicCallback()`
- `applyRecoveredTracerPidPostStage()`

The model accepts injected syscall outcomes/status bytes and never reads the
host `/proc` filesystem during regression.
""")

print("TRACERPID_PERIODIC_CALLBACK_STATIC_OK")
