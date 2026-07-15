#!/usr/bin/env python3
"""Recover the timestamp-to-log front end used twice by nSign."""

from __future__ import annotations

import pathlib
import re
import struct


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM = (HERE / "disasm-12ec1c-12f298.txt").read_text()
NSIGN = (HERE / "disasm-cc604-cd934.txt").read_text()
X64_ALL = (HERE / "x86_64-full-objdump.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def virtual_bytes(path: pathlib.Path, address: int, size: int) -> bytes:
    data = path.read_bytes()
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    for index in range(shnum):
        section = struct.unpack_from(
                "<IIQQQQIIQQ", data, shoff + index * shentsize)
        address0, file_offset, section_size = (
                section[3], section[4], section[5])
        if address0 <= address < address0 + section_size:
            offset = file_offset + address - address0
            return data[offset:offset + size]
    raise AssertionError(f"unmapped VMA {address:#x}")


assert struct.unpack("<d", virtual_bytes(ARM_SO, 0x2F50, 8))[0] == 1000.0
assert struct.unpack("<d", virtual_bytes(X64_SO, 0x4110, 8))[0] == 1000.0

arm_date = virtual_bytes(ARM_SO, 0x145FB0, 18)
arm_zone = virtual_bytes(ARM_SO, 0x145FC4, 3)
arm_line = virtual_bytes(ARM_SO, 0x145FC8, 15)
assert bytes(value ^ 0xFE for value in arm_date) == b"%Y-%m-%dT%H:%M:%S\0"
assert bytes(value ^ 0x7C for value in arm_zone) == b"%z\0"
assert bytes(value ^ 0x8D for value in arm_line) == b"%s: %s.%03dZ%s\0"

begin_label = virtual_bytes(ARM_SO, 0x1457E0, 33)
end_label = virtual_bytes(ARM_SO, 0x145810, 33)
assert bytes(value ^ 0xB7 for value in begin_label) == (
        b"Signing all the parameters begin\0")
assert bytes(value ^ 0xEE for value in end_label) == (
        b"Signing all the parameters end  \0")

# ARM64 input and conversion pipeline.
require(r"12ecbc:.*fmov\s+d8, d0", ARM, "millisecond input save")
require(r"12f1dc:.*ldr\s+d1, \[x9, #0xf50\]", ARM, "1000.0 load")
require(r"12f1e0:.*fdiv\s+d0, d8, d1", ARM, "milliseconds to seconds")
require(r"12f1e4:.*fcvtzs\s+x9, d0", ARM, "truncating time_t")
require(r"12f1f0:.*bl\s+0x13a080 <fmod@plt>", ARM,
        "millisecond remainder")
require(r"12f1f8:.*fcvtzs\s+w23, d0", ARM, "signed millisecond component")
require(r"12f1fc:.*bl\s+0x13a090 <localtime@plt>", ARM, "localtime")
require(r"12f208:.*adr\s+x2, 0x145fb0", ARM, "date format")
require(r"12f218:.*bl\s+0x13a0a0 <strftime@plt>", ARM, "date strftime")
require(r"12f220:.*adr\s+x2, 0x145fc4", ARM, "zone format")
require(r"12f230:.*bl\s+0x13a0a0 <strftime@plt>", ARM, "zone strftime")
require(r"12f238:.*adr\s+x3, 0x145fc8", ARM, "final line format")
require(r"12f258:.*bl\s+0x12fa24", ARM, "logging sink")

# x86_64 equivalent conversion sequence.
require(r"129a36:.*movsd.*# 0x4110", X64_ALL, "x86 1000.0")
require(r"129a42:.*divsd", X64_ALL, "x86 milliseconds to seconds")
require(r"129a46:.*cvttsd2si", X64_ALL, "x86 truncating time_t")
require(r"129a4f:.*callq.*<fmod@plt>", X64_ALL, "x86 fmod")
require(r"129a5b:.*callq.*<localtime@plt>", X64_ALL, "x86 localtime")
require(r"129a73:.*callq.*<strftime@plt>", X64_ALL, "x86 date strftime")

# nSign has begin/end labels and passes first/second samples respectively.
require(r"cd060:.*fmov\s+d0, d8", NSIGN, "begin sample")
require(r"cd070:.*adr\s+x0, 0x1457e0", NSIGN, "begin label")
require(r"ccf54:.*fmov\s+d0, d9", NSIGN, "end sample")
require(r"ccf64:.*adr\s+x0, 0x145810", NSIGN, "end label")

for symbol in ("RecoveredTimestampLogOutput",
               "modelRecoveredTimestampLog",
               "runRecoveredTimestampLog"):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

(HERE / "arm64-timestamp-log-frontend.md").write_text("""# Timestamp log front end

## Ranges

- ARM64: `0x12ec1c..0x12f298`
- x86_64: `0x1296f4..0x129ad0`

## Signature

```cpp
void timestampLog(const char* label, double epochMilliseconds);
```

ARM64 receives the label in `x0` and milliseconds in `d0`; x86_64 uses
`rdi`/`xmm0`.

## Recovered transformation

```text
seconds = trunc(milliseconds / 1000.0)
millisecondComponent = trunc(fmod(milliseconds, 1000.0))
local = localtime(&seconds)
date = strftime(20, "%Y-%m-%dT%H:%M:%S", local)
zone = strftime(6, "%z", local)
line = "%s: %s.%03dZ%s" % (label, date, millisecondComponent, zone)
forward line through 0x12fa24
```

`localtime` is intentional: the line contains a literal `Z` followed by the
numeric local offset, for example `...123Z+0800`. This odd format must not be
silently normalized to UTC in a compatibility implementation.

The nSign labels decode to:

```text
Signing all the parameters begin
Signing all the parameters end  
```

The second label contains two spaces after `end` before its NUL terminator.
The first outer realtime sample is used for the begin line and the second for
the end line.

## C++

- `modelRecoveredTimestampLog()`
- `runRecoveredTimestampLog()`

The downstream `0x12fa24..0x13063c` Android-log routing remains a separate
recovery unit; this front end is closed at its exact callee boundary.
""")

print("TIMESTAMP_LOG_FRONTEND_STATIC_OK")
