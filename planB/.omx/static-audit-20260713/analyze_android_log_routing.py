#!/usr/bin/env python3
"""Recover the timestamp logger's complete formatting and Android-log sink."""

from __future__ import annotations

import pathlib
import re
import struct


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM = (HERE / "disasm-12fa24-13063c.txt").read_text()
X64 = (HERE / "disasm-x86_64-12a08e-12a8ff.txt").read_text()
FRONT = (HERE / "disasm-12ec1c-12f298.txt").read_text()
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
        address0, file_offset, section_size = section[3:6]
        if address0 <= address < address0 + section_size:
            offset = file_offset + address - address0
            return data[offset:offset + size]
    raise AssertionError(f"unmapped VMA {address:#x}")


def decoded(path: pathlib.Path, address: int, size: int, key: int) -> bytes:
    return bytes(value ^ key for value in virtual_bytes(path, address, size))


# Mutable XOR-once strings and the four-entry priority mapping agree across
# ARM64 and x86_64.
assert decoded(ARM_SO, 0x145FE8, 9, 0xD9) == b"== %s@%d\0"
assert decoded(ARM_SO, 0x145FF4, 7, 0xCE) == b"signer\0"
assert decoded(ARM_SO, 0x145FFC, 7, 0x90) == b"%s: %s\0"
assert decoded(ARM_SO, 0x146004, 3, 0x59) == b"%s\0"
assert struct.unpack("<4i", virtual_bytes(ARM_SO, 0x2FE0, 16)) == (2, 3, 5, 6)

assert decoded(X64_SO, 0x13EA78, 9, 0xD1) == b"== %s@%d\0"
assert decoded(X64_SO, 0x13EA84, 7, 0xD7) == b"signer\0"
assert decoded(X64_SO, 0x13EA8C, 7, 0x09) == b"%s: %s\0"
assert decoded(X64_SO, 0x13EA93, 3, 0xA9) == b"%s\0"
assert struct.unpack("<4i", virtual_bytes(X64_SO, 0x3920, 16)) == (2, 3, 5, 6)

# 0x12fa24 is the AArch64 varargs adapter: save remaining GP/FP registers,
# construct a va_list at x4, and forward the original x0..x3 to 0x12fab4.
require(r"12fa34:.*stp\s+x4, x5", ARM, "ARM varargs GP save")
require(r"12fa44:.*stp\s+q0, q1", ARM, "ARM varargs FP save")
require(r"12fa70:.*sub\s+x4, x29, #0x50", ARM, "ARM va_list argument")
require(r"12fa8c:.*bl\s+0x12fab4", ARM, "ARM formatter call")

# The formatter owns two zeroed 0x400-byte buffers, formats the message first,
# conditionally formats "== source@line", then invokes the Android-log sink.
require(r"12faec:.*add\s+x0, sp, #0x440", ARM, "prefix buffer")
require(r"12fb0c:.*add\s+x0, sp, #0x40", ARM, "message buffer")
require(r"12fb34:.*bl\s+0x139f40 <vsnprintf@plt>", ARM,
        "message vsnprintf")
require(r"12fea0:.*adr\s+x2, 0x145fe8", ARM, "prefix format")
require(r"12feb4:.*bl\s+0x130098", ARM, "prefix snprintf adapter")
require(r"130028:.*adr\s+x20, 0x145ff4", ARM, "signer tag")
require(r"130044:.*bl\s+0x13012c", ARM, "Android-log sink")
require(r"130058:.*bl\s+0x130128", ARM, "post-log no-op")

# 0x130098 is only a vsnprintf varargs wrapper.
require(r"130100:.*bl\s+0x139f40 <vsnprintf@plt>", ARM,
        "bounded snprintf wrapper")

# The sink loads the priority table and has exactly the one-argument and
# prefix+message __android_log_print branches.
require(r"130468:.*add\s+x9, x9, #0xfe0", ARM, "ARM priority table")
require(r"1303e4:.*bl\s+0x13a0d0 <__android_log_print@plt>", ARM,
        "ARM one-argument log")
require(r"130498:.*bl\s+0x13a0d0 <__android_log_print@plt>", ARM,
        "ARM two-argument log")

# x86_64 independently confirms the same ABI split and both native calls.
require(r"12a10b:.*callq\s+0x12a130", X64, "x86 formatter call")
require(r"12a1c9:.*callq.*<vsnprintf@plt>", X64,
        "x86 message vsnprintf")
require(r"12a3cf:.*callq\s+0x12a4f8", X64, "x86 prefix snprintf")
require(r"12a4b9:.*callq\s+0x12a59f", X64, "x86 Android-log sink")
require(r"12a7d4:.*movl\s+\(%rcx,%rax,4\), %eax", X64,
        "x86 priority lookup")
require(r"12a780:.*callq.*<__android_log_print@plt>", X64,
        "x86 one-argument log")
require(r"12a808:.*callq.*<__android_log_print@plt>", X64,
        "x86 two-argument log")

# The only direct caller passes null source, zero line, priority index zero.
require(r"12f23c:.*mov\s+x0, xzr", FRONT, "timestamp null source")
require(r"12f240:.*mov\s+w1, wzr", FRONT, "timestamp zero line")
require(r"12f244:.*mov\s+w2, wzr", FRONT, "timestamp priority index zero")
require(r"12f258:.*bl\s+0x12fa24", FRONT, "timestamp logging call")

for symbol in ("recoveredBoundedSnprintf",
               "RecoveredAndroidLogOutput",
               "modelRecoveredAndroidLogRoute",
               "runRecovered12fa24Log"):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

(HERE / "arm64-android-log-routing.md").write_text("""# Android log routing

## Ranges

| Role | ARM64 | x86_64 |
|---|---|---|
| varargs adapter | `0x12fa24..0x12fab4` | `0x12a08e..0x12a130` |
| formatter/router | `0x12fab4..0x130098` | `0x12a130..0x12a4f8` |
| snprintf adapter | `0x130098..0x130128` | `0x12a4f8..0x12a59e` |
| no-op post hook | `0x130128..0x13012c` | `0x12a59e..0x12a59f` |
| Android log sink | `0x13012c..0x13063c` | `0x12a59f..0x12a8ff` |

## Source-level signature and flow

```cpp
void logf(const char* source,
          int sourceLine,
          int priorityIndex,
          const char* format,
          ...);
```

```text
message[0x400] = {0}
prefix[0x400] = {0}
vsnprintf(message, 0x400, format, args)

if source != null:
    snprintf(prefix, 0x400, "== %s@%d", source, sourceLine)
else:
    selectedPrefix = null

priority = {2, 3, 5, 6}[priorityIndex]
tag = "signer"

if selectedPrefix == null:
    __android_log_print(priority, tag, "%s", message)
else:
    __android_log_print(priority, tag, "%s: %s", prefix, message)
```

The table maps valid indices `0..3` to Android `VERBOSE`, `DEBUG`, `WARN`,
and `ERROR`. The native caller contract assumes an in-range index; the sink
does not expose a safe public bounds check.

The timestamp front end is the only direct `0x12fa24` caller. It passes
`source=null`, `sourceLine=0`, and `priorityIndex=0`, so both nSign timestamp
lines are emitted as:

```cpp
__android_log_print(ANDROID_LOG_VERBOSE, "signer", "%s", timestampLine);
```

Both `vsnprintf` return values and the `__android_log_print` return value are
ignored. This chain neither reads nor writes signer status and cannot clear or
replace the `jbyteArray` returned by the signing context.

## C++

- `recoveredBoundedSnprintf()`
- `modelRecoveredAndroidLogRoute()`
- `runRecovered12fa24Log()`
- `runRecoveredTimestampLog()` now continues through the recovered sink
""")

print("ANDROID_LOG_ROUTING_STATIC_OK")
