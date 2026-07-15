#!/usr/bin/env python3
"""Prove the two nSign pre-context helpers without executing libsigner.so."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TIMER = (HERE / "disasm-d4908-d4e0c.txt").read_text()
MAP_COPY = (HERE / "disasm-aebf8-af438.txt").read_text()
NSIGN = (HERE / "disasm-cc604-cd934.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, text: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


# 0xd4908: no incoming argument register is consumed before the synchronous
# callback.  The only external effects are the callback, global flag/handle,
# timer_create and timer_settime.
require(r"d4c74:.*bl\s+0xd4e0c", TIMER, "synchronous callback")
require(r"d4c50:.*ldrb.*\[x8, #0xb20\]", TIMER, "installed-byte load")
require(r"d4d4c:.*mov\s+w0, #0x1", TIMER, "CLOCK_MONOTONIC")
require(r"d4d58:.*stur\s+w8, \[x29, #-0x44\]", TIMER,
        "SIGEV_THREAD field")
require(r"d4d60:.*adr\s+x8, 0xd4e0c", TIMER, "callback address")
require(r"d4d64:.*stp\s+x8, xzr", TIMER, "callback and null attributes")
require(r"d4d74:.*bl\s+0x139f60 <timer_create@plt>", TIMER,
        "timer_create")
require(r"d4b38:.*bl\s+0x139f50 <timer_settime@plt>", TIMER,
        "timer_settime")
require(r"d4dcc:.*strb\s+w10, \[x9, #0xb20\]", TIMER,
        "installed-byte store")
require(r"ccdc0:.*bl\s+0xd4908", NSIGN, "nSign timer call")
for symbol in ("modelRecoveredPeriodicTimerInstall",
               "runRecoveredPeriodicTimerInstall"):
    require(rf"\b{symbol}\b", CPP, f"C++ {symbol}")


# 0xaebf8: x0=status, x1=JNIEnv, x2=Map, x3=key, x4=owned output.
require(r"aec18:.*stur\s+x4, \[x29, #-0x48\]", MAP_COPY,
        "output pointer save")
require(r"aec20:.*stp\s+x0, x1", MAP_COPY, "status and env save")
require(r"aec2c:.*cmp\s+x3, #0x0", MAP_COPY, "key null gate")
require(r"aec34:.*ccmp\s+x2, #0x0", MAP_COPY, "map null gate")
require(r"aef48:.*str\s+xzr, \[x8\]", MAP_COPY, "output clear")
require(r"aef50:.*str\s+w11, \[x8\]", MAP_COPY,
        "invalid-input status 2")
require(r"af0f8:.*bl\s+0xadbf4", MAP_COPY, "Map.get helper")
require(r"aef98:.*bl\s+0x92b24", MAP_COPY, "String UTF acquisition")
require(r"af198:.*bl\s+0x139e20 <malloc@plt>", MAP_COPY,
        "owned allocation")
require(r"af244:.*str\s+w11, \[x8\]", MAP_COPY,
        "allocation status 3")
require(r"af280:.*strb\s+wzr, \[x11, x8\]", MAP_COPY,
        "NUL terminator")
require(r"af384:.*ldrb", MAP_COPY, "byte-copy load")
require(r"af390:.*strb", MAP_COPY, "byte-copy store")
require(r"af048:.*ldr\s+x8, \[x8, #0x550\]", MAP_COPY,
        "ReleaseStringUTFChars vtable slot")
require(r"af2c4:.*ldr\s+x8, \[x8, #0xb8\]", MAP_COPY,
        "DeleteLocalRef vtable slot")
require(r"cce40:.*bl\s+0xaebf8", NSIGN, "nSign map-copy call")
for symbol in ("modelRecoveredMapStringCopy", "runRecoveredMapStringCopy"):
    require(rf"\b{symbol}\b", CPP, f"C++ {symbol}")


(HERE / "arm64-nsign-periodic-timer.md").write_text("""# ARM64 nSign periodic timer installer

## Range and ABI

- ARM64 FDE: `0xd4908..0xd4e0c`
- x86_64 equivalent: `0xc1c33..0xc2115`
- signature: no consumed input arguments and no meaningful return value
- nSign call-site: `0xccdc0`

## Recovered order

1. `0xd4c74` invokes callback `0xd4e0c` synchronously on every call.
2. `0xd4c4c` reads process-global installed byte `0x146b20`.
3. When already installed, return without another `timer_create`.
4. Otherwise build `sigevent` with `SIGEV_THREAD` (`2`), callback
   `0xd4e0c`, zero `sigval`, and null thread attributes.
5. `timer_create(CLOCK_MONOTONIC=1, ..., &globalTimer@0x146b28)`.
6. On create success, arm the timer with both `it_interval` and `it_value`
   equal to `{1 second, 0 nanoseconds}` and flags `0`.
7. Set installed byte to `1` only after `timer_settime` succeeds.

Both failures are silently ignored.  A timer created before a
`timer_settime` failure is not deleted in this function.

## Owned C++

- `modelRecoveredPeriodicTimerInstall()`
- `runRecoveredPeriodicTimerInstall()`

The runtime form injects timer operations and therefore does not execute an
OS timer during static-analysis regression.
""")

(HERE / "arm64-map-string-owned-copy.md").write_text("""# ARM64 Map string owned-copy helper

## Range and ABI

- ARM64 FDE: `0xaebf8..0xaf438`
- nSign call-site: `0xcce40`

| register | recovered meaning |
|---|---|
| `x0` | `uint32_t* status` |
| `x1` | `JNIEnv*` |
| `x2` | Java `Map` reference |
| `x3` | decoded C-string key |
| `x4` | `char**`/owned native output |

## Recovered behavior

1. Null Map or key clears output and writes status `2`.
2. Call `0xadbf4`, the recovered JNI `Map.get` helper.
3. A null value with status zero is a successful null output.
4. For a non-null Java String, `0x92b24` acquires modified UTF-8 bytes and
   byte length.
5. Allocate `length + 1`; allocation failure writes status `3`.
6. Copy exactly `length` bytes and append NUL.
7. Release UTF chars through JNIEnv vtable `+0x550` and delete the Map.get
   local reference through vtable `+0xb8`.
8. Any nonzero final status leaves the owned output null.

## Owned C++

- `modelRecoveredMapStringCopy()`
- `runRecoveredMapStringCopy()`
""")

print("NSIGN_SUPPORT_HELPERS_STATIC_OK")
