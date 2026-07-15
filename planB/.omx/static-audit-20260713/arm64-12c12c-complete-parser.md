# `0x12c12c` complete marker/triplet parser

## Function and arguments

ARM64 FDE:

```text
0x12c12c..0x12e95c
```

Cross-ABI argument slots establish:

```text
arg0: mutable input
arg1: case-insensitive marker (caller decodes "android")
arg2: uint32_t[3] output
```

x86_64 saves these at `sp+0x120`, `sp+0x108`, and `sp+0x118` respectively.
The entry states reject any null argument before dereference.

## Marker search

The scanner is a naive first-match substring search, not a locale-aware or
Unicode search.  Both ASCII-fold blocks (`0x12dcd4..0x12dcf4` and
`0x12e28c..0x12e2ac`) map only `A..Z` to `byte | 0x20`.

x86_64 makes the persistent cursors visible:

```text
0x127876..0x127c9e  measure marker length
0x12903c             candidate = mutable input
0x128424             marker-relative length/offset
0x12797d..0x127f41  compare candidate and marker bytes
0x128342             advance both cursors
0x128c0d             matched end = candidate + marker length
```

The first full case-insensitive match wins.  An empty marker resolves to the
input start.  No input byte is modified during marker matching.

## Triplet scanner

Starting at the byte after the marker match, each component uses the same
cursor language:

```text
skip zero or more '.' bytes
require a non-NUL component start
scan until the next '.' or NUL
```

Evidence groups are:

| stage | skip dots | component start | terminator scan/check |
|---:|---:|---:|---:|
| 0 | ARM64 `0x12e018`; x86_64 `0x127392` | ARM64 `0x12e818`; x86_64 `0x128055` | ARM64 `0x12e88c..0x12e734`; x86_64 `0x1293ac..0x127e4a` |
| 1 | ARM64 `0x12dfb0`; x86_64 `0x1272bd` | ARM64 `0x12d9f4`; x86_64 `0x126d1c` | ARM64 `0x12d7a0..0x12dc18`; x86_64 `0x128257..0x126fa2` |
| 2 | ARM64 `0x12e218`; x86_64 `0x127668` | ARM64 `0x12d82c`; x86_64 `0x126a51` | ARM64 `0x12df64..0x12df18`; x86_64 `0x128dc1..0x1271c6` |

The first two terminators must be a real non-NUL byte.  Native replaces that
byte with NUL, saves `terminator + 1`, and then calls `strtol`.  If the scan
reaches NUL, native still performs that component's `strtol`, but the null
continuation guard forces failure.  The third terminator may already be NUL;
otherwise it is replaced by NUL.

## Conversion and failure ordering

The three calls are:

```text
0x12db64 -> output +0
0x12e080 -> output +4
0x12de7c -> output +8
```

`errno` is cleared once before the first call.  Every call stores the low
32 bits of the returned `long` before checking `end != start` and
`errno != ERANGE`.  The third call does not require full consumption.

Location, separator mutation, and conversion are interleaved.  There is no
retry with a later triplet after a conversion failure.  Therefore a second
component failure retains the first and second NUL writes and the first two
output stores.  The C++ entry `parseProtectedAndroidTriplet` preserves this
ordering instead of pre-locating all six cursors.
