# arm64 `0x135640..0x136a00` complete marker/range gate

This report is based only on local ELF disassembly. The target shared object
was not loaded or executed.

## Nine-argument ABI

The ARM64 call at `0x8658..0x8690` and x86_64 call at `0xeb51..0xeb75` agree on:

```cpp
bool protectedAndroidMarkerRangeGate(
    const char* marker,
    const char* source,
    const ProtectedRangeBoundary* firstBoundaries,
    uint64_t firstCount,
    const ProtectedRangeBoundary* secondBoundaries,
    uint64_t secondCount,
    const char* const* joinedStrings,
    size_t joinedCount,
    uint32_t* status);
```

ARM64 passes arguments 0 through 7 in `x0..x7` and the status pointer on the
stack. x86_64 saves the first six register arguments at function-entry stack
slots `+0xc8..+0xe8`; the final three inputs are at caller-stack slots
`+0x1c0`, `+0x1c8` and `+0x1d0` after the prologue.

## Source scan, allocation and copy

x86_64 `0x13080f..0x13086c` reads the source cursor byte before advancing it.
There is no null guard: null source has the native null-dereference behavior.
After the terminal NUL is found, `0x1302d0..0x1302ee` computes the byte length,
calls `malloc(length + 1)` and saves the result. `0x1301b6..0x13021b` and
`0x1305f8..0x13065d` copy the source byte by byte; `0x130544..0x130551` writes
the final NUL.

If malloc returns null, x86_64 `0x13028e..0x1302ab` selects status code `2`.
The ARM64 equivalent allocation and null branch are
`0x136470..0x136540`. Failure still reaches the common status write and
cleanup path.

## Join and parser inputs

The delimiter is initialized once and decodes to a one-byte space. The join
calls are ARM64 `0x1363a8..0x1363ac` and x86_64
`0x130678..0x13068f`; they consume `joinedStrings`, `joinedCount`, and `" "`.
This call is unconditional after a successful source allocation.

The parser calls immediately afterward are ARM64 `0x1363b4..0x1363c0` and
x86_64 `0x130699..0x1306ae`. Their mutable input is the separately allocated
source copy, not the joined result. Therefore the join is not a null-source
fallback and parser NUL insertion does not mutate the caller's source.

Join allocation failure has no independent status assignment. Its null result
is retained for the common `free`, while parsing still proceeds on sourceCopy.

## Parser failure and status write

Parser false selects code `5`: ARM64 `0x136808..0x13684c`, x86_64
`0x13077f..0x1307cb`. The x86_64 common write at `0x13050a..0x130516` and
ARM64 store at `0x13684c` dereference the supplied status pointer without a
null check. A successful parse does not write status.

Thus the confirmed failure mapping is:

```text
source-copy malloc failure -> status 2, return false
triplet parser failure     -> status 5, return false
successful parser          -> status unchanged
```

## Query packing and range predicate

The parser output is three adjacent 32-bit values. The two range calls load
the first two as a 64-bit low/middle pair and the third as the high limb:

```cpp
uint64_t queryLow64 = uint64_t(component0)
                    | (uint64_t(component1) << 32);
uint32_t queryHigh32 = component2;
```

Calls are ARM64 `0x136854..0x136878` and x86_64
`0x13047b..0x1304c6`. `0x13716c`/x86_64 `0x130e77` returns its fifth input as
a non-null match cookie; this caller uses only nullness. The final combination
is explicit at ARM64 `0x13687c..0x136890` and x86_64
`0x1304d3..0x130501`:

```cpp
firstLookup == nullptr && secondLookup != nullptr
```

## Cleanup and return

The common ARM64 cleanup at `0x1369b0..0x1369bc` and x86_64 cleanup at
`0x1308cf..0x1308dc` release in this exact order:

```text
free(sourceCopy)
free(joinedResult)
```

Both use normal `free(nullptr)` behavior. ARM64 `0x1369d4..0x1369e0` and
x86_64 `0x1308f4..0x1308f8` mask the stored result to its low bit before
returning.

## C++ parity location

The recovered entry is `protectedAndroidMarkerRangeGate` in
`native-reimplementation/recovered_primitives.cpp`. Static regression cases
cover success with unchanged status/source, first-table hit, second-table miss,
and parser failure with status `5`. Allocation failure is represented in the
implementation but is not forced by an allocator test hook.
