# ARM64 string/range pipeline evidence

Target: `libsigner.so` SHA-256
`8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371`.

## `0x136a00..0x13716c`: string-array builder

Inputs at the only call site (`0x1363ac`) are:

- `x0`: the original `x6` saved by `0x135640`, a `char **`-shaped array;
- `x1`: the original `x7`, the element count;
- `x2`: `0x1460c8`, decoded once to the NUL-terminated delimiter `" "`.

### First pass and allocation

The flattened states implement:

```c
size_t allocation_size = 0;
for (size_t i = 0; i != count; ++i)
    allocation_size += strlen(strings[i]) + 1;
char *output = calloc(allocation_size + 1, 1);
```

Evidence locations:

- `0x136b6c`: zeroes the loop index;
- `0x136a30`: zeroes the accumulated length and saves `strings`;
- `0x136d8c..0x136da8`: compares the index to `count`;
- `0x136f84..0x1370b4`: calls `strlen`, adds its result and one, increments
  the index, and repeats;
- `0x136de0..0x136f04`: calls `calloc(total + 1, 1)` and returns null if it
  fails.

There is no null check for an individual string before `strlen` and no checked
integer-overflow path.

### Second pass

For every array element the native function performs two NUL-inclusive byte
copies.  Before each copy it rescans the output from its base to its current
NUL terminator.

1. `0x1370e8..0x137144` selects `strings[i]` and finds the current output end.
2. `0x136d50..0x136d70` copies the selected string byte by byte, including its
   terminating NUL; `0x136d0c..0x136d28` advances both cursors for nonzero
   bytes.
3. `0x136f08..0x136f24` scans the output again.
4. `0x136d2c..0x136d4c` selects the delimiter and current output end.
5. `0x136db8..0x136ddc` copies the delimiter including its NUL;
   `0x136f50..0x136f80` advances both cursors for nonzero bytes.
6. `0x136f28..0x136f4c` increments the element index and returns to the outer
   count check.

The delimiter copy is unconditional for each element.  Consequently the
decoded one-byte delimiter produces a trailing space:

```text
[]              -> ""
["a"]           -> "a "
["a", "b"]      -> "a b "
["alpha","","beta"] -> "alpha  beta "
```

The allocation reserves only one delimiter byte per element even though the
copy loop accepts an arbitrary NUL-terminated delimiter.  A delimiter longer
than one byte therefore has the same out-of-bounds-write risk in the native
function.  The recovered C++ intentionally does not add a behavior-changing
guard.

Implementation: `joinStringArrayWithTrailingDelimiter` in
`native-reimplementation/recovered_primitives.cpp`.

## Completed caller pipeline

`0x135640..0x136a00` is recovered at the caller-visible level.  Its edges are:

```text
decoded delimiter " "
        |
        v
0x136a00 string builder
        |
        v
0x12c12c large consumer
        |
        v
0x13716c range lookup (twice)
```

The two `0x13716c` calls and their final boolean combination are statically
visible.  At `0x13687c..0x136890` the native predicate explicitly forms:

```c
first_lookup == nullptr && second_lookup != nullptr
```

### Marker and parser structure

Cross-ABI static decoding closes the marker passed as the second argument to
`0x12c12c` as:

```text
android
```

On x86_64 it occupies `0x13b858..0x13b85f` before one-time decoding and is
XOR-decoded with `0xf3` at `0xee61..0xee72`; the call at `0xeb51` passes this
address.  ARM64 passes the corresponding encoded object at `0x142e88` from
`0x8658`.

The nearby independently decoded string at ARM64 `0x142e70` / x86_64
`0x13b840` is `ActivityPackageSender`; it is not the parser marker and must not
be used to name this pipeline.

`0x12c12c` has exactly three `strtol(..., 10)` calls:

```text
0x12db64 -> output +0x00
0x12e080 -> output +0x04
0x12de7c -> output +0x08
```

The flattened parser repeatedly checks byte `0x2e` (`'.'`) and contains two
ASCII case-fold comparison blocks at `0x12dcd4..0x12dcf4` and
`0x12e28c..0x12e2ac`.  Every conversion uses an end pointer, clears `errno`,
and rejects the `ERANGE` value `34`/no-consumption combinations.  Therefore
the output consumed by the range helper is a three-`uint32_t` decimal triplet,
located as `low`, `middle`, `high` limbs in the 96-bit query object.

The parser calls `__errno()` only once at `0x12db48`, clears the returned slot
at `0x12db54`, and reuses it for all three conversions.  Each conversion stores
the low 32 bits of the returned `long` before testing validity.  The common
validity rule is:

```c
end != start && *errno_slot != ERANGE /* 34 */
```

It does not reject other nonzero errno values.  Because the native operation
is `strtol` rather than a digit-only loop, leading whitespace and `+`/`-` retain
the C library behavior.  The third conversion computes the final result from
only the ERANGE and no-consumption checks at `0x12dea0..0x12ded0`; there is no
post-conversion end-of-string comparison in that success block.

The exact folded-byte and one-component conversion primitives are now present
in C++ as `foldProtectedAsciiMarkerByte`,
`protectedAsciiMarkerBytesEqual`, and `parseProtectedDecimalComponent`.

### Located component/terminator pairing

The three conversion starts and the three bytes overwritten with NUL are now
paired across ARM64 and x86_64:

| component | ARM64 start | ARM64 terminator | x86_64 start | x86_64 terminator |
|---:|---:|---:|---:|---:|
| 0 | `fp-0xb0` | `sp+0x28` | `sp+0x190` | `sp+0x198` |
| 1 | `sp+0xf0` | `sp+0x18` | `sp+0x170` | `sp+0x1a0` |
| 2 | `sp+0x108` | `sp+0x08` | `sp+0x178` | `sp+0x1a8` |

NUL writes and following conversions are:

```text
component 0 terminator: 0x12dddc -> strtol 0x12db64
component 1 terminator: 0x12daec -> strtol 0x12e080
component 2 terminator: 0x12de5c -> strtol 0x12de7c
```

For components 0 and 1 the terminator byte must be nonzero.  A nonzero byte is
overwritten and `terminator + 1` becomes a continuation guard; an already-NUL
byte leaves the guard null and makes that conversion stage fail.  Component 2
accepts an already-NUL terminator and otherwise overwrites it before parsing.

This complete post-location stage is implemented as
`parseProtectedLocatedDecimalTriplet`.  The scanner, conversion ordering and
partial mutation behavior are closed in `arm64-12c12c-complete-parser.md` and
implemented by `parseProtectedAndroidTriplet`.

The caller's nine-argument ABI, source allocation/copy, unconditional join,
status `2`/`5` failure paths, two range calls, final predicate and cleanup are
closed in `arm64-135640-complete-gate.md` and implemented by
`protectedAndroidMarkerRangeGate`.  Both `0x135640` and `0x12c12c` are now
classified as **recovered**; this does not imply that the whole SO is complete.
